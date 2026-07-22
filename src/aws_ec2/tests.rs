use std::{
    fs,
    io::Cursor,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use serde_json::Value;
use tempfile::TempDir;

use super::{
    bundle::{InstallRequest, InstalledReceipt, ReceiptState, StackFile, StackManifest, hash},
    store::Store,
    *,
};

const INSTALLER: &str = "dirextalk-vnext-stack/usr/local/libexec/dirextalk/install-vnext";
const READER: &str = "dirextalk-vnext-stack/usr/local/libexec/dirextalk/read-vnext-receipt";

fn append(builder: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, bytes: &[u8]) {
    let mut header = tar::Header::new_gnu();
    header.set_mode(mode);
    header.set_size(u64::try_from(bytes.len()).expect("size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, Cursor::new(bytes))
        .expect("append fixture");
}

fn fixture(version: &str, server_digest: char) -> (TempDir, AwsEc2Manifest) {
    let dir = TempDir::new().expect("tempdir");
    let installer = b"#!/bin/sh\nexit 0\n";
    let reader = b"#!/bin/sh\nexit 0\n";
    let mut files = vec![
        StackFile {
            path: INSTALLER.into(),
            sha256: hash(installer),
            mode: 0o555,
        },
        StackFile {
            path: READER.into(),
            sha256: hash(reader),
            mode: 0o555,
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest = StackManifest {
        schema: "dirextalk.vnext-stack-bundle".into(),
        schema_version: 1,
        version: version.into(),
        source_commit: "d".repeat(40),
        target: "linux-amd64".into(),
        server: format!(
            "dirextalk/vnet-server@sha256:{}",
            server_digest.to_string().repeat(64)
        ),
        migrator: format!("dirextalk/vnet-server@sha256:{}", "c".repeat(64)),
        installer_sha256: hash(installer),
        files,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).expect("manifest");
    let mut tar = tar::Builder::new(Vec::new());
    append(&mut tar, INSTALLER, 0o555, installer);
    append(&mut tar, READER, 0o555, reader);
    append(
        &mut tar,
        "dirextalk-vnext-stack/manifest.json",
        0o444,
        &manifest_bytes,
    );
    let bytes = tar.into_inner().expect("tar");
    let bundle_path = dir.path().join("vnext.tar");
    fs::write(&bundle_path, &bytes).expect("bundle");
    let outer = AwsEc2Manifest {
        schema_version: 1,
        target: "x6".into(),
        provider: PROVIDER.into(),
        region: REGION.into(),
        domain: "x6.example.invalid".into(),
        instance_type: "t3.small".into(),
        disk_gib: 30,
        operator_ssh_cidr: "203.0.113.9/32".into(),
        stack_bundle_sha256: hash(&bytes),
        stack_bundle_path: bundle_path,
        release_version: version.into(),
        source_commit: "d".repeat(40),
        server_image: manifest.server,
        migrator_image: manifest.migrator,
        ubuntu_ami_owner: UBUNTU_OWNER.into(),
        ubuntu_ami_pattern: UBUNTU_PATTERN.into(),
        key_name: "x6-key".into(),
    };
    (dir, outer)
}

struct Never(AtomicUsize);

impl AwsExecutor for Never {
    fn run(&self, _: &FixedCommand) -> Result<ExecOutput> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Err(contract("unexpected executor call"))
    }
}

struct Registry(&'static str);

impl RegistryExecutor for Registry {
    fn inspect_latest(&self) -> Result<ExecOutput> {
        Ok(ExecOutput {
            status: 0,
            stdout: self.0.into(),
            stderr: String::new(),
        })
    }
}

struct Identity;

impl AwsExecutor for Identity {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        assert_eq!(command.id, "verify-caller-account");
        Ok(ExecOutput {
            status: 0,
            stdout: "{\"Account\":\"123456789012\"}".into(),
            stderr: String::new(),
        })
    }
}

fn receipt_for(request: &InstallRequest, state: ReceiptState) -> InstalledReceipt {
    let mut receipt = InstalledReceipt {
        schema: "dirextalk.vnext-installed-release".into(),
        schema_version: 1,
        state,
        target: request.target.clone(),
        domain: request.domain.clone(),
        version: request.version.clone(),
        source_commit: request.source_commit.clone(),
        bundle_sha256: request.bundle_sha256.clone(),
        manifest_sha256: request.manifest_sha256.clone(),
        server_image: request.server_image.clone(),
        migrator_image: request.migrator_image.clone(),
        previous_receipt_sha256: request.previous_receipt_sha256.clone(),
        installed_at_ms: 1,
        receipt_sha256: String::new(),
    };
    let mut canonical: Value = serde_json::to_value(&receipt).expect("value");
    canonical
        .as_object_mut()
        .expect("object")
        .remove("receipt_sha256");
    receipt.receipt_sha256 = hash(&serde_json::to_vec(&canonical).expect("canonical"));
    receipt
}

#[test]
fn bundle_manifest_and_dry_run_are_digest_bound_without_effects() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let plan = plan(&manifest, Some(100)).expect("plan");
    assert_eq!(plan.region, REGION);
    assert_eq!(plan.ingress.len(), 3);
    assert!(
        plan.ingress
            .iter()
            .any(|rule| { rule.from_port == 22 && rule.cidr == "203.0.113.9/32" })
    );
    let executor = Never(AtomicUsize::new(0));
    let state =
        apply(&manifest, &dir.path().join("state"), 100, false, &executor).expect("dry-run state");
    assert_eq!(state.phase, LifecyclePhase::Planned);
    assert_eq!(executor.0.load(Ordering::Relaxed), 0);
    state.verify().expect("integrity-sealed state");
}

#[test]
fn bundle_tampering_and_mutable_images_fail_closed() {
    let (_dir, mut manifest) = fixture("1.2.3", 'a');
    fs::write(&manifest.stack_bundle_path, b"tampered").expect("tamper");
    assert!(manifest.bundle().is_err());
    manifest.server_image = "dirextalk/vnet-server:latest".into();
    assert!(manifest.validate().is_err());
}

#[test]
fn latest_discovery_selects_exact_linux_amd64_and_rejects_ambiguity() {
    let digest = format!("sha256:{}", "a".repeat(64));
    let body = format!(
        "{{\"manifests\":[{{\"digest\":\"{digest}\",\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}},{{\"digest\":\"sha256:{}\",\"platform\":{{\"os\":\"linux\",\"architecture\":\"arm64\"}}}}]}}",
        "b".repeat(64)
    );
    assert_eq!(
        resolve_latest_digest(&Registry(Box::leak(body.into_boxed_str()))).expect("digest"),
        digest
    );
    let duplicate = format!(
        "{{\"manifests\":[{{\"digest\":\"{digest}\",\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}},{{\"digest\":\"{digest}\",\"platform\":{{\"os\":\"linux\",\"architecture\":\"amd64\"}}}}]}}"
    );
    assert!(resolve_latest_digest(&Registry(Box::leak(duplicate.into_boxed_str()))).is_err());
    assert!(resolve_latest_digest(&Registry("not-json")).is_err());
}

#[test]
fn registry_failures_are_classified_without_echoing_secrets() {
    assert!(
        classify_registry_failure("401 UNAUTHORIZED token=secret")
            .to_string()
            .contains("authentication failed")
    );
    assert!(
        classify_registry_failure("TOO MANY REQUESTS")
            .to_string()
            .contains("rate limited")
    );
    assert!(
        !classify_registry_failure("token=secret")
            .to_string()
            .contains("secret")
    );
}

#[test]
fn receipt_is_bound_to_request_and_canonical_self_hash() {
    let (_dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let request = InstallRequest::new("x6", "x6.example.invalid", &facts, None);
    let mut receipt = receipt_for(&request, ReceiptState::Installed);
    let bytes = serde_json::to_vec(&receipt).expect("receipt");
    InstalledReceipt::parse_and_verify(&bytes, &request, ReceiptState::Installed)
        .expect("valid receipt");
    receipt.server_image = format!("dirextalk/vnet-server@sha256:{}", "f".repeat(64));
    assert!(
        InstalledReceipt::parse_and_verify(
            &serde_json::to_vec(&receipt).expect("bad receipt"),
            &request,
            ReceiptState::Installed,
        )
        .is_err()
    );
}

#[test]
fn update_uses_explicit_digest_and_cross_version_fails_closed() {
    let (old_dir, old) = fixture("1.2.3", 'a');
    let old_facts = old.bundle().expect("old facts");
    let old_request = InstallRequest::new("x6", "x6.example.invalid", &old_facts, None);
    let state_dir = old_dir.path().join("state");
    let mut state =
        apply(&old, &state_dir, 100, false, &Never(AtomicUsize::new(0))).expect("state");
    state.account_id = Some("123456789012".into());
    state.current = Some(BundleRecord::from_facts(&old_facts));
    state.current_receipt = Some(receipt_for(&old_request, ReceiptState::Installed));
    state.current_bundle_suffix = Some("current.bundle".into());
    state.current_request_suffix = Some("current.request".into());
    state.phase = LifecyclePhase::Verified;
    state = state.seal().expect("seal");
    Store::lock(&state_dir, "x6")
        .expect("store")
        .write(&state)
        .expect("write state");

    let (_same_dir, same_version) = fixture("1.2.3", 'b');
    update(&same_version, &state_dir, false, &Identity).expect("explicit digest plan");

    let (_new_dir, cross_version) = fixture("2.0.0", 'b');
    let error = update(&cross_version, &state_dir, false, &Identity)
        .expect_err("unsupported cross-version update");
    assert!(
        error
            .to_string()
            .contains("cross-version update is unsupported")
    );
}

#[cfg(unix)]
#[test]
fn process_deadline_is_bounded() {
    let error = run_process("sleep", &["1"], Duration::from_millis(20)).expect_err("timeout");
    assert!(error.to_string().contains("deadline exceeded"));
}
