use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;
use tempfile::TempDir;

use super::{
    bundle::{InstallRequest, InstalledReceipt, ReceiptState, StackFile, StackManifest, hash},
    provision::{HostReadyReceipt, ProvisionRequest},
    store::Store,
    *,
};

const STACK_INSTALLER: &str = "scripts/production-stack/install.sh";

fn canonical(value: &impl Serialize) -> Vec<u8> {
    let mut bytes =
        serde_json::to_vec(&serde_json::to_value(value).expect("value")).expect("canonical JSON");
    bytes.push(b'\n');
    bytes
}

#[test]
fn derived_public_key_accepts_openssh_comment_only_when_identity_matches() {
    let key = STANDARD.encode([7_u8; 32]);
    let comment = "dirextalk:x6:019f89e7-47ef-7ed3-b8e8-de8d31e8f99e";
    workflow::validate_derived_public_key(
        &format!("ssh-ed25519 {key}\n"),
        "ssh-ed25519",
        &key,
        comment,
    )
    .expect("comment-free output");
    workflow::validate_derived_public_key(
        &format!("ssh-ed25519 {key} {comment}\n"),
        "ssh-ed25519",
        &key,
        comment,
    )
    .expect("OpenSSH comment output");
    assert!(
        workflow::validate_derived_public_key(
            &format!("ssh-ed25519 {key} dirextalk:x7:different\n"),
            "ssh-ed25519",
            &key,
            comment,
        )
        .is_err()
    );
}

fn append_directory(builder: &mut tar::Builder<Vec<u8>>, path: &str) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o555);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_data(&mut header, format!("{path}/"), Cursor::new([]))
        .expect("append directory");
}

fn append_file(builder: &mut tar::Builder<Vec<u8>>, path: &str, mode: u32, bytes: &[u8]) {
    let mut header = tar::Header::new_ustar();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(u64::try_from(bytes.len()).expect("size"));
    header.set_cksum();
    builder
        .append_data(&mut header, path, Cursor::new(bytes))
        .expect("append file");
}

fn fixture_with_directories(
    version: &str,
    server_digest: char,
    include_all_directories: bool,
) -> (TempDir, AwsEc2Manifest) {
    let dir = TempDir::new().expect("tempdir");
    let stack_installer = b"#!/bin/sh\nexit 0\n";
    let compose = b"services: {}\n";
    let host_installer = b"#!/usr/bin/env python3\nprint('install')\n";
    let host_provisioner = b"#!/usr/bin/env python3\nprint('provision')\n";
    let receipt_reader = b"#!/usr/bin/env python3\nprint('{}')\n";
    let files = vec![
        StackFile {
            path: "docker/production/docker-compose.yml".into(),
            sha256: hash(compose),
            mode: "0444".into(),
        },
        StackFile {
            path: STACK_INSTALLER.into(),
            sha256: hash(stack_installer),
            mode: "0555".into(),
        },
    ];
    let manifest = StackManifest {
        schema: "dirextalk.vnext-stack-bundle".into(),
        schema_version: 1,
        version: version.into(),
        source_commit: "d".repeat(40),
        target: "linux-amd64".into(),
        server_image: format!(
            "dirextalk/vnet-server@sha256:{}",
            server_digest.to_string().repeat(64)
        ),
        migrator_image: format!("dirextalk/vnet-server@sha256:{}", "c".repeat(64)),
        installer_sha256: hash(stack_installer),
        files,
    };
    let mut tar = tar::Builder::new(Vec::new());
    append_directory(&mut tar, "dirextalk-vnext-stack");
    if include_all_directories {
        append_directory(&mut tar, "dirextalk-vnext-stack/docker");
        append_directory(&mut tar, "dirextalk-vnext-stack/docker/production");
        append_directory(&mut tar, "dirextalk-vnext-stack/scripts");
        append_directory(&mut tar, "dirextalk-vnext-stack/scripts/production-stack");
    }
    append_file(
        &mut tar,
        "dirextalk-vnext-stack/manifest.json",
        0o444,
        &canonical(&manifest),
    );
    append_file(
        &mut tar,
        "dirextalk-vnext-stack/docker/production/docker-compose.yml",
        0o444,
        compose,
    );
    append_file(
        &mut tar,
        "dirextalk-vnext-stack/scripts/production-stack/install.sh",
        0o555,
        stack_installer,
    );
    let bundle = tar.into_inner().expect("tar");
    let bundle_path = dir.path().join("dirextalk-vnext.bundle");
    let host_installer_path = dir.path().join("install-vnext");
    let host_provisioner_path = dir.path().join("provision-vnext");
    let receipt_reader_path = dir.path().join("read-vnext-receipt");
    fs::write(&bundle_path, &bundle).expect("bundle");
    fs::write(&host_installer_path, host_installer).expect("host installer");
    fs::write(&host_provisioner_path, host_provisioner).expect("host provisioner");
    fs::write(&receipt_reader_path, receipt_reader).expect("receipt reader");
    let outer = AwsEc2Manifest {
        schema_version: 1,
        target: "x6".into(),
        provider: PROVIDER.into(),
        region: REGION.into(),
        domain: "x6.example.invalid".into(),
        instance_type: "t3.small".into(),
        disk_gib: 30,
        operator_ssh_cidr: "203.0.113.9/32".into(),
        stack_bundle_sha256: hash(&bundle),
        stack_bundle_path: bundle_path,
        host_installer_path,
        host_installer_sha256: hash(host_installer),
        host_provisioner_path,
        host_provisioner_sha256: hash(host_provisioner),
        receipt_reader_path,
        receipt_reader_sha256: hash(receipt_reader),
        release_version: version.into(),
        source_commit: "d".repeat(40),
        server_image: manifest.server_image,
        migrator_image: manifest.migrator_image,
        postgres_image: format!("postgres@sha256:{}", "1".repeat(64)),
        caddy_image: format!("caddy@sha256:{}", "2".repeat(64)),
        probe_image: format!("curlimages/curl@sha256:{}", "3".repeat(64)),
        ubuntu_ami_owner: UBUNTU_OWNER.into(),
        ubuntu_ami_pattern: UBUNTU_PATTERN.into(),
        key_name: "x6-key".into(),
    };
    (dir, outer)
}

fn fixture(version: &str, server_digest: char) -> (TempDir, AwsEc2Manifest) {
    fixture_with_directories(version, server_digest, true)
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

struct ObservePending {
    state_path: PathBuf,
    phase: LifecyclePhase,
}

struct ExistingReceipt {
    receipt: String,
    calls: Mutex<Vec<String>>,
}

impl AwsExecutor for ExistingReceipt {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        self.calls.lock().expect("calls").push(command.id.clone());
        let stdout = match command.id.as_str() {
            "inspect-current-installed-receipt" => format!(
                "f root root 600 1 {} {}\n",
                self.receipt.len(),
                REMOTE_CURRENT_RECEIPT
            ),
            "read-existing-installed-receipt" => self.receipt.clone(),
            _ => return Err(contract("unexpected effect after existing receipt")),
        };
        Ok(ExecOutput {
            status: 0,
            stdout,
            stderr: String::new(),
        })
    }
}

impl AwsExecutor for ObservePending {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        let state: Ec2State = serde_json::from_slice(
            &fs::read(&self.state_path).expect("state persisted before executor"),
        )
        .expect("persisted state JSON");
        state.verify().expect("persisted state integrity");
        assert_eq!(state.phase, self.phase);
        assert_eq!(state.pending_effect.as_deref(), Some(command.id.as_str()));
        Ok(ExecOutput::default())
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
        installed_at_ms: 0,
        receipt_sha256: String::new(),
    };
    let mut body: Value = serde_json::to_value(&receipt).expect("value");
    body.as_object_mut()
        .expect("object")
        .remove("receipt_sha256");
    receipt.receipt_sha256 = hash(&canonical(&body));
    receipt
}

#[test]
fn bundle_manifest_and_dry_run_are_digest_bound_without_effects() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let plan = plan(&manifest, Some(100)).expect("plan");
    assert_eq!(plan.region, REGION);
    assert_eq!(plan.ingress.len(), 4);
    assert!(plan.ingress.iter().any(|rule| rule.from_port == 80));
    assert!(
        plan.ingress
            .iter()
            .any(|rule| rule.from_port == 22 && rule.cidr == "203.0.113.9/32")
    );
    let executor = Never(AtomicUsize::new(0));
    let state =
        apply(&manifest, &dir.path().join("state"), 100, false, &executor).expect("dry run");
    assert_eq!(state.phase, LifecyclePhase::Planned);
    assert_eq!(executor.0.load(Ordering::Relaxed), 0);
    state.verify().expect("integrity-sealed state");
}

#[test]
fn missing_derived_directory_and_helper_tamper_fail_closed() {
    let (_dir, missing_directory) = fixture_with_directories("1.2.3", 'a', false);
    assert!(missing_directory.bundle().is_err());

    let (_dir, helper_tamper) = fixture("1.2.3", 'a');
    fs::write(&helper_tamper.host_installer_path, b"tampered").expect("tamper helper");
    assert!(helper_tamper.bundle().is_err());
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
fn request_and_receipt_match_canonical_host_contract() {
    let (_dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let request = InstallRequest::new("x6.example.invalid", &facts, None);
    assert_eq!(request.target, "linux-amd64");
    assert_eq!(
        request.canonical_bytes().expect("request"),
        canonical(&request)
    );
    let mut receipt = receipt_for(&request, ReceiptState::Installed);
    InstalledReceipt::parse_and_verify(&canonical(&receipt), &request, ReceiptState::Installed)
        .expect("valid receipt");
    receipt.server_image = format!("dirextalk/vnet-server@sha256:{}", "f".repeat(64));
    assert!(
        InstalledReceipt::parse_and_verify(
            &canonical(&receipt),
            &request,
            ReceiptState::Installed,
        )
        .is_err()
    );
}

#[test]
fn provision_request_and_ready_receipt_are_exact_and_self_authenticating() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let mut state = apply(
        &manifest,
        &dir.path().join("state"),
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("dry state");
    state.private_ipv4 = Some("10.0.0.7".into());
    let request = ProvisionRequest::new(&manifest, &state, &facts).expect("request");
    let request_bytes = request.canonical_bytes().expect("canonical request");
    assert_eq!(request_bytes, canonical(&request));
    assert_eq!(
        ProvisionRequest::parse_and_verify(&request_bytes).expect("parsed request"),
        request
    );
    assert_eq!(request.target, "x6");
    assert_eq!(request.private_ipv4, "10.0.0.7");

    let mut ready = HostReadyReceipt {
        schema: "dirextalk.vnext-host-provision-ready".into(),
        schema_version: 1,
        state: "ready".into(),
        request_sha256: request.sha256().expect("request digest"),
        target: request.target.clone(),
        domain: request.domain.clone(),
        tenant_id: request.tenant_id.clone(),
        indexer_id: request.indexer_id.clone(),
        release_version: request.release_version.clone(),
        bundle_sha256: request.bundle_sha256.clone(),
        compose_sha256: request.compose_sha256.clone(),
        receipt_sha256: String::new(),
    };
    let mut body = serde_json::to_value(&ready).expect("receipt body");
    body.as_object_mut()
        .expect("receipt object")
        .remove("receipt_sha256");
    ready.receipt_sha256 = hash(&canonical(&body));
    HostReadyReceipt::parse_and_verify(&canonical(&ready), &request).expect("ready receipt");
    ready.compose_sha256 = "f".repeat(64);
    assert!(HostReadyReceipt::parse_and_verify(&canonical(&ready), &request).is_err());
}

#[test]
fn cloud_init_fits_ec2_limit_and_contains_no_helpers_or_provision_secrets() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let mut state = apply(
        &manifest,
        &dir.path().join("state"),
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("dry state");
    state.ami = Some(AmiRecord {
        image_id: "ami-0123456789abcdef0".into(),
        name: "ubuntu-noble".into(),
        creation_date: "2026-01-01T00:00:00Z".into(),
        owner_id: UBUNTU_OWNER.into(),
        architecture: "x86_64".into(),
        root_device_type: "ebs".into(),
        virtualization_type: "hvm".into(),
    });
    let user_data = workflow::cloud_init(&state).expect("cloud-init");
    assert!(user_data.len() <= 16 * 1024);
    for helper in [
        &facts.host_installer,
        &facts.host_provisioner,
        &facts.receipt_reader,
    ] {
        assert!(!user_data.contains(&STANDARD.encode(helper)));
        assert!(!user_data.contains(std::str::from_utf8(helper).expect("fixture helper UTF-8")));
    }
    for forbidden in [
        REMOTE_INSTALLER,
        REMOTE_PROVISIONER,
        REMOTE_RECEIPT_READER,
        state.tenant_id.as_str(),
        state.indexer_id.as_str(),
        state.domain.as_str(),
    ] {
        assert!(!user_data.contains(forbidden));
    }
}

#[test]
fn update_mutation_and_cross_version_fail_closed_without_effects() {
    let (old_dir, old) = fixture("1.2.3", 'a');
    let old_facts = old.bundle().expect("old facts");
    let old_request = InstallRequest::new("x6.example.invalid", &old_facts, None);
    let state_dir = old_dir.path().join("state");
    let mut state =
        apply(&old, &state_dir, 100, false, &Never(AtomicUsize::new(0))).expect("state");
    state.account_id = Some("123456789012".into());
    state.current = Some(BundleRecord::from_facts(&old_facts, &old));
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
    let executor = Never(AtomicUsize::new(0));
    let error = update(&same_version, &state_dir, true, &executor)
        .expect_err("update mutation remains disabled");
    assert!(error.to_string().contains("update mutation is disabled"));
    assert_eq!(executor.0.load(Ordering::Relaxed), 0);

    let (_new_dir, cross_version) = fixture("2.0.0", 'b');
    let error = update(&cross_version, &state_dir, false, &Identity)
        .expect_err("unsupported cross-version update");
    assert!(
        error
            .to_string()
            .contains("cross-version update is unsupported")
    );
}

fn remote_file(
    owner: &str,
    group: &str,
    mode: &str,
    size: usize,
    path: &str,
) -> workflow::RemoteFileMetadata {
    workflow::RemoteFileMetadata {
        kind: "f".into(),
        owner: owner.into(),
        group: group.into(),
        mode: mode.into(),
        links: "1".into(),
        size,
        path: path.into(),
    }
}

#[test]
fn install_input_crash_windows_reconcile_exactly() {
    use workflow::InstallInputState;

    let path = REMOTE_BUNDLE;
    let size = 61_440;
    assert_eq!(
        workflow::classify_install_input(None, path, size).expect("absent"),
        InstallInputState::Absent
    );
    for (owner, group, mode, expected) in [
        ("ubuntu", "ubuntu", "600", InstallInputState::UbuntuStaged),
        (
            "ubuntu",
            "ubuntu",
            "400",
            InstallInputState::UbuntuProtected,
        ),
        ("root", "root", "400", InstallInputState::RootProtected),
    ] {
        let metadata = remote_file(owner, group, mode, size, path);
        assert_eq!(
            workflow::classify_install_input(Some(&metadata), path, size).expect("crash window"),
            expected
        );
    }
    for metadata in [
        remote_file("root", "root", "600", size, path),
        remote_file("ubuntu", "ubuntu", "644", size, path),
        remote_file("root", "root", "400", size + 1, path),
        workflow::RemoteFileMetadata {
            kind: "l".into(),
            ..remote_file("root", "root", "400", size, path)
        },
        workflow::RemoteFileMetadata {
            links: "2".into(),
            ..remote_file("root", "root", "400", size, path)
        },
    ] {
        assert!(workflow::classify_install_input(Some(&metadata), path, size).is_err());
    }
}

#[test]
fn initial_install_resume_accepts_exact_post_effect_receipt_without_reinstall() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let request = InstallRequest::new(&manifest.domain, &facts, None);
    let receipt = canonical(&receipt_for(&request, ReceiptState::Installed));
    let executor = ExistingReceipt {
        receipt: String::from_utf8(receipt).expect("receipt UTF-8"),
        calls: Mutex::new(Vec::new()),
    };
    let state_dir = dir.path().join("post-effect");
    let mut state = apply(
        &manifest,
        &state_dir,
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("state");
    state.eip = Some(EipRecord {
        allocation_id: "eipalloc-1".into(),
        association_id: "eipassoc-1".into(),
        public_ip: "203.0.113.8".into(),
    });
    let store = Store::lock(&state_dir, "x6").expect("store");
    let actual = workflow::stage_install_read_receipt(
        &store,
        &mut state,
        "missing.bundle",
        "missing.request",
        &request,
        ReceiptState::Installed,
        &executor,
    )
    .expect("resume receipt");
    assert_eq!(actual.bundle_sha256, request.bundle_sha256);
    assert_eq!(
        *executor.calls.lock().expect("calls"),
        vec![
            "inspect-current-installed-receipt".to_owned(),
            "read-existing-installed-receipt".to_owned(),
        ]
    );
}

#[test]
fn lifecycle_state_is_persisted_before_every_effect() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let state_dir = dir.path().join("effect-state");
    let mut state = apply(
        &manifest,
        &state_dir,
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("dry state");
    state.phase = LifecyclePhase::Provisioning;
    state = state.seal().expect("seal");
    let store = Store::lock(&state_dir, "x6").expect("store");
    store.write(&state).expect("initial state");
    let observer = ObservePending {
        state_path: store.state_path(),
        phase: LifecyclePhase::Provisioning,
    };
    let command = FixedCommand::new("fixed-test-effect", "fixed-test", ["arg"], true, 1);
    workflow::run_effect(&store, &mut state, &command, &observer).expect("effect");
    assert_eq!(state.pending_effect, None);
    let persisted: Ec2State =
        serde_json::from_slice(&fs::read(store.state_path()).expect("state after effect"))
            .expect("state JSON");
    assert_eq!(persisted.pending_effect, None);
}

#[test]
fn apply_and_resume_reject_update_and_destroy_states_before_effects() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let executor = Never(AtomicUsize::new(0));
    for (index, phase) in [
        LifecyclePhase::UpdateStaged,
        LifecyclePhase::UpdateInstalling,
        LifecyclePhase::RollbackInstalling,
        LifecyclePhase::Destroying,
        LifecyclePhase::InfrastructureRemovedVolumeRetained,
        LifecyclePhase::VolumePurged,
    ]
    .into_iter()
    .enumerate()
    {
        let state_dir = dir.path().join(format!("terminal-{index}"));
        let mut state = apply(&manifest, &state_dir, 100, false, &executor).expect("dry state");
        state.phase = phase;
        state = state.seal().expect("seal");
        Store::lock(&state_dir, "x6")
            .expect("store")
            .write(&state)
            .expect("state");
        assert!(apply(&manifest, &state_dir, 100, true, &executor).is_err());
        assert!(resume(&manifest, &state_dir, 100, true, &executor).is_err());
    }
    assert_eq!(executor.0.load(Ordering::Relaxed), 0);
}

#[test]
fn terminalization_clears_remote_authentication_evidence() {
    let (dir, manifest) = fixture("1.2.3", 'a');
    let facts = manifest.bundle().expect("facts");
    let request = InstallRequest::new(&manifest.domain, &facts, None);
    let mut state = apply(
        &manifest,
        &dir.path().join("state"),
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("state");
    state.host_key = Some(HostKeyRecord {
        algorithm: "ssh-ed25519".into(),
        key_base64: "AAAA".into(),
        key_sha256: "a".repeat(64),
        console_line_sha256: "b".repeat(64),
        known_hosts_suffix: "known_hosts".into(),
    });
    let receipt = receipt_for(&request, ReceiptState::Installed);
    state.current_receipt = Some(receipt.clone());
    state.previous_receipt = Some(receipt.clone());
    state.rollback_receipt = Some(receipt);
    workflow::clear_terminal_runtime_evidence(&mut state);
    assert!(state.host_key.is_none());
    assert!(state.current_receipt.is_none());
    assert!(state.previous_receipt.is_none());
    assert!(state.rollback_receipt.is_none());
    assert!(state.host_ready_receipt.is_none());
}

#[test]
fn real_server_bundle_5bf0090_parses_and_plans() {
    let server = Path::new("/home/adam/dirextalk/dirextalk-vnext-server");
    let bundle = server.join("target/production-release/dirextalk-vnext.bundle");
    let installer = server.join("scripts/production-stack/host/install-vnext");
    let reader = server.join("scripts/production-stack/host/read-vnext-receipt");
    let provisioner = server.join("scripts/production-stack/host/provision-vnext");
    assert!(bundle.is_file() && installer.is_file() && provisioner.is_file() && reader.is_file());
    let manifest = AwsEc2Manifest {
        schema_version: 1,
        target: "x6".into(),
        provider: PROVIDER.into(),
        region: REGION.into(),
        domain: "x6.example.invalid".into(),
        instance_type: "t3.small".into(),
        disk_gib: 30,
        operator_ssh_cidr: "203.0.113.9/32".into(),
        stack_bundle_sha256:
            "5539fe5a2c1a836e352fcf6216378ca10391de6dcd8821240d3e50c1db2a2275".into(),
        stack_bundle_path: bundle,
        host_installer_path: installer,
        host_installer_sha256:
            "7deda8b33531bef1f1564f0b68b07ff12d6a2deceaf312cf98529998a207cc84".into(),
        host_provisioner_path: provisioner,
        host_provisioner_sha256:
            "21a67bea150a2466a7ce22f0f2cdb234fde901539ea62a18a1471616b3e645c3".into(),
        receipt_reader_path: reader,
        receipt_reader_sha256:
            "0d4ddcc5fdf4906d010a441c33031a1c16530f5d6ab3e66db005c1c7f7b8f17b".into(),
        release_version: "0.1.0".into(),
        source_commit: "5bf0090621c90a68936ecf174e96a0e20654f688".into(),
        server_image:
            "dirextalk/vnet-server@sha256:c396239cd8df60fef0c7e1e320f03c032fc634febfdee4e3700c122518698e74".into(),
        migrator_image:
            "dirextalk/vnet-server@sha256:7f630952d9651db0b3a488ea174de6eb6f5d75a2d35a8e27343b51ffd0a3cc5e".into(),
        postgres_image:
            "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15".into(),
        caddy_image:
            "caddy@sha256:ae4458638da8e1a91aafffb231c5f8778e964bca650c8a8cb23a7e8ac557aa3c".into(),
        probe_image:
            "curlimages/curl@sha256:9a1ed35addb45476afa911696297f8e115993df459278ed036182dd2cd22b67b".into(),
        ubuntu_ami_owner: UBUNTU_OWNER.into(),
        ubuntu_ami_pattern: UBUNTU_PATTERN.into(),
        key_name: "x6-key".into(),
    };
    assert_eq!(
        manifest.bundle().expect("real bundle").manifest.files.len(),
        17
    );
    assert_eq!(
        plan(&manifest, Some(100)).expect("real plan").ingress.len(),
        4
    );
}

#[cfg(unix)]
#[test]
fn process_deadline_is_bounded() {
    let error = run_process("sleep", &["1"], Duration::from_millis(20)).expect_err("timeout");
    assert!(error.to_string().contains("deadline exceeded"));
}
