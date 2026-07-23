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
use serde_json::{Value, json};
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

#[test]
fn ed25519_fingerprint_matches_aws_padding_and_openssh_prefix() {
    let digest = [13_u8; 32];
    let aws = STANDARD.encode(digest);
    let openssh = format!("SHA256:{}", aws.trim_end_matches('='));
    assert!(workflow::fingerprints_match(&aws, &openssh).expect("same digest"));
    assert!(workflow::fingerprints_match(&aws, "not-base64").is_err());
    assert!(
        workflow::fingerprints_match(&format!("{aws}="), &openssh).is_err(),
        "noncanonical padding must fail closed"
    );
}

#[test]
fn console_output_accepts_aws_cli_raw_text_and_canonical_blob_json() {
    let raw = "boot\nDTXHK01 instance token ami ssh-ed25519 key\nready\n";
    assert_eq!(workflow::decode_console_output(raw).expect("raw"), raw);
    let encoded = STANDARD.encode(raw);
    assert_eq!(
        workflow::decode_console_output(&encoded).expect("encoded"),
        raw
    );
    assert!(workflow::decode_console_output("not encoded and no attestation").is_err());
}

#[test]
fn remote_ssh_command_preserves_fixed_argument_boundaries() {
    assert_eq!(
        workflow::render_remote_command([
            "/usr/bin/find",
            "/usr/local/libexec/dirextalk",
            "-printf",
            "%y %u %g %m %n %s %p\\n",
            "a'b",
        ])
        .expect("render"),
        "'/usr/bin/find' '/usr/local/libexec/dirextalk' '-printf' '%y %u %g %m %n %s %p\\n' 'a'\"'\"'b'"
    );
    assert!(workflow::render_remote_command(["line\nbreak"]).is_err());
    assert!(workflow::render_remote_command::<0>([]).is_err());
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
        cross_version_compatibility: matches!(version, "0.1.1" | "0.1.4").then(|| {
            bundle::CrossVersionCompatibility {
                schema: "dirextalk.vnext.cross-version-compatibility".into(),
                schema_version: 1,
                retained_version: "0.1.1".into(),
                candidate_version: "0.1.4".into(),
                forward_migrations_only: true,
                code_only_rollback: true,
            }
        }),
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

#[derive(Clone, Copy)]
enum SshIngressShape {
    Old,
    Both,
    New,
}

struct RebindExecutor {
    state: Mutex<SshIngressShape>,
    revoke_converges: bool,
    group: Value,
    calls: Mutex<Vec<String>>,
}

impl RebindExecutor {
    fn new(state: &Ec2State, shape: SshIngressShape, owned: bool) -> Self {
        Self::with_revoke_convergence(state, shape, owned, true)
    }

    fn with_revoke_convergence(
        state: &Ec2State,
        shape: SshIngressShape,
        owned: bool,
        revoke_converges: bool,
    ) -> Self {
        let tags = if owned {
            state
                .ownership_tags
                .iter()
                .map(|(key, value)| json!({"Key": key, "Value": value}))
                .collect()
        } else {
            vec![json!({"Key":"DirextalkManaged","Value":"false"})]
        };
        Self {
            state: Mutex::new(shape),
            revoke_converges,
            group: json!({
                "GroupId": state.security_group_id,
                "VpcId": state.vpc_id,
                "Tags": tags,
            }),
            calls: Mutex::new(Vec::new()),
        }
    }

    fn ingress(shape: SshIngressShape) -> Value {
        let mut rules = vec![
            json!({"IpProtocol":"tcp","FromPort":80,"ToPort":80,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk ACME HTTP challenge"}]}),
            json!({"IpProtocol":"tcp","FromPort":443,"ToPort":443,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk public HTTPS"}]}),
            json!({"IpProtocol":"tcp","FromPort":9443,"ToPort":9445,"IpRanges":[{"CidrIp":"0.0.0.0/0","Description":"Dirextalk Agent Control TLS"}]}),
        ];
        let operator_ranges = match shape {
            SshIngressShape::Old => {
                vec![json!({"CidrIp":"203.0.113.9/32","Description":"Dirextalk operator SSH"})]
            }
            SshIngressShape::Both => vec![
                json!({"CidrIp":"203.0.113.9/32","Description":"Dirextalk operator SSH"}),
                json!({"CidrIp":"198.51.100.7/32","Description":"Dirextalk operator SSH"}),
            ],
            SshIngressShape::New => {
                vec![json!({"CidrIp":"198.51.100.7/32","Description":"Dirextalk operator SSH"})]
            }
        };
        rules
            .push(json!({"IpProtocol":"tcp","FromPort":22,"ToPort":22,"IpRanges":operator_ranges}));
        Value::Array(rules)
    }
}

impl AwsExecutor for RebindExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        self.calls.lock().expect("calls").push(command.id.clone());
        let stdout = match command.id.as_str() {
            "verify-caller-account" => "{\"Account\":\"123456789012\"}".into(),
            "describe-exact-owned-security-group" => {
                let mut group = self.group.clone();
                group["IpPermissions"] = Self::ingress(*self.state.lock().expect("state"));
                json!({"SecurityGroups":[group]}).to_string()
            }
            "rebind-authorize-operator-ssh-cidr" => {
                *self.state.lock().expect("state") = SshIngressShape::Both;
                String::new()
            }
            "rebind-revoke-operator-ssh-cidr" => {
                if self.revoke_converges {
                    *self.state.lock().expect("state") = SshIngressShape::New;
                }
                String::new()
            }
            _ => return Err(contract("unexpected rebind command")),
        };
        Ok(ExecOutput {
            status: 0,
            stdout,
            stderr: String::new(),
        })
    }
}

fn rebind_state(
    dir: &TempDir,
    manifest: &AwsEc2Manifest,
    phase: LifecyclePhase,
) -> (PathBuf, Ec2State) {
    let state_dir = dir.path().join("rebind-state");
    let mut state = apply(
        manifest,
        &state_dir,
        100,
        false,
        &Never(AtomicUsize::new(0)),
    )
    .expect("dry state");
    state.account_id = Some("123456789012".into());
    state.vpc_id = Some("vpc-01234567".into());
    state.security_group_id = Some("sg-01234567".into());
    state.phase = phase;
    state = state.seal().expect("seal");
    Store::lock(&state_dir, &manifest.target)
        .expect("store")
        .write(&state)
        .expect("write");
    (state_dir, state)
}

struct ExistingReceipt {
    receipt: String,
    calls: Mutex<Vec<String>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RemoteInput {
    Absent,
    UbuntuStaged,
    UbuntuProtected,
    RootProtected,
}

struct UpdateReplayExecutor {
    candidate_receipt: String,
    rollback_receipt: Option<String>,
    ready: String,
    state_path: PathBuf,
    bundle_size: usize,
    request_size: usize,
    bundle_sha256: String,
    request_sha256: String,
    old_bundle_size: usize,
    old_request_size: usize,
    old_bundle_sha256: String,
    old_request_sha256: String,
    bundle: Mutex<RemoteInput>,
    request: Mutex<RemoteInput>,
    remote_receipt: Mutex<String>,
    calls: Mutex<Vec<String>>,
    persisted: Mutex<Vec<(LifecyclePhase, Option<String>)>>,
}

impl UpdateReplayExecutor {
    fn inspect_input(id: &str, path: &str, size: usize, input: RemoteInput) -> String {
        let (owner, group, mode) = match input {
            RemoteInput::Absent => return String::new(),
            RemoteInput::UbuntuStaged => ("ubuntu", "ubuntu", "600"),
            RemoteInput::UbuntuProtected => ("ubuntu", "ubuntu", "400"),
            RemoteInput::RootProtected => ("root", "root", "400"),
        };
        let _ = id;
        format!("f {owner} {group} {mode} 1 {size} {path}\n")
    }

    fn input_for(&self, id: &str) -> Option<(&Mutex<RemoteInput>, &str, usize)> {
        let rollback = fs::read(&self.state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Ec2State>(&bytes).ok())
            .is_some_and(|state| matches!(state.phase, LifecyclePhase::RollbackInstalling));
        if id.contains("stack-bundle") {
            Some((
                &self.bundle,
                REMOTE_BUNDLE,
                if rollback {
                    self.old_bundle_size
                } else {
                    self.bundle_size
                },
            ))
        } else if id.contains("install-request") {
            Some((
                &self.request,
                REMOTE_REQUEST,
                if rollback {
                    self.old_request_size
                } else {
                    self.request_size
                },
            ))
        } else {
            None
        }
    }

    fn expected_hash(&self, id: &str) -> Option<(&str, &str)> {
        let rollback = fs::read(&self.state_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Ec2State>(&bytes).ok())
            .is_some_and(|state| matches!(state.phase, LifecyclePhase::RollbackInstalling));
        if id.contains("stack-bundle") {
            Some((
                if rollback {
                    &self.old_bundle_sha256
                } else {
                    &self.bundle_sha256
                },
                REMOTE_BUNDLE,
            ))
        } else if id.contains("install-request") {
            Some((
                if rollback {
                    &self.old_request_sha256
                } else {
                    &self.request_sha256
                },
                REMOTE_REQUEST,
            ))
        } else {
            None
        }
    }

    fn assert_persisted_tuple(&self, command: &FixedCommand) {
        if !command.mutation {
            return;
        }
        let state: Ec2State = serde_json::from_slice(
            &fs::read(&self.state_path).expect("state persisted before effect"),
        )
        .expect("persisted state JSON");
        state.verify().expect("persisted state integrity");
        assert!(matches!(
            state.phase,
            LifecyclePhase::UpdateInstalling | LifecyclePhase::RollbackInstalling
        ));
        assert_eq!(state.pending_effect.as_deref(), Some(command.id.as_str()));
        assert_eq!(state.desired.version, "0.1.4");
        assert_eq!(
            state.previous.as_ref().expect("retained tuple").version,
            "0.1.1"
        );
        assert_eq!(
            state
                .previous_receipt
                .as_ref()
                .expect("retained receipt")
                .version,
            "0.1.1"
        );
        self.persisted
            .lock()
            .expect("persisted calls")
            .push((state.phase, state.pending_effect.clone()));
    }
}

impl AwsExecutor for UpdateReplayExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        self.calls.lock().expect("calls").push(command.id.clone());
        self.assert_persisted_tuple(command);
        let stdout = match command.id.as_str() {
            "check-authenticated-update-capacity" => "Avail IAvail\n134217728 128\n".into(),
            "inspect-current-installed-receipt" => {
                let receipt = self.remote_receipt.lock().expect("receipt");
                format!(
                    "f root root 600 1 {} {}\n",
                    receipt.len(),
                    REMOTE_CURRENT_RECEIPT
                )
            }
            "read-existing-installed-receipt"
            | "verify-authenticated-installed-receipt"
            | "read-authenticated-installed-receipt" => {
                self.remote_receipt.lock().expect("receipt").clone()
            }
            "verify-caller-account" => {
                let state: Ec2State =
                    serde_json::from_slice(&fs::read(&self.state_path).expect("state"))?;
                format!("{{\"Account\":\"{}\"}}", state.account_id.expect("account"))
            }
            "verify-dns-to-owned-eip" => "203.0.113.8 STREAM x\n".into(),
            "verify-system-tls-https-health" | "verify-host-ready-receipt-regular-file" => {
                String::new()
            }
            "verify-host-ready-receipt-metadata" => format!("0 0 600 1 {}\n", self.ready.len()),
            "read-sanitized-host-ready-receipt" => self.ready.clone(),
            "clear-retained-install-inputs-before-replay" => {
                *self.bundle.lock().expect("bundle") = RemoteInput::Absent;
                *self.request.lock().expect("request") = RemoteInput::Absent;
                String::new()
            }
            "run-fixed-stack-installer" => {
                let state: Ec2State =
                    serde_json::from_slice(&fs::read(&self.state_path).expect("state"))?;
                *self.remote_receipt.lock().expect("receipt") =
                    if matches!(state.phase, LifecyclePhase::RollbackInstalling) {
                        self.rollback_receipt
                            .clone()
                            .ok_or_else(|| contract("rollback receipt not configured"))?
                    } else {
                        self.candidate_receipt.clone()
                    };
                String::new()
            }
            id if id.starts_with("stage-exact-") => {
                if let Some((input, _, _)) = self.input_for(id) {
                    *input.lock().expect("input") = RemoteInput::UbuntuStaged;
                    String::new()
                } else {
                    return Err(contract("unexpected staging command"));
                }
            }
            id if id.starts_with("protect-staged-") => {
                if let Some((input, _, _)) = self.input_for(id) {
                    *input.lock().expect("input") = RemoteInput::UbuntuProtected;
                    String::new()
                } else {
                    return Err(contract("unexpected protect command"));
                }
            }
            id if id.starts_with("own-protected-") => {
                if let Some((input, _, _)) = self.input_for(id) {
                    *input.lock().expect("input") = RemoteInput::RootProtected;
                    String::new()
                } else {
                    return Err(contract("unexpected ownership command"));
                }
            }
            id if id.starts_with("inspect-") => {
                let Some((input, path, size)) = self.input_for(id) else {
                    return Err(contract("unexpected inspect command"));
                };
                Self::inspect_input(id, path, size, *input.lock().expect("input"))
            }
            id if id.starts_with("verify-") && self.expected_hash(id).is_some() => {
                let (digest, path) = self.expected_hash(id).expect("hash");
                format!("{digest}  {path}\n")
            }
            _ => return Err(contract("unexpected update replay command")),
        };
        Ok(ExecOutput {
            status: 0,
            stdout,
            stderr: String::new(),
        })
    }
}

fn ready_for(request: &ProvisionRequest) -> HostReadyReceipt {
    let mut ready = HostReadyReceipt {
        schema: "dirextalk.vnext-host-provision-ready".into(),
        schema_version: 1,
        state: "ready".into(),
        request_sha256: request.sha256().expect("sha"),
        target: request.target.clone(),
        domain: request.domain.clone(),
        tenant_id: request.tenant_id.clone(),
        indexer_id: request.indexer_id.clone(),
        release_version: request.release_version.clone(),
        bundle_sha256: request.bundle_sha256.clone(),
        compose_sha256: request.compose_sha256.clone(),
        receipt_sha256: String::new(),
    };
    let mut body = serde_json::to_value(&ready).expect("value");
    body.as_object_mut().expect("obj").remove("receipt_sha256");
    ready.receipt_sha256 = hash(&canonical(&body));
    ready
}

fn update_ready_state(
    dir: &TempDir,
    old: &AwsEc2Manifest,
) -> (PathBuf, Ec2State, InstallRequest, ProvisionRequest) {
    let facts = old.bundle().expect("facts");
    let state_dir = dir.path().join("update-state");
    let mut state = apply(old, &state_dir, 100, false, &Never(AtomicUsize::new(0))).expect("state");
    state.account_id = Some("123456789012".into());
    state.private_ipv4 = Some("10.0.0.7".into());
    state.eip = Some(EipRecord {
        allocation_id: "eipalloc-1".into(),
        association_id: "eipassoc-1".into(),
        public_ip: "203.0.113.8".into(),
    });
    let request = InstallRequest::new(&old.domain, &facts, None);
    let provision = ProvisionRequest::new(old, &state, &facts).expect("provision");
    let ready = ready_for(&provision);
    state.current = Some(BundleRecord::from_facts(&facts, old));
    state.current_receipt = Some(receipt_for(&request, ReceiptState::Installed));
    state.current_bundle_suffix = Some("current.bundle".into());
    state.current_request_suffix = Some("current.request".into());
    state.provision_request_suffix = Some("current.provision".into());
    state.host_ready_receipt = Some(ready);
    state.phase = LifecyclePhase::Verified;
    state = state.seal().expect("seal");
    let store = Store::lock(&state_dir, "x6").expect("store");
    store
        .write_artifact(
            "current.request",
            &request.canonical_bytes().expect("request"),
            0o600,
        )
        .expect("artifact");
    store
        .write_artifact(
            "current.provision",
            &provision.canonical_bytes().expect("provision"),
            0o600,
        )
        .expect("artifact");
    store.write(&state).expect("state");
    drop(store);
    (state_dir, state, request, provision)
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

#[cfg(unix)]
#[test]
fn pre_cross_version_sealed_state_is_exactly_authenticated_and_migrated_under_lock() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, manifest) = fixture("1.2.3", 'a');
    let state_dir = dir.path().join("legacy-state");
    let fixture_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/legacy-5a6c2e9-x6.json");
    let legacy_file = fs::read(&fixture_path).expect("literal legacy fixture");
    let legacy = legacy_file[..legacy_file.len() - 1].to_vec();
    let legacy_state: Ec2State = serde_json::from_slice(&legacy).expect("legacy state JSON");
    assert_eq!(
        legacy_state.integrity_sha256,
        "e7f193205337e5dcb951909555696d4c696c3f7572f606413bd74bc31410b24e"
    );
    legacy_state
        .verify_legacy_bytes(&legacy)
        .expect("exact old seal");
    let store = Store::lock(&state_dir, "x6").expect("store");
    fs::write(store.state_path(), &legacy).expect("legacy state");
    fs::set_permissions(store.state_path(), fs::Permissions::from_mode(0o600)).expect("mode");
    drop(store);
    status(&manifest, &state_dir).expect("locked migration");
    let migrated: Ec2State = Store::lock(&state_dir, "x6")
        .expect("store")
        .read()
        .expect("state")
        .expect("present");
    migrated.verify().expect("new seal");
    assert_eq!(migrated.candidate_bundle_suffix, None);
    let mut tampered = legacy;
    tampered[0] = b'[';
    fs::write(state_dir.join("x6.json"), tampered).expect("tamper");
    fs::set_permissions(state_dir.join("x6.json"), fs::Permissions::from_mode(0o600))
        .expect("mode");
    assert!(status(&manifest, &state_dir).is_err());
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
        .expect_err("missing marker remains fail closed");
    assert!(error.to_string().contains("compatibility marker"));
    assert_eq!(executor.0.load(Ordering::Relaxed), 0);

    let (_new_dir, cross_version) = fixture("2.0.0", 'b');
    let error = update(&cross_version, &state_dir, false, &Identity)
        .expect_err("unsupported cross-version update");
    assert!(error.to_string().contains("compatibility marker"));
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
        None,
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
fn update_receipt_classifier_distinguishes_retained_candidate_rollback_and_third_identity() {
    let (_dir, manifest) = fixture("0.1.1", 'a');
    let retained_facts = manifest.bundle().expect("retained");
    let retained = InstallRequest::new(&manifest.domain, &retained_facts, None);
    let mut candidate = retained.clone();
    candidate.version = "0.1.4".into();
    candidate.bundle_sha256 = "b".repeat(64);
    candidate.manifest_sha256 = "c".repeat(64);
    candidate.server_image = format!("dirextalk/vnet-server@sha256:{}", "b".repeat(64));
    candidate.previous_receipt_sha256 =
        Some(receipt_for(&retained, ReceiptState::Installed).receipt_sha256);
    let prior = canonical(&receipt_for(&retained, ReceiptState::Installed));
    assert!(matches!(
        workflow::classify_existing_install_receipt(
            &prior,
            &candidate,
            ReceiptState::Installed,
            Some((&retained, ReceiptState::Installed))
        )
        .expect("prior"),
        workflow::ExistingInstallReceipt::PreEffect
    ));
    let installed = canonical(&receipt_for(&candidate, ReceiptState::Installed));
    assert!(matches!(
        workflow::classify_existing_install_receipt(
            &installed,
            &candidate,
            ReceiptState::Installed,
            Some((&retained, ReceiptState::Installed))
        )
        .expect("candidate"),
        workflow::ExistingInstallReceipt::PostEffect(_)
    ));
    let rollback = canonical(&receipt_for(&candidate, ReceiptState::RolledBack));
    assert!(matches!(
        workflow::classify_existing_install_receipt(
            &rollback,
            &candidate,
            ReceiptState::RolledBack,
            Some((&retained, ReceiptState::Installed))
        )
        .expect("rollback"),
        workflow::ExistingInstallReceipt::PostEffect(_)
    ));
    let mut third = candidate.clone();
    third.target = "other".into();
    let third_bytes = canonical(&receipt_for(&third, ReceiptState::Installed));
    assert!(
        workflow::classify_existing_install_receipt(
            &third_bytes,
            &candidate,
            ReceiptState::Installed,
            Some((&retained, ReceiptState::Installed))
        )
        .is_err()
    );
}

#[test]
fn update_capacity_parser_enforces_exact_bytes_inodes_and_rejects_invalid_values() {
    for (bytes, inodes, accepted) in [
        (128_u64 * 1024 * 1024 - 1, 128, false),
        (128_u64 * 1024 * 1024, 127, false),
        (128_u64 * 1024 * 1024, 128, true),
        (u64::MAX, u64::MAX, true),
    ] {
        let output = format!("Avail IAvail\n{bytes} {inodes}\n");
        assert_eq!(workflow::parse_update_capacity(&output).is_ok(), accepted);
    }
    for output in [
        "Avail IAvail\n18446744073709551616 128\n",
        "Avail IAvail\n1 nope\n",
        "Avail IAvail\n1 2 3\n",
        "",
    ] {
        assert!(workflow::parse_update_capacity(output).is_err());
    }
}

#[test]
fn executable_cross_version_update_replays_update_installing_and_verifying_without_installer_effect()
 {
    let (dir, old) = fixture("0.1.1", 'a');
    let (state_dir, mut state, old_request, provision) = update_ready_state(&dir, &old);
    let (_candidate_dir, candidate) = fixture("0.1.4", 'b');
    let facts = candidate.bundle().expect("candidate facts");
    let request = InstallRequest::new(
        &candidate.domain,
        &facts,
        Some(
            state
                .current_receipt
                .as_ref()
                .expect("prior")
                .receipt_sha256
                .clone(),
        ),
    );
    let retained_receipt = String::from_utf8(canonical(
        state.current_receipt.as_ref().expect("retained receipt"),
    ))
    .expect("retained receipt");
    let candidate_receipt =
        String::from_utf8(canonical(&receipt_for(&request, ReceiptState::Installed)))
            .expect("candidate receipt");
    let ready = String::from_utf8(canonical(&ready_for(&provision))).expect("ready");
    let bundle_bytes = fs::read(&candidate.stack_bundle_path).expect("candidate bundle");
    let request_bytes = request.canonical_bytes().expect("candidate request");
    let executor = UpdateReplayExecutor {
        candidate_receipt,
        rollback_receipt: None,
        ready,
        state_path: state_dir.join("x6.json"),
        bundle_size: bundle_bytes.len(),
        request_size: request_bytes.len(),
        bundle_sha256: hash(&bundle_bytes),
        request_sha256: hash(&request_bytes),
        old_bundle_size: bundle_bytes.len(),
        old_request_size: request_bytes.len(),
        old_bundle_sha256: hash(&bundle_bytes),
        old_request_sha256: hash(&request_bytes),
        bundle: Mutex::new(RemoteInput::RootProtected),
        request: Mutex::new(RemoteInput::RootProtected),
        remote_receipt: Mutex::new(retained_receipt.clone()),
        calls: Mutex::new(Vec::new()),
        persisted: Mutex::new(Vec::new()),
    };
    let updated = update(&candidate, &state_dir, true, &executor).expect("successful update");
    assert_eq!(updated.phase, LifecyclePhase::Verified);
    assert_eq!(updated.current.as_ref().expect("current").version, "0.1.4");
    assert_eq!(
        updated.previous.as_ref().expect("previous").version,
        "0.1.1"
    );
    let calls = executor.calls.lock().expect("calls").clone();
    let effects: Vec<&str> = calls
        .iter()
        .filter(|id| {
            matches!(
                id.as_str(),
                "clear-retained-install-inputs-before-replay"
                    | "stage-exact-stack-bundle"
                    | "protect-staged-stack-bundle"
                    | "own-protected-stack-bundle"
                    | "stage-exact-install-request"
                    | "protect-staged-install-request"
                    | "own-protected-install-request"
                    | "run-fixed-stack-installer"
            )
        })
        .map(String::as_str)
        .collect();
    assert_eq!(
        effects,
        vec![
            "clear-retained-install-inputs-before-replay",
            "stage-exact-stack-bundle",
            "protect-staged-stack-bundle",
            "own-protected-stack-bundle",
            "stage-exact-install-request",
            "protect-staged-install-request",
            "own-protected-install-request",
            "run-fixed-stack-installer",
        ]
    );
    assert_eq!(executor.persisted.lock().expect("persisted").len(), 8);
    // Persisted restart from either durable boundary reuses the authenticated candidate receipt.
    for phase in [
        LifecyclePhase::UpdateInstalling,
        LifecyclePhase::UpdateVerifying,
    ] {
        state.phase = phase.clone();
        state.desired = BundleRecord::from_facts(&facts, &candidate);
        state.previous = Some(BundleRecord::from_facts(
            &old.bundle().expect("old facts"),
            &old,
        ));
        state.previous_receipt = Some(receipt_for(&old_request, ReceiptState::Installed));
        state.previous_bundle_suffix = Some("current.bundle".into());
        state.previous_request_suffix = Some("current.request".into());
        if phase == LifecyclePhase::UpdateInstalling {
            state.current = state.previous.clone();
            state.current_receipt = state.previous_receipt.clone();
            state.current_bundle_suffix = Some("current.bundle".into());
            state.current_request_suffix = Some("current.request".into());
            *executor.remote_receipt.lock().expect("receipt") = retained_receipt.clone();
            *executor.bundle.lock().expect("bundle") = RemoteInput::RootProtected;
            *executor.request.lock().expect("request") = RemoteInput::RootProtected;
        } else {
            state.current = Some(BundleRecord::from_facts(&facts, &candidate));
            state.current_receipt = Some(receipt_for(&request, ReceiptState::Installed));
            state.current_bundle_suffix = Some("update-candidate.bundle".into());
            state.current_request_suffix = Some("update-candidate.request".into());
            *executor.remote_receipt.lock().expect("receipt") = executor.candidate_receipt.clone();
        }
        state.candidate_bundle_suffix = Some("update-candidate.bundle".into());
        state.candidate_request_suffix = Some("update-candidate.request".into());
        state = state.seal().expect("seal");
        let store = Store::lock(&state_dir, "x6").expect("store");
        store
            .write_artifact(
                "update-candidate.request",
                &request.canonical_bytes().expect("request"),
                0o600,
            )
            .expect("artifact");
        store.write(&state).expect("state");
        drop(store);
        let persisted: Ec2State = Store::lock(&state_dir, "x6")
            .expect("store")
            .read()
            .expect("read")
            .expect("persisted restart state");
        persisted.verify().expect("restart state integrity");
        assert_eq!(persisted.phase, phase);
        assert_eq!(persisted.desired.version, "0.1.4");
        assert_eq!(
            persisted.previous.as_ref().expect("retained tuple").version,
            "0.1.1"
        );
        if phase == LifecyclePhase::UpdateInstalling {
            assert_eq!(
                persisted
                    .current
                    .as_ref()
                    .expect("installing current")
                    .version,
                "0.1.1"
            );
            assert_eq!(
                persisted
                    .current_receipt
                    .as_ref()
                    .expect("installing receipt")
                    .version,
                "0.1.1"
            );
        } else {
            assert_eq!(
                persisted
                    .current
                    .as_ref()
                    .expect("verifying current")
                    .version,
                "0.1.4"
            );
            assert_eq!(
                persisted
                    .current_receipt
                    .as_ref()
                    .expect("verifying receipt")
                    .version,
                "0.1.4"
            );
        }
        let calls_before_restart = executor.calls.lock().expect("calls").len();
        let replay = update(&candidate, &state_dir, true, &executor).expect("replay");
        assert_eq!(replay.phase, LifecyclePhase::Verified);
        let restart_effects = executor
            .calls
            .lock()
            .expect("calls")
            .iter()
            .skip(calls_before_restart)
            .filter(|id| {
                matches!(
                    id.as_str(),
                    "clear-retained-install-inputs-before-replay"
                        | "stage-exact-stack-bundle"
                        | "protect-staged-stack-bundle"
                        | "own-protected-stack-bundle"
                        | "stage-exact-install-request"
                        | "protect-staged-install-request"
                        | "own-protected-install-request"
                        | "run-fixed-stack-installer"
                )
            })
            .count();
        assert_eq!(
            restart_effects,
            if phase == LifecyclePhase::UpdateInstalling {
                8
            } else {
                0
            }
        );
    }
}

#[test]
fn code_only_rollback_replays_rolled_back_receipt_and_rejects_third_identity() {
    let (dir, old) = fixture("0.1.1", 'a');
    let (state_dir, mut state, _old_request, provision) = update_ready_state(&dir, &old);
    let (_candidate_dir, candidate) = fixture("0.1.4", 'b');
    let candidate_facts = candidate.bundle().expect("candidate facts");
    let candidate_request = InstallRequest::new(
        &candidate.domain,
        &candidate_facts,
        Some(
            state
                .current_receipt
                .as_ref()
                .expect("retained receipt")
                .receipt_sha256
                .clone(),
        ),
    );
    let retained_receipt = state.current_receipt.clone().expect("retained receipt");
    let old_facts = old.bundle().expect("old facts");
    let old_bundle = fs::read(&old.stack_bundle_path).expect("old bundle");
    let candidate_bundle = fs::read(&candidate.stack_bundle_path).expect("candidate bundle");
    let candidate_receipt = receipt_for(&candidate_request, ReceiptState::Installed);
    let rollback_request = InstallRequest {
        schema: "dirextalk.vnext-install-request".into(),
        schema_version: 1,
        target: state.target.clone(),
        domain: state.domain.clone(),
        version: old_facts.manifest.version.clone(),
        source_commit: old_facts.manifest.source_commit.clone(),
        bundle_sha256: old_facts.bundle_sha256.clone(),
        manifest_sha256: old_facts.manifest_sha256.clone(),
        server_image: old_facts.manifest.server_image.clone(),
        migrator_image: old_facts.manifest.migrator_image.clone(),
        previous_receipt_sha256: Some(candidate_receipt.receipt_sha256.clone()),
    };
    let rollback_receipt = receipt_for(&rollback_request, ReceiptState::RolledBack);
    state.current = Some(BundleRecord::from_facts(&candidate_facts, &candidate));
    state.current_receipt = Some(candidate_receipt.clone());
    state.previous = Some(BundleRecord::from_facts(&old_facts, &old));
    state.previous_receipt = Some(retained_receipt);
    state.desired = BundleRecord::from_facts(&candidate_facts, &candidate);
    state.current_bundle_suffix = Some("update-candidate.bundle".into());
    state.current_request_suffix = Some("update-candidate.request".into());
    state.previous_bundle_suffix = Some("current.bundle".into());
    state.previous_request_suffix = Some("current.request".into());
    state.candidate_bundle_suffix = Some("update-candidate.bundle".into());
    state.candidate_request_suffix = Some("update-candidate.request".into());
    state.phase = LifecyclePhase::UpdateVerifying;
    state = state.seal().expect("seal");
    let store = Store::lock(&state_dir, "x6").expect("store");
    store
        .write_artifact("current.bundle", &old_bundle, 0o600)
        .expect("old bundle");
    store
        .write_artifact("update-candidate.bundle", &candidate_bundle, 0o600)
        .expect("candidate bundle");
    store
        .write_artifact(
            "update-candidate.request",
            &candidate_request
                .canonical_bytes()
                .expect("candidate request"),
            0o600,
        )
        .expect("candidate request");
    store.write(&state).expect("rollback state");
    drop(store);
    let ready = String::from_utf8(canonical(&ready_for(&provision))).expect("ready");
    let candidate_receipt_text =
        String::from_utf8(canonical(&candidate_receipt)).expect("candidate");
    let executor = UpdateReplayExecutor {
        candidate_receipt: candidate_receipt_text.clone(),
        rollback_receipt: Some(String::from_utf8(canonical(&rollback_receipt)).expect("rollback")),
        ready,
        state_path: state_dir.join("x6.json"),
        bundle_size: candidate_bundle.len(),
        request_size: candidate_request
            .canonical_bytes()
            .expect("candidate request")
            .len(),
        bundle_sha256: hash(&candidate_bundle),
        request_sha256: hash(
            &candidate_request
                .canonical_bytes()
                .expect("candidate request"),
        ),
        old_bundle_size: old_bundle.len(),
        old_request_size: rollback_request
            .canonical_bytes()
            .expect("rollback request")
            .len(),
        old_bundle_sha256: hash(&old_bundle),
        old_request_sha256: hash(
            &rollback_request
                .canonical_bytes()
                .expect("rollback request"),
        ),
        bundle: Mutex::new(RemoteInput::RootProtected),
        request: Mutex::new(RemoteInput::RootProtected),
        remote_receipt: Mutex::new(candidate_receipt_text),
        calls: Mutex::new(Vec::new()),
        persisted: Mutex::new(Vec::new()),
    };
    let rolled_back =
        rollback_update(&candidate, &state_dir, true, &executor).unwrap_or_else(|error| {
            panic!(
                "rollback: {error:?}; calls={:?}",
                executor.calls.lock().expect("calls")
            )
        });
    assert_eq!(rolled_back.phase, LifecyclePhase::RolledBack);
    assert_eq!(
        rolled_back
            .rollback_receipt
            .as_ref()
            .expect("rollback receipt")
            .receipt_sha256,
        rollback_receipt.receipt_sha256
    );
    let effects: Vec<String> = executor
        .calls
        .lock()
        .expect("calls")
        .iter()
        .filter(|id| {
            id.contains("stage-exact-")
                || id.contains("protect-staged-")
                || id.contains("own-protected-")
                || id.contains("clear-retained")
                || id.as_str() == "run-fixed-stack-installer"
        })
        .cloned()
        .collect();
    assert_eq!(effects.len(), 8);
    let mut third = candidate_request.clone();
    third.target = "other".into();
    assert!(
        workflow::classify_existing_install_receipt(
            &canonical(&receipt_for(&third, ReceiptState::RolledBack)),
            &rollback_request,
            ReceiptState::RolledBack,
            Some((&candidate_request, ReceiptState::Installed))
        )
        .is_err()
    );
}

#[test]
fn rolled_back_state_rejects_new_forward_update_without_mutating_state() {
    let (dir, old) = fixture("0.1.1", 'a');
    let (state_dir, mut state, _, _) = update_ready_state(&dir, &old);
    state.phase = LifecyclePhase::RolledBack;
    state = state.seal().expect("seal");
    Store::lock(&state_dir, "x6")
        .expect("store")
        .write(&state)
        .expect("write");
    let before = fs::read(state_dir.join("x6.json")).expect("before");
    let (_candidate_dir, candidate) = fixture("0.1.4", 'b');
    let never = Never(AtomicUsize::new(0));
    assert!(update(&candidate, &state_dir, true, &never).is_err());
    assert_eq!(never.0.load(Ordering::Relaxed), 0);
    assert_eq!(fs::read(state_dir.join("x6.json")).expect("after"), before);
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
fn operator_cidr_rebind_authorizes_then_revokes_and_reseals_state() {
    let (dir, old_manifest) = fixture("1.2.3", 'a');
    let (state_dir, state) = rebind_state(&dir, &old_manifest, LifecyclePhase::DnsReady);
    let mut new_manifest = old_manifest.clone();
    new_manifest.operator_ssh_cidr = "198.51.100.7/32".into();
    let executor = RebindExecutor::new(&state, SshIngressShape::Old, true);

    let updated =
        rebind_operator_cidr(&new_manifest, &state_dir, "203.0.113.9/32", true, &executor)
            .expect("rebind");
    assert_eq!(updated.phase, LifecyclePhase::DnsReady);
    assert_eq!(updated.infrastructure.operator_ssh_cidr, "198.51.100.7/32");
    updated.verify().expect("resealed state");
    assert_eq!(
        *executor.calls.lock().expect("calls"),
        vec![
            "verify-caller-account",
            "describe-exact-owned-security-group",
            "rebind-authorize-operator-ssh-cidr",
            "describe-exact-owned-security-group",
            "rebind-revoke-operator-ssh-cidr",
            "describe-exact-owned-security-group",
        ]
    );
}

#[test]
fn operator_cidr_rebind_refuses_to_advance_state_when_revoke_does_not_converge() {
    let (dir, old_manifest) = fixture("1.2.3", 'a');
    let (state_dir, state) = rebind_state(&dir, &old_manifest, LifecyclePhase::DnsReady);
    let mut new_manifest = old_manifest.clone();
    new_manifest.operator_ssh_cidr = "198.51.100.7/32".into();
    let executor =
        RebindExecutor::with_revoke_convergence(&state, SshIngressShape::Both, true, false);

    assert!(
        rebind_operator_cidr(&new_manifest, &state_dir, "203.0.113.9/32", true, &executor,)
            .is_err()
    );
    let persisted: Ec2State = Store::lock(&state_dir, "x6")
        .expect("store")
        .read()
        .expect("read")
        .expect("state");
    assert_eq!(
        persisted.infrastructure.operator_ssh_cidr, "203.0.113.9/32",
        "failed post-revoke readback must not advance durable CIDR state"
    );
    assert_eq!(
        *executor.calls.lock().expect("calls"),
        vec![
            "verify-caller-account",
            "describe-exact-owned-security-group",
            "rebind-revoke-operator-ssh-cidr",
            "describe-exact-owned-security-group",
        ]
    );
}

#[test]
fn operator_cidr_rebind_replays_crash_windows_without_widening() {
    for (shape, expected_effects) in [
        (
            SshIngressShape::Both,
            vec!["rebind-revoke-operator-ssh-cidr"],
        ),
        (SshIngressShape::New, vec![]),
    ] {
        let (dir, old_manifest) = fixture("1.2.3", 'a');
        let (state_dir, state) = rebind_state(&dir, &old_manifest, LifecyclePhase::DnsReady);
        let mut new_manifest = old_manifest.clone();
        new_manifest.operator_ssh_cidr = "198.51.100.7/32".into();
        let executor = RebindExecutor::new(&state, shape, true);
        let updated =
            rebind_operator_cidr(&new_manifest, &state_dir, "203.0.113.9/32", true, &executor)
                .expect("replay");
        assert_eq!(updated.infrastructure.operator_ssh_cidr, "198.51.100.7/32");
        let calls = executor.calls.lock().expect("calls");
        let effects: Vec<&str> = calls
            .iter()
            .filter_map(|call| call.starts_with("rebind-").then_some(call.as_str()))
            .collect();
        assert_eq!(effects, expected_effects);
    }
}

#[test]
fn operator_cidr_rebind_rejects_wrong_identity_phase_ownership_and_dry_run_has_no_effects() {
    let (dir, old_manifest) = fixture("1.2.3", 'a');
    let (state_dir, _state) = rebind_state(&dir, &old_manifest, LifecyclePhase::DnsReady);
    let mut new_manifest = old_manifest.clone();
    new_manifest.operator_ssh_cidr = "198.51.100.7/32".into();
    let never = Never(AtomicUsize::new(0));
    assert!(rebind_operator_cidr(&new_manifest, &state_dir, "192.0.2.8/32", true, &never).is_err());
    assert!(
        rebind_operator_cidr(&new_manifest, &state_dir, "198.51.100.7/32", true, &never).is_err()
    );
    assert_eq!(never.0.load(Ordering::Relaxed), 0);
    let dry = rebind_operator_cidr(&new_manifest, &state_dir, "203.0.113.9/32", false, &never)
        .expect("dry rebind");
    assert_eq!(dry.infrastructure.operator_ssh_cidr, "203.0.113.9/32");
    assert_eq!(never.0.load(Ordering::Relaxed), 0);

    let (terminal_dir, _) = rebind_state(&dir, &old_manifest, LifecyclePhase::Destroying);
    assert!(
        rebind_operator_cidr(&new_manifest, &terminal_dir, "203.0.113.9/32", true, &never).is_err()
    );
    assert_eq!(never.0.load(Ordering::Relaxed), 0);

    let (owner_dir, owner_state) = rebind_state(&dir, &old_manifest, LifecyclePhase::DnsReady);
    let unowned = RebindExecutor::new(&owner_state, SshIngressShape::Old, false);
    assert!(
        rebind_operator_cidr(&new_manifest, &owner_dir, "203.0.113.9/32", true, &unowned).is_err()
    );
    assert!(
        !unowned
            .calls
            .lock()
            .expect("calls")
            .iter()
            .any(|call| call.starts_with("rebind-")),
        "ownership rejection must produce zero cloud effects"
    );
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
