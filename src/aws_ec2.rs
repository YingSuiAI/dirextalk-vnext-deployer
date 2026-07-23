//! Durable, fail-closed lifecycle for one immutable Dirextalk vNext EC2 node.
#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

pub(crate) mod bundle;
mod provision;
pub(crate) mod store;
pub(crate) mod workflow;

use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{ReleaseError, Result, error::io_error};
use bundle::{BundleFacts, InstalledReceipt, ReceiptState, digest, image, load_bundle};
use provision::HostReadyReceipt;

pub use workflow::{
    apply, destroy, rebind_operator_cidr, resume, status, status_with_registry, update, verify,
};

pub(super) const REGION: &str = "ap-east-1";
pub(super) const PROVIDER: &str = "aws";
pub(super) const UBUNTU_OWNER: &str = "099720109477";
pub(super) const UBUNTU_PATTERN: &str =
    "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*";
pub(super) const AWS: &str = "aws";
pub(super) const SSH: &str = "ssh";
pub(super) const SCP: &str = "scp";
pub(super) const SSH_KEYGEN: &str = "ssh-keygen";
pub(super) const SSH_KEYSCAN: &str = "ssh-keyscan";
pub(super) const CURL: &str = "curl";
pub(super) const GETENT: &str = "getent";
pub(super) const DOCKER: &str = "docker";
pub(super) const DOCKER_HUB_LATEST: &str = "docker.io/dirextalk/vnet-server:latest";
pub(super) const REMOTE_BUNDLE: &str = "/home/ubuntu/dirextalk-vnext.bundle";
pub(super) const REMOTE_REQUEST: &str = "/home/ubuntu/dirextalk-vnext.request";
pub(super) const REMOTE_PROVISION_REQUEST: &str = "/home/ubuntu/dirextalk-vnext.provision";
pub(super) const REMOTE_INSTALLER_UPLOAD: &str = "/home/ubuntu/install-vnext.upload";
pub(super) const REMOTE_PROVISIONER_UPLOAD: &str = "/home/ubuntu/provision-vnext.upload";
pub(super) const REMOTE_RECEIPT_READER_UPLOAD: &str = "/home/ubuntu/read-vnext-receipt.upload";
pub(super) const REMOTE_INSTALLER: &str = "/usr/local/libexec/dirextalk/install-vnext";
pub(super) const REMOTE_PROVISIONER: &str = "/usr/local/libexec/dirextalk/provision-vnext";
pub(super) const REMOTE_RECEIPT_READER: &str = "/usr/local/libexec/dirextalk/read-vnext-receipt";
pub(super) const REMOTE_CURRENT_RECEIPT: &str = "/var/lib/dirextalk-vnext/receipts/current.json";
pub(super) const REMOTE_INSTALLER_ATOMIC: &str = "/usr/local/libexec/dirextalk/.install-vnext.new";
pub(super) const REMOTE_PROVISIONER_ATOMIC: &str =
    "/usr/local/libexec/dirextalk/.provision-vnext.new";
pub(super) const REMOTE_RECEIPT_READER_ATOMIC: &str =
    "/usr/local/libexec/dirextalk/.read-vnext-receipt.new";
pub(super) const REMOTE_READY_RECEIPT: &str = "/var/lib/dirextalk-vnext/host-provision/ready.json";
pub(super) const HEALTH_PATH: &str = "/healthz";
pub(super) const MAX_OUTPUT: u64 = 256 * 1024;
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRY_ARGV: [&str; 6] = [
    "buildx",
    "imagetools",
    "inspect",
    "--format",
    "{{json .Manifest}}",
    DOCKER_HUB_LATEST,
];

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsEc2Manifest {
    pub schema_version: u32,
    pub target: String,
    pub provider: String,
    pub region: String,
    pub domain: String,
    pub instance_type: String,
    pub disk_gib: u32,
    pub operator_ssh_cidr: String,
    pub stack_bundle_sha256: String,
    pub stack_bundle_path: PathBuf,
    pub host_installer_path: PathBuf,
    pub host_installer_sha256: String,
    pub host_provisioner_path: PathBuf,
    pub host_provisioner_sha256: String,
    pub receipt_reader_path: PathBuf,
    pub receipt_reader_sha256: String,
    pub release_version: String,
    pub source_commit: String,
    pub server_image: String,
    pub migrator_image: String,
    pub postgres_image: String,
    pub caddy_image: String,
    pub probe_image: String,
    pub ubuntu_ami_owner: String,
    pub ubuntu_ami_pattern: String,
    pub key_name: String,
}

impl AwsEc2Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 2 * 1024 * 1024 {
            return Err(ReleaseError::UnsafeFile(path.to_owned()));
        }
        let manifest: Self = serde_json::from_slice(&fs::read(path).map_err(io_error(path))?)?;
        manifest.validate()?;
        manifest.bundle()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(contract("EC2 schema_version must be 1"));
        }
        if self.provider != PROVIDER || self.region != REGION {
            return Err(contract("provider/region must be aws/ap-east-1"));
        }
        token(&self.target, "target")?;
        domain(&self.domain)?;
        if !matches!(self.instance_type.as_str(), "t3.small" | "t3.medium") {
            return Err(contract("instance_type must be t3.small or t3.medium"));
        }
        if !(30..=200).contains(&self.disk_gib) {
            return Err(contract("disk_gib must be between 30 and 200 GiB"));
        }
        operator_cidr(&self.operator_ssh_cidr)?;
        digest(&self.stack_bundle_sha256, "stack bundle")?;
        digest(&self.host_installer_sha256, "host installer")?;
        digest(&self.host_provisioner_sha256, "host provisioner")?;
        digest(&self.receipt_reader_sha256, "receipt reader")?;
        Version::parse(&self.release_version)
            .map_err(|_| contract("release_version must be SemVer"))?;
        bundle::commit(&self.source_commit)?;
        exact_image(&self.server_image, "dirextalk/vnet-server", "server_image")?;
        exact_image(
            &self.migrator_image,
            "dirextalk/vnet-server",
            "migrator_image",
        )?;
        exact_image(&self.postgres_image, "postgres", "postgres_image")?;
        exact_image(&self.caddy_image, "caddy", "caddy_image")?;
        exact_image(&self.probe_image, "curlimages/curl", "probe_image")?;
        if self.ubuntu_ami_owner != UBUNTU_OWNER || self.ubuntu_ami_pattern != UBUNTU_PATTERN {
            return Err(contract(
                "Ubuntu AMI owner/pattern must be the Canonical 24.04 amd64 allowlist",
            ));
        }
        token(&self.key_name, "key_name")?;
        Ok(())
    }

    pub(super) fn bundle(&self) -> Result<BundleFacts> {
        let facts = load_bundle(
            &self.stack_bundle_path,
            &self.stack_bundle_sha256,
            &self.host_installer_path,
            &self.host_installer_sha256,
            &self.host_provisioner_path,
            &self.host_provisioner_sha256,
            &self.receipt_reader_path,
            &self.receipt_reader_sha256,
        )?;
        if facts.manifest.version != self.release_version
            || facts.manifest.source_commit != self.source_commit
            || facts.manifest.server_image != self.server_image
            || facts.manifest.migrator_image != self.migrator_image
        {
            return Err(contract(
                "deployment manifest does not match the digest-bound stack manifest",
            ));
        }
        Ok(facts)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FixedCommand {
    pub id: String,
    pub program: String,
    pub argv: Vec<String>,
    pub mutation: bool,
    pub timeout_seconds: u64,
}

impl FixedCommand {
    pub(super) fn new(
        id: &str,
        program: &str,
        argv: impl IntoIterator<Item = impl Into<String>>,
        mutation: bool,
        timeout_seconds: u64,
    ) -> Self {
        Self {
            id: id.into(),
            program: program.into(),
            argv: argv.into_iter().map(Into::into).collect(),
            mutation,
            timeout_seconds,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct ExecOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait AwsExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput>;
}

#[derive(Default)]
pub struct ProductionAwsExecutor;

impl AwsExecutor for ProductionAwsExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        run_process(
            &command.program,
            &command.argv.iter().map(String::as_str).collect::<Vec<_>>(),
            Duration::from_secs(command.timeout_seconds),
        )
    }
}

pub trait RegistryExecutor {
    fn inspect_latest(&self) -> Result<ExecOutput>;
}

#[derive(Default)]
pub struct ProductionRegistryExecutor;

impl RegistryExecutor for ProductionRegistryExecutor {
    fn inspect_latest(&self) -> Result<ExecOutput> {
        run_process(DOCKER, &REGISTRY_ARGV, REGISTRY_TIMEOUT).map_err(|error| {
            if matches!(error, ReleaseError::CommandFailed { .. }) {
                contract("Docker Hub latest discovery failed")
            } else {
                error
            }
        })
    }
}

fn run_process(program: &str, argv: &[&str], timeout: Duration) -> Result<ExecOutput> {
    enum Completion {
        Status(std::process::ExitStatus),
        Timeout,
        WaitError(std::io::Error),
    }

    let mut command = Command::new(program);
    command
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    command.process_group(0);
    let mut child = command
        .spawn()
        .map_err(|_| ReleaseError::CommandStart(program.into()))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let (Some(stdout), Some(stderr)) = (stdout, stderr) else {
        terminate_process_tree(&mut child);
        return Err(contract("external command output pipe is unavailable"));
    };
    #[cfg(unix)]
    if set_nonblocking(&stdout).is_err() || set_nonblocking(&stderr).is_err() {
        terminate_process_tree(&mut child);
        return Err(contract("external command output pipe setup failed"));
    }
    let cancel_readers = Arc::new(AtomicBool::new(false));
    let stdout_program = program.to_owned();
    let stderr_program = program.to_owned();
    let stdout_cancel = Arc::clone(&cancel_readers);
    let stderr_cancel = Arc::clone(&cancel_readers);
    let stdout_reader = thread::spawn(move || read_output(stdout, &stdout_program, &stdout_cancel));
    let stderr_reader = thread::spawn(move || read_output(stderr, &stderr_program, &stderr_cancel));
    let deadline = Instant::now() + timeout;
    let completion = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Completion::Status(status),
            Ok(None) if Instant::now() >= deadline => break Completion::Timeout,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(error) => break Completion::WaitError(error),
        }
    };
    if !matches!(completion, Completion::Status(_)) {
        terminate_process_tree(&mut child);
    }
    cancel_readers.store(true, Ordering::Release);
    let stdout_result = stdout_reader
        .join()
        .map_err(|_| contract("external command stdout reader failed"))
        .and_then(|result| result);
    let stderr_result = stderr_reader
        .join()
        .map_err(|_| contract("external command stderr reader failed"))
        .and_then(|result| result);
    let mut stdout = stdout_result?;
    let mut stderr = stderr_result?;
    let status = match completion {
        Completion::Status(status) => status,
        Completion::Timeout => return Err(contract(&format!("{program} deadline exceeded"))),
        Completion::WaitError(error) => return Err(io_error(program)(error)),
    };
    if !status.success() {
        if program == DOCKER {
            return Err(classify_registry_failure(&stderr));
        }
        return Err(ReleaseError::CommandFailed {
            program: program.into(),
            status,
        });
    }
    Ok(ExecOutput {
        status: status.code().unwrap_or(1),
        stdout: std::mem::take(&mut *stdout),
        stderr: std::mem::take(&mut *stderr),
    })
}

fn terminate_process_tree(child: &mut Child) {
    #[cfg(unix)]
    let _ = rustix::process::kill_process_group(
        rustix::process::Pid::from_child(child),
        rustix::process::Signal::KILL,
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
fn set_nonblocking(stream: &impl std::os::fd::AsFd) -> Result<()> {
    let flags = rustix::fs::fcntl_getfl(stream)
        .map_err(|_| contract("external command output pipe setup failed"))?;
    rustix::fs::fcntl_setfl(stream, flags | rustix::fs::OFlags::NONBLOCK)
        .map_err(|_| contract("external command output pipe setup failed"))
}

fn read_output(
    mut stream: impl Read,
    program: &str,
    cancel: &AtomicBool,
) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u8; 8 * 1024]);
    loop {
        match stream.read(chunk.as_mut()) {
            Ok(0) => break,
            Ok(count) => {
                bytes.extend_from_slice(&chunk[..count]);
                if bytes.len() as u64 > MAX_OUTPUT {
                    return Err(contract("external command output exceeded the fixed limit"));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(io_error(program)(error)),
        }
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| contract("external command output is not UTF-8"))?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn classify_registry_failure(stderr: &str) -> ReleaseError {
    let lower = Zeroizing::new(stderr.to_ascii_lowercase());
    if lower.contains("unauthorized") || lower.contains("authentication required") {
        contract("Docker Hub latest discovery authentication failed")
    } else if lower.contains("too many requests") || lower.contains("rate limit") {
        contract("Docker Hub latest discovery rate limited")
    } else if lower.contains("not found") || lower.contains("no such manifest") {
        contract("Docker Hub latest is missing")
    } else {
        contract("Docker Hub latest discovery failed")
    }
}

pub(super) fn resolve_latest_digest(executor: &dyn RegistryExecutor) -> Result<String> {
    let output = executor.inspect_latest()?;
    if output.status != 0 {
        return Err(contract("Docker Hub latest discovery failed"));
    }
    let manifest: serde_json::Value = serde_json::from_str(output.stdout.trim())
        .map_err(|_| contract("Docker Hub latest discovery returned malformed JSON"))?;
    let digest_value = if let Some(platforms) = manifest.get("manifests") {
        let matches = platforms
            .as_array()
            .ok_or_else(|| contract("Docker Hub manifest list is malformed"))?
            .iter()
            .filter(|entry| {
                entry["platform"]["os"].as_str() == Some("linux")
                    && entry["platform"]["architecture"].as_str() == Some("amd64")
                    && entry["platform"]["variant"]
                        .as_str()
                        .is_none_or(str::is_empty)
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(contract(
                "Docker Hub latest must contain exactly one linux/amd64 manifest",
            ));
        }
        matches[0]["digest"]
            .as_str()
            .ok_or_else(|| contract("Docker Hub platform digest is missing"))?
    } else {
        manifest["digest"]
            .as_str()
            .ok_or_else(|| contract("Docker Hub latest digest is missing"))?
    };
    let canonical = digest_value
        .strip_prefix("sha256:")
        .ok_or_else(|| contract("Docker Hub latest digest is malformed"))?;
    digest(canonical, "Docker Hub latest")?;
    Ok(format!("sha256:{canonical}"))
}

#[derive(Clone, Debug, Serialize)]
pub struct Ec2Plan {
    pub target: String,
    pub provider: String,
    pub region: String,
    pub dry_run: bool,
    pub monthly_estimate_usd: String,
    pub max_monthly_usd: Option<u32>,
    pub within_cost_guard: Option<bool>,
    pub ingress: Vec<IngressRule>,
    pub actions: Vec<PlannedAction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IngressRule {
    pub protocol: String,
    pub from_port: u16,
    pub to_port: u16,
    pub cidr: String,
    pub purpose: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PlannedAction {
    pub id: String,
    pub program: String,
    pub mutation: bool,
}

pub fn plan(manifest: &AwsEc2Manifest, max_monthly_usd: Option<u32>) -> Result<Ec2Plan> {
    manifest.validate()?;
    manifest.bundle()?;
    let estimate = monthly_estimate_cents(manifest);
    let allowed = max_monthly_usd.map(|limit| u64::from(limit) * 100 >= estimate);
    Ok(Ec2Plan {
        target: manifest.target.clone(),
        provider: PROVIDER.into(),
        region: REGION.into(),
        dry_run: true,
        monthly_estimate_usd: format!("{}.{:02}", estimate / 100, estimate % 100),
        max_monthly_usd,
        within_cost_guard: allowed,
        ingress: ingress_rules(manifest),
        actions: [
            ("bind-account", AWS, false),
            ("resolve-ami", AWS, false),
            ("create-key", SSH_KEYGEN, true),
            ("import-key", AWS, true),
            ("create-security-group", AWS, true),
            ("run-instance", AWS, true),
            ("allocate-associate-eip", AWS, true),
            ("create-dns", AWS, true),
            ("pin-host-key", SSH_KEYSCAN, false),
            ("stage-host-helpers", SCP, true),
            ("stage-bundle", SCP, true),
            ("install", SSH, true),
            ("verify-receipt", SSH, false),
            ("verify-https", CURL, false),
        ]
        .into_iter()
        .map(|(id, program, mutation)| PlannedAction {
            id: id.into(),
            program: program.into(),
            mutation,
        })
        .collect(),
    })
}

pub(super) fn enforce_cost_guard(manifest: &AwsEc2Manifest, limit: u32) -> Result<u64> {
    let estimate = monthly_estimate_cents(manifest);
    if u64::from(limit) * 100 < estimate {
        return Err(contract("monthly estimate exceeds --max-monthly-usd"));
    }
    Ok(estimate)
}

fn monthly_estimate_cents(manifest: &AwsEc2Manifest) -> u64 {
    // Deliberately conservative planning ceilings, not an AWS quote: compute,
    // gp3, one public IPv4 address, and a small Route53 allowance.
    let compute = if manifest.instance_type == "t3.small" {
        3_600
    } else {
        7_200
    };
    compute + u64::from(manifest.disk_gib) * 14 + 500 + 100
}

pub(super) fn ingress_rules(manifest: &AwsEc2Manifest) -> Vec<IngressRule> {
    vec![
        IngressRule {
            protocol: "tcp".into(),
            from_port: 80,
            to_port: 80,
            cidr: "0.0.0.0/0".into(),
            purpose: "public ACME HTTP challenge".into(),
        },
        IngressRule {
            protocol: "tcp".into(),
            from_port: 443,
            to_port: 443,
            cidr: "0.0.0.0/0".into(),
            purpose: "public HTTPS".into(),
        },
        IngressRule {
            protocol: "tcp".into(),
            from_port: 9443,
            to_port: 9445,
            cidr: "0.0.0.0/0".into(),
            purpose: "Agent Control native TLS".into(),
        },
        IngressRule {
            protocol: "tcp".into(),
            from_port: 22,
            to_port: 22,
            cidr: manifest.operator_ssh_cidr.clone(),
            purpose: "manifest-bound operator SSH".into(),
        },
    ]
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecyclePhase {
    Planned,
    AccountBound,
    AmiResolved,
    KeyReady,
    SecurityGroupReady,
    InstanceReady,
    EipReady,
    DnsReady,
    HostKeyPinned,
    ProvisionPending,
    Provisioning,
    HostReady,
    Installed,
    Verified,
    UpdateStaged,
    UpdateInstalling,
    UpdateVerifying,
    RollbackStaged,
    RollbackInstalling,
    RolledBack,
    Destroying,
    InfrastructureRemovedVolumeRetained,
    VolumePurged,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleRecord {
    pub version: String,
    pub source_commit: String,
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub compose_sha256: String,
    pub server_image: String,
    pub migrator_image: String,
    pub postgres_image: String,
    pub caddy_image: String,
    pub probe_image: String,
    pub installer_sha256: String,
    pub host_installer_sha256: String,
    pub host_provisioner_sha256: String,
    pub receipt_reader_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InfrastructureRecord {
    pub instance_type: String,
    pub disk_gib: u32,
    pub operator_ssh_cidr: String,
    pub key_name: String,
    pub ubuntu_ami_owner: String,
    pub ubuntu_ami_pattern: String,
}

impl InfrastructureRecord {
    pub(super) fn from_manifest(manifest: &AwsEc2Manifest) -> Self {
        Self {
            instance_type: manifest.instance_type.clone(),
            disk_gib: manifest.disk_gib,
            operator_ssh_cidr: manifest.operator_ssh_cidr.clone(),
            key_name: manifest.key_name.clone(),
            ubuntu_ami_owner: manifest.ubuntu_ami_owner.clone(),
            ubuntu_ami_pattern: manifest.ubuntu_ami_pattern.clone(),
        }
    }
}

impl BundleRecord {
    pub(super) fn from_facts(facts: &BundleFacts, manifest: &AwsEc2Manifest) -> Self {
        Self {
            version: facts.manifest.version.clone(),
            source_commit: facts.manifest.source_commit.clone(),
            bundle_sha256: facts.bundle_sha256.clone(),
            manifest_sha256: facts.manifest_sha256.clone(),
            compose_sha256: facts.compose_sha256.clone(),
            server_image: facts.manifest.server_image.clone(),
            migrator_image: facts.manifest.migrator_image.clone(),
            postgres_image: manifest.postgres_image.clone(),
            caddy_image: manifest.caddy_image.clone(),
            probe_image: manifest.probe_image.clone(),
            installer_sha256: facts.manifest.installer_sha256.clone(),
            host_installer_sha256: facts.host_installer_sha256.clone(),
            host_provisioner_sha256: facts.host_provisioner_sha256.clone(),
            receipt_reader_sha256: facts.receipt_reader_sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AmiRecord {
    pub image_id: String,
    pub name: String,
    pub creation_date: String,
    pub owner_id: String,
    pub architecture: String,
    pub root_device_type: String,
    pub virtualization_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyRecord {
    pub key_name: String,
    pub private_key_suffix: String,
    pub public_key_suffix: String,
    pub public_key_sha256: String,
    pub fingerprint: String,
    pub imported: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EipRecord {
    pub allocation_id: String,
    pub association_id: String,
    pub public_ip: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OwnedRecordSet {
    pub hosted_zone_id: String,
    pub hosted_zone_name: String,
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
    pub change_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostKeyRecord {
    pub algorithm: String,
    pub key_base64: String,
    pub key_sha256: String,
    pub console_line_sha256: String,
    pub known_hosts_suffix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ec2State {
    pub schema: String,
    pub schema_version: u32,
    pub operation_id: String,
    pub client_token: String,
    pub client_token_sha256: String,
    pub target: String,
    pub account_id: Option<String>,
    pub region: String,
    pub domain: String,
    pub tenant_id: String,
    pub indexer_id: String,
    pub ownership_tags: BTreeMap<String, String>,
    pub monthly_estimate_cents: u64,
    pub max_monthly_usd: u32,
    pub infrastructure: InfrastructureRecord,
    pub desired: BundleRecord,
    pub current: Option<BundleRecord>,
    pub previous: Option<BundleRecord>,
    pub ami: Option<AmiRecord>,
    pub key: Option<KeyRecord>,
    pub vpc_id: Option<String>,
    pub security_group_id: Option<String>,
    pub instance_id: Option<String>,
    pub private_ipv4: Option<String>,
    pub volume_id: Option<String>,
    pub eip: Option<EipRecord>,
    pub dns: Option<OwnedRecordSet>,
    pub host_key: Option<HostKeyRecord>,
    pub current_receipt: Option<InstalledReceipt>,
    pub previous_receipt: Option<InstalledReceipt>,
    pub rollback_receipt: Option<InstalledReceipt>,
    pub host_ready_receipt: Option<HostReadyReceipt>,
    pub current_bundle_suffix: Option<String>,
    pub current_request_suffix: Option<String>,
    pub previous_bundle_suffix: Option<String>,
    pub previous_request_suffix: Option<String>,
    pub provision_request_suffix: Option<String>,
    pub phase: LifecyclePhase,
    #[serde(default)]
    pub pending_effect: Option<String>,
    #[serde(default)]
    pub retained_volume: bool,
    pub integrity_sha256: String,
}

impl Ec2State {
    pub(super) fn seal(mut self) -> Result<Self> {
        self.integrity_sha256.clear();
        self.integrity_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }

    pub(super) fn verify(&self) -> Result<()> {
        if self.schema != "dirextalk.aws-ec2-lifecycle"
            || self.schema_version != 1
            || self.region != REGION
        {
            return Err(contract("EC2 state schema or region is invalid"));
        }
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_sha256);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
        }
        let operation = uuid::Uuid::parse_str(&self.operation_id)
            .map_err(|_| ReleaseError::StateUnsafe(PathBuf::from("EC2 state")))?;
        let tenant = uuid::Uuid::parse_str(&self.tenant_id)
            .map_err(|_| ReleaseError::StateUnsafe(PathBuf::from("EC2 state")))?;
        let indexer = uuid::Uuid::parse_str(&self.indexer_id)
            .map_err(|_| ReleaseError::StateUnsafe(PathBuf::from("EC2 state")))?;
        if operation.get_version_num() != 7
            || tenant.get_version_num() != 7
            || indexer.get_version_num() != 7
            || self.tenant_id == self.indexer_id
            || self.client_token != self.operation_id
            || self.client_token_sha256 != bundle::hash(self.client_token.as_bytes())
            || self.max_monthly_usd == 0
            || self.monthly_estimate_cents > u64::from(self.max_monthly_usd) * 100
        {
            return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
        }
        token(&self.target, "state target")?;
        domain(&self.domain)?;
        let mut tags = BTreeMap::new();
        tags.insert("DirextalkManaged".into(), "true".into());
        tags.insert("DirextalkTarget".into(), self.target.clone());
        tags.insert("DirextalkOperation".into(), self.operation_id.clone());
        tags.insert(
            "DirextalkClientTokenSha256".into(),
            self.client_token_sha256.clone(),
        );
        tags.insert("DirextalkDomain".into(), self.domain.clone());
        if tags != self.ownership_tags {
            return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
        }
        validate_infrastructure_record(&self.infrastructure)?;
        validate_bundle_record(&self.desired)?;
        for record in [&self.current, &self.previous].into_iter().flatten() {
            validate_bundle_record(record)?;
        }
        if self.account_id.as_ref().is_some_and(|account| {
            account.len() != 12 || !account.bytes().all(|byte| byte.is_ascii_digit())
        }) {
            return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
        }
        if self.private_ipv4.as_ref().is_some_and(|value| {
            value
                .parse::<Ipv4Addr>()
                .ok()
                .is_none_or(|address| !address.is_private())
        }) {
            return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
        }
        Ok(())
    }
}

fn validate_infrastructure_record(record: &InfrastructureRecord) -> Result<()> {
    if !matches!(record.instance_type.as_str(), "t3.small" | "t3.medium")
        || !(30..=200).contains(&record.disk_gib)
        || record.ubuntu_ami_owner != UBUNTU_OWNER
        || record.ubuntu_ami_pattern != UBUNTU_PATTERN
    {
        return Err(ReleaseError::StateUnsafe(PathBuf::from("EC2 state")));
    }
    operator_cidr(&record.operator_ssh_cidr)?;
    token(&record.key_name, "state key_name")
}

fn validate_bundle_record(record: &BundleRecord) -> Result<()> {
    Version::parse(&record.version)
        .map_err(|_| ReleaseError::StateUnsafe(PathBuf::from("EC2 state")))?;
    bundle::commit(&record.source_commit)?;
    for (value, name) in [
        (&record.bundle_sha256, "state bundle"),
        (&record.manifest_sha256, "state manifest"),
        (&record.compose_sha256, "state compose"),
        (&record.installer_sha256, "state installer"),
        (&record.host_installer_sha256, "state host installer"),
        (&record.host_provisioner_sha256, "state host provisioner"),
        (&record.receipt_reader_sha256, "state receipt reader"),
    ] {
        digest(value, name)?;
    }
    exact_image(
        &record.server_image,
        "dirextalk/vnet-server",
        "state server image",
    )?;
    exact_image(
        &record.migrator_image,
        "dirextalk/vnet-server",
        "state migrator image",
    )?;
    exact_image(&record.postgres_image, "postgres", "state postgres image")?;
    exact_image(&record.caddy_image, "caddy", "state caddy image")?;
    exact_image(&record.probe_image, "curlimages/curl", "state probe image")
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusReport {
    pub target: String,
    pub operation_id: String,
    pub account_id: Option<String>,
    pub region: String,
    pub domain: String,
    pub phase: LifecyclePhase,
    pub current_image: Option<String>,
    pub desired_image: String,
    pub latest_digest: Option<String>,
    pub update_available: Option<bool>,
    pub offline_update_available: Option<bool>,
    pub instance_id: Option<String>,
    pub public_ip: Option<String>,
    pub retained_volume_id: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifyReport {
    pub target: String,
    pub domain: String,
    pub public_ip: String,
    pub receipt_sha256: String,
    pub bundle_sha256: String,
    pub server_image: String,
    pub migrator_image: String,
    pub https_health_verified: bool,
}

pub(super) fn expected_tags(state: &Ec2State) -> Vec<(String, String)> {
    state
        .ownership_tags
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn exact_image(value: &str, repository: &str, name: &str) -> Result<()> {
    image(value, name)?;
    if !value.starts_with(&format!("{repository}@sha256:")) {
        return Err(contract(&format!("{name} repository is not allowed")));
    }
    Ok(())
}

fn token(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(contract(&format!("{name} is invalid")));
    }
    Ok(())
}

fn domain(value: &str) -> Result<()> {
    if value.len() < 3
        || value.len() > 253
        || value.ends_with('.')
        || value != value.to_ascii_lowercase()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(contract("domain must be a normalized lowercase DNS name"));
    }
    Ok(())
}

fn operator_cidr(value: &str) -> Result<()> {
    let Some(address) = value.strip_suffix("/32") else {
        return Err(contract("operator_ssh_cidr must be an IPv4 /32"));
    };
    address
        .parse::<Ipv4Addr>()
        .map_err(|_| contract("operator_ssh_cidr must be an IPv4 /32"))?;
    Ok(())
}

pub(super) fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.into())
}

#[cfg(test)]
mod tests;
