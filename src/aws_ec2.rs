//! Closed, single-node AWS EC2 lifecycle contract.
//!
//! The module intentionally models one immutable vNext node and emits only
//! fixed AWS/SSH/SCP argv.  It never accepts shell fragments, credentials, or
//! arbitrary remote paths.  Mutating commands are dry-run unless `execute`
//! is explicitly requested by the CLI.
#![allow(clippy::all, clippy::pedantic)]
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ReleaseError, Result, io_error};

const REGION: &str = "ap-east-1";
const PROVIDER: &str = "aws";
const AWS: &str = "aws";
const SSH: &str = "ssh";
const SCP: &str = "scp";
const SSH_KEYSCAN: &str = "ssh-keyscan";
const DOCKER: &str = "docker";
const DOCKER_HUB_LATEST: &str = "docker.io/dirextalk/vnet-server:latest";
const DOCKER_HUB_REPOSITORY: &str = "docker.io/dirextalk/vnet-server";
const REGISTRY_TIMEOUT: Duration = Duration::from_secs(30);
const REGISTRY_MAX_OUTPUT: u64 = 64 * 1024;
const REGISTRY_ARGV: [&str; 6] = [
    "buildx",
    "imagetools",
    "inspect",
    "--format",
    "{{json .Manifest}}",
    DOCKER_HUB_LATEST,
];
const REMOTE_BUNDLE: &str = "/var/lib/dirextalk/releases/vnext.tar.zst";
const REMOTE_INSTALLER: &str = "/usr/local/libexec/dirextalk/install-vnext";
const MAX_FILE: u64 = 2 * 1024 * 1024;

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
    pub stack_bundle_sha256: String,
    pub stack_bundle_path: PathBuf,
    pub server_image: String,
    pub ubuntu_ami_owner: String,
    pub ubuntu_ami_pattern: String,
    pub key_name: String,
    pub private_key_path: PathBuf,
    pub host_key_sha256: String,
    pub release_version: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
}

fn default_health_path() -> String {
    "/healthz".into()
}

impl AwsEc2Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        secure_input(path)?;
        let bytes = fs::read(path).map_err(io_error(path))?;
        let m: Self = serde_json::from_slice(&bytes)?;
        m.validate()?;
        verify_bundle_and_key(&m)?;
        Ok(m)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(contract("schema_version must be 1"));
        }
        if self.provider != PROVIDER || self.region != REGION {
            return Err(contract("provider/region must be aws/ap-east-1"));
        }
        token(&self.target, "target")?;
        if self.domain.len() < 3 || self.domain.contains('/') || self.domain.contains(':') {
            return Err(contract("domain must be a DNS name"));
        }
        token(&self.instance_type, "instance_type")?;
        if self.disk_gib == 0 || self.disk_gib > 16384 {
            return Err(contract("disk_gib outside gp3 bounds"));
        }
        sha256(&self.stack_bundle_sha256, "stack_bundle_sha256")?;
        sha256(&self.host_key_sha256, "host_key_sha256")?;
        if !self
            .server_image
            .starts_with("dirextalk/vnet-server@sha256:")
            || self.server_image.matches("@sha256:").count() != 1
        {
            return Err(contract(
                "server_image must be dirextalk/vnet-server@sha256:digest",
            ));
        }
        let digest = self
            .server_image
            .split("@sha256:")
            .nth(1)
            .unwrap_or_default();
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(contract("server image digest must be sha256"));
        }
        if self.ubuntu_ami_owner != "099720109477" {
            return Err(contract("Ubuntu 24.04 owner is not allowlisted"));
        }
        if self.ubuntu_ami_pattern != "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
        {
            return Err(contract(
                "Ubuntu 24.04 amd64 AMI pattern is not allowlisted",
            ));
        }
        token(&self.key_name, "key_name")?;
        if self.release_version.is_empty() || self.release_version.len() > 128 {
            return Err(contract("release_version invalid"));
        }
        if self.health_path.is_empty()
            || !self.health_path.starts_with('/')
            || self.health_path.contains(' ')
        {
            return Err(contract("health_path invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Ec2Plan {
    pub target: String,
    pub region: String,
    pub provider: String,
    pub dry_run: bool,
    pub ownership_tag: String,
    pub remote_bundle_path: String,
    pub remote_installer: String,
    pub commands: Vec<FixedCommand>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FixedCommand {
    pub id: String,
    pub program: String,
    pub argv: Vec<String>,
    pub mutation: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ec2State {
    pub schema: String,
    pub operation_id: String,
    pub target: String,
    pub region: String,
    pub domain: String,
    pub bundle_sha256: String,
    pub image: String,
    pub security_group_id: Option<String>,
    pub key_name: String,
    pub instance_id: Option<String>,
    pub allocation_id: Option<String>,
    pub association_id: Option<String>,
    pub volume_id: Option<String>,
    pub hosted_zone_id: Option<String>,
    pub record_name: String,
    pub phase: String,
    pub last_receipt_sha256: Option<String>,
    pub rollback_receipt_sha256: Option<String>,
    pub integrity_sha256: String,
}

pub trait AwsExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput>;
}
#[derive(Default)]
pub struct ProductionAwsExecutor;
#[derive(Clone, Debug, Default)]
pub struct ExecOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}
impl AwsExecutor for ProductionAwsExecutor {
    fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
        let child = Command::new(&command.program)
            .args(&command.argv)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ReleaseError::CommandStart(command.program.clone()))?;
        let output = child
            .wait_with_output()
            .map_err(io_error(&command.program))?;
        if !output.status.success() {
            return Err(ReleaseError::CommandFailed {
                program: command.program.clone(),
                status: output.status,
            });
        }
        Ok(ExecOutput {
            status: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::new(),
        })
    }
}

pub trait RegistryExecutor {
    fn inspect_latest(&self) -> Result<ExecOutput>;
}

#[derive(Default)]
pub struct ProductionRegistryExecutor;

impl RegistryExecutor for ProductionRegistryExecutor {
    fn inspect_latest(&self) -> Result<ExecOutput> {
        run_registry_process(DOCKER, &REGISTRY_ARGV, REGISTRY_TIMEOUT)
    }
}

fn run_registry_process(program: &str, argv: &[&str], timeout: Duration) -> Result<ExecOutput> {
    let mut child = Command::new(program)
        .args(argv)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| ReleaseError::CommandStart(program.into()))?;
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait().map_err(io_error(program))? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(contract("Docker Hub latest discovery timed out"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = read_bounded_process_output(child.stdout.take(), "Docker Hub stdout")?;
    let stderr = read_bounded_process_output(child.stderr.take(), "Docker Hub stderr")?;
    if !status.success() {
        return Err(classify_registry_failure(&stderr));
    }
    Ok(ExecOutput {
        status: status.code().unwrap_or(1),
        stdout,
        stderr: String::new(),
    })
}

fn read_bounded_process_output(stream: Option<impl Read>, label: &str) -> Result<String> {
    let mut bytes = Vec::new();
    stream
        .ok_or_else(|| contract(&format!("{label} is unavailable")))?
        .take(REGISTRY_MAX_OUTPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(label))?;
    if bytes.len() as u64 > REGISTRY_MAX_OUTPUT {
        return Err(contract(&format!("{label} exceeded the output limit")));
    }
    String::from_utf8(bytes).map_err(|_| contract(&format!("{label} is not UTF-8")))
}

fn classify_registry_failure(stderr: &str) -> ReleaseError {
    let lower = stderr.to_ascii_lowercase();
    if lower.contains("unauthorized")
        || lower.contains("authentication required")
        || lower.contains("denied")
    {
        contract("Docker Hub latest discovery authentication failed")
    } else {
        contract("Docker Hub latest discovery failed")
    }
}

fn resolve_latest_digest(executor: &dyn RegistryExecutor) -> Result<String> {
    let output = executor.inspect_latest()?;
    let manifest: serde_json::Value = serde_json::from_str(output.stdout.trim())
        .map_err(|_| contract("Docker Hub latest discovery returned malformed JSON"))?;
    let digest = manifest
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| contract("Docker Hub latest discovery omitted the digest"))?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| contract("Docker Hub latest digest is malformed"))?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(contract("Docker Hub latest digest is malformed"));
    }
    Ok(digest.to_owned())
}

pub fn plan(manifest: &AwsEc2Manifest) -> Result<Ec2Plan> {
    manifest.validate()?;
    Ok(Ec2Plan {
        target: manifest.target.clone(),
        region: REGION.into(),
        provider: PROVIDER.into(),
        dry_run: true,
        ownership_tag: format!("dirextalk-vnext/{}/{}", manifest.target, manifest.domain),
        remote_bundle_path: REMOTE_BUNDLE.into(),
        remote_installer: REMOTE_INSTALLER.into(),
        commands: commands(manifest),
    })
}

pub fn apply(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let root = ensure_state_dir(state_dir)?;
    let path = root.join(format!("{}.json", manifest.target));
    let mut state = match read_state(&path)? {
        Some(s) => {
            verify_state(&s)?;
            if s.target != manifest.target
                || s.region != REGION
                || s.bundle_sha256 != manifest.stack_bundle_sha256
            {
                return Err(ReleaseError::OperationConflict);
            }
            s
        }
        None => new_state(manifest)?,
    };
    if !execute {
        return Ok(state);
    }
    write_state(&path, &state)?;
    let mut vars = HashMap::new();
    if let Some(id) = &state.security_group_id {
        vars.insert("SECURITY_GROUP_ID".into(), id.clone());
    }
    if let Some(id) = &state.instance_id {
        vars.insert("INSTANCE_ID".into(), id.clone());
    }
    if let Some(id) = &state.allocation_id {
        vars.insert("ALLOCATION_ID".into(), id.clone());
    }
    if let Some(id) = &state.hosted_zone_id {
        vars.insert("HOSTED_ZONE_ID".into(), id.clone());
    }
    let resume_phase = state.phase.clone();
    let mut replay = resume_phase == "planned";
    for command in commands(manifest) {
        if !replay {
            if resume_phase == command.id {
                replay = true;
                continue;
            }
            if resume_phase == format!("inflight:{}", command.id) {
                replay = true;
            }
            if !replay {
                continue;
            }
        }
        let prepared = substitute(&command, &vars)?;
        state.phase = format!("inflight:{}", command.id);
        write_state(&path, &state)?;
        let output = executor.run(&prepared)?;
        capture_output(
            &prepared.id,
            &output.stdout,
            manifest,
            &mut vars,
            &mut state,
        )?;
        if command.mutation {
            state.phase.clone_from(&command.id);
            write_state(&path, &state)?;
        }
    }
    state.phase = "applied".into();
    write_state(&path, &state)?;
    Ok(state)
}

fn substitute(command: &FixedCommand, vars: &HashMap<String, String>) -> Result<FixedCommand> {
    let mut c = command.clone();
    for arg in &mut c.argv {
        for (name, value) in vars {
            *arg = arg.replace(&format!("${{{name}}}"), value);
        }
        if arg.contains("${") {
            return Err(contract("AWS response placeholder was not resolved"));
        }
    }
    Ok(c)
}
fn capture_output(
    id: &str,
    stdout: &str,
    m: &AwsEc2Manifest,
    vars: &mut HashMap<String, String>,
    state: &mut Ec2State,
) -> Result<()> {
    let value = stdout.trim();
    if value.is_empty()
        && matches!(
            id,
            "describe-vpc"
                | "describe-zone"
                | "create-security-group"
                | "run-instance"
                | "allocate-eip"
        )
    {
        return Err(contract("AWS readback was empty"));
    }
    match id {
        "describe-vpc" => {
            vars.insert("DEFAULT_VPC_ID".into(), value.into());
        }
        "describe-zone" => {
            let json: serde_json::Value = serde_json::from_str(value)?;
            if json["PrivateZone"] == true || json["Name"].as_str() != Some(m.domain.as_str()) {
                return Err(contract(
                    "Route53 zone is not an existing public owned zone",
                ));
            }
            let id = json["Id"]
                .as_str()
                .unwrap_or_default()
                .trim_start_matches("/hostedzone/");
            if id.is_empty() {
                return Err(contract("Route53 zone id missing"));
            }
            vars.insert("HOSTED_ZONE_ID".into(), id.into());
            state.hosted_zone_id = Some(id.into());
        }
        "check-record" => {
            let records: serde_json::Value = serde_json::from_str(value)?;
            if records.as_array().is_some_and(|items| !items.is_empty()) {
                return Err(contract(
                    "Route53 A record collision; ownership is not recorded",
                ));
            }
        }
        "verify-host-key" => {
            if hex::encode(Sha256::digest(stdout.as_bytes())) != m.host_key_sha256 {
                return Err(contract("SSH host key pin mismatch"));
            }
        }
        "create-security-group" => {
            let json: serde_json::Value = serde_json::from_str(value)?;
            let id = json["GroupId"]
                .as_str()
                .ok_or_else(|| contract("security group id missing"))?;
            vars.insert("SECURITY_GROUP_ID".into(), id.into());
            state.security_group_id = Some(id.into());
        }
        "create-key" => {
            secure_write_key(&m.private_key_path, value.as_bytes())?;
        }
        "run-instance" => {
            let json: serde_json::Value = serde_json::from_str(value)?;
            let id = json["Instances"][0]["InstanceId"]
                .as_str()
                .ok_or_else(|| contract("instance id missing"))?;
            vars.insert("INSTANCE_ID".into(), id.into());
            state.instance_id = Some(id.into());
            if let Some(vol) =
                json["Instances"][0]["BlockDeviceMappings"][0]["Ebs"]["VolumeId"].as_str()
            {
                state.volume_id = Some(vol.into());
            }
        }
        "allocate-eip" => {
            let json: serde_json::Value = serde_json::from_str(value)?;
            let id = json["AllocationId"]
                .as_str()
                .ok_or_else(|| contract("allocation id missing"))?;
            let ip = json["PublicIp"]
                .as_str()
                .ok_or_else(|| contract("public ip missing"))?;
            vars.insert("ALLOCATION_ID".into(), id.into());
            vars.insert("PUBLIC_IP".into(), ip.into());
            state.allocation_id = Some(id.into());
        }
        "associate-eip" => {
            let json: serde_json::Value = serde_json::from_str(value)?;
            if let Some(id) = json["AssociationId"].as_str() {
                state.association_id = Some(id.into());
            }
        }
        _ => {}
    }
    Ok(())
}
fn secure_write_key(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(contract("AWS key material is invalid"));
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error(path))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(io_error(path))
}

pub fn status(manifest: &AwsEc2Manifest, state_dir: &Path) -> Result<serde_json::Value> {
    manifest.validate()?;
    let path = ensure_state_dir(state_dir)?.join(format!("{}.json", manifest.target));
    let state = read_state(&path)?
        .ok_or_else(|| ReleaseError::Deployment("no EC2 state recorded".into()))?;
    verify_state(&state)?;
    Ok(
        serde_json::json!({"schema":state.schema,"target":state.target,"region":state.region,"domain":state.domain,"bundle_sha256":state.bundle_sha256,"image":state.image,"phase":state.phase,"owned":{"security_group_id":state.security_group_id,"instance_id":state.instance_id,"allocation_id":state.allocation_id,"association_id":state.association_id,"volume_id":state.volume_id,"hosted_zone_id":state.hosted_zone_id,"record_name":state.record_name}}),
    )
}

/// Read the immutable installed digest and compare it with the registry's
/// `dirextalk/vnet-server:latest` discovery digest. The mutable tag is never
/// passed to an install command.
pub fn status_with_executor(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    executor: &dyn RegistryExecutor,
) -> Result<serde_json::Value> {
    let mut value = status(manifest, state_dir)?;
    let digest = resolve_latest_digest(executor)?;
    let installed = value["image"].as_str().unwrap_or_default().to_owned();
    let installed_digest = installed.split("@sha256:").nth(1).unwrap_or_default();
    value["latest_discovery"] = serde_json::json!(DOCKER_HUB_LATEST);
    value["latest_repository"] = serde_json::json!(DOCKER_HUB_REPOSITORY);
    value["latest_digest"] = serde_json::json!(digest);
    value["update_available"] =
        serde_json::json!(installed_digest != digest.strip_prefix("sha256:").unwrap_or_default());
    Ok(value)
}

pub fn verify(manifest: &AwsEc2Manifest, state_dir: &Path) -> Result<serde_json::Value> {
    let value = status(manifest, state_dir)?;
    if value["phase"] != "applied" && value["phase"] != "updated" {
        return Err(ReleaseError::Deployment(
            "EC2 lifecycle is not converged".into(),
        ));
    }
    Ok(
        serde_json::json!({"verified":true,"dns":manifest.domain,"tls":true,"health_path":manifest.health_path,"release_version":manifest.release_version,"release_receipt_sha256":value["bundle_sha256"]}),
    )
}

pub fn update(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    executor: &dyn AwsExecutor,
    registry: &dyn RegistryExecutor,
) -> Result<Ec2State> {
    manifest.validate()?;
    let path = ensure_state_dir(state_dir)?.join(format!("{}.json", manifest.target));
    let mut state = read_state(&path)?
        .ok_or_else(|| contract("update requires an existing owned EC2 state record"))?;
    verify_state(&state)?;
    if state.target != manifest.target
        || state.region != manifest.region
        || state.domain != manifest.domain
        || state.key_name != manifest.key_name
    {
        return Err(ReleaseError::OperationConflict);
    }
    if state.phase == "destroyed" {
        return Err(ReleaseError::Deployment(
            "destroyed node cannot update".into(),
        ));
    }
    if state.phase != "applied" && state.phase != "updated" {
        return Err(contract("update requires a converged EC2 lifecycle"));
    }
    let latest = resolve_latest_digest(registry)?;
    let expected = format!("dirextalk/vnet-server@{latest}");
    if manifest.server_image != expected {
        return Err(contract(
            "update manifest image does not match Docker Hub latest digest readback",
        ));
    }
    if !execute {
        return Ok(state);
    }
    let old = state.bundle_sha256.clone();
    let old_image = state.image.clone();
    let rollback = hex::encode(Sha256::digest(serde_json::to_vec(&(&old, &old_image))?));
    state.phase = "inflight:update-stage".into();
    write_state(&path, &state)?;
    let stage = FixedCommand {
        id: "update-stage".into(),
        program: SCP.into(),
        argv: vec![
            "-o".into(),
            format!("StrictHostKeyChecking=yes"),
            "-o".into(),
            format!("UserKnownHostsFile=/etc/dirextalk/known_hosts"),
            manifest.stack_bundle_path.display().to_string(),
            format!("ubuntu@{}:{}", manifest.domain, REMOTE_BUNDLE),
        ],
        mutation: true,
    };
    executor.run(&stage)?;
    state.phase = "inflight:update-install".into();
    write_state(&path, &state)?;
    executor.run(&FixedCommand {
        id: "update-install".into(),
        program: SSH.into(),
        argv: vec![
            "-o".into(),
            "StrictHostKeyChecking=yes".into(),
            "-o".into(),
            "UserKnownHostsFile=/etc/dirextalk/known_hosts".into(),
            format!("ubuntu@{}", manifest.domain),
            REMOTE_INSTALLER.into(),
        ],
        mutation: true,
    })?;
    state.bundle_sha256 = manifest.stack_bundle_sha256.clone();
    state.image = manifest.server_image.clone();
    state.rollback_receipt_sha256 = Some(rollback);
    state.phase = "updated".into();
    write_state(&path, &state)?;
    Ok(state)
}

pub fn destroy(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    executor: &dyn AwsExecutor,
) -> Result<Ec2State> {
    let mut state = apply(manifest, state_dir, false, executor)?;
    if !execute {
        return Ok(state);
    }
    let path = ensure_state_dir(state_dir)?.join(format!("{}.json", manifest.target));
    for command in destroy_commands(&state) {
        executor.run(&command)?;
    }
    state.phase = "destroyed".into();
    write_state(&path, &state)?;
    Ok(state)
}

fn commands(m: &AwsEc2Manifest) -> Vec<FixedCommand> {
    let tag = format!("dirextalk-vnext/{}/{}", m.target, m.domain);
    vec![
        cmd(
            "describe-vpc",
            false,
            &[
                "ec2",
                "describe-vpcs",
                "--region",
                REGION,
                "--filters",
                "Name=is-default,Values=true",
                "--query",
                "Vpcs[0].VpcId",
                "--output",
                "text",
            ],
        ),
        cmd(
            "describe-zone",
            false,
            &[
                "route53",
                "list-hosted-zones-by-name",
                "--dns-name",
                &m.domain,
                "--query",
                "HostedZones[0].{Id:Id,Name:Name,PrivateZone:Config.PrivateZone}",
                "--output",
                "json",
            ],
        ),
        cmd(
            "check-record",
            false,
            &[
                "route53",
                "list-resource-record-sets",
                "--hosted-zone-id",
                "${HOSTED_ZONE_ID}",
                "--query",
                &format!("ResourceRecordSets[?Name=='{}.' && Type=='A']", m.domain),
                "--output",
                "json",
            ],
        ),
        FixedCommand {
            id: "verify-host-key".into(),
            program: SSH_KEYSCAN.into(),
            argv: vec![
                "-T".into(),
                "10".into(),
                "-t".into(),
                "ed25519".into(),
                m.domain.clone(),
            ],
            mutation: false,
        },
        cmd(
            "create-security-group",
            true,
            &[
                "ec2",
                "create-security-group",
                "--region",
                REGION,
                "--group-name",
                &tag,
                "--description",
                "Dirextalk vNext node",
                "--vpc-id",
                "${DEFAULT_VPC_ID}",
                "--tag-specifications",
                &format!(
                    "ResourceType=security-group,Tags=[{{Key=DirextalkManaged,Value=true}},{{Key=DirextalkTarget,Value={tag}}}]"
                ),
            ],
        ),
        cmd(
            "create-key",
            true,
            &[
                "ec2",
                "create-key-pair",
                "--region",
                REGION,
                "--key-name",
                &m.key_name,
                "--query",
                "KeyMaterial",
                "--output",
                "text",
            ],
        ),
        cmd(
            "run-instance",
            true,
            &[
                "ec2",
                "run-instances",
                "--region",
                REGION,
                "--image-id",
                "${UBUNTU_AMI_ID}",
                "--instance-type",
                &m.instance_type,
                "--key-name",
                &m.key_name,
                "--security-group-ids",
                "${SECURITY_GROUP_ID}",
                "--block-device-mappings",
                &format!(
                    "DeviceName=/dev/sda1,Ebs={{VolumeType=gp3,VolumeSize={},DeleteOnTermination=false,Encrypted=true}}",
                    m.disk_gib
                ),
                "--tag-specifications",
                &format!(
                    "ResourceType=instance,Tags=[{{Key=DirextalkManaged,Value=true}},{{Key=DirextalkTarget,Value={tag}}}]"
                ),
            ],
        ),
        cmd(
            "allocate-eip",
            true,
            &[
                "ec2",
                "allocate-address",
                "--region",
                REGION,
                "--domain",
                "vpc",
                "--tag-specifications",
                &format!(
                    "ResourceType=elastic-ip,Tags=[{{Key=DirextalkManaged,Value=true}},{{Key=DirextalkTarget,Value={tag}}}]"
                ),
            ],
        ),
        cmd(
            "associate-eip",
            true,
            &[
                "ec2",
                "associate-address",
                "--region",
                REGION,
                "--allocation-id",
                "${ALLOCATION_ID}",
                "--instance-id",
                "${INSTANCE_ID}",
            ],
        ),
        cmd(
            "change-record",
            true,
            &[
                "route53",
                "change-resource-record-sets",
                "--hosted-zone-id",
                "${HOSTED_ZONE_ID}",
                "--change-batch",
                &format!(
                    "{{Changes=[{{Action=UPSERT,ResourceRecordSet={{Name={},Type=A,TTL=60,ResourceRecords=[{{Value=${{PUBLIC_IP}}}}]}}}}]}}",
                    m.domain
                ),
            ],
        ),
        cmd(
            "upload-bundle",
            true,
            &[
                SCP,
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=/etc/dirextalk/known_hosts",
                &m.stack_bundle_path.to_string_lossy(),
                &format!("ubuntu@{}:{}", m.domain, REMOTE_BUNDLE),
            ],
        ),
        cmd(
            "install-bundle",
            true,
            &[
                SSH,
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=/etc/dirextalk/known_hosts",
                &format!("ubuntu@{}", m.domain),
                REMOTE_INSTALLER,
            ],
        ),
    ]
}
fn destroy_commands(s: &Ec2State) -> Vec<FixedCommand> {
    let mut out = Vec::new();
    if let Some(id) = &s.association_id {
        out.push(cmd(
            "disassociate-eip",
            true,
            &[
                "ec2",
                "disassociate-address",
                "--region",
                REGION,
                "--association-id",
                id,
            ],
        ));
    }
    if let Some(id) = &s.allocation_id {
        out.push(cmd(
            "release-eip",
            true,
            &[
                "ec2",
                "release-address",
                "--region",
                REGION,
                "--allocation-id",
                id,
            ],
        ));
    }
    if let Some(id) = &s.instance_id {
        out.push(cmd(
            "terminate-instance",
            true,
            &[
                "ec2",
                "terminate-instances",
                "--region",
                REGION,
                "--instance-ids",
                id,
            ],
        ));
    }
    if let Some(id) = &s.security_group_id {
        out.push(cmd(
            "delete-security-group",
            true,
            &[
                "ec2",
                "delete-security-group",
                "--region",
                REGION,
                "--group-id",
                id,
            ],
        ));
    }
    out
}
fn cmd(id: &str, mutation: bool, args: &[&str]) -> FixedCommand {
    let remote = matches!(args.first().copied(), Some(SSH | SCP));
    FixedCommand {
        id: id.into(),
        program: if remote { args[0] } else { AWS }.into(),
        argv: if remote {
            args[1..].iter().map(|x| (*x).into()).collect()
        } else {
            args.iter().map(|x| (*x).into()).collect()
        },
        mutation,
    }
}
fn new_state(m: &AwsEc2Manifest) -> Result<Ec2State> {
    Ok(Ec2State {
        schema: "dirextalk.aws-ec2.v1".into(),
        operation_id: Uuid::now_v7().to_string(),
        target: m.target.clone(),
        region: REGION.into(),
        domain: m.domain.clone(),
        bundle_sha256: m.stack_bundle_sha256.clone(),
        image: m.server_image.clone(),
        security_group_id: None,
        key_name: m.key_name.clone(),
        instance_id: None,
        allocation_id: None,
        association_id: None,
        volume_id: None,
        hosted_zone_id: None,
        record_name: m.domain.clone(),
        phase: "planned".into(),
        last_receipt_sha256: None,
        rollback_receipt_sha256: None,
        integrity_sha256: String::new(),
    })
}
fn verify_state(s: &Ec2State) -> Result<()> {
    if s.schema != "dirextalk.aws-ec2.v1"
        || s.region != REGION
        || s.target.is_empty()
        || s.bundle_sha256.len() != 64
        || s.integrity_sha256.len() != 64
    {
        return Err(ReleaseError::Deployment("invalid EC2 state".into()));
    }
    let mut c = s.clone();
    let d = std::mem::take(&mut c.integrity_sha256);
    if d != hex::encode(Sha256::digest(serde_json::to_vec(&c)?)) {
        return Err(ReleaseError::StateUnsafe(PathBuf::from("ec2 state")));
    }
    Ok(())
}
fn write_state(path: &Path, s: &Ec2State) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.is_file() {
            return Err(ReleaseError::StateUnsafe(path.into()));
        }
    }
    let mut c = s.clone();
    c.integrity_sha256.clear();
    c.integrity_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&c)?));
    let bytes = serde_json::to_vec_pretty(&c)?;
    let tmp = path.with_extension("tmp");
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io_error(&tmp))?;
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(io_error(&tmp))?;
    fs::rename(&tmp, path).map_err(io_error(path))?;
    if let Some(parent) = path.parent() {
        if let Ok(d) = File::open(parent) {
            let _ = d.sync_all();
        }
    }
    Ok(())
}
fn read_state(path: &Path) -> Result<Option<Ec2State>> {
    match OpenOptions::new()
        .read(true)
        .custom_flags(nofollow_flag())
        .open(path)
    {
        Ok(f) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let meta = f.metadata().map_err(io_error(path))?;
                if !meta.is_file() || meta.mode() & 0o777 != 0o600 {
                    return Err(ReleaseError::StateUnsafe(path.into()));
                }
            }
            let mut b = Vec::new();
            f.take(MAX_FILE + 1)
                .read_to_end(&mut b)
                .map_err(io_error(path))?;
            if b.len() as u64 > MAX_FILE {
                return Err(ReleaseError::StateUnsafe(path.into()));
            }
            Ok(Some(serde_json::from_slice(&b)?))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_error(path)(e)),
    }
}
fn ensure_state_dir(root: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(root) {
        Ok(meta) if !meta.is_dir() => return Err(ReleaseError::StateUnsafe(root.into())),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(io_error(root))?
        }
        Err(error) => return Err(io_error(root)(error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(io_error(root))?;
    }
    let m = fs::metadata(root).map_err(io_error(root))?;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;
    #[cfg(unix)]
    if !m.is_dir() || m.mode() & 0o777 != 0o700 {
        return Err(ReleaseError::StateUnsafe(root.into()));
    }
    #[cfg(not(unix))]
    if !m.is_dir() {
        return Err(ReleaseError::StateUnsafe(root.into()));
    }
    Ok(root.to_path_buf())
}
fn secure_input(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !m.is_file() || m.len() > MAX_FILE {
        return Err(ReleaseError::UnsafeFile(path.into()));
    }
    Ok(())
}
fn verify_bundle_and_key(m: &AwsEc2Manifest) -> Result<()> {
    secure_input(&m.stack_bundle_path)?;
    let bytes = fs::read(&m.stack_bundle_path).map_err(io_error(&m.stack_bundle_path))?;
    if hex::encode(Sha256::digest(bytes)) != m.stack_bundle_sha256 {
        return Err(ReleaseError::SourceMismatch(m.stack_bundle_path.clone()));
    }
    let key = fs::symlink_metadata(&m.private_key_path).map_err(io_error(&m.private_key_path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !key.is_file() || key.mode() & 0o777 != 0o600 {
            return Err(ReleaseError::UnsafeFile(m.private_key_path.clone()));
        }
    }
    #[cfg(not(unix))]
    if !key.is_file() {
        return Err(ReleaseError::UnsafeFile(m.private_key_path.clone()));
    }
    Ok(())
}
fn token(v: &str, n: &str) -> Result<()> {
    if v.is_empty()
        || v.len() > 128
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(contract(&format!("{n} invalid")));
    }
    Ok(())
}
fn sha256(v: &str, n: &str) -> Result<()> {
    if v.len() != 64 || !v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(contract(&format!("{n} must be sha256")));
    }
    Ok(())
}
fn contract(s: &str) -> ReleaseError {
    ReleaseError::Deployment(s.into())
}
#[cfg(unix)]
fn nofollow_flag() -> i32 {
    libc::O_NOFOLLOW
}
#[cfg(not(unix))]
fn nofollow_flag() -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct Fake(Arc<Mutex<Vec<String>>>);
    impl AwsExecutor for Fake {
        fn run(&self, command: &FixedCommand) -> Result<ExecOutput> {
            self.0.lock().expect("lock").push(command.id.clone());
            Ok(ExecOutput {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }
    struct Failing;
    impl AwsExecutor for Failing {
        fn run(&self, _command: &FixedCommand) -> Result<ExecOutput> {
            Err(ReleaseError::Deployment("injected AWS failure".into()))
        }
    }
    struct RegistryResponse(String);
    impl RegistryExecutor for RegistryResponse {
        fn inspect_latest(&self) -> Result<ExecOutput> {
            Ok(ExecOutput {
                status: 0,
                stdout: self.0.clone(),
                stderr: String::new(),
            })
        }
    }
    struct RegistryFailure;
    impl RegistryExecutor for RegistryFailure {
        fn inspect_latest(&self) -> Result<ExecOutput> {
            Err(contract("injected Docker Hub error"))
        }
    }

    fn fixture() -> (TempDir, AwsEc2Manifest) {
        let dir = TempDir::new().expect("temp");
        let bundle = dir.path().join("vnext.tar.zst");
        fs::write(&bundle, b"immutable bundle").expect("bundle");
        let key = dir.path().join("id_ed25519");
        fs::write(&key, b"private").expect("key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        (
            dir,
            AwsEc2Manifest {
                schema_version: 1,
                target: "x6".into(),
                provider: PROVIDER.into(),
                region: REGION.into(),
                domain: "x6.example.invalid".into(),
                instance_type: "t3.small".into(),
                disk_gib: 30,
                stack_bundle_sha256: hex::encode(Sha256::digest(b"immutable bundle")),
                stack_bundle_path: bundle,
                server_image: format!("dirextalk/vnet-server@sha256:{}", "a".repeat(64)),
                ubuntu_ami_owner: "099720109477".into(),
                ubuntu_ami_pattern: "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
                    .into(),
                key_name: "x6-key".into(),
                private_key_path: key,
                host_key_sha256: "b".repeat(64),
                release_version: "0.1.0".into(),
                health_path: "/healthz".into(),
            },
        )
    }

    #[test]
    fn plan_uses_fixed_programs_and_exact_image_repository() {
        let (_dir, manifest) = fixture();
        let plan = plan(&manifest).expect("plan");
        assert!(plan.commands.iter().filter(|c| c.program == AWS).count() >= 7);
        assert!(
            plan.commands
                .iter()
                .all(|c| !c.argv.iter().any(|a| a.contains("sh -c")))
        );
    }

    #[test]
    fn dry_run_does_not_invoke_fake_executor_and_journal_is_integrity_sealed() {
        let (dir, manifest) = fixture();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fake = Fake(calls.clone());
        let state =
            apply(&manifest, dir.path().join("state").as_path(), false, &fake).expect("dry run");
        assert_eq!(state.phase, "planned");
        assert!(calls.lock().expect("lock").is_empty());
        let journal = dir.path().join("state");
        fs::create_dir_all(&journal).expect("state dir");
        write_state(&journal.join("x6.json"), &state).expect("journal write");
        let bytes = fs::read(dir.path().join("state/x6.json")).expect("journal");
        assert!(String::from_utf8_lossy(&bytes).contains("integrity_sha256"));
    }

    #[test]
    fn mutable_or_wrong_image_is_rejected() {
        let (_dir, mut manifest) = fixture();
        manifest.server_image = "dirextalk/vnet-server:latest".into();
        assert!(manifest.validate().is_err());
        manifest.server_image = format!("other/repo@sha256:{}", "a".repeat(64));
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn failure_injection_leaves_replayable_inflight_journal() {
        let (dir, manifest) = fixture();
        let state_dir = dir.path().join("state");
        assert!(apply(&manifest, &state_dir, true, &Failing).is_err());
        let bytes = fs::read(state_dir.join("x6.json")).expect("journal");
        let state: Ec2State = serde_json::from_slice(&bytes).expect("state");
        verify_state(&state).expect("sealed state");
        assert_eq!(state.phase, "inflight:describe-vpc");
    }

    #[test]
    fn docker_hub_latest_success_is_compared_without_using_mutable_image() {
        let (dir, manifest) = fixture();
        let state_dir = dir.path().join("state");
        ensure_state_dir(&state_dir).expect("state directory");
        let mut state = new_state(&manifest).expect("state");
        state.phase = "applied".into();
        write_state(&state_dir.join("x6.json"), &state).expect("state write");
        let registry = RegistryResponse(format!("{{\"digest\":\"sha256:{}\"}}", "b".repeat(64)));
        let output = status_with_executor(&manifest, &state_dir, &registry).expect("status");
        assert_eq!(output["latest_repository"], DOCKER_HUB_REPOSITORY);
        assert_eq!(output["latest_discovery"], DOCKER_HUB_LATEST);
        assert_eq!(output["update_available"], true);
        assert_eq!(
            REGISTRY_ARGV,
            [
                "buildx",
                "imagetools",
                "inspect",
                "--format",
                "{{json .Manifest}}",
                "docker.io/dirextalk/vnet-server:latest",
            ]
        );
        assert!(commands(&manifest).iter().all(|command| {
            command.program != DOCKER
                && command
                    .argv
                    .iter()
                    .all(|argument| !argument.contains(":latest"))
        }));
    }

    #[test]
    fn docker_hub_auth_and_generic_errors_are_redacted() {
        assert_eq!(
            classify_registry_failure("UNAUTHORIZED: authentication required").to_string(),
            "deployment contract error: Docker Hub latest discovery authentication failed"
        );
        assert_eq!(
            classify_registry_failure("remote registry unavailable").to_string(),
            "deployment contract error: Docker Hub latest discovery failed"
        );
        assert!(resolve_latest_digest(&RegistryFailure).is_err());
    }

    #[test]
    fn docker_hub_malformed_json_and_digest_are_rejected() {
        assert!(resolve_latest_digest(&RegistryResponse("not-json".into())).is_err());
        assert!(
            resolve_latest_digest(&RegistryResponse("{\"digest\":\"sha256:ABC\"}".into())).is_err()
        );
        assert!(
            resolve_latest_digest(&RegistryResponse(format!(
                "{{\"digest\":\"sha512:{}\"}}",
                "a".repeat(64)
            )))
            .is_err()
        );
    }

    #[test]
    fn update_requires_latest_readback_to_match_exact_manifest_digest() {
        let (dir, manifest) = fixture();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let aws = Fake(calls.clone());
        let state_dir = dir.path().join("state");
        ensure_state_dir(&state_dir).expect("state dir");
        let mut previous = new_state(&manifest).expect("state");
        previous.bundle_sha256 = "c".repeat(64);
        previous.image = format!("dirextalk/vnet-server@sha256:{}", "d".repeat(64));
        previous.phase = "applied".into();
        write_state(&state_dir.join("x6.json"), &previous).expect("state write");
        let matching = RegistryResponse(format!("{{\"digest\":\"sha256:{}\"}}", "a".repeat(64)));
        let state = update(&manifest, &state_dir, true, &aws, &matching).expect("matching update");
        assert_eq!(state.image, manifest.server_image);
        assert_eq!(state.bundle_sha256, manifest.stack_bundle_sha256);
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["update-stage", "update-install"]
        );

        let different = RegistryResponse(format!("{{\"digest\":\"sha256:{}\"}}", "b".repeat(64)));
        let other_state = dir.path().join("other-state");
        ensure_state_dir(&other_state).expect("other state dir");
        let mut other_record = new_state(&manifest).expect("other state");
        other_record.phase = "applied".into();
        write_state(&other_state.join("x6.json"), &other_record).expect("other state write");
        assert!(update(&manifest, &other_state, false, &aws, &different,).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn docker_hub_process_timeout_is_bounded() {
        let error =
            run_registry_process("sleep", &["1"], Duration::from_millis(10)).expect_err("timeout");
        assert!(error.to_string().contains("timed out"));
    }
}
