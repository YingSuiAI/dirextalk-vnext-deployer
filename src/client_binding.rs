//! Closed, typed client-binding issuance workflow.
//!
//! The issuer is a server-owned executable.  This module deliberately exposes
//! a typed executor seam rather than a shell/SSH escape hatch and keeps the
//! protected binding material out of durable state and operator output.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{
    aws_ec2::{self, AwsEc2Manifest, AwsExecutor, Ec2State, LifecyclePhase},
    deployment::{
        BindingWorkload, DeploymentStateStore, OperationPhase, OperationRecord,
        require_canonical_uuid7,
    },
    error::{ReleaseError, Result, io_error},
};

const STATE_DIR: &str = "/var/lib/dirextalk-vnext-deployer";
const MAX_BINDING: usize = 24 * 1024;
const MAX_CA: usize = 12 * 1024;
const MAX_LIFETIME_MS: u64 = 15 * 60 * 1_000;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClientBindingIssueRequest {
    pub deployment_operation_id: String,
    pub target: String,
    pub tenant_id: String,
    pub server_origin: String,
    pub artifact_digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientBindingIssueResponse {
    pub schema: String,
    pub schema_version: u32,
    pub binding_id: String,
    pub deployment_operation_id: String,
    pub tenant_id: String,
    pub server_origin: String,
    pub identity_tls_root_ca_pem: String,
    pub identity_tls_root_ca_sha256: String,
    pub expires_at_unix_ms: u64,
    pub authorization: String,
    pub issuance_receipt_digest: String,
}

impl Zeroize for ClientBindingIssueResponse {
    fn zeroize(&mut self) {
        self.authorization.zeroize();
        self.identity_tls_root_ca_pem.zeroize();
    }
}

impl Drop for ClientBindingIssueResponse {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct ClientBindingArtifact<'a> {
    schema: &'a str,
    schema_version: u32,
    binding_id: &'a str,
    deployment_operation_id: &'a str,
    tenant_id: &'a str,
    server_origin: &'a str,
    identity_tls_root_ca_pem: &'a str,
    identity_tls_root_ca_sha256: &'a str,
    expires_at_unix_ms: u64,
    authorization: &'a str,
}

/// Typed transport seam for the fixed server-owned issuer action.
pub trait ClientBindingExecutor {
    /// # Errors
    ///
    /// Returns an error when the fixed issuer rejects or cannot produce a
    /// validated response.
    fn issue(&self, request: &ClientBindingIssueRequest) -> Result<ClientBindingIssueResponse>;
}

#[derive(Default)]
pub struct ProductionClientBindingExecutor;

impl ClientBindingExecutor for ProductionClientBindingExecutor {
    fn issue(&self, request: &ClientBindingIssueRequest) -> Result<ClientBindingIssueResponse> {
        let _ = request;
        Err(contract(
            "local client binding issuer is disabled; use the EC2 transport",
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ClientBindingState {
    schema_version: u32,
    operation_id: String,
    target: String,
    tenant_id: String,
    server_origin: String,
    artifact_digest: String,
    binding_id: String,
    expires_at_unix_ms: u64,
    state: BindingState,
    server_receipt_digest: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BindingState {
    PendingCleanup,
    Issued,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ClientBindingProjection {
    pub operation_id: String,
    pub target: String,
    pub tenant_id: String,
    pub binding_id: String,
    pub expires_at_unix_ms: u64,
    pub state: String,
    pub artifact_digest: String,
    pub server_receipt_digest: String,
}

impl From<&ClientBindingState> for ClientBindingProjection {
    fn from(value: &ClientBindingState) -> Self {
        Self {
            operation_id: value.operation_id.clone(),
            target: value.target.clone(),
            tenant_id: value.tenant_id.clone(),
            binding_id: value.binding_id.clone(),
            expires_at_unix_ms: value.expires_at_unix_ms,
            state: match value.state {
                BindingState::PendingCleanup => "pending_cleanup",
                BindingState::Issued => "issued",
                BindingState::Expired => "expired",
                BindingState::Revoked => "revoked",
            }
            .into(),
            artifact_digest: value.artifact_digest.clone(),
            server_receipt_digest: value.server_receipt_digest.clone(),
        }
    }
}

pub struct ClientBindingStore {
    root: PathBuf,
}

impl ClientBindingStore {
    /// # Errors
    ///
    /// Returns an error when the fixed root-owned state directory cannot be
    /// selected by the current process.
    pub fn fixed() -> Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(contract("fixed deployment state requires root"));
        }
        Ok(Self {
            root: STATE_DIR.into(),
        })
    }

    #[cfg(test)]
    #[must_use]
    pub fn for_test(root: PathBuf) -> Self {
        Self { root }
    }

    fn ensure_root(&self) -> Result<()> {
        let link_metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(&self.root).map_err(io_error(&self.root))?;
                fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                    .map_err(io_error(&self.root))?;
                sync_dir(self.root.parent().unwrap_or_else(|| Path::new(".")))?;
                fs::symlink_metadata(&self.root).map_err(io_error(&self.root))?
            }
            Err(error) => return Err(io_error(&self.root)(error)),
        };
        if !link_metadata.is_dir() {
            return Err(ReleaseError::StateUnsafe(self.root.clone()));
        }
        let metadata = link_metadata;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o777 != 0o700
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(ReleaseError::StateUnsafe(self.root.clone()));
            }
        }
        Ok(())
    }

    fn lock(&self, operation_id: &str) -> Result<File> {
        self.ensure_root()?;
        let path = self
            .root
            .join(format!("client-binding-{operation_id}.lock"));
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(io_error(&path))?;
        validate_state_file(&path, &file)?;
        file.lock_exclusive()
            .map_err(|_| ReleaseError::OperationLocked)?;
        Ok(file)
    }

    fn state_path(&self, operation_id: &str) -> PathBuf {
        self.root
            .join(format!("client-binding-{operation_id}.json"))
    }

    fn read(&self, operation_id: &str) -> Result<Option<ClientBindingState>> {
        let path = self.state_path(operation_id);
        let mut file = match open(
            &path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(fd) => File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(None),
            Err(error) => return Err(io_error(&path)(std::io::Error::from(error))),
        };
        validate_state_file(&path, &file)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(io_error(&path))?;
        let state = serde_json::from_slice(&bytes)?;
        Ok(Some(state))
    }

    fn write(&self, state: &ClientBindingState) -> Result<()> {
        self.ensure_root()?;
        let path = self.state_path(&state.operation_id);
        let bytes = serde_json::to_vec(state)?;
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && (!metadata.is_file() || metadata.nlink() != 1)
        {
            return Err(ReleaseError::StateUnsafe(path));
        }
        let mut created = None;
        for _ in 0..64 {
            let temp = self.root.join(format!(
                ".client-binding-{}.{}.tmp",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp)
            {
                Ok(file) => {
                    created = Some((temp, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(&temp)(error)),
            }
        }
        let (temp, mut file) =
            created.ok_or_else(|| contract("client binding state temporary path unavailable"))?;
        file.write_all(&bytes).map_err(io_error(&temp))?;
        file.sync_all().map_err(io_error(&temp))?;
        validate_state_file(&temp, &file)?;
        fs::rename(&temp, &path).map_err(io_error(&path))?;
        sync_dir(&self.root)?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
/// # Errors
///
/// Returns an error when the operation is not terminal-successful, the issuer
/// response is not exact, or protected state/output cannot be safely written.
pub fn issue(
    operation_id: &str,
    target: &str,
    tenant_id: &str,
    server_origin: &str,
    output: &Path,
    deployment_store: &DeploymentStateStore,
    binding_store: &ClientBindingStore,
    executor: &dyn ClientBindingExecutor,
) -> Result<ClientBindingProjection> {
    require_canonical_uuid7(operation_id, "operation_id")?;
    require_canonical_uuid7(tenant_id, "tenant_id")?;
    validate_token(target, "target")?;
    validate_origin(server_origin)?;
    let operation = deployment_store.read(operation_id)?;
    validate_terminal_operation(&operation, target, tenant_id, server_origin)?;
    let artifact_digest = operation.binding().artifact.digest.clone();
    let request = ClientBindingIssueRequest {
        deployment_operation_id: operation_id.into(),
        target: target.into(),
        tenant_id: tenant_id.into(),
        server_origin: server_origin.into(),
        artifact_digest: artifact_digest.clone(),
    };
    validate_request(&request)?;
    let _lock = binding_store.lock(operation_id)?;
    let prior_state = if let Some(existing) = binding_store.read(operation_id)? {
        validate_state(&existing)?;
        if !same_identity(&existing, &request) {
            return Err(ReleaseError::OperationConflict);
        }
        if existing.state != BindingState::Issued || existing.expires_at_unix_ms <= now_ms()? {
            return Err(contract(
                "client binding is no longer live; reissue requires a new operation",
            ));
        }
        Some(existing)
    } else {
        None
    };
    if prior_state.is_some() && !output.exists() {
        return Err(ReleaseError::OperationConflict);
    }
    let mut response = executor.issue(&request)?;
    if let Err(error) = validate_response(&response, &request) {
        zeroize_response(&mut response);
        return Err(error);
    }
    if let Some(existing) = &prior_state
        && (existing.binding_id != response.binding_id
            || existing.expires_at_unix_ms != response.expires_at_unix_ms
            || existing.server_receipt_digest != response.issuance_receipt_digest)
    {
        zeroize_response(&mut response);
        return Err(ReleaseError::OperationConflict);
    }
    let bytes = match binding_bytes(&response) {
        Ok(bytes) => bytes,
        Err(error) => {
            zeroize_response(&mut response);
            return Err(error);
        }
    };
    if let Err(error) = write_protected_output(output, &bytes) {
        zeroize_response(&mut response);
        return Err(error);
    }
    let state = ClientBindingState {
        schema_version: 1,
        operation_id: operation_id.into(),
        target: target.into(),
        tenant_id: tenant_id.into(),
        server_origin: server_origin.into(),
        artifact_digest,
        binding_id: response.binding_id.clone(),
        expires_at_unix_ms: response.expires_at_unix_ms,
        state: BindingState::Issued,
        server_receipt_digest: response.issuance_receipt_digest.clone(),
    };
    if let Err(error) = validate_state(&state).and_then(|()| binding_store.write(&state)) {
        zeroize_response(&mut response);
        return Err(error);
    }
    zeroize_response(&mut response);
    Ok(ClientBindingProjection::from(&state))
}

const REMOTE_BINDING_REQUEST: &str = "/home/ubuntu/dirextalk-client-binding.request";
const REMOTE_BINDING_IMPORT: &str = "/home/ubuntu/dirextalk-client-binding.import.json";
const REMOTE_RELEASE_ROOT: &str = "/var/lib/dirextalk/vnext/releases";
const REMOTE_HELPER_RELATIVE: &str = "scripts/production-stack/host/client-binding-issue";
const REMOTE_CLEANUP_RELATIVE: &str = "scripts/production-stack/host/client-binding-export-cleanup";
const REMOTE_CA_FILE: &str = "/run/dtx-client-binding/private-ca.pem";
const CLIENT_BINDING_TTL_MILLIS: u64 = 900_000;

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct Ec2IssueRequest<'a> {
    schema: &'a str,
    schema_version: u32,
    deployment_operation_id: &'a str,
    tenant_id: &'a str,
    server_origin: &'a str,
    identity_tls_root_ca_file: &'a str,
    ttl_millis: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ec2ImportArtifact {
    schema: String,
    schema_version: u32,
    binding_id: String,
    deployment_operation_id: String,
    tenant_id: String,
    server_origin: String,
    identity_tls_root_ca_pem: String,
    identity_tls_root_ca_sha256: String,
    expires_at_unix_ms: u64,
    authorization: String,
}

/// Issue a binding through the fixed production EC2 host helper.
///
/// The EC2 lifecycle Store lock fences this action against apply/update/destroy;
/// the separate binding lock makes exact retries single-writer and replay-safe.
///
/// # Errors
///
/// Returns an error if the sealed lifecycle state is not terminal-successful,
/// fixed transport evidence does not match, or protected output/state cannot be
/// safely persisted.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn issue_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    output: &Path,
    binding_store: &ClientBindingStore,
    executor: &dyn AwsExecutor,
) -> Result<ClientBindingProjection> {
    manifest.validate()?;
    let facts = manifest.bundle()?;
    let ec2_store = aws_ec2::store::Store::lock(state_dir, &manifest.target)?;
    let state = ec2_store
        .read::<Ec2State>()?
        .ok_or_else(|| contract("EC2 lifecycle state is missing"))?;
    state.verify()?;
    validate_ec2_terminal(&state, manifest, &facts)?;
    let _binding_lock = binding_store.lock(&state.operation_id)?;
    let release = format!(
        "{REMOTE_RELEASE_ROOT}/{}/{}",
        facts.bundle_sha256, REMOTE_HELPER_RELATIVE
    );
    let cleanup = format!(
        "{REMOTE_RELEASE_ROOT}/{}/{}",
        facts.bundle_sha256, REMOTE_CLEANUP_RELATIVE
    );
    let issue_digest = bundle_helper_digest(&facts, REMOTE_HELPER_RELATIVE)?;
    let cleanup_digest = bundle_helper_digest(&facts, REMOTE_CLEANUP_RELATIVE)?;
    verify_remote_helper(
        &state,
        &ec2_store,
        &release,
        issue_digest,
        "verify-client-binding-issue-helper",
        executor,
    )?;
    verify_remote_helper(
        &state,
        &ec2_store,
        &cleanup,
        cleanup_digest,
        "verify-client-binding-cleanup-helper",
        executor,
    )?;
    if let Some(existing) = binding_store.read(&state.operation_id)? {
        validate_state(&existing)?;
        if existing.target != state.target
            || existing.tenant_id != state.tenant_id
            || existing.server_origin != format!("https://{}", state.domain)
            || existing.artifact_digest.is_empty()
        {
            return Err(ReleaseError::OperationConflict);
        }
        if existing.expires_at_unix_ms <= now_ms()? {
            return Err(contract(
                "client binding is no longer live; reissue requires a new operation",
            ));
        }
        let bytes = read_existing_output(output)?;
        if hex::encode(Sha256::digest(&bytes)) != existing.artifact_digest {
            return Err(ReleaseError::OperationConflict);
        }
        if existing.state == BindingState::PendingCleanup {
            cleanup_remote_binding(&state, &ec2_store, &cleanup, executor)?;
            let mut completed = existing;
            completed.state = BindingState::Issued;
            binding_store.write(&completed)?;
            return Ok(ClientBindingProjection::from(&completed));
        }
        return Ok(ClientBindingProjection::from(&existing));
    }

    let origin = format!("https://{}", state.domain);
    validate_origin(&origin)?;
    let request = Ec2IssueRequest {
        schema: "dirextalk.client-binding-issue",
        schema_version: 1,
        deployment_operation_id: &state.operation_id,
        tenant_id: &state.tenant_id,
        server_origin: &origin,
        identity_tls_root_ca_file: REMOTE_CA_FILE,
        ttl_millis: CLIENT_BINDING_TTL_MILLIS,
    };
    let request_bytes = serde_json::to_vec(&request)?;
    if request_bytes.len() > MAX_BINDING {
        return Err(contract("client binding request exceeds size limit"));
    }
    let local_request =
        ec2_store.write_artifact("client-binding.request", &request_bytes, 0o600)?;
    let request_digest = hex::encode(Sha256::digest(&request_bytes));
    reconcile_remote_request(
        &state,
        &ec2_store,
        &local_request,
        &request_digest,
        request_bytes.len(),
        executor,
    )?;

    let operation = issue_remote_binding(&state, &ec2_store, &release, &cleanup, output, executor);
    let remove_result = ec2_store.remove_artifact("client-binding.request");
    let mut response = operation?;
    if let Err(error) = remove_result {
        zeroize_response(&mut response);
        let _ = cleanup_remote_binding(&state, &ec2_store, &cleanup, executor);
        return Err(error);
    }
    let bytes = match binding_bytes(&response) {
        Ok(bytes) => bytes,
        Err(error) => {
            zeroize_response(&mut response);
            let _ = cleanup_remote_binding(&state, &ec2_store, &cleanup, executor);
            return Err(error);
        }
    };
    if let Err(error) = write_protected_output(output, &bytes) {
        zeroize_response(&mut response);
        let _ = cleanup_remote_binding(&state, &ec2_store, &cleanup, executor);
        return Err(error);
    }
    let pending = ClientBindingState {
        schema_version: 1,
        operation_id: state.operation_id.clone(),
        target: state.target.clone(),
        tenant_id: state.tenant_id.clone(),
        server_origin: origin,
        artifact_digest: hex::encode(Sha256::digest(&bytes)),
        binding_id: response.binding_id.clone(),
        expires_at_unix_ms: response.expires_at_unix_ms,
        state: BindingState::PendingCleanup,
        server_receipt_digest: response.issuance_receipt_digest.clone(),
    };
    if let Err(error) = validate_state(&pending).and_then(|()| binding_store.write(&pending)) {
        zeroize_response(&mut response);
        let _ = cleanup_remote_binding(&state, &ec2_store, &cleanup, executor);
        return Err(error);
    }
    zeroize_response(&mut response);
    cleanup_remote_binding(&state, &ec2_store, &cleanup, executor)?;
    let mut completed = pending;
    completed.state = BindingState::Issued;
    binding_store.write(&completed)?;
    Ok(ClientBindingProjection::from(&completed))
}

fn validate_ec2_terminal(
    state: &Ec2State,
    manifest: &AwsEc2Manifest,
    facts: &aws_ec2::bundle::BundleFacts,
) -> Result<()> {
    if state.target != manifest.target
        || state.domain != manifest.domain
        || state.phase != LifecyclePhase::Verified
        || state.current_receipt.is_none()
        || state.host_ready_receipt.is_none()
        || state.current.as_ref().map(|record| &record.bundle_sha256) != Some(&facts.bundle_sha256)
    {
        return Err(contract(
            "client binding requires a terminal-successful EC2 deployment",
        ));
    }
    Ok(())
}

fn bundle_helper_digest<'a>(
    facts: &'a aws_ec2::bundle::BundleFacts,
    relative: &str,
) -> Result<&'a str> {
    facts
        .manifest
        .files
        .iter()
        .find(|file| file.path == relative)
        .map(|file| file.sha256.as_str())
        .ok_or_else(|| contract("client binding helper is absent from authenticated bundle"))
}

fn verify_remote_helper(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    path: &str,
    expected_digest: &str,
    id: &str,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    executor.run(&aws_ec2::workflow::ssh_command(
        &format!("{id}-regular"),
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/test",
            "-f",
            path,
        ],
        false,
        30,
    )?)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        &format!("{id}-not-symlink"),
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/test",
            "!",
            "-L",
            path,
        ],
        false,
        30,
    )?)?;
    let metadata = executor.run(&aws_ec2::workflow::ssh_command(
        &format!("{id}-metadata"),
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/stat",
            "--format=%u %g %a %h",
            path,
        ],
        false,
        30,
    )?)?;
    if metadata.stdout.split_ascii_whitespace().collect::<Vec<_>>() != ["0", "0", "555", "1"] {
        return Err(ReleaseError::OperationConflict);
    }
    verify_remote_hash(
        state,
        store,
        executor,
        &format!("{id}-digest"),
        path,
        expected_digest,
    )
}

fn reconcile_remote_request(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    local: &Path,
    digest: &str,
    size: usize,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let metadata = executor.run(&aws_ec2::workflow::ssh_command(
        "inspect-client-binding-request",
        state,
        store,
        [
            "/usr/bin/find",
            "/home/ubuntu",
            "-maxdepth",
            "1",
            "-type",
            "f",
            "-name",
            "dirextalk-client-binding.request",
            "-printf",
            "%u %g %m %h %s %p\\n",
        ],
        false,
        30,
    )?)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "reject-client-binding-request-symlink",
        state,
        store,
        ["/usr/bin/test", "!", "-L", REMOTE_BINDING_REQUEST],
        false,
        30,
    )?)?;
    if metadata.stdout.trim().is_empty() {
        executor.run(&aws_ec2::workflow::scp_command(
            "stage-client-binding-request",
            state,
            store,
            local,
            REMOTE_BINDING_REQUEST,
        )?)?;
        executor.run(&aws_ec2::workflow::ssh_command(
            "protect-client-binding-request",
            state,
            store,
            ["/usr/bin/chmod", "0400", REMOTE_BINDING_REQUEST],
            true,
            30,
        )?)?;
    }
    executor.run(&aws_ec2::workflow::ssh_command(
        "verify-client-binding-request-regular",
        state,
        store,
        ["/usr/bin/test", "-f", REMOTE_BINDING_REQUEST],
        false,
        30,
    )?)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "verify-client-binding-request-not-symlink",
        state,
        store,
        ["/usr/bin/test", "!", "-L", REMOTE_BINDING_REQUEST],
        false,
        30,
    )?)?;
    let metadata = executor.run(&aws_ec2::workflow::ssh_command(
        "verify-client-binding-request",
        state,
        store,
        [
            "/usr/bin/stat",
            "--format=%u %g %a %h %s",
            REMOTE_BINDING_REQUEST,
        ],
        false,
        30,
    )?)?;
    let fields = metadata.stdout.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || fields[0] != "1000"
        || fields[1] != "1000"
        || fields[2] != "400"
        || fields[3] != "1"
        || fields[4].parse::<usize>().ok() != Some(size)
    {
        return Err(ReleaseError::OperationConflict);
    }
    verify_remote_hash(
        state,
        store,
        executor,
        "hash-client-binding-request",
        REMOTE_BINDING_REQUEST,
        digest,
    )
}

fn verify_remote_hash(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    executor: &dyn AwsExecutor,
    id: &str,
    path: &str,
    expected: &str,
) -> Result<()> {
    let output = executor.run(&aws_ec2::workflow::ssh_command(
        id,
        state,
        store,
        ["/usr/bin/sha256sum", path],
        false,
        30,
    )?)?;
    let mut fields = output.stdout.split_ascii_whitespace();
    if fields.next() != Some(expected) || fields.next() != Some(path) || fields.next().is_some() {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn issue_remote_binding(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    helper: &str,
    cleanup: &str,
    output: &Path,
    executor: &dyn AwsExecutor,
) -> Result<ClientBindingIssueResponse> {
    let run = aws_ec2::workflow::ssh_command(
        "run-client-binding-issue",
        state,
        store,
        ["/usr/bin/sudo", "--non-interactive", helper],
        true,
        900,
    )
    .and_then(|command| executor.run(&command));
    if let Err(error) = run.and_then(require_silent_output) {
        let _ = cleanup_remote_binding(state, store, cleanup, executor);
        return Err(error);
    }
    match pull_import(state, store, output, executor) {
        Ok(response) => Ok(response),
        Err(error) => {
            let _ = cleanup_remote_binding(state, store, cleanup, executor);
            Err(error)
        }
    }
}

fn cleanup_remote_binding(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    cleanup: &str,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let command = aws_ec2::workflow::ssh_command(
        "cleanup-client-binding-export",
        state,
        store,
        ["/usr/bin/sudo", "--non-interactive", cleanup],
        true,
        120,
    )?;
    let output = executor.run(&command)?;
    require_silent_output(output)
}

fn require_silent_output(mut output: aws_ec2::ExecOutput) -> Result<()> {
    let silent = output.status == 0 && output.stdout.is_empty() && output.stderr.is_empty();
    output.stdout.zeroize();
    output.stderr.zeroize();
    if silent {
        Ok(())
    } else {
        Err(contract("client binding helper produced unexpected output"))
    }
}

#[allow(clippy::too_many_lines)]
fn pull_import(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    output: &Path,
    executor: &dyn AwsExecutor,
) -> Result<ClientBindingIssueResponse> {
    executor.run(&aws_ec2::workflow::ssh_command(
        "verify-client-binding-import-regular",
        state,
        store,
        ["/usr/bin/test", "-f", REMOTE_BINDING_IMPORT],
        false,
        30,
    )?)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "verify-client-binding-import-not-symlink",
        state,
        store,
        ["/usr/bin/test", "!", "-L", REMOTE_BINDING_IMPORT],
        false,
        30,
    )?)?;
    let metadata = executor.run(&aws_ec2::workflow::ssh_command(
        "inspect-client-binding-import",
        state,
        store,
        [
            "/usr/bin/stat",
            "--format=%u %g %a %h %s",
            REMOTE_BINDING_IMPORT,
        ],
        false,
        30,
    )?)?;
    let fields = metadata.stdout.split_ascii_whitespace().collect::<Vec<_>>();
    if fields.len() != 5
        || fields[0] != "1000"
        || fields[1] != "1000"
        || fields[2] != "400"
        || fields[3] != "1"
        || fields[4]
            .parse::<usize>()
            .ok()
            .is_none_or(|size| size == 0 || size > MAX_BINDING)
    {
        return Err(ReleaseError::OperationConflict);
    }
    let remote_size = fields[4]
        .parse::<usize>()
        .map_err(|_| ReleaseError::OperationConflict)?;
    let remote_hash = executor.run(&aws_ec2::workflow::ssh_command(
        "hash-client-binding-import",
        state,
        store,
        ["/usr/bin/sha256sum", REMOTE_BINDING_IMPORT],
        false,
        30,
    )?)?;
    let mut hash_fields = remote_hash.stdout.split_ascii_whitespace();
    let expected_digest = hash_fields
        .next()
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(ReleaseError::OperationConflict)?
        .to_owned();
    if hash_fields.next() != Some(REMOTE_BINDING_IMPORT) || hash_fields.next().is_some() {
        return Err(ReleaseError::OperationConflict);
    }
    validate_output_path(output)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(io_error(parent))?;
    let temp = output.with_file_name(format!(
        ".{}.client-binding.tmp",
        output.file_name().unwrap().to_string_lossy()
    ));
    if let Ok(metadata) = fs::symlink_metadata(&temp) {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ReleaseError::StateUnsafe(temp));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temp)
            .map_err(io_error(&temp))?;
        validate_output_file(&file)?;
        drop(file);
        fs::remove_file(&temp).map_err(io_error(&temp))?;
        sync_dir(parent)?;
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp)
        .map_err(io_error(&temp))?;
    drop(file);
    let result = (|| {
        executor.run(&aws_ec2::workflow::scp_from_command(
            "pull-client-binding-import",
            state,
            store,
            REMOTE_BINDING_IMPORT,
            &temp,
        )?)?;
        let bytes = Zeroizing::new(fs::read(&temp).map_err(io_error(&temp))?);
        validate_output_file(&File::open(&temp).map_err(io_error(&temp))?)?;
        if bytes.len() != remote_size
            || hex::encode(Sha256::digest(&bytes)) != expected_digest
            || bytes.is_empty()
            || bytes.len() > MAX_BINDING
        {
            return Err(contract("client binding import is invalid"));
        }
        let artifact: Ec2ImportArtifact = serde_json::from_slice(&bytes)?;
        let receipt_digest = hex::encode(Sha256::digest(&bytes));
        let response = ClientBindingIssueResponse {
            schema: artifact.schema,
            schema_version: artifact.schema_version,
            binding_id: artifact.binding_id,
            deployment_operation_id: artifact.deployment_operation_id,
            tenant_id: artifact.tenant_id,
            server_origin: artifact.server_origin,
            identity_tls_root_ca_pem: artifact.identity_tls_root_ca_pem,
            identity_tls_root_ca_sha256: artifact.identity_tls_root_ca_sha256,
            expires_at_unix_ms: artifact.expires_at_unix_ms,
            authorization: artifact.authorization,
            issuance_receipt_digest: receipt_digest,
        };
        let request = ClientBindingIssueRequest {
            deployment_operation_id: response.deployment_operation_id.clone(),
            target: state.target.clone(),
            tenant_id: response.tenant_id.clone(),
            server_origin: response.server_origin.clone(),
            artifact_digest: state.desired.bundle_sha256.clone(),
        };
        if let Err(error) = validate_response(&response, &request) {
            let mut response = response;
            zeroize_response(&mut response);
            return Err(error);
        }
        Ok(response)
    })();
    let _ = fs::remove_file(&temp);
    result
}

fn read_existing_output(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ReleaseError::OperationConflict)?;
    validate_output_file(&file)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_BINDING as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ReleaseError::OperationConflict)?;
    if bytes.len() > MAX_BINDING {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(bytes)
}

fn validate_terminal_operation(
    operation: &OperationRecord,
    target: &str,
    tenant_id: &str,
    origin: &str,
) -> Result<()> {
    if operation.phase() != OperationPhase::Completed || operation.target() != target {
        return Err(contract(
            "client binding requires a terminal-successful deployment",
        ));
    }
    if operation.binding().host.tenant_id != tenant_id {
        return Err(contract("client binding tenant does not match deployment"));
    }
    match &operation.binding().workload {
        BindingWorkload::Node {
            origin: expected, ..
        } if expected == origin => Ok(()),
        BindingWorkload::Node { .. } => {
            Err(contract("client binding origin does not match deployment"))
        }
        BindingWorkload::ConnectorHost { .. } => Err(contract(
            "client binding requires a server deployment target",
        )),
    }
}

fn same_identity(state: &ClientBindingState, request: &ClientBindingIssueRequest) -> bool {
    state.operation_id == request.deployment_operation_id
        && state.target == request.target
        && state.tenant_id == request.tenant_id
        && state.server_origin == request.server_origin
        && state.artifact_digest == request.artifact_digest
}

fn validate_request(request: &ClientBindingIssueRequest) -> Result<()> {
    require_canonical_uuid7(&request.deployment_operation_id, "deployment_operation_id")?;
    require_canonical_uuid7(&request.tenant_id, "tenant_id")?;
    validate_token(&request.target, "target")?;
    validate_origin(&request.server_origin)?;
    validate_sha256(&request.artifact_digest, "artifact_digest")
}

fn validate_response(
    response: &ClientBindingIssueResponse,
    request: &ClientBindingIssueRequest,
) -> Result<()> {
    if response.schema != "dirextalk.client-binding" || response.schema_version != 1 {
        return Err(contract("client binding schema is unsupported"));
    }
    require_canonical_uuid7(&response.binding_id, "binding_id")?;
    if response.deployment_operation_id != request.deployment_operation_id
        || response.tenant_id != request.tenant_id
        || response.server_origin != request.server_origin
    {
        return Err(contract("identity issuer response does not match request"));
    }
    validate_origin(&response.server_origin)?;
    let now = now_ms()?;
    if response.expires_at_unix_ms <= now
        || response.expires_at_unix_ms > now.saturating_add(MAX_LIFETIME_MS)
    {
        return Err(contract(
            "client binding expiry is outside the allowed lifetime",
        ));
    }
    let mut authorization = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(response.authorization.as_bytes())
            .map_err(|_| contract("client binding authorization is invalid"))?,
    );
    let authorization_valid = authorization.len() == 32 && response.authorization.len() == 43;
    authorization.zeroize();
    if !authorization_valid {
        return Err(contract("client binding authorization is invalid"));
    }
    validate_sha256(
        &response.identity_tls_root_ca_sha256,
        "identity_tls_root_ca_sha256",
    )?;
    if response.identity_tls_root_ca_pem.is_empty()
        || response.identity_tls_root_ca_pem.len() > MAX_CA
    {
        return Err(contract("identity TLS root CA is invalid"));
    }
    if response
        .identity_tls_root_ca_pem
        .matches("BEGIN CERTIFICATE")
        .count()
        != 1
        || response
            .identity_tls_root_ca_pem
            .matches("END CERTIFICATE")
            .count()
            != 1
    {
        return Err(contract("identity TLS root CA must be a certificate"));
    }
    if hex::encode(Sha256::digest(response.identity_tls_root_ca_pem.as_bytes()))
        != response.identity_tls_root_ca_sha256
    {
        return Err(contract("identity TLS root CA digest mismatch"));
    }
    validate_sha256(&response.issuance_receipt_digest, "issuance_receipt_digest")
}

fn binding_bytes(response: &ClientBindingIssueResponse) -> Result<Zeroizing<Vec<u8>>> {
    let artifact = ClientBindingArtifact {
        schema: &response.schema,
        schema_version: response.schema_version,
        binding_id: &response.binding_id,
        deployment_operation_id: &response.deployment_operation_id,
        tenant_id: &response.tenant_id,
        server_origin: &response.server_origin,
        identity_tls_root_ca_pem: &response.identity_tls_root_ca_pem,
        identity_tls_root_ca_sha256: &response.identity_tls_root_ca_sha256,
        expires_at_unix_ms: response.expires_at_unix_ms,
        authorization: &response.authorization,
    };
    let bytes = Zeroizing::new(serde_json::to_vec(&artifact)?);
    if bytes.len() > MAX_BINDING {
        return Err(contract("client binding output exceeds size limit"));
    }
    Ok(bytes)
}

fn write_protected_output(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_output_path(path)?;
    if path.exists() {
        let mut existing = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|_| contract("client binding output file is unsafe"))?;
        validate_output_file(&existing)?;
        let mut prior = Vec::new();
        existing
            .read_to_end(&mut prior)
            .map_err(|_| contract("client binding output file is unavailable"))?;
        if prior != bytes {
            return Err(ReleaseError::OperationConflict);
        }
        return Ok(());
    }
    let temp = path.with_file_name(format!(
        ".{}.client-binding.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    if let Ok(metadata) = fs::symlink_metadata(&temp) {
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(ReleaseError::StateUnsafe(temp));
        }
        fs::remove_file(&temp).map_err(io_error(&temp))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&temp)
        .map_err(|_| contract("client binding output file is unsafe"))?;
    if file.write_all(bytes).is_err() || file.sync_all().is_err() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(contract("client binding output file is unavailable"));
    }
    if validate_output_file(&file).is_err() {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(contract("client binding output file is unsafe"));
    }
    drop(file);
    if fs::rename(&temp, path).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(contract("client binding output file is unsafe"));
    }
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(())
}

fn validate_output_file(file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| contract("client binding output file is unsafe"))?;
    if !metadata.is_file() || metadata.len() > MAX_BINDING as u64 {
        return Err(contract("client binding output file is unsafe"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(contract("client binding output file is unsafe"));
        }
    }
    Ok(())
}

fn validate_state_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata().map_err(io_error(path))?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
        }
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error(path))
}

fn validate_state(state: &ClientBindingState) -> Result<()> {
    if state.schema_version != 1 {
        return Err(contract("client binding state schema must be 1"));
    }
    require_canonical_uuid7(&state.operation_id, "operation_id")?;
    require_canonical_uuid7(&state.binding_id, "binding_id")?;
    require_canonical_uuid7(&state.tenant_id, "tenant_id")?;
    validate_token(&state.target, "target")?;
    validate_origin(&state.server_origin)?;
    validate_sha256(&state.artifact_digest, "artifact_digest")?;
    validate_sha256(&state.server_receipt_digest, "server_receipt_digest")
}

fn validate_output_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(contract("client binding output path is invalid"));
    }
    Ok(())
}

fn validate_token(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(contract(&format!("{name} is invalid")));
    }
    Ok(())
}

fn validate_origin(value: &str) -> Result<()> {
    if !value.starts_with("https://") || value.len() > 256 {
        return Err(contract("server_origin must be canonical HTTPS origin"));
    }
    let host = &value[8..];
    if host.is_empty()
        || host.contains(['/', '?', '#', '@', ':', '[', ']'])
        || host.starts_with('.')
        || host.ends_with('.')
        || host == "localhost"
        || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(contract("server_origin must be canonical HTTPS origin"));
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return Err(contract("server_origin must be canonical HTTPS origin"));
    }
    Ok(())
}

fn validate_sha256(value: &str, name: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(contract(&format!("{name} must be lowercase SHA-256")));
    }
    Ok(())
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| contract("system clock is before Unix epoch"))
        .and_then(|d| u64::try_from(d.as_millis()).map_err(|_| contract("system clock overflow")))
}

fn zeroize_response(response: &mut ClientBindingIssueResponse) {
    response.zeroize();
}

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_response_fields() {
        let value = serde_json::json!({"schema":"dirextalk.client-binding","schema_version":1,"binding_id":"018f856e-e0bd-71d2-9428-58d50cf77eaf","deployment_operation_id":"018f856e-e0bd-71d2-9428-58d50cf77eaf","tenant_id":"018f856e-e0bd-71d2-9428-58d50cf77eaf","server_origin":"https://example.com","identity_tls_root_ca_pem":"-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----","identity_tls_root_ca_sha256":"0000000000000000000000000000000000000000000000000000000000000000","expires_at_unix_ms":1,"authorization":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","issuance_receipt_digest":"0000000000000000000000000000000000000000000000000000000000000000","extra":true});
        assert!(serde_json::from_value::<ClientBindingIssueResponse>(value).is_err());
    }

    #[test]
    fn origin_rejects_confusion() {
        for origin in [
            "http://example.com",
            "https://example.com/path",
            "https://user@example.com",
            "https://localhost",
        ] {
            assert!(validate_origin(origin).is_err());
        }
    }

    #[test]
    fn ec2_issue_request_has_only_fixed_server_fields() {
        let request = Ec2IssueRequest {
            schema: "dirextalk.client-binding-issue",
            schema_version: 1,
            deployment_operation_id: "018f856e-e0bd-71d2-9428-58d50cf77eaf",
            tenant_id: "018f856e-e0bd-71d2-9428-58d50cf77eaf",
            server_origin: "https://example.com",
            identity_tls_root_ca_file: REMOTE_CA_FILE,
            ttl_millis: CLIENT_BINDING_TTL_MILLIS,
        };
        let value: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&request).expect("request serialization"))
                .expect("request JSON");
        assert_eq!(
            value
                .as_object()
                .expect("request object")
                .keys()
                .collect::<Vec<_>>(),
            vec![
                "deployment_operation_id",
                "identity_tls_root_ca_file",
                "schema",
                "schema_version",
                "server_origin",
                "tenant_id",
                "ttl_millis",
            ]
        );
        assert_eq!(value["identity_tls_root_ca_file"], REMOTE_CA_FILE);
    }

    #[test]
    fn local_issuer_path_is_fail_closed() {
        let executor = ProductionClientBindingExecutor;
        let request = ClientBindingIssueRequest {
            deployment_operation_id: "018f856e-e0bd-71d2-9428-58d50cf77eaf".into(),
            target: "x6".into(),
            tenant_id: "018f856e-e0bd-71d2-9428-58d50cf77eaf".into(),
            server_origin: "https://example.com".into(),
            artifact_digest: "0".repeat(64),
        };
        assert!(matches!(
            executor.issue(&request),
            Err(ReleaseError::Deployment(message)) if message.contains("EC2 transport")
        ));
    }

    #[test]
    fn helper_output_must_be_silent_and_is_consumed() {
        assert!(
            require_silent_output(aws_ec2::ExecOutput {
                status: 0,
                stdout: "unexpected".into(),
                stderr: String::new(),
            })
            .is_err()
        );
        assert!(
            require_silent_output(aws_ec2::ExecOutput {
                status: 0,
                stdout: String::new(),
                stderr: "unexpected".into(),
            })
            .is_err()
        );
        assert!(require_silent_output(aws_ec2::ExecOutput::default()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn protected_output_is_atomic_mode_0600_and_rejects_symlinks() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().expect("temporary directory");
        let output = root.path().join("binding.json");
        let bytes = Zeroizing::new(br#"{"schema":"dirextalk.client-binding"}"#.to_vec());
        write_protected_output(&output, &bytes).expect("protected output");
        let metadata = fs::symlink_metadata(&output).expect("output metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        let symlink = root.path().join("symlink.json");
        std::os::unix::fs::symlink(&output, &symlink).expect("symlink");
        assert!(write_protected_output(&symlink, &bytes).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn binding_store_state_is_no_follow_0600_and_directory_synced() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().expect("temporary directory");
        let store = ClientBindingStore::for_test(root.path().join("state"));
        let operation = "018f856e-e0bd-71d2-9428-58d50cf77eaf";
        let state = ClientBindingState {
            schema_version: 1,
            operation_id: operation.into(),
            target: "x6".into(),
            tenant_id: operation.into(),
            server_origin: "https://example.com".into(),
            artifact_digest: "0".repeat(64),
            binding_id: operation.into(),
            expires_at_unix_ms: u64::MAX,
            state: BindingState::PendingCleanup,
            server_receipt_digest: "1".repeat(64),
        };
        store.write(&state).expect("state write");
        let path = root
            .path()
            .join("state")
            .join(format!("client-binding-{operation}.json"));
        let metadata = fs::symlink_metadata(&path).expect("state metadata");
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
        assert!(store.read(operation).expect("state read").is_some());
    }
}
