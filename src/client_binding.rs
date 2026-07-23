//! Closed, typed client-binding issuance workflow.
//!
//! The issuer is a server-owned executable.  This module deliberately exposes
//! a typed executor seam rather than a shell/SSH escape hatch and keeps the
//! protected binding material out of durable state and operator output.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use rustix::fs::{Mode, OFlags, open};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    deployment::{
        BindingWorkload, DeploymentStateStore, OperationPhase, OperationRecord,
        require_canonical_uuid7,
    },
    error::{ReleaseError, Result, io_error},
};

const STATE_DIR: &str = "/var/lib/dirextalk-vnext-deployer";
const ISSUER: &str = "dtx-identity-provision";
const ACTION: &str = "client-binding-issue";
const MAX_OUTPUT: usize = 64 * 1024;
const MAX_BINDING: usize = 24 * 1024;
const MAX_CA: usize = 12 * 1024;
const MAX_LIFETIME_MS: u64 = 15 * 60 * 1_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ClientBindingIssueRequest {
    pub deployment_operation_id: String,
    pub target: String,
    pub tenant_id: String,
    pub server_origin: String,
    pub artifact_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
        validate_request(request)?;
        let input = serde_json::to_vec(request).map_err(ReleaseError::Json)?;
        let mut child = Command::new(ISSUER)
            .arg(ACTION)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ReleaseError::CommandStart(ISSUER.into()))?;
        child
            .stdin
            .take()
            .ok_or_else(|| contract("identity issuer stdin unavailable"))?
            .write_all(&input)
            .map_err(|_| contract("identity issuer request failed"))?;
        let output = child
            .wait_with_output()
            .map_err(|_| contract("identity issuer invocation failed"))?;
        if !output.status.success() || output.stdout.len() > MAX_OUTPUT {
            return Err(contract("identity issuer rejected client binding request"));
        }
        serde_json::from_slice(&output.stdout).map_err(ReleaseError::Json)
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
        fs::create_dir_all(&self.root).map_err(io_error(&self.root))?;
        let metadata = fs::metadata(&self.root).map_err(io_error(&self.root))?;
        if !metadata.is_dir() {
            return Err(ReleaseError::StateUnsafe(self.root.clone()));
        }
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
            .open(&path)
            .map_err(io_error(&path))?;
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
        let temp = self
            .root
            .join(format!(".client-binding-{}.tmp", std::process::id()));
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&temp)
            .map_err(io_error(&temp))?;
        file.write_all(&bytes).map_err(io_error(&temp))?;
        file.sync_all().map_err(io_error(&temp))?;
        fs::rename(&temp, &path).map_err(io_error(&path))?;
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
    validate_response(&response, &request)?;
    if let Some(existing) = &prior_state
        && (existing.binding_id != response.binding_id
            || existing.expires_at_unix_ms != response.expires_at_unix_ms
            || existing.server_receipt_digest != response.issuance_receipt_digest)
    {
        zeroize_response(&mut response);
        return Err(ReleaseError::OperationConflict);
    }
    let bytes = binding_bytes(&response)?;
    write_protected_output(output, &bytes)?;
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
    validate_state(&state)?;
    binding_store.write(&state)?;
    zeroize_response(&mut response);
    Ok(ClientBindingProjection::from(&state))
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
    let mut authorization = URL_SAFE_NO_PAD
        .decode(response.authorization.as_bytes())
        .map_err(|_| contract("client binding authorization is invalid"))?;
    let authorization_valid = authorization.len() == 32 && response.authorization.len() == 43;
    authorization.fill(0);
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

fn binding_bytes(response: &ClientBindingIssueResponse) -> Result<Vec<u8>> {
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
    let bytes = serde_json::to_vec(&artifact)?;
    if bytes.len() > MAX_BINDING {
        return Err(contract("client binding output exceeds size limit"));
    }
    Ok(bytes)
}

fn write_protected_output(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_output_path(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
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
    let mut file = options
        .open(path)
        .map_err(|_| contract("client binding output file is unsafe"))?;
    validate_output_file(&file)?;
    file.write_all(bytes)
        .map_err(|_| contract("client binding output file is unavailable"))?;
    file.sync_all()
        .map_err(|_| contract("client binding output file is unavailable"))?;
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
    let mut secret = std::mem::take(&mut response.authorization).into_bytes();
    secret.fill(0);
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
}
