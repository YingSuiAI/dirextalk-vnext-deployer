//! Short-lived App deployment binding ticket issuance and status polling.

#![allow(
    clippy::missing_errors_doc,
    clippy::struct_field_names,
    clippy::too_many_lines
)]

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use qrcode::{QrCode, render::unicode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    ReleaseError, Result,
    aws_ec2::{self, AwsEc2Manifest, AwsExecutor, Ec2State, LifecyclePhase},
};

const REQUEST_SUFFIX: &str = "deployment-binding.request";
const STATE_SUFFIX: &str = "deployment-binding.json";
const REMOTE_REQUEST: &str = "/home/ubuntu/dirextalk-deployment-binding.request";
const REMOTE_OUTPUT: &str = "/home/ubuntu/dirextalk-deployment-binding.ticket.json";
const RELEASE_ROOT: &str = "/opt/dirextalk-vnext/releases";
const ISSUE_HELPER: &str = "scripts/production-stack/host/deployment-binding-ticket-issue";
const CLEANUP_HELPER: &str = "scripts/production-stack/host/deployment-binding-ticket-cleanup";
const REMOTE_CA: &str = "/run/dtx-deployment-binding/private-ca.pem";
const MAX_TICKET: u64 = 24 * 1024;
const TTL_MS: u64 = 15 * 60 * 1_000;

#[derive(Serialize)]
struct IssueRequest<'a> {
    schema: &'static str,
    schema_version: u8,
    deployment_operation_id: &'a str,
    tenant_id: &'a str,
    server_origin: &'a str,
    identity_tls_root_ca_file: &'static str,
    ttl_millis: u64,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ticket {
    schema: String,
    schema_version: u8,
    ticket_id: Uuid,
    binding_id: Uuid,
    deployment_operation_id: Uuid,
    tenant_id: Uuid,
    server_origin: String,
    expires_at_unix_ms: u64,
    protocol_version: u8,
    capability: String,
    status_token: String,
    qr_payload: String,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.capability.zeroize();
        self.status_token.zeroize();
        self.qr_payload.zeroize();
    }
}

#[derive(Serialize)]
struct QrPayload<'a> {
    server_origin: &'a str,
    ticket_id: Uuid,
    capability: &'a str,
    protocol_version: u8,
    expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TicketState {
    schema_version: u8,
    operation_id: String,
    target: String,
    ticket_id: Uuid,
    binding_id: Uuid,
    server_origin: String,
    expires_at_unix_ms: u64,
    status_token_sha256: String,
    output_sha256: String,
    state: String,
    integrity_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TicketProjection {
    pub operation_id: String,
    pub target: String,
    pub ticket_id: Uuid,
    pub binding_id: Uuid,
    pub server_origin: String,
    pub expires_at_unix_ms: u64,
    pub state: String,
    pub qr_payload: String,
    pub qr_terminal: String,
    pub fallback_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TicketStatus {
    pub ticket_id: Uuid,
    pub state: String,
    pub ready: bool,
}

pub fn issue_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    output: &Path,
    executor: &dyn AwsExecutor,
) -> Result<TicketProjection> {
    manifest.validate()?;
    let facts = manifest.bundle()?;
    let store = aws_ec2::store::Store::lock(state_dir, &manifest.target)?;
    let state = store
        .read::<Ec2State>()?
        .ok_or_else(|| contract("EC2 lifecycle state is missing"))?;
    state.verify()?;
    if state.target != manifest.target
        || state.domain != manifest.domain
        || state.phase != LifecyclePhase::Verified
        || state.pending_effect.is_some()
        || state.current_receipt.is_none()
        || state.host_ready_receipt.is_none()
        || state.current.as_ref().map(|record| &record.bundle_sha256) != Some(&facts.bundle_sha256)
    {
        return Err(contract(
            "deployment binding requires a verified deployment",
        ));
    }
    let issue = remote_helper(&facts, ISSUE_HELPER)?;
    let cleanup = remote_helper(&facts, CLEANUP_HELPER)?;
    verify_remote_helper(
        &state,
        &store,
        &issue,
        helper_digest(&facts, ISSUE_HELPER)?,
        executor,
    )?;
    verify_remote_helper(
        &state,
        &store,
        &cleanup,
        helper_digest(&facts, CLEANUP_HELPER)?,
        executor,
    )?;

    let origin = format!("https://{}", state.domain);
    let request = IssueRequest {
        schema: "dirextalk.deployment-binding-ticket-issue",
        schema_version: 1,
        deployment_operation_id: &state.operation_id,
        tenant_id: &state.tenant_id,
        server_origin: &origin,
        identity_tls_root_ca_file: REMOTE_CA,
        ttl_millis: TTL_MS,
    };
    let request_bytes = serde_json::to_vec(&request)?;
    let local_request = store.write_artifact(REQUEST_SUFFIX, &request_bytes, 0o600)?;
    stage_request(&state, &store, &local_request, executor)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "issue-deployment-binding-ticket",
        &state,
        &store,
        ["/usr/bin/sudo", "--non-interactive", issue.as_str()],
        true,
        900,
    )?)?;
    pull_output(&state, &store, output, executor)?;
    let mut bytes = Zeroizing::new(read_output(output)?);
    let ticket = parse_ticket(&bytes, &state, &origin)?;
    let output_sha256 = hex::encode(Sha256::digest(&*bytes));
    let mut ticket_state = TicketState {
        schema_version: 1,
        operation_id: state.operation_id.clone(),
        target: state.target.clone(),
        ticket_id: ticket.ticket_id,
        binding_id: ticket.binding_id,
        server_origin: origin.clone(),
        expires_at_unix_ms: ticket.expires_at_unix_ms,
        status_token_sha256: hex::encode(Sha256::digest(ticket.status_token.as_bytes())),
        output_sha256,
        state: "issued".into(),
        integrity_sha256: String::new(),
    };
    seal_state(&mut ticket_state)?;
    store.write_artifact(
        STATE_SUFFIX,
        &serde_json::to_vec_pretty(&ticket_state)?,
        0o600,
    )?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "cleanup-deployment-binding-ticket",
        &state,
        &store,
        ["/usr/bin/sudo", "--non-interactive", cleanup.as_str()],
        true,
        120,
    )?)?;
    store.remove_artifact(REQUEST_SUFFIX)?;
    bytes.zeroize();
    let qr_terminal = QrCode::new(ticket.qr_payload.as_bytes())
        .map_err(|_| contract("deployment binding QR could not be rendered"))?
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    Ok(TicketProjection {
        operation_id: state.operation_id,
        target: state.target,
        ticket_id: ticket.ticket_id,
        binding_id: ticket.binding_id,
        server_origin: origin,
        expires_at_unix_ms: ticket.expires_at_unix_ms,
        state: "issued".into(),
        qr_payload: ticket.qr_payload.clone(),
        qr_terminal,
        fallback_file: output.to_owned(),
    })
}

pub fn status_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    output: &Path,
) -> Result<TicketStatus> {
    let store = aws_ec2::store::Store::lock(state_dir, &manifest.target)?;
    let bytes = Zeroizing::new(read_output(output)?);
    let ticket: Ticket = serde_json::from_slice(&bytes)?;
    let state_bytes = store.read_artifact(STATE_SUFFIX, 64 * 1024)?;
    let mut local: TicketState = serde_json::from_slice(&state_bytes)?;
    verify_state(&local)?;
    if local.ticket_id != ticket.ticket_id
        || local.operation_id != ticket.deployment_operation_id.to_string()
        || local.output_sha256 != hex::encode(Sha256::digest(&*bytes))
        || local.status_token_sha256 != hex::encode(Sha256::digest(ticket.status_token.as_bytes()))
    {
        return Err(ReleaseError::OperationConflict);
    }
    let url = format!(
        "{}/v1/deployment-bindings/{}/status",
        ticket.server_origin, ticket.ticket_id
    );
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .referer(false)
        .timeout(Duration::from_secs(20))
        .https_only(true)
        .build()
        .map_err(|_| contract("binding status client initialization failed"))?;
    let response = client
        .get(url)
        .header("accept", "application/json")
        .header(
            "authorization",
            format!("Dirextalk-Binding-Status {}", ticket.status_token),
        )
        .send()
        .map_err(|_| contract("binding status is temporarily unavailable"))?;
    if !response.status().is_success() {
        return Err(contract("binding status request was rejected"));
    }
    let body = response
        .bytes()
        .map_err(|_| contract("binding status response failed"))?;
    if body.len() > 4 * 1024 {
        return Err(contract("binding status response is too large"));
    }
    let status: TicketStatus = serde_json::from_slice(&body)?;
    if status.ticket_id != ticket.ticket_id
        || status.ready != (status.state == "consumed")
        || !matches!(
            status.state.as_str(),
            "issued" | "redeemed" | "identity_bound" | "consumed" | "expired" | "revoked"
        )
    {
        return Err(contract("binding status response is invalid"));
    }
    local.state.clone_from(&status.state);
    seal_state(&mut local)?;
    store.write_artifact(STATE_SUFFIX, &serde_json::to_vec_pretty(&local)?, 0o600)?;
    if status.ready || matches!(status.state.as_str(), "expired" | "revoked") {
        remove_output(output)?;
    }
    Ok(status)
}

pub fn wait_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    output: &Path,
) -> Result<TicketStatus> {
    loop {
        let status = status_ec2(manifest, state_dir, output)?;
        if status.ready || matches!(status.state.as_str(), "expired" | "revoked") {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

fn parse_ticket(bytes: &[u8], state: &Ec2State, origin: &str) -> Result<Ticket> {
    let ticket: Ticket = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&ticket)? != bytes
        || ticket.schema != "dirextalk.deployment-binding-ticket"
        || ticket.schema_version != 1
        || ticket.protocol_version != 1
        || ticket.ticket_id.get_version_num() != 7
        || ticket.binding_id.get_version_num() != 7
        || ticket.deployment_operation_id.to_string() != state.operation_id
        || ticket.tenant_id.to_string() != state.tenant_id
        || ticket.server_origin != origin
        || ticket.expires_at_unix_ms <= now_ms()?
        || ticket.expires_at_unix_ms > now_ms()?.saturating_add(TTL_MS)
    {
        return Err(contract("deployment binding ticket is invalid"));
    }
    for secret in [&ticket.capability, &ticket.status_token] {
        let decoded = URL_SAFE_NO_PAD
            .decode(secret)
            .map_err(|_| contract("deployment binding ticket is invalid"))?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != *secret {
            return Err(contract("deployment binding ticket is invalid"));
        }
    }
    let payload = QrPayload {
        server_origin: &ticket.server_origin,
        ticket_id: ticket.ticket_id,
        capability: &ticket.capability,
        protocol_version: 1,
        expires_at_unix_ms: ticket.expires_at_unix_ms,
    };
    let expected = format!(
        "dtxb1:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    );
    if ticket.qr_payload != expected || ticket.qr_payload.len() > 2048 {
        return Err(contract("deployment binding QR payload is invalid"));
    }
    Ok(ticket)
}

fn stage_request(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    local: &Path,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    executor.run(&aws_ec2::workflow::scp_command(
        "stage-deployment-binding-request",
        state,
        store,
        local,
        REMOTE_REQUEST,
    )?)?;
    executor.run(&aws_ec2::workflow::ssh_command(
        "protect-deployment-binding-request",
        state,
        store,
        ["/usr/bin/chmod", "0400", REMOTE_REQUEST],
        true,
        30,
    )?)?;
    Ok(())
}

fn pull_output(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    output: &Path,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    validate_output_path(output)?;
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(crate::error::io_error(parent))?;
    let temp = output.with_extension("ticket.tmp");
    let _ = fs::remove_file(&temp);
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(crate::error::io_error(&temp))?;
    executor.run(&aws_ec2::workflow::scp_from_command(
        "pull-deployment-binding-ticket",
        state,
        store,
        REMOTE_OUTPUT,
        &temp,
    )?)?;
    fs::set_permissions(&temp, fs::Permissions::from_mode(0o600))
        .map_err(crate::error::io_error(&temp))?;
    fs::rename(&temp, output).map_err(crate::error::io_error(output))
}

fn remote_helper(facts: &aws_ec2::bundle::BundleFacts, relative: &str) -> Result<String> {
    helper_digest(facts, relative)?;
    Ok(format!("{RELEASE_ROOT}/{}/{relative}", facts.bundle_sha256))
}

fn helper_digest<'a>(facts: &'a aws_ec2::bundle::BundleFacts, relative: &str) -> Result<&'a str> {
    facts
        .manifest
        .files
        .iter()
        .find(|file| file.path == relative)
        .map(|file| file.sha256.as_str())
        .ok_or_else(|| contract("deployment binding helper is absent from authenticated bundle"))
}

fn verify_remote_helper(
    state: &Ec2State,
    store: &aws_ec2::store::Store,
    path: &str,
    digest: &str,
    executor: &dyn AwsExecutor,
) -> Result<()> {
    let output = executor.run(&aws_ec2::workflow::ssh_command(
        "verify-deployment-binding-helper",
        state,
        store,
        [
            "/usr/bin/sudo",
            "--non-interactive",
            "/usr/bin/sha256sum",
            path,
        ],
        false,
        30,
    )?)?;
    let mut fields = output.stdout.split_ascii_whitespace();
    if fields.next() != Some(digest) || fields.next() != Some(path) || fields.next().is_some() {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn read_output(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(crate::error::io_error(path))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_TICKET
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(crate::error::io_error(path))?
        .take(MAX_TICKET + 1)
        .read_to_end(&mut bytes)
        .map_err(crate::error::io_error(path))?;
    Ok(bytes)
}

fn validate_output_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(ReleaseError::InvalidPath(path.to_owned()));
    }
    Ok(())
}

fn remove_output(path: &Path) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(crate::error::io_error(path))?;
    let size = file.metadata().map_err(crate::error::io_error(path))?.len();
    file.write_all(&vec![0_u8; usize::try_from(size).unwrap_or(0)])
        .map_err(crate::error::io_error(path))?;
    file.sync_all().map_err(crate::error::io_error(path))?;
    drop(file);
    fs::remove_file(path).map_err(crate::error::io_error(path))
}

fn seal_state(state: &mut TicketState) -> Result<()> {
    state.integrity_sha256.clear();
    state.integrity_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&state)?));
    Ok(())
}

fn verify_state(state: &TicketState) -> Result<()> {
    let mut copy = state.clone();
    let digest = std::mem::take(&mut copy.integrity_sha256);
    seal_state(&mut copy)?;
    if digest != copy.integrity_sha256 {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| contract("system clock is invalid"))
        .and_then(|value| {
            u64::try_from(value.as_millis()).map_err(|_| contract("system clock is invalid"))
        })
}

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.into())
}
