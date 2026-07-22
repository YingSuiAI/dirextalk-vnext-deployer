//! Closed, root-only local Host Control v2 lifecycle consumer.
#![allow(
    clippy::too_many_lines,
    reason = "the lifecycle is intentionally linear and crash-replayable"
)]

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    fs::{Mode, OFlags, open},
    process::geteuid,
};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    deployment::{
        AdapterKind, BindingWorkload, ConnectorClaimPhase, DeploymentManifest,
        DeploymentStateStore, OperationPhase, OperationRecord, require_canonical_uuid7,
        validate_host_evidence,
    },
    error::{ReleaseError, Result, io_error},
};

const SUPERVISOR: &str = "/usr/local/libexec/dirextalk/dtx-agent-host-supervisor";
const PROTOCOL_V1: &str = "dirextalk.host-control.operator.v1";
const PROTOCOL_V2: &str = "dirextalk.host-control.operator.v2";
const MAX_PLAN: u64 = 65_536;
const MAX_FILE: u64 = 65_536;
const MAX_MANIFEST: u64 = 1_048_576;
const MAX_OUTPUT: usize = 65_536;
const OPERATOR_TIMEOUT: Duration = Duration::from_secs(45);
const OBSERVE_TIMEOUT: Duration = Duration::from_secs(45);

pub struct ConnectorApplyInputs {
    pub operation_id: String,
    pub manifest: PathBuf,
    pub target: String,
    pub plan: PathBuf,
    pub handoff: PathBuf,
    pub config: PathBuf,
    pub enrollment_ca: PathBuf,
    pub control_ca: PathBuf,
    pub issuer_ca: PathBuf,
}

#[derive(Debug, Serialize)]
pub struct ApplyResult {
    pub operation_id: String,
    pub lifecycle_operation_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConnectorExecutionRecordV1 {
    schema: String,
    operation_id: String,
    lifecycle_operation_id: String,
    target: String,
    tenant_id: String,
    host_id: String,
    connector_id: String,
    adapter: Adapter,
    release_sha256: String,
    expiry_millis: u64,
    manifest_sha256: String,
    plan_sha256: String,
    handoff_sha256: String,
    config_sha256: String,
    enrollment_ca_sha256: String,
    control_ca_sha256: String,
    issuer_ca_sha256: String,
    lifecycle_material_sha256: String,
    initial_revision: Revision,
    prepare_host_operation_id: String,
    start_host_operation_id: String,
    finalize_host_operation_id: String,
    prepare_replay_header_sha256: String,
    finalize_replay_header_sha256: Option<String>,
    phase: Phase,
    prepare_result: Option<V2Result>,
    start_revision: Option<Revision>,
    running_revision: Option<Revision>,
    finalize_result: Option<V2Result>,
    integrity_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Claimed,
    Prepared,
    Started,
    Running,
    Finalized,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Revision {
    desired: u64,
    observed: Option<u64>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Adapter {
    Codex,
    OpenclawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
}

impl Adapter {
    const fn deployment(self) -> AdapterKind {
        match self {
            Self::Codex => AdapterKind::Codex,
            Self::OpenclawAcp => AdapterKind::OpenclawAcp,
            Self::Eino => AdapterKind::Eino,
            Self::Rig => AdapterKind::Rig,
            Self::ClaudeCode => AdapterKind::ClaudeCode,
            Self::CustomAcp => AdapterKind::CustomAcp,
            Self::HermesAcp => AdapterKind::HermesAcp,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapPlan {
    schema: String,
    schema_version: u8,
    state: String,
    operation_id: String,
    manifest_digest: String,
    target: String,
    connector_artifact: ConnectorArtifact,
    host: PlanHost,
    connector: PlanConnector,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ConnectorArtifact {
    version: String,
    digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct PlanHost {
    tenant_id: String,
    host_id: String,
    owner_id: String,
    host_credential_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanConnector {
    instance_id: String,
    adapter_kind: Adapter,
    handoff_digest: String,
    display_name: String,
    generation: u64,
    spec_revision: u64,
    enrollment_request_id: String,
    enrollment_intent_id: String,
    installation_id: String,
    agent_device_id: String,
    binding_id: String,
    expires_at_millis: u64,
    server_origin: String,
    trust: PlanTrust,
    runtime_profile: String,
    remote_mcp: RemoteMcp,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PlanTrust {
    enrollment_url: String,
    enrollment_server_name: String,
    enrollment_root_ca_sha256: String,
    control_url: String,
    control_server_name: String,
    control_server_root_ca_sha256: String,
    connector_issuer_root_ca_sha256: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RemoteMcp {
    mcp_server_name: String,
    mcp_url: String,
    mcp_node_id: String,
    max_concurrent_runs: u64,
    offline_policy: String,
}

#[derive(Clone, Copy)]
enum ProtectedKind {
    Handoff,
    NonSecret,
}

struct ProtectedBytes {
    bytes: Vec<u8>,
    digest: String,
}
impl ProtectedBytes {
    fn read(path: &Path, max: u64, kind: ProtectedKind) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
        let file: File = descriptor.into();
        let metadata = file.metadata().map_err(io_error(path))?;
        let mode = metadata.mode() & 0o777;
        if !protected_metadata_valid(
            metadata.is_file(),
            metadata.nlink(),
            metadata.uid(),
            mode,
            metadata.len(),
            max,
            kind,
        ) {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        if bytes.len() as u64 != metadata.len() {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        let digest = digest(&bytes);
        Ok(Self { bytes, digest })
    }
}
const fn protected_metadata_valid(
    regular: bool,
    links: u64,
    uid: u32,
    mode: u32,
    size: u64,
    max: u64,
    kind: ProtectedKind,
) -> bool {
    let allowed_mode = match kind {
        ProtectedKind::Handoff => mode == 0o600,
        ProtectedKind::NonSecret => matches!(mode, 0o400 | 0o440 | 0o600),
    };
    regular && links == 1 && uid == 0 && allowed_mode && size > 0 && size <= max
}

trait Operator {
    fn invoke(&self, frame: Vec<u8>) -> Result<Vec<u8>>;
}
struct ProductionOperator;
impl Operator for ProductionOperator {
    fn invoke(&self, frame: Vec<u8>) -> Result<Vec<u8>> {
        invoke_process(SUPERVISOR, &[], frame, OPERATOR_TIMEOUT)
    }
}

/// Applies or exactly resumes one canonical deployment operation.
///
/// # Errors
/// Fails closed on unsafe input/state, identity or response mismatch, concurrency,
/// timeout, unsupported platform, or any Host Supervisor rejection.
pub fn apply(inputs: &ConnectorApplyInputs) -> Result<ApplyResult> {
    let store = DeploymentStateStore::fixed()?;
    apply_with(inputs, &ProductionOperator, &store)
}

fn apply_with(
    inputs: &ConnectorApplyInputs,
    operator: &dyn Operator,
    store: &DeploymentStateStore,
) -> Result<ApplyResult> {
    if geteuid().as_raw() != 0 {
        return Err(deployment("deployment-connector-apply requires root"));
    }
    require_canonical_uuid7(&inputs.operation_id, "deployment operation")?;
    let manifest_file =
        ProtectedBytes::read(&inputs.manifest, MAX_MANIFEST, ProtectedKind::NonSecret)?;
    let manifest = DeploymentManifest::from_bytes(&manifest_file.bytes)?;
    let plan_file = ProtectedBytes::read(&inputs.plan, MAX_PLAN, ProtectedKind::NonSecret)?;
    let plan = parse_plan(&plan_file.bytes)?;
    validate_plan_platform(&plan)?;

    let mut operation = store.read(&inputs.operation_id)?;
    validate_operation(&operation, &manifest, &plan, &inputs.target)?;
    let proof = validate_host_evidence(&plan_host_tuple(&plan))?;
    let existing_claim =
        store.read_connector_claim(&inputs.operation_id, &plan.connector.instance_id)?;
    if expired(plan.connector.expires_at_millis)? && existing_claim.is_none() {
        return Err(deployment("expired plan cannot create a Connector claim"));
    }
    let mut preflight_files = if existing_claim.is_none() {
        Some(load_material_files(inputs, &plan, &plan_file.digest)?)
    } else {
        None
    };
    let claim = store.prepare_connector_claim(&operation, &plan.connector.instance_id)?;
    let claim = store.claim_connector(&claim, &proof)?;
    if !matches!(
        claim.phase(),
        ConnectorClaimPhase::Prepared
            | ConnectorClaimPhase::HandoffObserved
            | ConnectorClaimPhase::Released
    ) {
        return Err(ReleaseError::OperationConflict);
    }
    advance_to(store, &mut operation, OperationPhase::ArtifactsVerified)?;
    let lease =
        store.lock_connector_execution(&inputs.operation_id, &plan.connector.instance_id)?;
    let existing_record = lease.read()?;
    if existing_record.is_none() && claim.phase() != ConnectorClaimPhase::Prepared {
        return Err(ReleaseError::OperationConflict);
    }
    let mut record = if let Some(bytes) = existing_record {
        let record: ConnectorExecutionRecordV1 = serde_json::from_slice(&bytes)?;
        verify_record(&record)?;
        validate_record_identity(
            &record,
            inputs,
            &manifest_file.digest,
            &plan_file.digest,
            &plan,
        )?;
        record
    } else {
        let files = match preflight_files.take() {
            Some(files) => files,
            None => load_material_files(inputs, &plan, &plan_file.digest)?,
        };
        let snapshot = invoke_v1(operator, &V1Request::snapshot(&plan))?;
        let initial_revision = validate_snapshot(snapshot, &plan)?;
        let mut record = new_record(
            inputs,
            &plan,
            &manifest_file.digest,
            &plan_file.digest,
            &files,
            initial_revision,
        );
        let replay_header = v2_header(
            &record,
            V2Operation::PrepareConnectorMaterial,
            initial_revision,
            &[],
        )?;
        record.prepare_replay_header_sha256 = digest(&serde_json::to_vec(&replay_header)?);
        persist_record(&lease, &record)?;
        record
    };
    if (claim.phase() == ConnectorClaimPhase::Released && record.phase != Phase::Finalized)
        || (claim.phase() == ConnectorClaimPhase::HandoffObserved && record.phase == Phase::Claimed)
    {
        return Err(ReleaseError::OperationConflict);
    }
    converge_deployment_projection(store, &mut operation, &record)?;

    if record.phase == Phase::Claimed {
        let result = invoke_v2_recoverable(
            operator,
            &record,
            V2Operation::PrepareConnectorMaterial,
            inputs,
            &plan,
        )?;
        record.prepare_result = Some(result);
        record.phase = Phase::Prepared;
        persist_record(&lease, &record)?;
        let _ = store.observe_connector_handoff(&record.connector_id)?;
        advance_to(store, &mut operation, OperationPhase::ConfigsWritten)?;
    }
    if record.phase == Phase::Prepared {
        let prepare = record
            .prepare_result
            .as_ref()
            .ok_or_else(|| deployment("missing prepared response"))?;
        let response = invoke_v1(operator, &V1Request::start(&record, prepare.revision()))?;
        let revision = validate_start(response, &record, prepare.revision())?;
        record.start_revision = Some(revision);
        record.phase = Phase::Started;
        persist_record(&lease, &record)?;
        advance_to(store, &mut operation, OperationPhase::ServicesConverged)?;
    }
    if record.phase == Phase::Started {
        let expected = record
            .start_revision
            .ok_or_else(|| deployment("missing start revision"))?;
        let revision = observe_running(operator, &record, expected)?;
        record.running_revision = Some(revision);
        record.phase = Phase::Running;
        persist_record(&lease, &record)?;
        advance_to(store, &mut operation, OperationPhase::ReadinessVerified)?;
    }
    if record.phase == Phase::Running {
        let running = record
            .running_revision
            .ok_or_else(|| deployment("missing Running revision"))?;
        let replay_header = v2_header(
            &record,
            V2Operation::FinalizeConnectorMaterial,
            running,
            &[],
        )?;
        let replay_digest = digest(&serde_json::to_vec(&replay_header)?);
        match &record.finalize_replay_header_sha256 {
            Some(persisted) if persisted != &replay_digest => {
                return Err(ReleaseError::OperationConflict);
            }
            Some(_) => {}
            None => {
                record.finalize_replay_header_sha256 = Some(replay_digest);
                persist_record(&lease, &record)?;
            }
        }
        let result = invoke_v2_recoverable(
            operator,
            &record,
            V2Operation::FinalizeConnectorMaterial,
            inputs,
            &plan,
        )?;
        record.finalize_result = Some(result);
        record.phase = Phase::Finalized;
        persist_record(&lease, &record)?;
        let _ = store.release_connector_claim(&record.connector_id)?;
        advance_to(store, &mut operation, OperationPhase::Completed)?;
    }
    Ok(ApplyResult {
        operation_id: record.operation_id,
        lifecycle_operation_id: record.lifecycle_operation_id,
        state: "finalized".into(),
    })
}

fn converge_deployment_projection(
    store: &DeploymentStateStore,
    operation: &mut OperationRecord,
    record: &ConnectorExecutionRecordV1,
) -> Result<()> {
    if phase_rank(record.phase) >= phase_rank(Phase::Prepared) {
        let _ = store.observe_connector_handoff(&record.connector_id)?;
        advance_to(store, operation, OperationPhase::ConfigsWritten)?;
    }
    if phase_rank(record.phase) >= phase_rank(Phase::Started) {
        advance_to(store, operation, OperationPhase::ServicesConverged)?;
    }
    if phase_rank(record.phase) >= phase_rank(Phase::Running) {
        advance_to(store, operation, OperationPhase::ReadinessVerified)?;
    }
    if record.phase == Phase::Finalized {
        let _ = store.release_connector_claim(&record.connector_id)?;
        advance_to(store, operation, OperationPhase::Completed)?;
    }
    Ok(())
}

const fn phase_rank(phase: Phase) -> u8 {
    match phase {
        Phase::Claimed => 0,
        Phase::Prepared => 1,
        Phase::Started => 2,
        Phase::Running => 3,
        Phase::Finalized => 4,
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct V1Request {
    protocol: &'static str,
    tenant_id: String,
    host_id: String,
    request: V1Body,
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum V1Body {
    Snapshot,
    Observe {
        connector_id: String,
    },
    Execute {
        operation_id: String,
        expected_desired_revision: u64,
        expected_observed_revision: Option<u64>,
        command: V1Command,
    },
}
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum V1Command {
    Start { connector_id: String },
}
impl V1Request {
    fn snapshot(plan: &BootstrapPlan) -> Self {
        Self {
            protocol: PROTOCOL_V1,
            tenant_id: plan.host.tenant_id.clone(),
            host_id: plan.host.host_id.clone(),
            request: V1Body::Snapshot,
        }
    }
    fn start(record: &ConnectorExecutionRecordV1, revision: Revision) -> Self {
        Self {
            protocol: PROTOCOL_V1,
            tenant_id: record.tenant_id.clone(),
            host_id: record.host_id.clone(),
            request: V1Body::Execute {
                operation_id: record.start_host_operation_id.clone(),
                expected_desired_revision: revision.desired,
                expected_observed_revision: revision.observed,
                command: V1Command::Start {
                    connector_id: record.connector_id.clone(),
                },
            },
        }
    }
    fn observe(record: &ConnectorExecutionRecordV1) -> Self {
        Self {
            protocol: PROTOCOL_V1,
            tenant_id: record.tenant_id.clone(),
            host_id: record.host_id.clone(),
            request: V1Body::Observe {
                connector_id: record.connector_id.clone(),
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Response {
    protocol: String,
    status: ResponseStatus,
    result: Option<V1Result>,
    error: Option<V1Failure>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum ResponseStatus {
    Succeeded,
    Rejected,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum V1Result {
    Snapshot {
        host: HostProjection,
    },
    Observation {
        revision: Revision,
        connector: ConnectorProjection,
        actual_observation: Observation,
    },
    Command {
        application: V1Application,
        disposition: Disposition,
        revision: Revision,
        connector: ConnectorProjection,
    },
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostProjection {
    tenant_id: String,
    host_id: String,
    revision: Revision,
    connectors: Vec<ConnectorProjection>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectorProjection {
    connector_id: String,
    adapter_kind: Adapter,
    release_sha256: String,
    desired_state: DesiredState,
    recorded_observation: Observation,
    credential_generation: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum V1Application {
    Applied,
    Replayed,
    Reconciled,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    Applied,
    ExpiredUnclaimed,
    PolicyBlocked,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Observation {
    Unknown,
    Stopped,
    Starting,
    Running,
    Failed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum DesiredState {
    EnsuredStopped,
    Running,
    Stopped,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V1Failure {
    code: String,
    current_revision: Option<Revision>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum V2Operation {
    PrepareConnectorMaterial,
    FinalizeConnectorMaterial,
}
#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct V2Header {
    protocol: &'static str,
    tenant_id: String,
    host_id: String,
    host_operation_id: String,
    expected_desired_revision: u64,
    expected_observed_revision: Option<u64>,
    connector_id: String,
    adapter: Adapter,
    approved_release_sha256: String,
    lifecycle_operation_id: String,
    platform_target: String,
    expiry_millis: u64,
    plan_sha256: String,
    handoff_sha256: String,
    config_sha256: String,
    enrollment_ca_sha256: String,
    control_ca_sha256: String,
    issuer_ca_sha256: String,
    lifecycle_material_sha256: String,
    payload_sha256: String,
    prepared_receipt_sha256: Option<String>,
    operation: V2Operation,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct V2Response {
    protocol: String,
    status: ResponseStatus,
    error: Option<String>,
    result: Option<V2Result>,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct V2Result {
    operation: V2Operation,
    application: V2Application,
    disposition: Disposition,
    desired_revision: u64,
    observed_revision: Option<u64>,
    connector_id: String,
    lifecycle_state: LifecycleState,
    prepared_receipt_sha256: Option<String>,
    finalized_receipt_sha256: Option<String>,
}
impl V2Result {
    const fn revision(&self) -> Revision {
        Revision {
            desired: self.desired_revision,
            observed: self.observed_revision,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum V2Application {
    Applied,
    Replayed,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum LifecycleState {
    Prepared,
    Finalized,
}

struct MaterialFiles {
    handoff: ProtectedBytes,
    config: ProtectedBytes,
    enrollment: ProtectedBytes,
    control: ProtectedBytes,
    issuer: ProtectedBytes,
    prepare_material: Vec<u8>,
}

fn load_material_files(
    inputs: &ConnectorApplyInputs,
    plan: &BootstrapPlan,
    expected_plan_sha256: &str,
) -> Result<MaterialFiles> {
    let config = ProtectedBytes::read(&inputs.config, MAX_FILE, ProtectedKind::NonSecret)?;
    let enrollment =
        ProtectedBytes::read(&inputs.enrollment_ca, MAX_FILE, ProtectedKind::NonSecret)?;
    let control = ProtectedBytes::read(&inputs.control_ca, MAX_FILE, ProtectedKind::NonSecret)?;
    let issuer = ProtectedBytes::read(&inputs.issuer_ca, MAX_FILE, ProtectedKind::NonSecret)?;
    if enrollment.digest != plan.connector.trust.enrollment_root_ca_sha256
        || control.digest != plan.connector.trust.control_server_root_ca_sha256
        || issuer.digest != plan.connector.trust.connector_issuer_root_ca_sha256
    {
        return Err(deployment(
            "plan trust digests do not match protected CA files",
        ));
    }
    // The complete typed, canonical plan and all non-secret bindings are proven
    // before the secret descriptor is opened.
    let handoff = ProtectedBytes::read(&inputs.handoff, MAX_FILE, ProtectedKind::Handoff)?;
    if handoff.digest != plan.connector.handoff_digest {
        return Err(deployment("handoff does not match authenticated plan"));
    }
    let plan_bytes = ProtectedBytes::read(&inputs.plan, MAX_PLAN, ProtectedKind::NonSecret)?;
    if plan_bytes.digest != expected_plan_sha256 {
        return Err(ReleaseError::OperationConflict);
    }
    let prepare_material = encode_material([
        &config.bytes,
        &enrollment.bytes,
        &control.bytes,
        &issuer.bytes,
        &plan_bytes.bytes,
        &handoff.bytes,
    ])?;
    Ok(MaterialFiles {
        handoff,
        config,
        enrollment,
        control,
        issuer,
        prepare_material,
    })
}

fn new_record(
    inputs: &ConnectorApplyInputs,
    plan: &BootstrapPlan,
    manifest_sha256: &str,
    plan_sha256: &str,
    files: &MaterialFiles,
    initial_revision: Revision,
) -> ConnectorExecutionRecordV1 {
    ConnectorExecutionRecordV1 {
        schema: "dirextalk.deployer.connector-execution.v1".into(),
        operation_id: inputs.operation_id.clone(),
        lifecycle_operation_id: plan.operation_id.clone(),
        target: inputs.target.clone(),
        tenant_id: plan.host.tenant_id.clone(),
        host_id: plan.host.host_id.clone(),
        connector_id: plan.connector.instance_id.clone(),
        adapter: plan.connector.adapter_kind,
        release_sha256: plan.connector_artifact.digest.clone(),
        expiry_millis: plan.connector.expires_at_millis,
        manifest_sha256: manifest_sha256.to_owned(),
        plan_sha256: plan_sha256.to_owned(),
        handoff_sha256: files.handoff.digest.clone(),
        config_sha256: files.config.digest.clone(),
        enrollment_ca_sha256: files.enrollment.digest.clone(),
        control_ca_sha256: files.control.digest.clone(),
        issuer_ca_sha256: files.issuer.digest.clone(),
        lifecycle_material_sha256: digest(&files.prepare_material),
        initial_revision,
        prepare_host_operation_id: Uuid::now_v7().to_string(),
        start_host_operation_id: Uuid::now_v7().to_string(),
        finalize_host_operation_id: Uuid::now_v7().to_string(),
        prepare_replay_header_sha256: String::new(),
        finalize_replay_header_sha256: None,
        phase: Phase::Claimed,
        prepare_result: None,
        start_revision: None,
        running_revision: None,
        finalize_result: None,
        integrity_sha256: String::new(),
    }
}

fn invoke_v2_recoverable(
    operator: &dyn Operator,
    record: &ConnectorExecutionRecordV1,
    operation: V2Operation,
    inputs: &ConnectorApplyInputs,
    plan: &BootstrapPlan,
) -> Result<V2Result> {
    let expected = match operation {
        V2Operation::PrepareConnectorMaterial => record.initial_revision,
        V2Operation::FinalizeConnectorMaterial => record
            .running_revision
            .ok_or_else(|| deployment("missing Running revision"))?,
    };
    let empty = Vec::new();
    let header = v2_header(record, operation, expected, &empty)?;
    let replay_digest = digest(&serde_json::to_vec(&header)?);
    let persisted = match operation {
        V2Operation::PrepareConnectorMaterial => Some(&record.prepare_replay_header_sha256),
        V2Operation::FinalizeConnectorMaterial => record.finalize_replay_header_sha256.as_ref(),
    }
    .ok_or_else(|| deployment("missing persisted replay header"))?;
    if &replay_digest != persisted {
        return Err(ReleaseError::OperationConflict);
    }
    match invoke_v2(operator, &header, &empty)? {
        V2Reply::Success(result) => validate_v2_result(result, record, operation, expected),
        V2Reply::MaterialRequired => {
            let files = load_material_files(inputs, plan, &record.plan_sha256)?;
            validate_material_identity(
                record,
                &files,
                &ProtectedBytes::read(&inputs.plan, MAX_PLAN, ProtectedKind::NonSecret)?,
            )?;
            let material = match operation {
                V2Operation::PrepareConnectorMaterial => files.prepare_material,
                V2Operation::FinalizeConnectorMaterial => encode_material([
                    &[],
                    &[],
                    &[],
                    &[],
                    &ProtectedBytes::read(&inputs.plan, MAX_PLAN, ProtectedKind::NonSecret)?.bytes,
                    &files.handoff.bytes,
                ])?,
            };
            let header = v2_header(record, operation, expected, &material)?;
            match invoke_v2(operator, &header, &material)? {
                V2Reply::Success(result) => validate_v2_result(result, record, operation, expected),
                V2Reply::MaterialRequired => {
                    Err(deployment("Host still requires exact persisted material"))
                }
            }
        }
    }
}

fn v2_header(
    record: &ConnectorExecutionRecordV1,
    operation: V2Operation,
    revision: Revision,
    payload: &[u8],
) -> Result<V2Header> {
    Ok(V2Header {
        protocol: PROTOCOL_V2,
        tenant_id: record.tenant_id.clone(),
        host_id: record.host_id.clone(),
        host_operation_id: match operation {
            V2Operation::PrepareConnectorMaterial => record.prepare_host_operation_id.clone(),
            V2Operation::FinalizeConnectorMaterial => record.finalize_host_operation_id.clone(),
        },
        expected_desired_revision: revision.desired,
        expected_observed_revision: revision.observed,
        connector_id: record.connector_id.clone(),
        adapter: record.adapter,
        approved_release_sha256: record.release_sha256.clone(),
        lifecycle_operation_id: record.lifecycle_operation_id.clone(),
        platform_target: platform()?.into(),
        expiry_millis: record.expiry_millis,
        plan_sha256: record.plan_sha256.clone(),
        handoff_sha256: record.handoff_sha256.clone(),
        config_sha256: record.config_sha256.clone(),
        enrollment_ca_sha256: record.enrollment_ca_sha256.clone(),
        control_ca_sha256: record.control_ca_sha256.clone(),
        issuer_ca_sha256: record.issuer_ca_sha256.clone(),
        lifecycle_material_sha256: record.lifecycle_material_sha256.clone(),
        payload_sha256: digest(payload),
        prepared_receipt_sha256: match operation {
            V2Operation::PrepareConnectorMaterial => None,
            V2Operation::FinalizeConnectorMaterial => Some(
                record
                    .prepare_result
                    .as_ref()
                    .and_then(|r| r.prepared_receipt_sha256.clone())
                    .ok_or_else(|| deployment("missing exact prepared receipt"))?,
            ),
        },
        operation,
    })
}

enum V2Reply {
    Success(V2Result),
    MaterialRequired,
}
fn invoke_v2(operator: &dyn Operator, header: &V2Header, payload: &[u8]) -> Result<V2Reply> {
    let response: V2Response =
        decode_strict(&operator.invoke(frame(*b"DTXHC02\0", header, payload)?)?)?;
    if response.protocol != PROTOCOL_V2 {
        return Err(deployment("V2 response protocol mismatch"));
    }
    match (response.status, response.result, response.error) {
        (ResponseStatus::Succeeded, Some(result), None) => Ok(V2Reply::Success(result)),
        (ResponseStatus::Rejected, None, Some(code)) if code == "MATERIAL_REQUIRED" => {
            Ok(V2Reply::MaterialRequired)
        }
        (ResponseStatus::Rejected, None, Some(_)) => {
            Err(deployment("Host Supervisor rejected V2 operation"))
        }
        _ => Err(deployment("invalid V2 response shape")),
    }
}

fn invoke_v1(operator: &dyn Operator, request: &V1Request) -> Result<V1Result> {
    let response: V1Response =
        decode_strict(&operator.invoke(frame(*b"DTXHC01\0", request, &[])?)?)?;
    if response.protocol != PROTOCOL_V1 {
        return Err(deployment("V1 response protocol mismatch"));
    }
    match (response.status, response.result, response.error) {
        (ResponseStatus::Succeeded, Some(result), None) => Ok(result),
        (ResponseStatus::Rejected, None, Some(error)) => {
            let _ = (&error.code, error.current_revision);
            Err(deployment("Host Supervisor rejected V1 operation"))
        }
        _ => Err(deployment("invalid V1 response shape")),
    }
}

fn validate_snapshot(result: V1Result, plan: &BootstrapPlan) -> Result<Revision> {
    let V1Result::Snapshot { host } = result else {
        return Err(deployment("snapshot response kind mismatch"));
    };
    if host.tenant_id != plan.host.tenant_id || host.host_id != plan.host.host_id {
        return Err(deployment("snapshot Host identity mismatch"));
    }
    validate_revision(host.revision)?;
    let _ = host.connectors;
    Ok(host.revision)
}

fn validate_start(
    result: V1Result,
    record: &ConnectorExecutionRecordV1,
    prior: Revision,
) -> Result<Revision> {
    let V1Result::Command {
        application,
        disposition,
        revision,
        connector,
    } = result
    else {
        return Err(deployment("start response kind mismatch"));
    };
    if !matches!(
        application,
        V1Application::Applied | V1Application::Replayed | V1Application::Reconciled
    ) || disposition != Disposition::Applied
        || connector.connector_id != record.connector_id
        || connector.adapter_kind != record.adapter
        || connector.release_sha256 != record.release_sha256
        || connector.desired_state != DesiredState::Running
        || connector.credential_generation == 0
    {
        return Err(deployment("start response binding mismatch"));
    }
    let _ = connector.recorded_observation;
    require_next_revision(prior, revision)?;
    Ok(revision)
}

fn observe_running(
    operator: &dyn Operator,
    record: &ConnectorExecutionRecordV1,
    expected: Revision,
) -> Result<Revision> {
    let deadline = Instant::now()
        .checked_add(OBSERVE_TIMEOUT)
        .ok_or_else(|| deployment("invalid observation deadline"))?;
    loop {
        let result = invoke_v1(operator, &V1Request::observe(record))?;
        let V1Result::Observation {
            revision,
            connector,
            actual_observation,
        } = result
        else {
            return Err(deployment("observe response kind mismatch"));
        };
        if connector.connector_id != record.connector_id
            || connector.adapter_kind != record.adapter
            || connector.release_sha256 != record.release_sha256
            || connector.desired_state != DesiredState::Running
            || revision != expected
        {
            return Err(deployment("observe response binding or revision mismatch"));
        }
        let _ = connector.credential_generation;
        if actual_observation == Observation::Running
            && connector.recorded_observation == Observation::Running
        {
            return Ok(revision);
        }
        if Instant::now() >= deadline {
            return Err(deployment(
                "Connector did not reach exact Running before deadline",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn validate_v2_result(
    result: V2Result,
    record: &ConnectorExecutionRecordV1,
    operation: V2Operation,
    prior: Revision,
) -> Result<V2Result> {
    let expected_state = match operation {
        V2Operation::PrepareConnectorMaterial => LifecycleState::Prepared,
        V2Operation::FinalizeConnectorMaterial => LifecycleState::Finalized,
    };
    if result.operation != operation
        || result.connector_id != record.connector_id
        || result.lifecycle_state != expected_state
        || !matches!(
            result.application,
            V2Application::Applied | V2Application::Replayed
        )
        || result.disposition != Disposition::Applied
    {
        return Err(deployment("V2 response identity mismatch"));
    }
    require_next_revision(prior, result.revision())?;
    let prepared = result
        .prepared_receipt_sha256
        .as_deref()
        .filter(|value| is_digest(value))
        .ok_or_else(|| deployment("V2 response lacks prepared receipt digest"))?;
    match operation {
        V2Operation::PrepareConnectorMaterial if result.finalized_receipt_sha256.is_some() => {
            return Err(deployment("prepare returned finalized receipt"));
        }
        V2Operation::FinalizeConnectorMaterial => {
            let exact = record
                .prepare_result
                .as_ref()
                .and_then(|r| r.prepared_receipt_sha256.as_deref())
                .ok_or_else(|| deployment("missing persisted prepared receipt"))?;
            if prepared != exact
                || !result
                    .finalized_receipt_sha256
                    .as_deref()
                    .is_some_and(is_digest)
            {
                return Err(deployment("finalize receipt binding mismatch"));
            }
        }
        V2Operation::PrepareConnectorMaterial => {}
    }
    Ok(result)
}

fn require_next_revision(prior: Revision, next: Revision) -> Result<()> {
    validate_revision(prior)?;
    validate_revision(next)?;
    if prior.desired.checked_add(1) != Some(next.desired) || next.observed != Some(next.desired) {
        return Err(deployment("Host revision chain is not exact and monotonic"));
    }
    Ok(())
}
fn validate_revision(revision: Revision) -> Result<()> {
    if revision.desired == 0
        || revision.desired > 9_007_199_254_740_991
        || revision
            .observed
            .is_some_and(|value| value == 0 || value > revision.desired)
    {
        return Err(deployment("invalid Host revision"));
    }
    Ok(())
}

fn validate_operation(
    operation: &OperationRecord,
    manifest: &DeploymentManifest,
    plan: &BootstrapPlan,
    target: &str,
) -> Result<()> {
    if operation.operation_id() == plan.operation_id
        || operation.target() != target
        || operation.manifest_digest() != manifest.digest()
    {
        return Err(deployment(
            "deployment and lifecycle operation identities are invalid",
        ));
    }
    let binding = operation.binding();
    if binding.target != target
        || binding.host.tenant_id != plan.host.tenant_id
        || binding.host.host_id != plan.host.host_id
        || binding.host.owner_id != plan.host.owner_id
        || binding.host.host_credential_id != plan.host.host_credential_id
        || binding.artifact != manifest.contract().connector
    {
        return Err(deployment(
            "canonical deployment operation does not bind plan and manifest",
        ));
    }
    let BindingWorkload::ConnectorHost {
        connector_digest,
        connectors,
    } = &binding.workload
    else {
        return Err(deployment(
            "canonical operation is not a Connector-host operation",
        ));
    };
    let connector = connectors
        .iter()
        .find(|item| item.instance_id == plan.connector.instance_id)
        .ok_or_else(|| deployment("Connector absent from canonical operation"))?;
    if connector_digest != &plan.connector_artifact.digest
        || connector.adapter_kind != plan.connector.adapter_kind.deployment()
        || connector.handoff_digest != plan.connector.handoff_digest
        || binding.artifact.digest != plan.connector_artifact.digest
    {
        return Err(deployment("canonical operation Connector binding mismatch"));
    }
    Ok(())
}

fn plan_host_tuple(plan: &BootstrapPlan) -> crate::deployment::HostTuple {
    crate::deployment::HostTuple {
        tenant_id: plan.host.tenant_id.clone(),
        host_id: plan.host.host_id.clone(),
        owner_id: plan.host.owner_id.clone(),
        host_credential_id: plan.host.host_credential_id.clone(),
    }
}

fn advance_to(
    store: &DeploymentStateStore,
    operation: &mut OperationRecord,
    target: OperationPhase,
) -> Result<()> {
    if connector_phase_rank(operation.phase())
        .is_some_and(|rank| rank >= connector_phase_rank(target).unwrap_or(u8::MAX))
    {
        return Ok(());
    }
    while operation.phase() != target {
        let next = match operation.phase() {
            OperationPhase::Planned => OperationPhase::Claimed,
            OperationPhase::Claimed => OperationPhase::HostBound,
            OperationPhase::HostBound => OperationPhase::ArtifactsVerified,
            OperationPhase::ArtifactsVerified => OperationPhase::MaterialPrepared,
            OperationPhase::MaterialPrepared => OperationPhase::ConfigsWritten,
            OperationPhase::ConfigsWritten => OperationPhase::ServicesConverged,
            OperationPhase::ServicesConverged => OperationPhase::ReadinessVerified,
            OperationPhase::ReadinessVerified => OperationPhase::Completed,
            _ => {
                return Err(deployment(
                    "canonical deployment phase cannot advance to Connector lifecycle state",
                ));
            }
        };
        operation.clone_from(&store.advance(operation.operation_id(), next)?);
    }
    Ok(())
}
const fn connector_phase_rank(phase: OperationPhase) -> Option<u8> {
    match phase {
        OperationPhase::Planned => Some(0),
        OperationPhase::Claimed => Some(1),
        OperationPhase::HostBound => Some(2),
        OperationPhase::ArtifactsVerified => Some(3),
        OperationPhase::MaterialPrepared => Some(4),
        OperationPhase::ConfigsWritten => Some(5),
        OperationPhase::ServicesConverged => Some(6),
        OperationPhase::ReadinessVerified => Some(7),
        OperationPhase::Completed => Some(8),
        _ => None,
    }
}

fn parse_plan(bytes: &[u8]) -> Result<BootstrapPlan> {
    let plan: BootstrapPlan = decode_strict(bytes)?;
    let canonical = serde_json::to_vec(&plan)?;
    if canonical != bytes {
        return Err(deployment(
            "bootstrap plan is not the canonical Connector encoding",
        ));
    }
    if plan.schema != "dirextalk.connector-bootstrap-plan"
        || plan.schema_version != 1
        || plan.state != "prepared"
        || !is_digest(&plan.manifest_digest)
        || !is_digest(&plan.connector_artifact.digest)
        || !is_digest(&plan.connector.handoff_digest)
        || Version::parse(&plan.connector_artifact.version).is_err()
        || !matches!(plan.target.as_str(), "linux-amd64" | "linux-arm64")
        || !matches!(plan.connector.runtime_profile.as_str(), "default" | "safe")
        || plan.connector.remote_mcp.offline_policy != "queue"
        || plan.connector.remote_mcp.max_concurrent_runs == 0
        || plan.connector.remote_mcp.max_concurrent_runs > 4096
        || plan.connector.display_name.is_empty()
        || plan.connector.display_name.len() > 128
        || !positive(plan.connector.generation)
        || !positive(plan.connector.spec_revision)
        || !positive(plan.connector.expires_at_millis)
        || !valid_https_origin(&plan.connector.server_origin)
        || !valid_endpoint(
            &plan.connector.trust.enrollment_url,
            &plan.connector.trust.enrollment_server_name,
        )
        || !valid_endpoint(
            &plan.connector.trust.control_url,
            &plan.connector.trust.control_server_name,
        )
        || !valid_mcp_url(&plan.connector.remote_mcp.mcp_url)
        || !valid_mcp_name(&plan.connector.remote_mcp.mcp_server_name)
    {
        return Err(deployment("invalid canonical Connector bootstrap plan"));
    }
    for id in [
        &plan.operation_id,
        &plan.host.tenant_id,
        &plan.host.host_id,
        &plan.host.host_credential_id,
        &plan.connector.instance_id,
        &plan.connector.enrollment_request_id,
        &plan.connector.enrollment_intent_id,
        &plan.connector.installation_id,
        &plan.connector.agent_device_id,
        &plan.connector.binding_id,
        &plan.connector.remote_mcp.mcp_node_id,
    ] {
        require_canonical_uuid7(id, "bootstrap plan UUID")?;
    }
    require_identity_id(&plan.host.owner_id)?;
    for digest_value in [
        &plan.connector.trust.enrollment_root_ca_sha256,
        &plan.connector.trust.control_server_root_ca_sha256,
        &plan.connector.trust.connector_issuer_root_ca_sha256,
    ] {
        if !is_digest(digest_value) {
            return Err(deployment("invalid plan trust digest"));
        }
    }
    Ok(plan)
}

fn validate_plan_platform(plan: &BootstrapPlan) -> Result<()> {
    if plan.target != platform()? {
        return Err(deployment("bootstrap target does not match executing host"));
    }
    Ok(())
}
fn platform() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("linux-amd64"),
        "aarch64" => Ok("linux-arm64"),
        _ => Err(deployment("unsupported Connector host platform")),
    }
}

fn validate_record_identity(
    record: &ConnectorExecutionRecordV1,
    inputs: &ConnectorApplyInputs,
    manifest_sha256: &str,
    plan_sha256: &str,
    plan: &BootstrapPlan,
) -> Result<()> {
    if record.schema != "dirextalk.deployer.connector-execution.v1"
        || record.operation_id != inputs.operation_id
        || record.target != inputs.target
        || record.lifecycle_operation_id != plan.operation_id
        || record.manifest_sha256 != manifest_sha256
        || record.plan_sha256 != plan_sha256
        || record.tenant_id != plan.host.tenant_id
        || record.host_id != plan.host.host_id
        || record.connector_id != plan.connector.instance_id
        || record.adapter != plan.connector.adapter_kind
        || record.release_sha256 != plan.connector_artifact.digest
        || record.handoff_sha256 != plan.connector.handoff_digest
        || record.expiry_millis != plan.connector.expires_at_millis
    {
        return Err(ReleaseError::OperationConflict);
    }
    for id in [
        &record.prepare_host_operation_id,
        &record.start_host_operation_id,
        &record.finalize_host_operation_id,
    ] {
        require_canonical_uuid7(id, "persisted Host operation")?;
    }
    if record.prepare_host_operation_id == record.start_host_operation_id
        || record.prepare_host_operation_id == record.finalize_host_operation_id
        || record.start_host_operation_id == record.finalize_host_operation_id
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn validate_material_identity(
    record: &ConnectorExecutionRecordV1,
    files: &MaterialFiles,
    plan: &ProtectedBytes,
) -> Result<()> {
    if files.handoff.digest != record.handoff_sha256
        || files.config.digest != record.config_sha256
        || files.enrollment.digest != record.enrollment_ca_sha256
        || files.control.digest != record.control_ca_sha256
        || files.issuer.digest != record.issuer_ca_sha256
        || plan.digest != record.plan_sha256
        || digest(&files.prepare_material) != record.lifecycle_material_sha256
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}

fn persist_record(
    lease: &crate::deployment::ConnectorExecutionLease,
    record: &ConnectorExecutionRecordV1,
) -> Result<()> {
    let mut sealed = record.clone();
    sealed.integrity_sha256.clear();
    sealed.integrity_sha256 = digest(&serde_json::to_vec(&sealed)?);
    lease.write(&sealed)
}
fn verify_record(record: &ConnectorExecutionRecordV1) -> Result<()> {
    let mut copy = record.clone();
    let supplied = std::mem::take(&mut copy.integrity_sha256);
    if !is_digest(&supplied) || digest(&serde_json::to_vec(&copy)?) != supplied {
        return Err(deployment("Connector execution record integrity mismatch"));
    }
    Ok(())
}

fn frame(magic: [u8; 8], header: &impl Serialize, payload: &[u8]) -> Result<Vec<u8>> {
    let header = serde_json::to_vec(header)?;
    if header.is_empty() || header.len() > 16 * 1024 || payload.len() > 384 * 1024 {
        return Err(deployment("Host Control frame exceeds frozen bounds"));
    }
    let mut frame = Vec::with_capacity(16 + header.len() + payload.len());
    frame.extend_from_slice(&magic);
    frame.extend_from_slice(
        &(u32::try_from(header.len())
            .map_err(|_| deployment("Host Control header is oversized"))?)
        .to_be_bytes(),
    );
    frame.extend_from_slice(&header);
    frame.extend_from_slice(
        &(u32::try_from(payload.len())
            .map_err(|_| deployment("Host Control payload is oversized"))?)
        .to_be_bytes(),
    );
    frame.extend_from_slice(payload);
    Ok(frame)
}
fn encode_material(fields: [&[u8]; 6]) -> Result<Vec<u8>> {
    if fields[4].is_empty()
        || fields[5].is_empty()
        || fields.iter().any(|field| field.len() > 65_536)
    {
        return Err(deployment("invalid bounded bootstrap material"));
    }
    let mut output = Vec::new();
    output.extend_from_slice(b"DTXBMT01");
    for field in fields {
        output.extend_from_slice(
            &(u32::try_from(field.len())
                .map_err(|_| deployment("bootstrap material oversized"))?)
            .to_be_bytes(),
        );
    }
    for field in fields {
        output.extend_from_slice(field);
    }
    if output.len() > 384 * 1024 {
        return Err(deployment("bootstrap material oversized"));
    }
    Ok(output)
}
fn decode_strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut decoder)?;
    decoder.end()?;
    Ok(value)
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn require_identity_id(value: &str) -> Result<()> {
    if value.len() != 57
        || !value.starts_with("dtxi1")
        || !value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(deployment("owner_id must be a stable IdentityId"));
    }
    Ok(())
}
const fn positive(value: u64) -> bool {
    value > 0 && value <= 9_007_199_254_740_991
}
fn valid_https_origin(value: &str) -> bool {
    value.strip_prefix("https://").is_some_and(valid_dns_name)
}
fn valid_endpoint(value: &str, server_name: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    let host = authority.strip_suffix('/').unwrap_or(authority);
    !host.is_empty() && host == server_name && valid_dns_name(host)
}
fn valid_mcp_url(value: &str) -> bool {
    value
        .strip_prefix("https://")
        .and_then(|rest| rest.strip_suffix("/mcp"))
        .is_some_and(valid_dns_name)
}
fn valid_dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}
fn valid_mcp_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'_' | b'-'))
        })
}
fn deployment(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.into())
}
fn expired(expiry_millis: u64) -> Result<bool> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| deployment("system clock precedes Unix epoch"))?;
    Ok(u64::try_from(now.as_millis()).map_or(true, |millis| millis >= expiry_millis))
}

fn invoke_process(
    program: &str,
    arguments: &[&str],
    frame: Vec<u8>,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut child = Command::new(program)
        .args(arguments)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ReleaseError::CommandStart(program.into()))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| ReleaseError::CommandStart(program.into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ReleaseError::CommandStart(program.into()))?;
    let writer = thread::spawn(move || {
        let mut stdin = stdin;
        stdin.write_all(&frame)
    });
    let reader = thread::spawn(move || {
        let mut output = Vec::new();
        stdout
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut output)
            .map(|_| output)
    });
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| deployment("invalid subprocess deadline"))?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                terminate_and_reap(&mut child);
                let _ = writer.join();
                let _ = reader.join();
                return Err(deployment("Host Supervisor deadline exceeded"));
            }
            Err(error) => {
                terminate_and_reap(&mut child);
                let _ = writer.join();
                let _ = reader.join();
                return Err(io_error(program)(error));
            }
        }
    };
    let write_result = writer
        .join()
        .map_err(|_| deployment("Host Supervisor stdin worker failed"))?;
    let output = reader
        .join()
        .map_err(|_| deployment("Host Supervisor stdout worker failed"))?
        .map_err(io_error(program))?;
    if let Err(error) = write_result {
        return Err(io_error(program)(error));
    }
    validate_exit(program, status, output)
}
fn terminate_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}
fn validate_exit(program: &str, status: ExitStatus, output: Vec<u8>) -> Result<Vec<u8>> {
    if !status.success() {
        return Err(ReleaseError::CommandFailed {
            program: program.into(),
            status,
        });
    }
    if output.is_empty() || output.len() > MAX_OUTPUT {
        return Err(deployment("Host Supervisor response is empty or oversized"));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};

    const PLAN: &[u8] = br#"{"schema":"dirextalk.connector-bootstrap-plan","schema_version":1,"state":"prepared","operation_id":"0197f1f0-0000-7000-8000-000000000005","manifest_digest":"05b3abf2579a5eb66403cd78be557fd860633a1fe2103c7642030defe32c657f","target":"linux-amd64","connector_artifact":{"version":"1.2.3-alpha.1+build-1","digest":"a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829"},"host":{"tenant_id":"0197f1f0-0000-7000-8000-000000000001","host_id":"0197f1f0-0000-7000-8000-000000000002","owner_id":"dtxi1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","host_credential_id":"0197f1f0-0000-7000-8000-000000000009"},"connector":{"instance_id":"0197f1f0-0000-7000-8000-000000000003","adapter_kind":"codex","handoff_digest":"c21ed50aa964770b16d098c18f1845d4fd75a0eccda9c3cd791d9a86840902d3","display_name":"Connector","generation":1,"spec_revision":1,"enrollment_request_id":"0197f1f0-0000-7000-8000-000000000006","enrollment_intent_id":"0197f1f0-0000-7000-8000-000000000007","installation_id":"0197f1f0-0000-7000-8000-00000000000a","agent_device_id":"0197f1f0-0000-7000-8000-00000000000b","binding_id":"0197f1f0-0000-7000-8000-00000000000c","expires_at_millis":4000000000,"server_origin":"https://server.example","trust":{"enrollment_url":"https://enroll.example/","enrollment_server_name":"enroll.example","enrollment_root_ca_sha256":"2791bd4394efbf10623f3cd301dc57f37ff18ff2a806b2c013403e85bc62c530","control_url":"https://control.example","control_server_name":"control.example","control_server_root_ca_sha256":"0fcd568a5cb9bdb4677b69354b11ee415af8f784519cff3da49a26f84eaee7f2","connector_issuer_root_ca_sha256":"535c6f8eb511f5d966a1b0725df92ebf27514faba945cbbd698e23ac72c41757"},"runtime_profile":"safe","remote_mcp":{"mcp_server_name":"mcp_1","mcp_url":"https://mcp.example/mcp","mcp_node_id":"0197f1f0-0000-7000-8000-00000000000d","max_concurrent_runs":1,"offline_policy":"queue"}}}"#;

    struct QueueOperator {
        responses: Mutex<VecDeque<Vec<u8>>>,
        frames: Mutex<Vec<Vec<u8>>>,
    }
    impl Operator for QueueOperator {
        fn invoke(&self, frame: Vec<u8>) -> Result<Vec<u8>> {
            self.frames.lock().expect("frames").push(frame);
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .ok_or_else(|| deployment("missing mock response"))
        }
    }

    #[test]
    fn accepts_exact_frozen_connector_plan_vector() {
        let parsed = parse_plan(PLAN).expect("canonical plan");
        assert_eq!(parsed.state, "prepared");
        assert_eq!(
            digest(PLAN),
            "672c7ba9e3cd4704385abb839f8c275ecc9aa7b6fdc432f232065f790ccadbf7"
        );
        let changed = String::from_utf8(PLAN.to_vec())
            .expect("utf8")
            .replace("\"prepared\"", "\"issued\"");
        assert!(parse_plan(changed.as_bytes()).is_err());
    }

    #[test]
    fn v1_golden_snapshot_frame_is_frozen() {
        let plan = parse_plan(PLAN).expect("plan");
        let actual = frame(*b"DTXHC01\0", &V1Request::snapshot(&plan), &[]).expect("frame");
        let header = br#"{"protocol":"dirextalk.host-control.operator.v1","tenant_id":"0197f1f0-0000-7000-8000-000000000001","host_id":"0197f1f0-0000-7000-8000-000000000002","request":{"kind":"snapshot"}}"#;
        let mut expected = b"DTXHC01\0".to_vec();
        expected.extend_from_slice(
            &u32::try_from(header.len())
                .expect("header length")
                .to_be_bytes(),
        );
        expected.extend_from_slice(header);
        expected.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(actual, expected);
    }

    #[test]
    fn header_only_replay_is_sent_without_material() {
        let operator = QueueOperator { responses: Mutex::new(VecDeque::from([br#"{"protocol":"dirextalk.host-control.operator.v2","status":"rejected","error":"MATERIAL_REQUIRED"}"#.to_vec()])), frames: Mutex::new(Vec::new()) };
        let plan = parse_plan(PLAN).expect("plan");
        let record = record(&plan);
        let header = v2_header(
            &record,
            V2Operation::PrepareConnectorMaterial,
            record.initial_revision,
            &[],
        )
        .expect("header");
        assert!(matches!(
            invoke_v2(&operator, &header, &[]).expect("reply"),
            V2Reply::MaterialRequired
        ));
        let frames = operator.frames.lock().expect("frames");
        assert_eq!(&frames[0][frames[0].len() - 4..], &0u32.to_be_bytes());
    }

    #[test]
    fn completed_prepare_replay_accepts_exact_header_only_result() {
        let plan = parse_plan(PLAN).expect("plan");
        let record = record(&plan);
        let response = format!(
            "{{\"protocol\":\"{PROTOCOL_V2}\",\"status\":\"succeeded\",\"result\":{{\"operation\":\"prepare_connector_material\",\"application\":\"replayed\",\"disposition\":\"applied\",\"desired_revision\":2,\"observed_revision\":2,\"connector_id\":\"{}\",\"lifecycle_state\":\"prepared\",\"prepared_receipt_sha256\":\"{}\"}}}}",
            record.connector_id,
            "a".repeat(64),
        );
        let operator = QueueOperator {
            responses: Mutex::new(VecDeque::from([response.into_bytes()])),
            frames: Mutex::new(Vec::new()),
        };
        let header = v2_header(
            &record,
            V2Operation::PrepareConnectorMaterial,
            record.initial_revision,
            &[],
        )
        .expect("header");
        let V2Reply::Success(result) = invoke_v2(&operator, &header, &[]).expect("reply") else {
            panic!("success")
        };
        assert!(
            validate_v2_result(
                result,
                &record,
                V2Operation::PrepareConnectorMaterial,
                record.initial_revision
            )
            .is_ok()
        );
        let frames = operator.frames.lock().expect("frames");
        assert_eq!(&frames[0][frames[0].len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn response_identity_and_revision_mismatch_fail_closed() {
        let plan = parse_plan(PLAN).expect("plan");
        let record = record(&plan);
        let result = V2Result {
            operation: V2Operation::PrepareConnectorMaterial,
            application: V2Application::Applied,
            disposition: Disposition::Applied,
            desired_revision: 4,
            observed_revision: Some(4),
            connector_id: "0197f1f0-0000-7000-8000-000000000099".into(),
            lifecycle_state: LifecycleState::Prepared,
            prepared_receipt_sha256: Some("a".repeat(64)),
            finalized_receipt_sha256: None,
        };
        assert!(
            validate_v2_result(
                result,
                &record,
                V2Operation::PrepareConnectorMaterial,
                record.initial_revision
            )
            .is_err()
        );
    }

    #[test]
    fn subprocess_deadline_covers_blocked_stdin_and_reaps() {
        let start = Instant::now();
        let result = invoke_process(
            "/bin/sh",
            &["-c", "exec sleep 10"],
            vec![7; 384 * 1024],
            Duration::from_millis(50),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn protected_file_metadata_is_root_owned_closed_and_single_link() {
        assert!(protected_metadata_valid(
            true,
            1,
            0,
            0o600,
            1,
            65_536,
            ProtectedKind::Handoff
        ));
        assert!(protected_metadata_valid(
            true,
            1,
            0,
            0o440,
            1,
            65_536,
            ProtectedKind::NonSecret
        ));
        assert!(!protected_metadata_valid(
            true,
            1,
            1000,
            0o600,
            1,
            65_536,
            ProtectedKind::Handoff
        ));
        assert!(!protected_metadata_valid(
            true,
            2,
            0,
            0o600,
            1,
            65_536,
            ProtectedKind::Handoff
        ));
        assert!(!protected_metadata_valid(
            true,
            1,
            0,
            0o644,
            1,
            65_536,
            ProtectedKind::NonSecret
        ));
    }

    #[test]
    fn pending_material_replay_rejects_changed_files() {
        let plan = parse_plan(PLAN).expect("plan");
        let mut record = record(&plan);
        let plan_file = ProtectedBytes {
            bytes: PLAN.to_vec(),
            digest: digest(PLAN),
        };
        let mut files = MaterialFiles {
            handoff: ProtectedBytes {
                bytes: b"handoff".to_vec(),
                digest: digest(b"handoff"),
            },
            config: ProtectedBytes {
                bytes: b"config".to_vec(),
                digest: digest(b"config"),
            },
            enrollment: ProtectedBytes {
                bytes: b"enrollment".to_vec(),
                digest: digest(b"enrollment"),
            },
            control: ProtectedBytes {
                bytes: b"control".to_vec(),
                digest: digest(b"control"),
            },
            issuer: ProtectedBytes {
                bytes: b"issuer".to_vec(),
                digest: digest(b"issuer"),
            },
            prepare_material: encode_material([
                b"config",
                b"enrollment",
                b"control",
                b"issuer",
                PLAN,
                b"handoff",
            ])
            .expect("material"),
        };
        record.plan_sha256 = plan_file.digest.clone();
        record.handoff_sha256 = files.handoff.digest.clone();
        record.config_sha256 = files.config.digest.clone();
        record.enrollment_ca_sha256 = files.enrollment.digest.clone();
        record.control_ca_sha256 = files.control.digest.clone();
        record.issuer_ca_sha256 = files.issuer.digest.clone();
        record.lifecycle_material_sha256 = digest(&files.prepare_material);
        assert!(validate_material_identity(&record, &files, &plan_file).is_ok());
        files.config.digest = digest(b"changed");
        assert!(validate_material_identity(&record, &files, &plan_file).is_err());
    }

    fn record(plan: &BootstrapPlan) -> ConnectorExecutionRecordV1 {
        ConnectorExecutionRecordV1 {
            schema: "dirextalk.deployer.connector-execution.v1".into(),
            operation_id: "0197f1f0-0000-7000-8000-000000000099".into(),
            lifecycle_operation_id: plan.operation_id.clone(),
            target: "connector-host".into(),
            tenant_id: plan.host.tenant_id.clone(),
            host_id: plan.host.host_id.clone(),
            connector_id: plan.connector.instance_id.clone(),
            adapter: plan.connector.adapter_kind,
            release_sha256: plan.connector_artifact.digest.clone(),
            expiry_millis: plan.connector.expires_at_millis,
            manifest_sha256: "1".repeat(64),
            plan_sha256: digest(PLAN),
            handoff_sha256: plan.connector.handoff_digest.clone(),
            config_sha256: "2".repeat(64),
            enrollment_ca_sha256: plan.connector.trust.enrollment_root_ca_sha256.clone(),
            control_ca_sha256: plan.connector.trust.control_server_root_ca_sha256.clone(),
            issuer_ca_sha256: plan.connector.trust.connector_issuer_root_ca_sha256.clone(),
            lifecycle_material_sha256: "3".repeat(64),
            initial_revision: Revision {
                desired: 1,
                observed: Some(1),
            },
            prepare_host_operation_id: "0197f1f0-0000-7000-8000-000000000020".into(),
            start_host_operation_id: "0197f1f0-0000-7000-8000-000000000021".into(),
            finalize_host_operation_id: "0197f1f0-0000-7000-8000-000000000022".into(),
            prepare_replay_header_sha256: String::new(),
            finalize_replay_header_sha256: None,
            phase: Phase::Claimed,
            prepare_result: None,
            start_revision: None,
            running_revision: None,
            finalize_result: None,
            integrity_sha256: String::new(),
        }
    }
}
