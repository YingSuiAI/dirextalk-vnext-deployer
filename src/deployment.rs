//! Offline, durable deployment-contract primitives.  This module deliberately
//! contains no transport, command execution, credential handling, or service mutation.
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    path::Path,
};

#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, renameat, unlinkat};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::error::{ReleaseError, Result, io_error};

const MAX_BYTES: u64 = 1024 * 1024;
#[cfg(unix)]
const STATE_DIR: &str = "/var/lib/dirextalk-vnext-deployer";
#[cfg(unix)]
const MAX_STATE_ROOT_ENTRIES: usize = 4096;
#[cfg(unix)]
const TARGET_OWNER_PREFIX: &str = "target-owner-";
const HOST_EVIDENCE_PATH: &str = "/etc/dirextalk/host-supervisor/host.json";
#[cfg(unix)]
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct DeploymentManifest {
    manifest: DeploymentContract,
    digest: String,
}

#[allow(clippy::missing_errors_doc)]
impl DeploymentManifest {
    pub fn load(path: &Path) -> Result<Self> {
        require_safe_file(path, MAX_BYTES)?;
        let bytes = fs::read(path).map_err(io_error(path))?;
        Self::from_bytes(&bytes)
    }
    /// Loads the local production manifest through a root-owned, closed-mode file.
    ///
    /// # Errors
    ///
    /// Returns an error unless `path` is a non-symlink regular `0600` file owned
    /// by root and contains a strict deployment manifest.
    #[cfg(unix)]
    pub fn load_protected(path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
        let file: File = descriptor.into();
        let metadata = file.metadata().map_err(io_error(path))?;
        if !protected_manifest_metadata_valid(
            metadata.is_file(),
            metadata.nlink(),
            metadata.uid(),
            metadata.mode() & 0o777,
            metadata.len(),
        ) {
            return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        Self::from_bytes(&bytes)
    }
    #[cfg(not(unix))]
    pub fn load_protected(path: &Path) -> Result<Self> {
        let _ = path;
        Err(durable_state_unsupported())
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
            return Err(contract("deployment manifest bytes are invalid"));
        }
        let manifest: DeploymentContract = serde_json::from_slice(bytes)?;
        manifest.validate()?;
        Ok(Self {
            manifest,
            digest: hex::encode(Sha256::digest(bytes)),
        })
    }
    #[must_use]
    pub const fn contract(&self) -> &DeploymentContract {
        &self.manifest
    }
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }
}
#[cfg(unix)]
const fn protected_manifest_metadata_valid(
    is_regular: bool,
    nlink: u64,
    uid: u32,
    mode: u32,
    size: u64,
) -> bool {
    is_regular && nlink == 1 && uid == 0 && mode == 0o600 && size > 0 && size <= MAX_BYTES
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentContract {
    pub schema_version: u32,
    pub server: ImmutableArtifact,
    pub connector: ImmutableArtifact,
    pub targets: Vec<DeploymentTarget>,
}

impl DeploymentContract {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(contract("schema_version must be exactly 1"));
        }
        self.server.validate("server")?;
        self.connector.validate("connector")?;
        if self.targets.is_empty() {
            return Err(contract("targets must not be empty"));
        }
        let mut target_ids = HashSet::new();
        let mut origins = HashSet::new();
        let mut host_ids = std::collections::HashMap::new();
        let mut connectors = HashSet::new();
        for target in &self.targets {
            token(target.id(), "target.id")?;
            if !target_ids.insert(target.id()) {
                return Err(contract("duplicate target id"));
            }
            match target {
                DeploymentTarget::Node {
                    origin,
                    services,
                    host,
                    ..
                } => {
                    https_origin(origin)?;
                    if !origins.insert(origin) {
                        return Err(contract("duplicate node origin"));
                    }
                    if services.is_empty()
                        || services.iter().collect::<HashSet<_>>().len() != services.len()
                    {
                        return Err(contract(
                            "node services must be non-empty and duplicate-free",
                        ));
                    }
                    if !services.contains(&NodeService::Node) {
                        return Err(contract("node target must include node service"));
                    }
                    host.validate()?;
                    let tuple = (
                        host.tenant_id.clone(),
                        host.owner_id.clone(),
                        host.host_credential_id.clone(),
                    );
                    if let Some(old) = host_ids.insert(host.host_id.clone(), tuple.clone())
                        && old != tuple
                    {
                        return Err(contract("host id has inconsistent tuple"));
                    }
                }
                DeploymentTarget::ConnectorHost {
                    host,
                    connectors: bindings,
                    ..
                } => {
                    host.validate()?;
                    if bindings.is_empty() {
                        return Err(contract("connector host requires bindings"));
                    }
                    let tuple = (
                        host.tenant_id.clone(),
                        host.owner_id.clone(),
                        host.host_credential_id.clone(),
                    );
                    if let Some(old) = host_ids.insert(host.host_id.clone(), tuple.clone())
                        && old != tuple
                    {
                        return Err(contract("host id has inconsistent tuple"));
                    }
                    for connector in bindings {
                        connector.validate()?;
                        if !connectors.insert(&connector.instance_id) {
                            return Err(contract("duplicate connector instance"));
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ImmutableArtifact {
    pub version: String,
    pub digest: String,
}
impl ImmutableArtifact {
    fn validate(&self, name: &str) -> Result<()> {
        Version::parse(&self.version)
            .map_err(|_| contract(&format!("{name}.version must be SemVer")))?;
        sha256(&self.digest, &format!("{name}.digest"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeploymentTarget {
    Node {
        id: String,
        origin: String,
        services: Vec<NodeService>,
        host: HostTuple,
    },
    ConnectorHost {
        id: String,
        host: HostTuple,
        connectors: Vec<ConnectorBinding>,
    },
}
impl DeploymentTarget {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Node { id, .. } | Self::ConnectorHost { id, .. } => id,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum NodeService {
    Node,
    AgentControl,
    RealtimeGateway,
    OpaquePushBroker,
}
impl NodeService {
    const fn rank(self) -> u8 {
        match self {
            Self::Node => 0,
            Self::AgentControl => 1,
            Self::RealtimeGateway => 2,
            Self::OpaquePushBroker => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostTuple {
    pub tenant_id: String,
    pub host_id: String,
    pub owner_id: String,
    pub host_credential_id: String,
}
#[derive(Clone, Debug)]
#[cfg_attr(not(unix), allow(dead_code))]
pub struct VerifiedHostBinding(HostTuple);
impl VerifiedHostBinding {
    #[cfg(unix)]
    fn host(&self) -> &HostTuple {
        &self.0
    }
}
#[cfg(unix)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEvidence {
    schema_version: u32,
    tenant_id: String,
    host_id: String,
    owner_id: String,
    host_credential_id: String,
}
#[cfg(unix)]
fn parse_host_evidence(bytes: &[u8], expected: &HostTuple) -> Result<VerifiedHostBinding> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_BYTES {
        return Err(contract("host evidence bytes are invalid"));
    }
    let evidence: HostEvidence = serde_json::from_slice(bytes)?;
    if evidence.schema_version != 1 {
        return Err(contract("host evidence schema must be 1"));
    }
    let actual = HostTuple {
        tenant_id: evidence.tenant_id,
        host_id: evidence.host_id,
        owner_id: evidence.owner_id,
        host_credential_id: evidence.host_credential_id,
    };
    actual.validate()?;
    verify_host_tuple(expected, &actual)
}
#[cfg(unix)]
fn validate_host_metadata(is_regular: bool, uid: u32, mode: u32, size: u64) -> Result<()> {
    if !is_regular || uid != 0 || mode & 0o777 != 0o600 || size == 0 || size > MAX_BYTES {
        return Err(contract("unsafe host evidence metadata"));
    }
    Ok(())
}
#[cfg(test)]
fn validate_then<T>(
    proof: Result<VerifiedHostBinding>,
    observer: impl FnOnce(&VerifiedHostBinding) -> T,
) -> Result<T> {
    Ok(observer(&proof?))
}
#[cfg(unix)]
fn verify_host_tuple(expected: &HostTuple, actual: &HostTuple) -> Result<VerifiedHostBinding> {
    if expected != actual {
        return Err(contract("host evidence tuple does not match target"));
    }
    Ok(VerifiedHostBinding(expected.clone()))
}
#[cfg(test)]
pub(crate) fn verified_host_binding_for_test(host: HostTuple) -> VerifiedHostBinding {
    VerifiedHostBinding(host)
}
impl HostTuple {
    fn validate(&self) -> Result<()> {
        for (v, n) in [
            (&self.tenant_id, "tenant_id"),
            (&self.host_id, "host_id"),
            (&self.host_credential_id, "host_credential_id"),
        ] {
            uuid(v, n)?;
        }
        identity_id(&self.owner_id, "owner_id")?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorBinding {
    pub instance_id: String,
    pub adapter_kind: AdapterKind,
    pub handoff_digest: String,
}
impl ConnectorBinding {
    fn validate(&self) -> Result<()> {
        uuid(&self.instance_id, "connector.instance_id")?;
        sha256(&self.handoff_digest, "connector.handoff_digest")
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Codex,
    OpenclawAcp,
    Eino,
    Rig,
    ClaudeCode,
    CustomAcp,
    HermesAcp,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentAction {
    InspectHostBinding,
    ClaimOperation,
    VerifyArtifact,
    StageArtifact,
    PrepareMaterial,
    WriteConfig,
    PrepareUnit,
    ForwardMigration,
    ConvergeService,
    Readback,
    VerifyReadiness,
    WriteReceipt,
    RecordConnectorClaim,
    RollbackFence,
    RestoreService,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeploymentPlan {
    pub manifest_digest: String,
    pub offline: bool,
    pub actions: BTreeMap<String, Vec<PlannedDeploymentStep>>,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PlannedDeploymentStep {
    pub action: DeploymentAction,
    pub subject: PlanSubject,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanSubject {
    Target {
        id: String,
    },
    Service {
        id: String,
        service: NodeService,
    },
    Connector {
        id: String,
        instance_id: String,
        adapter_kind: AdapterKind,
    },
}
impl DeploymentPlan {
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn create(manifest: &DeploymentManifest) -> Self {
        let mut actions = BTreeMap::new();
        for target in &manifest.manifest.targets {
            let mut list = vec![
                DeploymentAction::ClaimOperation,
                DeploymentAction::VerifyArtifact,
                DeploymentAction::StageArtifact,
                DeploymentAction::PrepareMaterial,
                DeploymentAction::WriteConfig,
                DeploymentAction::PrepareUnit,
                DeploymentAction::ConvergeService,
                DeploymentAction::Readback,
                DeploymentAction::VerifyReadiness,
            ];
            match target {
                DeploymentTarget::Node { .. } => {
                    list.insert(0, DeploymentAction::InspectHostBinding);
                    list.insert(7, DeploymentAction::ForwardMigration);
                }
                DeploymentTarget::ConnectorHost { .. } => {
                    list.insert(0, DeploymentAction::InspectHostBinding);
                    list.insert(2, DeploymentAction::RecordConnectorClaim);
                }
            }
            list.push(DeploymentAction::WriteReceipt);
            let id = target.id().to_owned();
            let mut steps = Vec::new();
            if let DeploymentTarget::Node { services, .. } = target {
                for action in [
                    DeploymentAction::InspectHostBinding,
                    DeploymentAction::ClaimOperation,
                    DeploymentAction::VerifyArtifact,
                    DeploymentAction::StageArtifact,
                    DeploymentAction::ForwardMigration,
                ] {
                    steps.push(PlannedDeploymentStep {
                        action,
                        subject: PlanSubject::Target { id: id.clone() },
                    });
                }
                let mut ordered = services.clone();
                ordered.sort_by_key(|service| service.rank());
                for service in ordered {
                    for action in [
                        DeploymentAction::PrepareMaterial,
                        DeploymentAction::WriteConfig,
                        DeploymentAction::PrepareUnit,
                        DeploymentAction::ConvergeService,
                        DeploymentAction::Readback,
                        DeploymentAction::VerifyReadiness,
                    ] {
                        steps.push(PlannedDeploymentStep {
                            action,
                            subject: PlanSubject::Service {
                                id: id.clone(),
                                service,
                            },
                        });
                    }
                }
                steps.push(PlannedDeploymentStep {
                    action: DeploymentAction::WriteReceipt,
                    subject: PlanSubject::Target { id: id.clone() },
                });
            } else if let DeploymentTarget::ConnectorHost { connectors, .. } = target {
                for action in [
                    DeploymentAction::InspectHostBinding,
                    DeploymentAction::ClaimOperation,
                    DeploymentAction::VerifyArtifact,
                    DeploymentAction::StageArtifact,
                ] {
                    steps.push(PlannedDeploymentStep {
                        action,
                        subject: PlanSubject::Target { id: id.clone() },
                    });
                }
                let mut ordered = connectors.clone();
                ordered.sort_by(|a, b| a.instance_id.cmp(&b.instance_id));
                for connector in ordered {
                    let subject = PlanSubject::Connector {
                        id: id.clone(),
                        instance_id: connector.instance_id,
                        adapter_kind: connector.adapter_kind,
                    };
                    for action in [
                        DeploymentAction::RecordConnectorClaim,
                        DeploymentAction::PrepareMaterial,
                        DeploymentAction::WriteConfig,
                        DeploymentAction::PrepareUnit,
                        DeploymentAction::ConvergeService,
                        DeploymentAction::Readback,
                        DeploymentAction::VerifyReadiness,
                    ] {
                        steps.push(PlannedDeploymentStep {
                            action,
                            subject: subject.clone(),
                        });
                    }
                }
                steps.push(PlannedDeploymentStep {
                    action: DeploymentAction::WriteReceipt,
                    subject: PlanSubject::Target { id: id.clone() },
                });
            } else {
                for action in list {
                    steps.push(PlannedDeploymentStep {
                        action,
                        subject: PlanSubject::Target { id: id.clone() },
                    });
                }
            }
            actions.insert(id, steps);
        }
        Self {
            manifest_digest: manifest.digest.clone(),
            offline: true,
            actions,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationPhase {
    Planned,
    Claimed,
    HostBound,
    ArtifactsVerified,
    MaterialPrepared,
    ConfigsWritten,
    MigrationApplied,
    ServicesConverged,
    ReadinessVerified,
    Completed,
    /// The Host proved that an expired Connector bootstrap made no lifecycle effect.
    ExpiredUnclaimed,
    FailedRecoverable,
    RollbackFenced,
    RollbackConverged,
    RollbackBlocked,
}
impl OperationPhase {
    fn next(self, workload: &BindingWorkload) -> Option<Self> {
        match self {
            Self::Planned => Some(Self::Claimed),
            Self::Claimed => Some(Self::HostBound),
            Self::HostBound => Some(Self::ArtifactsVerified),
            Self::ArtifactsVerified => Some(Self::MaterialPrepared),
            Self::MaterialPrepared => Some(Self::ConfigsWritten),
            Self::ConfigsWritten => Some(match workload {
                BindingWorkload::Node { .. } => Self::MigrationApplied,
                BindingWorkload::ConnectorHost { .. } => Self::ServicesConverged,
            }),
            Self::MigrationApplied => Some(Self::ServicesConverged),
            Self::ServicesConverged => Some(Self::ReadinessVerified),
            Self::ReadinessVerified => Some(Self::Completed),
            Self::Completed
            | Self::ExpiredUnclaimed
            | Self::FailedRecoverable
            | Self::RollbackFenced
            | Self::RollbackConverged
            | Self::RollbackBlocked => None,
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    schema_version: u32,
    operation_id: String,
    manifest_digest: String,
    artifact: ImmutableArtifact,
    binding: OperationBinding,
    target: String,
    #[serde(default)]
    predecessor_operation_id: Option<String>,
    phase: OperationPhase,
    last_proven_phase: OperationPhase,
    #[serde(default)]
    last_failure: Option<OperationFailureEvidence>,
    integrity_digest: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationBinding {
    pub target: String,
    pub host: HostTuple,
    pub artifact: ImmutableArtifact,
    pub workload: BindingWorkload,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingWorkload {
    Node {
        origin: String,
        server_digest: String,
        services: Vec<NodeService>,
    },
    ConnectorHost {
        connector_digest: String,
        connectors: Vec<BoundConnector>,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BoundConnector {
    pub instance_id: String,
    pub adapter_kind: AdapterKind,
    pub handoff_digest: String,
}
fn binding_from_manifest(
    manifest: &DeploymentContract,
    target: &DeploymentTarget,
) -> (OperationBinding, ImmutableArtifact) {
    match target {
        DeploymentTarget::Node {
            id,
            origin,
            services,
            host,
        } => {
            let mut services = services.clone();
            services.sort_by_key(|service| service.rank());
            (
                OperationBinding {
                    target: id.clone(),
                    host: host.clone(),
                    artifact: manifest.server.clone(),
                    workload: BindingWorkload::Node {
                        origin: origin.clone(),
                        server_digest: manifest.server.digest.clone(),
                        services,
                    },
                },
                manifest.server.clone(),
            )
        }
        DeploymentTarget::ConnectorHost {
            id,
            host,
            connectors,
        } => {
            let mut connectors = connectors
                .iter()
                .map(|connector| BoundConnector {
                    instance_id: connector.instance_id.clone(),
                    adapter_kind: connector.adapter_kind,
                    handoff_digest: connector.handoff_digest.clone(),
                })
                .collect::<Vec<_>>();
            connectors.sort_by(|left, right| left.instance_id.cmp(&right.instance_id));
            (
                OperationBinding {
                    target: id.clone(),
                    host: host.clone(),
                    artifact: manifest.connector.clone(),
                    workload: BindingWorkload::ConnectorHost {
                        connector_digest: manifest.connector.digest.clone(),
                        connectors,
                    },
                },
                manifest.connector.clone(),
            )
        }
    }
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationFailureEvidence {
    #[serde(default)]
    pub service_revision_digest: Option<String>,
    #[serde(default)]
    pub config_digest: Option<String>,
    #[serde(default)]
    pub unit_digest: Option<String>,
    #[serde(default)]
    pub readiness_digest: Option<String>,
    #[serde(default)]
    pub runtime_uid: Option<u32>,
    #[serde(default)]
    pub runtime_gid: Option<u32>,
    #[serde(default)]
    pub entrypoint_digest: Option<String>,
}
#[allow(clippy::missing_errors_doc)]
impl OperationRecord {
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub const fn phase(&self) -> OperationPhase {
        self.phase
    }
    #[must_use]
    pub fn predecessor_operation_id(&self) -> Option<&str> {
        self.predecessor_operation_id.as_deref()
    }
    #[must_use]
    pub fn target(&self) -> &str {
        &self.target
    }
    #[must_use]
    pub const fn binding(&self) -> &OperationBinding {
        &self.binding
    }
    #[must_use]
    pub fn manifest_digest(&self) -> &str {
        &self.manifest_digest
    }
    pub fn planned(
        manifest: &DeploymentManifest,
        target: &str,
        operation_id: &str,
        predecessor_operation_id: Option<String>,
    ) -> Result<Self> {
        uuid(operation_id, "operation_id")?;
        if let Some(predecessor) = &predecessor_operation_id {
            uuid(predecessor, "predecessor_operation_id")?;
            if predecessor == operation_id {
                return Err(contract("operation cannot succeed itself"));
            }
        }
        let target_contract = manifest
            .manifest
            .targets
            .iter()
            .find(|candidate| candidate.id() == target)
            .ok_or_else(|| contract("operation target is absent from deployment manifest"))?;
        let (binding, artifact) = binding_from_manifest(&manifest.manifest, target_contract);
        let record = Self {
            schema_version: 1,
            operation_id: operation_id.into(),
            manifest_digest: manifest.digest.clone(),
            artifact,
            binding,
            target: target.into(),
            predecessor_operation_id,
            phase: OperationPhase::Planned,
            last_proven_phase: OperationPhase::Planned,
            last_failure: None,
            integrity_digest: String::new(),
        };
        valid_record(&record)?;
        Ok(record)
    }

    #[cfg(unix)]
    fn seal(mut self) -> Result<Self> {
        self.integrity_digest.clear();
        self.integrity_digest = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }
    #[cfg(unix)]
    fn verify(&self) -> Result<()> {
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_digest);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(contract("operation integrity mismatch"));
        }
        Ok(())
    }
    pub fn advance(&mut self, phase: OperationPhase) -> Result<()> {
        if self.phase == OperationPhase::FailedRecoverable {
            return Err(contract("failed operation must be explicitly resumed"));
        }
        if self.phase.next(&self.binding.workload) != Some(phase) {
            return Err(contract("illegal operation state transition"));
        }
        self.phase = phase;
        self.last_proven_phase = phase;
        Ok(())
    }
    pub fn fail(&mut self, evidence: OperationFailureEvidence) -> Result<()> {
        if matches!(
            self.phase,
            OperationPhase::Completed
                | OperationPhase::ExpiredUnclaimed
                | OperationPhase::RollbackFenced
                | OperationPhase::RollbackConverged
                | OperationPhase::RollbackBlocked
                | OperationPhase::FailedRecoverable
        ) {
            return Err(contract("completed operation is rollback-fenced"));
        }
        self.last_proven_phase = self.phase;
        self.phase = OperationPhase::FailedRecoverable;
        self.last_failure = Some(evidence);
        Ok(())
    }
    fn expire_unclaimed(&mut self, instance_id: &str) -> Result<()> {
        let BindingWorkload::ConnectorHost { connectors, .. } = &self.binding.workload else {
            return Err(contract(
                "only a Connector-host operation may expire unclaimed",
            ));
        };
        if self.phase != OperationPhase::ArtifactsVerified
            || self.last_proven_phase != OperationPhase::ArtifactsVerified
            || self.last_failure.is_some()
            || connectors.len() != 1
            || connectors[0].instance_id != instance_id
        {
            return Err(contract(
                "expired-unclaimed operation is not exact no-effect state",
            ));
        }
        self.phase = OperationPhase::ExpiredUnclaimed;
        self.last_proven_phase = OperationPhase::ExpiredUnclaimed;
        Ok(())
    }
    pub fn rollback_service_only(&mut self, phase: OperationPhase) -> Result<()> {
        if self.phase != OperationPhase::Completed {
            return Err(contract("only completed operations can be rollback fenced"));
        }
        if phase != OperationPhase::RollbackFenced {
            return Err(contract("rollback must begin with a fence"));
        }
        self.phase = phase;
        Ok(())
    }
    pub fn finish_rollback(&mut self, phase: OperationPhase) -> Result<()> {
        if self.phase != OperationPhase::RollbackFenced
            || !matches!(
                phase,
                OperationPhase::RollbackConverged | OperationPhase::RollbackBlocked
            )
        {
            return Err(contract("illegal rollback transition"));
        }
        self.phase = phase;
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TargetOwnership {
    schema_version: u32,
    target: String,
    host: HostTuple,
    current_operation_id: String,
    #[serde(default)]
    predecessor_operation_id: Option<String>,
    operation_identity_digest: String,
    integrity_digest: String,
}
#[cfg(unix)]
impl TargetOwnership {
    fn from_record(record: &OperationRecord) -> Result<Self> {
        Self {
            schema_version: 1,
            target: record.target.clone(),
            host: record.binding.host.clone(),
            current_operation_id: record.operation_id.clone(),
            predecessor_operation_id: record.predecessor_operation_id.clone(),
            operation_identity_digest: operation_identity_digest(record)?,
            integrity_digest: String::new(),
        }
        .seal()
    }
    fn seal(mut self) -> Result<Self> {
        self.integrity_digest.clear();
        self.integrity_digest = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }
    fn verify(&self) -> Result<()> {
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_digest);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(contract("target ownership integrity mismatch"));
        }
        if self.schema_version != 1 {
            return Err(contract("target ownership schema must be 1"));
        }
        token(&self.target, "ownership target")?;
        self.host.validate()?;
        uuid(&self.current_operation_id, "ownership operation")?;
        if let Some(predecessor) = &self.predecessor_operation_id {
            uuid(predecessor, "ownership predecessor")?;
        }
        sha256(
            &self.operation_identity_digest,
            "ownership operation identity",
        )
    }
}

#[cfg(unix)]
fn operation_identity_digest(record: &OperationRecord) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        record.schema_version,
        &record.operation_id,
        &record.manifest_digest,
        &record.artifact,
        &record.binding,
        &record.target,
        &record.predecessor_operation_id,
    ))?)))
}

#[cfg(unix)]
pub struct DeploymentStateStore {
    root: PathBuf,
}
#[cfg(not(unix))]
pub struct DeploymentStateStore;
#[cfg(unix)]
#[allow(clippy::missing_errors_doc)]
impl DeploymentStateStore {
    pub fn read_connector_claim(
        &self,
        operation_id: &str,
        instance_id: &str,
    ) -> Result<Option<ConnectorClaim>> {
        let path = self.connector_claim_path(instance_id, operation_id)?;
        match Self::read_claim(&path) {
            Ok(claim) => Ok(Some(claim)),
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    pub fn fixed() -> Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(contract("fixed deployment state requires root"));
        }
        Ok(Self {
            root: PathBuf::from(STATE_DIR),
        })
    }
    #[must_use]
    pub fn for_test(root: PathBuf) -> Self {
        Self { root }
    }
    pub fn claim(
        &self,
        manifest: &DeploymentManifest,
        record: &OperationRecord,
        proof: &VerifiedHostBinding,
    ) -> Result<OperationRecord> {
        valid_record(record)?;
        record_matches_manifest(record, manifest)?;
        if proof.host() != &record.binding.host {
            return Err(contract("verified host binding does not match operation"));
        }
        if record.phase != OperationPhase::Planned
            || record.last_proven_phase != OperationPhase::Planned
            || record.last_failure.is_some()
            || !record.integrity_digest.is_empty()
        {
            return Err(contract(
                "new operation claim must use canonical initial state",
            ));
        }
        let record = record.clone().seal()?;
        let ownership = TargetOwnership::from_record(&record)?;
        serialize_bounded(&record)?;
        serialize_bounded(&ownership)?;
        self.ensure_root()?;
        // Every claim takes the globally keyed operation lock before its target
        // lock. This prevents one UUID from being published under two target
        // ownership fences while preserving target-level serialization.
        let _operation_lock = self.lock(&format!("id-{}", record.operation_id))?;
        let existing = match self.read(&record.operation_id) {
            Ok(existing) => Some(existing),
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(existing) = &existing
            && operation_identity_digest(existing)? != operation_identity_digest(&record)?
        {
            return Err(ReleaseError::OperationConflict);
        }
        let fence = ownership_fence(&record.target, &record.binding.host)?;
        let owner_path = self.root.join(format!("target-owner-{fence}.json"));
        if existing.is_none() {
            self.reconcile_legacy_owner_for_absent_operation(&record, &ownership, &owner_path)?;
        }
        let _target_lock = self.lock(&format!("target-{fence}"))?;
        self.validate_owner_transition(&owner_path, &record, &ownership)?;
        if let Some(existing) = existing {
            // Complete an interrupted record-first claim (or atomically rewrite
            // the identical ownership projection on an exact retry).
            self.write_path(&owner_path, &ownership)?;
            return Ok(existing);
        }
        // Persist the immutable global identity before publishing target
        // ownership. A crash here is recoverable by the exact replay above.
        self.write_path(&self.record_path(&record.operation_id)?, &record)?;
        self.write_path(&owner_path, &ownership)?;
        Ok(record)
    }
    fn reconcile_legacy_owner_for_absent_operation(
        &self,
        record: &OperationRecord,
        ownership: &TargetOwnership,
        expected_owner_path: &Path,
    ) -> Result<()> {
        let entries = fs::read_dir(&self.root).map_err(io_error(&self.root))?;
        let mut matching = None;
        let mut candidate_count = 0;
        for entry in entries {
            let entry = entry.map_err(io_error(&self.root))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_target_owner_projection_filename(name) {
                continue;
            }
            candidate_count += 1;
            if candidate_count > MAX_STATE_ROOT_ENTRIES {
                return Err(ReleaseError::StateUnsafe(self.root.clone()));
            }
            let path = entry.path();
            let current = Self::read_owner(&path)?;
            if current.current_operation_id != record.operation_id {
                continue;
            }
            if matching.replace(path.clone()).is_some()
                || path != expected_owner_path
                || current != *ownership
            {
                return Err(ReleaseError::OperationConflict);
            }
        }
        Ok(())
    }
    fn validate_owner_transition(
        &self,
        owner_path: &Path,
        record: &OperationRecord,
        ownership: &TargetOwnership,
    ) -> Result<()> {
        match Self::read_owner(owner_path) {
            Ok(current) if current.current_operation_id == record.operation_id => {
                if current != *ownership {
                    return Err(ReleaseError::OperationConflict);
                }
            }
            Ok(current) => {
                if current.target != record.target
                    || current.host != record.binding.host
                    || record.predecessor_operation_id.as_deref()
                        != Some(current.current_operation_id.as_str())
                {
                    return Err(ReleaseError::OperationConflict);
                }
                let predecessor = self.read(&current.current_operation_id)?;
                if operation_identity_digest(&predecessor)? != current.operation_identity_digest {
                    return Err(ReleaseError::OperationConflict);
                }
                match predecessor.phase {
                    OperationPhase::Completed | OperationPhase::RollbackConverged => {}
                    OperationPhase::ExpiredUnclaimed => {
                        self.validate_expired_unclaimed_successor(&predecessor, record)?;
                    }
                    _ => return Err(ReleaseError::OperationConflict),
                }
            }
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                if record.predecessor_operation_id.is_some() {
                    return Err(ReleaseError::OperationConflict);
                }
            }
            Err(error) => return Err(error),
        }
        Ok(())
    }
    pub fn read(&self, id: &str) -> Result<OperationRecord> {
        uuid(id, "operation_id")?;
        let path = self.record_path(id)?;
        let bytes = Self::read_secure(&path)?;
        let record: OperationRecord = serde_json::from_slice(&bytes)?;
        valid_record(&record)?;
        record.verify()?;
        if record.operation_id != id {
            return Err(ReleaseError::StateUnsafe(path));
        }
        Ok(record)
    }
    pub fn lock_connector_execution(
        &self,
        operation_id: &str,
        instance_id: &str,
    ) -> Result<ConnectorExecutionLease> {
        uuid(operation_id, "operation_id")?;
        uuid(instance_id, "instance_id")?;
        let lock = self.lock(&format!("execution-{operation_id}"))?;
        let operation = self.read(operation_id)?;
        let owner = Self::read_connector_owner(&self.connector_owner_path(instance_id)?)?;
        let claim = Self::read_claim(&self.connector_claim_path(instance_id, operation_id)?)?;
        if owner.current_operation_id != operation_id
            || owner.claim_identity_digest != connector_claim_identity_digest(&claim)?
            || claim.operation_id != operation.operation_id
        {
            return Err(ReleaseError::OperationConflict);
        }
        Ok(ConnectorExecutionLease {
            store: Self {
                root: self.root.clone(),
            },
            operation_id: operation_id.to_owned(),
            _lock: lock,
        })
    }
    pub fn advance(&self, id: &str, phase: OperationPhase) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        record.advance(phase)?;
        self.persist_record(record)
    }
    pub fn fail(&self, id: &str, evidence: OperationFailureEvidence) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        record.fail(evidence)?;
        self.persist_record(record)
    }
    pub fn resume(&self, id: &str) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        if record.phase != OperationPhase::FailedRecoverable {
            return Err(contract("only a failed recoverable operation may resume"));
        }
        record.phase = record.last_proven_phase;
        record.last_failure = None;
        self.persist_record(record)
    }
    /// Terminally records the exact Host-proven no-effect expiry for one bootstrap.
    pub fn expire_unclaimed_operation(
        &self,
        id: &str,
        instance_id: &str,
    ) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        let claim = Self::read_claim(&self.connector_claim_path(instance_id, id)?)?;
        if claim.phase != ConnectorClaimPhase::ExpiredUnclaimed {
            return Err(ReleaseError::OperationConflict);
        }
        if record.phase == OperationPhase::ExpiredUnclaimed {
            return Ok(record);
        }
        record.expire_unclaimed(instance_id)?;
        self.persist_record(record)
    }
    pub fn rollback_fence(&self, id: &str) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        record.rollback_service_only(OperationPhase::RollbackFenced)?;
        self.persist_record(record)
    }
    pub fn finish_rollback(&self, id: &str, phase: OperationPhase) -> Result<OperationRecord> {
        let (_lock, mut record) = self.lock_current(id)?;
        record.finish_rollback(phase)?;
        self.persist_record(record)
    }
    fn persist_record(&self, record: OperationRecord) -> Result<OperationRecord> {
        valid_record(&record)?;
        if record.phase == OperationPhase::Completed {
            self.verify_connector_completion(&record)?;
        }
        let record = record.seal()?;
        self.write_path(&self.record_path(&record.operation_id)?, &record)?;
        Ok(record)
    }
    fn verify_connector_completion(&self, record: &OperationRecord) -> Result<()> {
        let BindingWorkload::ConnectorHost { connectors, .. } = &record.binding.workload else {
            return Ok(());
        };
        for connector in connectors {
            let owner =
                Self::read_connector_owner(&self.connector_owner_path(&connector.instance_id)?)?;
            let claim = Self::read_claim(
                &self.connector_claim_path(&connector.instance_id, &owner.current_operation_id)?,
            )?;
            if owner.current_operation_id != record.operation_id
                || connector_claim_identity_digest(&claim)? != owner.claim_identity_digest
                || claim.phase != ConnectorClaimPhase::Released
            {
                return Err(ReleaseError::OperationConflict);
            }
        }
        Ok(())
    }
    fn validate_expired_unclaimed_successor(
        &self,
        predecessor: &OperationRecord,
        successor: &OperationRecord,
    ) -> Result<()> {
        let (
            BindingWorkload::ConnectorHost {
                connectors: prior, ..
            },
            BindingWorkload::ConnectorHost {
                connectors: next, ..
            },
        ) = (&predecessor.binding.workload, &successor.binding.workload)
        else {
            return Err(ReleaseError::OperationConflict);
        };
        if prior.len() != 1 || next.len() != 1 || prior[0].instance_id != next[0].instance_id {
            return Err(ReleaseError::OperationConflict);
        }
        let claim = Self::read_claim(
            &self.connector_claim_path(&prior[0].instance_id, predecessor.operation_id())?,
        )?;
        if claim.phase != ConnectorClaimPhase::ExpiredUnclaimed
            || claim.operation_id != predecessor.operation_id
            || claim.target != predecessor.target
        {
            return Err(ReleaseError::OperationConflict);
        }
        Ok(())
    }
    fn lock_current(&self, id: &str) -> Result<(Lock, OperationRecord)> {
        let initial = self.read(id)?;
        let fence = ownership_fence(&initial.target, &initial.binding.host)?;
        let lock = self.lock(&format!("target-{fence}"))?;
        let current = self.read(id)?;
        let owner = Self::read_owner(&self.root.join(format!("target-owner-{fence}.json")))?;
        if owner.current_operation_id != current.operation_id
            || owner.operation_identity_digest != operation_identity_digest(&current)?
        {
            return Err(ReleaseError::OperationConflict);
        }
        Ok((lock, current))
    }
    fn verify_current_owner(&self, record: &OperationRecord) -> Result<()> {
        let fence = ownership_fence(&record.target, &record.binding.host)?;
        let owner = Self::read_owner(&self.root.join(format!("target-owner-{fence}.json")))?;
        if owner.current_operation_id != record.operation_id
            || owner.operation_identity_digest != operation_identity_digest(record)?
        {
            return Err(ReleaseError::OperationConflict);
        }
        Ok(())
    }
    fn record_path(&self, id: &str) -> Result<PathBuf> {
        uuid(id, "operation_id")?;
        Ok(self.root.join(format!("operation-{id}.json")))
    }
    fn lock(&self, id: &str) -> Result<Lock> {
        token(id, "lock id")?;
        self.ensure_root()?;
        let p = self.root.join(format!("operation-{id}.lock"));
        let descriptor = open(
            &p,
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map_err(|e| io_error(&p)(std::io::Error::from(e)))?;
        let file: File = descriptor.into();
        Self::validate_open_state_file(&p, &file)?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ReleaseError::OperationLocked
            } else {
                io_error(&p)(error)
            }
        })?;
        Ok(Lock { file })
    }
    fn write_path<T: Serialize>(&self, path: &Path, record: &T) -> Result<()> {
        let bytes = serialize_bounded(record)?;
        self.ensure_root()?;
        let name = path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .ok_or_else(|| contract("invalid state filename"))?;
        let root_fd = open(
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|e| io_error(&self.root)(std::io::Error::from(e)))?;
        match openat(
            &root_fd,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
        {
            Ok(file) => Self::validate_open_state_file(path, &file)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(path)(error)),
        }
        let mut created = None;
        for _ in 0..32 {
            let tmp = format!(
                ".tmp.{}.{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            );
            match openat(
                &root_fd,
                &tmp,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => {
                    created = Some((tmp, File::from(fd)));
                    break;
                }
                Err(rustix::io::Errno::EXIST) => {}
                Err(e) => return Err(io_error(self.root.join(&tmp))(std::io::Error::from(e))),
            }
        }
        let (tmp, mut f) =
            created.ok_or_else(|| contract("state temporary-name collision limit exceeded"))?;
        if let Err(error) = f.write_all(&bytes).and_then(|()| f.sync_all()) {
            let _ = unlinkat(&root_fd, &tmp, AtFlags::empty());
            return Err(io_error(self.root.join(&tmp))(error));
        }
        if let Err(error) = renameat(&root_fd, &tmp, &root_fd, name) {
            let _ = unlinkat(&root_fd, &tmp, AtFlags::empty());
            return Err(io_error(path)(std::io::Error::from(error)));
        }
        rustix::fs::fsync(&root_fd).map_err(|e| io_error(&self.root)(std::io::Error::from(e)))?;
        Ok(())
    }
    fn ensure_root(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        let descriptor = match open(
            &self.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        ) {
            Ok(descriptor) => descriptor,
            Err(rustix::io::Errno::NOENT) => {
                rustix::fs::mkdir(&self.root, Mode::from_raw_mode(0o700))
                    .map_err(|error| io_error(&self.root)(std::io::Error::from(error)))?;
                open(
                    &self.root,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| io_error(&self.root)(std::io::Error::from(error)))?
            }
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR) => {
                return Err(ReleaseError::StateUnsafe(self.root.clone()));
            }
            Err(error) => return Err(io_error(&self.root)(std::io::Error::from(error))),
        };
        let root: File = descriptor.into();
        let m = root.metadata().map_err(io_error(&self.root))?;
        if !m.is_dir()
            || m.mode() & 0o777 != 0o700
            || m.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ReleaseError::StateUnsafe(self.root.clone()));
        }
        Ok(())
    }
    fn open_existing(path: &Path) -> std::io::Result<File> {
        open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map(File::from)
        .map_err(std::io::Error::from)
    }
    fn validate_open_state_file(path: &Path, file: &File) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let m = file.metadata().map_err(io_error(path))?;
            if !m.is_file()
                || m.len() > MAX_BYTES
                || m.mode() & 0o777 != 0o600
                || m.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
            }
        }
        #[cfg(not(unix))]
        return Err(contract("durable state is unsupported off Unix"));
        Ok(())
    }
    fn read_secure(path: &Path) -> Result<Vec<u8>> {
        let file = Self::open_existing(path).map_err(io_error(path))?;
        Self::validate_open_state_file(path, &file)?;
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
        }
        Ok(bytes)
    }
    fn read_owner(path: &Path) -> Result<TargetOwnership> {
        let owner: TargetOwnership = serde_json::from_slice(&Self::read_secure(path)?)?;
        owner.verify()?;
        Ok(owner)
    }
}
#[cfg(unix)]
struct Lock {
    file: File,
}

#[cfg(unix)]
pub struct ConnectorExecutionLease {
    store: DeploymentStateStore,
    operation_id: String,
    _lock: Lock,
}
#[cfg(unix)]
impl ConnectorExecutionLease {
    /// Reads the exact durable execution projection, if one exists.
    ///
    /// # Errors
    /// Returns an error when state is missing unsafely, malformed, or unreadable.
    pub fn read(&self) -> Result<Option<Vec<u8>>> {
        let path = self
            .store
            .root
            .join(format!("connector-execution-{}.json", self.operation_id));
        match DeploymentStateStore::read_secure(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    /// Atomically replaces the execution projection and fsyncs the state directory.
    ///
    /// # Errors
    /// Returns an error when serialization or the protected atomic write fails.
    pub fn write<T: Serialize>(&self, value: &T) -> Result<()> {
        self.store.write_path(
            &self
                .store
                .root
                .join(format!("connector-execution-{}.json", self.operation_id)),
            value,
        )
    }
}
#[cfg(unix)]
impl Drop for Lock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorClaim {
    schema_version: u32,
    operation_id: String,
    manifest_digest: String,
    target: String,
    instance_id: String,
    artifact: ImmutableArtifact,
    adapter_kind: AdapterKind,
    handoff_digest: String,
    #[serde(default)]
    predecessor_operation_id: Option<String>,
    phase: ConnectorClaimPhase,
    integrity_digest: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorClaimPhase {
    Prepared,
    HandoffObserved,
    Released,
    /// The Host proved this expired bootstrap had no Connector lifecycle effect.
    ExpiredUnclaimed,
}
#[allow(clippy::missing_errors_doc)]
impl ConnectorClaim {
    #[must_use]
    pub const fn phase(&self) -> ConnectorClaimPhase {
        self.phase
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    #[must_use]
    pub fn predecessor_operation_id(&self) -> Option<&str> {
        self.predecessor_operation_id.as_deref()
    }
    pub fn prepared(
        parent: &OperationRecord,
        instance_id: &str,
        predecessor_operation_id: Option<String>,
    ) -> Result<Self> {
        valid_record(parent)?;
        let BindingWorkload::ConnectorHost { connectors, .. } = &parent.binding.workload else {
            return Err(contract(
                "connector claim parent must bind a connector host",
            ));
        };
        let binding = connectors
            .iter()
            .find(|binding| binding.instance_id == instance_id)
            .ok_or_else(|| contract("connector instance is absent from parent operation"))?;
        let claim = Self {
            schema_version: 1,
            operation_id: parent.operation_id.clone(),
            manifest_digest: parent.manifest_digest.clone(),
            target: parent.target.clone(),
            instance_id: binding.instance_id.clone(),
            artifact: parent.artifact.clone(),
            adapter_kind: binding.adapter_kind,
            handoff_digest: binding.handoff_digest.clone(),
            predecessor_operation_id,
            phase: ConnectorClaimPhase::Prepared,
            integrity_digest: String::new(),
        };
        valid_claim(&claim)?;
        Ok(claim)
    }
    #[cfg(unix)]
    fn seal(mut self) -> Result<Self> {
        self.integrity_digest.clear();
        self.integrity_digest = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }
    #[cfg(unix)]
    fn verify(&self) -> Result<()> {
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_digest);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(contract("connector claim integrity mismatch"));
        }
        Ok(())
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConnectorOwnership {
    schema_version: u32,
    instance_id: String,
    current_operation_id: String,
    #[serde(default)]
    predecessor_operation_id: Option<String>,
    claim_identity_digest: String,
    integrity_digest: String,
}
#[cfg(unix)]
impl ConnectorOwnership {
    fn from_claim(claim: &ConnectorClaim) -> Result<Self> {
        Self {
            schema_version: 1,
            instance_id: claim.instance_id.clone(),
            current_operation_id: claim.operation_id.clone(),
            predecessor_operation_id: claim.predecessor_operation_id.clone(),
            claim_identity_digest: connector_claim_identity_digest(claim)?,
            integrity_digest: String::new(),
        }
        .seal()
    }
    fn seal(mut self) -> Result<Self> {
        self.integrity_digest.clear();
        self.integrity_digest = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }
    fn verify(&self) -> Result<()> {
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_digest);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(contract("connector ownership integrity mismatch"));
        }
        if self.schema_version != 1 {
            return Err(contract("connector ownership schema must be 1"));
        }
        uuid(&self.instance_id, "connector owner instance")?;
        uuid(&self.current_operation_id, "connector owner operation")?;
        if let Some(predecessor) = &self.predecessor_operation_id {
            uuid(predecessor, "connector owner predecessor")?;
        }
        sha256(&self.claim_identity_digest, "connector claim identity")
    }
}

#[cfg(unix)]
fn connector_claim_identity_digest(claim: &ConnectorClaim) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        claim.schema_version,
        &claim.operation_id,
        &claim.manifest_digest,
        &claim.target,
        &claim.instance_id,
        &claim.artifact,
        claim.adapter_kind,
        &claim.handoff_digest,
        &claim.predecessor_operation_id,
    ))?)))
}

#[cfg(unix)]
#[allow(clippy::missing_errors_doc)]
impl DeploymentStateStore {
    pub fn prepare_connector_claim(
        &self,
        parent: &OperationRecord,
        instance_id: &str,
    ) -> Result<ConnectorClaim> {
        let predecessor = self.connector_predecessor_for_parent(parent, instance_id)?;
        ConnectorClaim::prepared(parent, instance_id, predecessor)
    }
    pub fn claim_connector(
        &self,
        claim: &ConnectorClaim,
        proof: &VerifiedHostBinding,
    ) -> Result<ConnectorClaim> {
        valid_claim(claim)?;
        if claim.phase != ConnectorClaimPhase::Prepared || !claim.integrity_digest.is_empty() {
            return Err(contract(
                "new connector claim must be canonical prepared state",
            ));
        }
        let claim = claim.clone().seal()?;
        let connector_owner = ConnectorOwnership::from_claim(&claim)?;
        serialize_bounded(&claim)?;
        serialize_bounded(&connector_owner)?;
        self.ensure_root()?;
        let parent = self.read(&claim.operation_id)?;
        claim_matches_parent(&claim, &parent, proof)?;
        let target_fence = ownership_fence(&parent.target, &parent.binding.host)?;
        let _target_lock = self.lock(&format!("target-{target_fence}"))?;
        let parent = self.read(&claim.operation_id)?;
        self.verify_current_owner(&parent)?;
        let connector_lock_id = format!("connector-{}", claim.instance_id);
        let _connector_lock = self.lock(&connector_lock_id)?;
        let claim_path = self.connector_claim_path(&claim.instance_id, &claim.operation_id)?;
        let owner_path = self.connector_owner_path(&claim.instance_id)?;
        let expected_predecessor =
            self.connector_predecessor_for_parent(&parent, &claim.instance_id)?;
        if claim.predecessor_operation_id != expected_predecessor {
            return Err(ReleaseError::OperationConflict);
        }
        match Self::read_connector_owner(&owner_path) {
            Ok(current) if current.current_operation_id == claim.operation_id => {
                if current != connector_owner {
                    return Err(ReleaseError::OperationConflict);
                }
            }
            Ok(current) => {
                if current.instance_id != claim.instance_id {
                    return Err(ReleaseError::OperationConflict);
                }
                if expected_predecessor
                    .as_deref()
                    .is_some_and(|predecessor| predecessor != current.current_operation_id)
                {
                    return Err(ReleaseError::OperationConflict);
                }
                let prior_path =
                    self.connector_claim_path(&claim.instance_id, &current.current_operation_id)?;
                let prior = Self::read_claim(&prior_path)?;
                let prior_parent = self.read(&prior.operation_id)?;
                if connector_claim_identity_digest(&prior)? != current.claim_identity_digest
                    || prior.target != parent.target
                    || prior_parent.binding.host != parent.binding.host
                {
                    return Err(ReleaseError::OperationConflict);
                }
                match prior.phase {
                    ConnectorClaimPhase::Released
                        if matches!(
                            prior_parent.phase,
                            OperationPhase::Completed | OperationPhase::RollbackConverged
                        ) => {}
                    ConnectorClaimPhase::ExpiredUnclaimed
                        if prior_parent.phase == OperationPhase::ExpiredUnclaimed
                            && parent.predecessor_operation_id.as_deref()
                                == Some(prior_parent.operation_id()) => {}
                    _ => return Err(ReleaseError::OperationConflict),
                }
                self.write_path(&owner_path, &connector_owner)?;
            }
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                if expected_predecessor.is_some() {
                    return Err(ReleaseError::OperationConflict);
                }
                self.write_path(&owner_path, &connector_owner)?;
            }
            Err(error) => return Err(error),
        }
        self.converge_connector_claim(&claim_path, &claim)
    }

    fn connector_predecessor_for_parent(
        &self,
        parent: &OperationRecord,
        instance_id: &str,
    ) -> Result<Option<String>> {
        let Some(predecessor_id) = &parent.predecessor_operation_id else {
            return Ok(None);
        };
        let predecessor = self.read(predecessor_id)?;
        if predecessor.target != parent.target || predecessor.binding.host != parent.binding.host {
            return Err(ReleaseError::OperationConflict);
        }
        let binds_instance = matches!(
            &predecessor.binding.workload,
            BindingWorkload::ConnectorHost { connectors, .. }
                if connectors.iter().any(|connector| connector.instance_id == instance_id)
        );
        Ok(binds_instance.then(|| predecessor_id.clone()))
    }

    pub fn observe_connector_handoff(&self, instance_id: &str) -> Result<ConnectorClaim> {
        uuid(instance_id, "instance_id")?;
        let (owner, mut claim, _target_lock, _connector_lock) =
            self.lock_current_connector(instance_id)?;
        if claim.phase == ConnectorClaimPhase::HandoffObserved {
            return Ok(claim);
        }
        if claim.phase != ConnectorClaimPhase::Prepared {
            return Err(contract("illegal connector enrollment transition"));
        }
        claim.phase = ConnectorClaimPhase::HandoffObserved;
        self.persist_connector_claim(&owner, claim)
    }

    pub fn release_connector_claim(&self, instance_id: &str) -> Result<ConnectorClaim> {
        uuid(instance_id, "instance_id")?;
        let (owner, mut claim, _target_lock, _connector_lock) =
            self.lock_current_connector(instance_id)?;
        if claim.phase == ConnectorClaimPhase::Released {
            return Ok(claim);
        }
        if claim.phase != ConnectorClaimPhase::HandoffObserved {
            return Err(contract(
                "only an observed connector handoff may be released",
            ));
        }
        claim.phase = ConnectorClaimPhase::Released;
        self.persist_connector_claim(&owner, claim)
    }

    /// Persists the Host-proven no-effect expiry before its parent operation is terminalized.
    pub fn expire_unclaimed_connector_claim(&self, instance_id: &str) -> Result<ConnectorClaim> {
        uuid(instance_id, "instance_id")?;
        let (owner, mut claim, _target_lock, _connector_lock) =
            self.lock_current_connector(instance_id)?;
        if claim.phase == ConnectorClaimPhase::ExpiredUnclaimed {
            return Ok(claim);
        }
        if claim.phase != ConnectorClaimPhase::Prepared {
            return Err(contract(
                "only an unobserved connector claim may expire unclaimed",
            ));
        }
        claim.phase = ConnectorClaimPhase::ExpiredUnclaimed;
        self.persist_connector_claim(&owner, claim)
    }

    fn read_claim(path: &Path) -> Result<ConnectorClaim> {
        let bytes = Self::read_secure(path)?;
        let claim: ConnectorClaim = serde_json::from_slice(&bytes)?;
        valid_claim(&claim)?;
        claim.verify()?;
        Ok(claim)
    }
    fn connector_claim_path(&self, instance_id: &str, operation_id: &str) -> Result<PathBuf> {
        uuid(instance_id, "instance_id")?;
        uuid(operation_id, "operation_id")?;
        Ok(self.root.join(format!(
            "connector-{instance_id}-operation-{operation_id}.json"
        )))
    }
    fn connector_owner_path(&self, instance_id: &str) -> Result<PathBuf> {
        uuid(instance_id, "instance_id")?;
        Ok(self
            .root
            .join(format!("connector-owner-{instance_id}.json")))
    }
    fn read_connector_owner(path: &Path) -> Result<ConnectorOwnership> {
        let owner: ConnectorOwnership = serde_json::from_slice(&Self::read_secure(path)?)?;
        owner.verify()?;
        Ok(owner)
    }
    fn converge_connector_claim(
        &self,
        path: &Path,
        claim: &ConnectorClaim,
    ) -> Result<ConnectorClaim> {
        match Self::read_claim(path) {
            Ok(existing) => {
                if connector_claim_identity_digest(&existing)?
                    != connector_claim_identity_digest(claim)?
                {
                    return Err(ReleaseError::OperationConflict);
                }
                Ok(existing)
            }
            Err(ReleaseError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                self.write_path(path, claim)?;
                Ok(claim.clone())
            }
            Err(error) => Err(error),
        }
    }
    fn persist_connector_claim(
        &self,
        owner: &ConnectorOwnership,
        claim: ConnectorClaim,
    ) -> Result<ConnectorClaim> {
        valid_claim(&claim)?;
        if connector_claim_identity_digest(&claim)? != owner.claim_identity_digest {
            return Err(ReleaseError::OperationConflict);
        }
        let claim = claim.seal()?;
        self.write_path(
            &self.connector_claim_path(&claim.instance_id, &claim.operation_id)?,
            &claim,
        )?;
        Ok(claim)
    }
    fn lock_current_connector(
        &self,
        instance_id: &str,
    ) -> Result<(ConnectorOwnership, ConnectorClaim, Lock, Lock)> {
        let initial_owner = Self::read_connector_owner(&self.connector_owner_path(instance_id)?)?;
        let initial_claim = Self::read_claim(
            &self.connector_claim_path(instance_id, &initial_owner.current_operation_id)?,
        )?;
        let parent = self.read(&initial_claim.operation_id)?;
        let target_fence = ownership_fence(&parent.target, &parent.binding.host)?;
        let target_lock = self.lock(&format!("target-{target_fence}"))?;
        let parent = self.read(&initial_claim.operation_id)?;
        self.verify_current_owner(&parent)?;
        let connector_lock = self.lock(&format!("connector-{instance_id}"))?;
        let owner = Self::read_connector_owner(&self.connector_owner_path(instance_id)?)?;
        let claim = Self::read_claim(
            &self.connector_claim_path(instance_id, &owner.current_operation_id)?,
        )?;
        if owner.instance_id != instance_id
            || connector_claim_identity_digest(&claim)? != owner.claim_identity_digest
            || claim.operation_id != parent.operation_id
        {
            return Err(ReleaseError::OperationConflict);
        }
        Ok((owner, claim, target_lock, connector_lock))
    }
}

#[cfg(not(unix))]
#[allow(clippy::missing_errors_doc)]
impl DeploymentStateStore {
    pub fn fixed() -> Result<Self> {
        Err(durable_state_unsupported())
    }
    pub fn claim(
        &self,
        manifest: &DeploymentManifest,
        record: &OperationRecord,
        proof: &VerifiedHostBinding,
    ) -> Result<OperationRecord> {
        let _ = (self, manifest, record, proof);
        Err(durable_state_unsupported())
    }
    pub fn read(&self, id: &str) -> Result<OperationRecord> {
        let _ = (self, id);
        Err(durable_state_unsupported())
    }
    pub fn advance(&self, id: &str, phase: OperationPhase) -> Result<OperationRecord> {
        let _ = (self, id, phase);
        Err(durable_state_unsupported())
    }
    pub fn fail(&self, id: &str, evidence: OperationFailureEvidence) -> Result<OperationRecord> {
        let _ = (self, id, evidence);
        Err(durable_state_unsupported())
    }
    pub fn resume(&self, id: &str) -> Result<OperationRecord> {
        let _ = (self, id);
        Err(durable_state_unsupported())
    }
    pub fn expire_unclaimed_operation(
        &self,
        id: &str,
        instance_id: &str,
    ) -> Result<OperationRecord> {
        let _ = (self, id, instance_id);
        Err(durable_state_unsupported())
    }
    pub fn rollback_fence(&self, id: &str) -> Result<OperationRecord> {
        let _ = (self, id);
        Err(durable_state_unsupported())
    }
    pub fn finish_rollback(&self, id: &str, phase: OperationPhase) -> Result<OperationRecord> {
        let _ = (self, id, phase);
        Err(durable_state_unsupported())
    }
    pub fn claim_connector(
        &self,
        claim: &ConnectorClaim,
        proof: &VerifiedHostBinding,
    ) -> Result<ConnectorClaim> {
        let _ = (self, claim, proof);
        Err(durable_state_unsupported())
    }
    pub fn prepare_connector_claim(
        &self,
        parent: &OperationRecord,
        instance_id: &str,
    ) -> Result<ConnectorClaim> {
        let _ = (self, parent, instance_id);
        Err(durable_state_unsupported())
    }
    pub fn read_connector_claim(
        &self,
        operation_id: &str,
        instance_id: &str,
    ) -> Result<Option<ConnectorClaim>> {
        let _ = (self, operation_id, instance_id);
        Err(durable_state_unsupported())
    }
    pub fn observe_connector_handoff(&self, instance_id: &str) -> Result<ConnectorClaim> {
        let _ = (self, instance_id);
        Err(durable_state_unsupported())
    }
    pub fn release_connector_claim(&self, instance_id: &str) -> Result<ConnectorClaim> {
        let _ = (self, instance_id);
        Err(durable_state_unsupported())
    }
    pub fn expire_unclaimed_connector_claim(&self, instance_id: &str) -> Result<ConnectorClaim> {
        let _ = (self, instance_id);
        Err(durable_state_unsupported())
    }
}

/// Validate fixed host evidence before an adapter can be observed. Tests may inject only `path`.
///
/// # Errors
///
/// Returns an error unless the fixed root-owned host evidence file exactly matches.
pub fn validate_host_evidence(expected: &HostTuple) -> Result<VerifiedHostBinding> {
    validate_host_evidence_at(Path::new(HOST_EVIDENCE_PATH), expected)
}

#[allow(clippy::items_after_statements)]
fn validate_host_evidence_at(path: &Path, expected: &HostTuple) -> Result<VerifiedHostBinding> {
    #[cfg(not(unix))]
    {
        let _ = (path, expected);
        return Err(contract("host evidence validation is unsupported off Unix"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
        let file: File = descriptor.into();
        let m = file.metadata().map_err(io_error(path))?;
        validate_host_metadata(m.is_file(), m.uid(), m.mode(), m.len())?;
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        parse_host_evidence(&bytes, expected)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReceipt {
    pub schema_version: u32,
    pub operation_id: String,
    pub manifest_digest: String,
    pub binding: OperationBinding,
    pub artifact: ImmutableArtifact,
    pub phase: OperationPhase,
    pub last_proven_phase: OperationPhase,
    pub outcome: ReceiptOutcome,
    pub services: Vec<ServiceReceiptEvidence>,
    #[serde(default)]
    pub forward_migration: Option<ForwardMigrationEvidence>,
    pub integrity_digest: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOutcome {
    Succeeded,
    FailedRecoverable,
    RollbackConverged,
    RollbackBlocked,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReceiptService {
    Node {
        service: NodeService,
    },
    Connector {
        instance_id: String,
        adapter_kind: AdapterKind,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceReceiptEvidence {
    pub service: ReceiptService,
    pub service_revision_digest: String,
    pub config_digest: String,
    pub unit_digest: String,
    pub readiness_digest: String,
    pub entrypoint_digest: String,
    pub runtime_uid: u32,
    pub runtime_gid: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ForwardMigrationEvidence {
    pub from_version: u64,
    pub to_version: u64,
    pub before_digest: String,
    pub after_digest: String,
    pub migration_artifact_digest: String,
}
#[allow(clippy::missing_errors_doc)]
impl DeploymentReceipt {
    pub fn verify(&self) -> Result<()> {
        validate_receipt(self)?;
        let mut copy = self.clone();
        let supplied = std::mem::take(&mut copy.integrity_digest);
        copy.integrity_digest = String::new();
        let bytes = serde_json::to_vec(&copy)?;
        if supplied != hex::encode(Sha256::digest(bytes)) {
            return Err(contract("deployment receipt integrity mismatch"));
        }
        Ok(())
    }
    pub fn seal(mut self) -> Result<Self> {
        validate_receipt(&self)?;
        self.integrity_digest = String::new();
        self.integrity_digest = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }
}
#[allow(clippy::too_many_lines)]
fn validate_receipt(receipt: &DeploymentReceipt) -> Result<()> {
    let self_ = receipt;
    if self_.schema_version != 1 {
        return Err(contract("receipt schema must be 1"));
    }
    uuid(&self_.operation_id, "receipt operation")?;
    sha256(&self_.manifest_digest, "receipt manifest")?;
    valid_binding(&self_.binding)?;
    self_.artifact.validate("receipt artifact")?;
    let (expected, required_migration) = match &self_.binding.workload {
        BindingWorkload::Node { services, .. } => (
            services
                .iter()
                .map(|service| ReceiptService::Node { service: *service })
                .collect::<Vec<_>>(),
            self_.last_proven_phase as u8 >= OperationPhase::MigrationApplied as u8,
        ),
        BindingWorkload::ConnectorHost { connectors, .. } => (
            connectors
                .iter()
                .map(|connector| ReceiptService::Connector {
                    instance_id: connector.instance_id.clone(),
                    adapter_kind: connector.adapter_kind,
                })
                .collect(),
            false,
        ),
    };
    if self_.artifact != self_.binding.artifact {
        return Err(contract("receipt artifact does not match binding"));
    }
    match self_.outcome {
        ReceiptOutcome::Succeeded
            if self_.phase == OperationPhase::Completed
                && self_.last_proven_phase == OperationPhase::Completed => {}
        ReceiptOutcome::FailedRecoverable
            if self_.phase == OperationPhase::FailedRecoverable
                && is_forward_nonterminal(self_.last_proven_phase, &self_.binding.workload) => {}
        ReceiptOutcome::RollbackConverged
            if self_.phase == OperationPhase::RollbackConverged
                && self_.last_proven_phase == OperationPhase::Completed => {}
        ReceiptOutcome::RollbackBlocked
            if self_.phase == OperationPhase::RollbackBlocked
                && self_.last_proven_phase == OperationPhase::Completed => {}
        _ => return Err(contract("receipt outcome and phase mismatch")),
    }
    let complete = !matches!(self_.outcome, ReceiptOutcome::FailedRecoverable);
    if complete
        && self_
            .services
            .iter()
            .map(|e| e.service.clone())
            .collect::<Vec<_>>()
            != expected
    {
        return Err(contract("receipt service evidence is incomplete"));
    }
    if !complete && !canonical_service_subsequence(&expected, &self_.services) {
        return Err(contract("receipt service evidence is unknown"));
    }
    let migration_needed = matches!(self_.binding.workload, BindingWorkload::Node { .. })
        && (complete || required_migration);
    if migration_needed != self_.forward_migration.is_some() {
        return Err(contract("receipt migration evidence requirement mismatch"));
    }
    for evidence in &self_.services {
        for digest in [
            &evidence.service_revision_digest,
            &evidence.config_digest,
            &evidence.unit_digest,
            &evidence.readiness_digest,
            &evidence.entrypoint_digest,
        ] {
            sha256(digest, "service evidence")?;
        }
        if evidence.runtime_uid == 0 || evidence.runtime_gid == 0 {
            return Err(contract("receipt runtime identity must be non-root"));
        }
    }
    if let Some(migration) = &self_.forward_migration {
        if migration.to_version < migration.from_version {
            return Err(contract("migration must be forward"));
        }
        for digest in [
            &migration.before_digest,
            &migration.after_digest,
            &migration.migration_artifact_digest,
        ] {
            sha256(digest, "migration evidence")?;
        }
        if migration.migration_artifact_digest != self_.artifact.digest {
            return Err(contract("migration artifact must match node artifact"));
        }
    }
    Ok(())
}

fn canonical_service_subsequence(
    expected: &[ReceiptService],
    evidence: &[ServiceReceiptEvidence],
) -> bool {
    let mut remaining = expected.iter();
    evidence
        .iter()
        .all(|actual| remaining.by_ref().any(|planned| planned == &actual.service))
}

#[allow(clippy::too_many_lines)]
fn valid_record(r: &OperationRecord) -> Result<()> {
    if r.schema_version != 1 {
        return Err(contract("operation schema_version must be 1"));
    }
    uuid(&r.operation_id, "operation_id")?;
    sha256(&r.manifest_digest, "manifest_digest")?;
    r.artifact.validate("operation artifact")?;
    if r.artifact != r.binding.artifact {
        return Err(contract("operation artifact does not match binding"));
    }
    if let Some(predecessor) = &r.predecessor_operation_id {
        uuid(predecessor, "predecessor_operation_id")?;
        if predecessor == &r.operation_id {
            return Err(contract("operation cannot succeed itself"));
        }
    }
    token(&r.target, "target")?;
    if r.binding.target != r.target {
        return Err(contract("operation binding target mismatch"));
    }
    r.binding.host.validate()?;
    r.binding.artifact.validate("binding artifact")?;
    match &r.binding.workload {
        BindingWorkload::Node {
            origin,
            server_digest,
            services,
        } => {
            https_origin(origin)?;
            sha256(server_digest, "server digest")?;
            if *server_digest != r.binding.artifact.digest {
                return Err(contract("node workload artifact digest mismatch"));
            }
            if services.is_empty()
                || !services.contains(&NodeService::Node)
                || services.iter().collect::<HashSet<_>>().len() != services.len()
                || services
                    .windows(2)
                    .any(|pair| pair[0].rank() >= pair[1].rank())
            {
                return Err(contract("invalid node binding services"));
            }
        }
        BindingWorkload::ConnectorHost {
            connector_digest,
            connectors,
        } => {
            sha256(connector_digest, "connector digest")?;
            if *connector_digest != r.binding.artifact.digest {
                return Err(contract("connector workload artifact digest mismatch"));
            }
            if connectors.is_empty() {
                return Err(contract("connector binding is empty"));
            }
            let mut previous = "";
            for connector in connectors {
                uuid(&connector.instance_id, "connector instance")?;
                sha256(&connector.handoff_digest, "connector handoff")?;
                if connector.instance_id.as_str() <= previous {
                    return Err(contract("connectors must be canonical sorted"));
                }
                previous = &connector.instance_id;
            }
        }
    }
    match r.phase {
        OperationPhase::FailedRecoverable => {
            if !is_forward_nonterminal(r.last_proven_phase, &r.binding.workload)
                || r.last_failure.is_none()
            {
                return Err(contract(
                    "failed operation must retain a nonterminal proven phase and failure evidence",
                ));
            }
        }
        OperationPhase::RollbackFenced
        | OperationPhase::RollbackConverged
        | OperationPhase::RollbackBlocked => {
            if r.last_proven_phase != OperationPhase::Completed || r.last_failure.is_some() {
                return Err(contract("rollback operation state is invalid"));
            }
        }
        OperationPhase::ExpiredUnclaimed => {
            if !matches!(r.binding.workload, BindingWorkload::ConnectorHost { ref connectors, .. } if connectors.len() == 1)
                || r.last_proven_phase != OperationPhase::ExpiredUnclaimed
                || r.last_failure.is_some()
            {
                return Err(contract("expired-unclaimed operation state is invalid"));
            }
        }
        phase => {
            if phase != r.last_proven_phase || r.last_failure.is_some() {
                return Err(contract("forward operation state is invalid"));
            }
            if phase == OperationPhase::MigrationApplied
                && matches!(r.binding.workload, BindingWorkload::ConnectorHost { .. })
            {
                return Err(contract("connector operation cannot enter migration phase"));
            }
        }
    }
    valid_evidence(r.last_failure.as_ref())?;
    Ok(())
}
fn valid_binding(binding: &OperationBinding) -> Result<()> {
    let record = OperationRecord {
        schema_version: 1,
        operation_id: "018f856e-e0bd-71d2-9428-58d50cf77eaf".into(),
        manifest_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        artifact: binding.artifact.clone(),
        target: binding.target.clone(),
        binding: binding.clone(),
        predecessor_operation_id: None,
        phase: OperationPhase::Planned,
        last_proven_phase: OperationPhase::Planned,
        last_failure: None,
        integrity_digest: String::new(),
    };
    valid_record(&record)
}
fn is_forward_nonterminal(phase: OperationPhase, workload: &BindingWorkload) -> bool {
    matches!(
        phase,
        OperationPhase::Planned
            | OperationPhase::Claimed
            | OperationPhase::HostBound
            | OperationPhase::ArtifactsVerified
            | OperationPhase::MaterialPrepared
            | OperationPhase::ConfigsWritten
            | OperationPhase::ServicesConverged
            | OperationPhase::ReadinessVerified
    ) || (phase == OperationPhase::MigrationApplied
        && matches!(workload, BindingWorkload::Node { .. }))
}
fn valid_evidence(evidence: Option<&OperationFailureEvidence>) -> Result<()> {
    if let Some(e) = evidence {
        for digest in [
            &e.service_revision_digest,
            &e.config_digest,
            &e.unit_digest,
            &e.readiness_digest,
            &e.entrypoint_digest,
        ]
        .into_iter()
        .flatten()
        {
            sha256(digest, "evidence digest")?;
        }
    }
    Ok(())
}
fn valid_claim(c: &ConnectorClaim) -> Result<()> {
    if c.schema_version != 1 {
        return Err(contract("connector claim schema_version must be 1"));
    }
    uuid(&c.operation_id, "operation_id")?;
    uuid(&c.instance_id, "instance_id")?;
    sha256(&c.manifest_digest, "manifest_digest")?;
    c.artifact.validate("connector claim artifact")?;
    sha256(&c.handoff_digest, "handoff_digest")?;
    if let Some(predecessor) = &c.predecessor_operation_id {
        uuid(predecessor, "connector claim predecessor")?;
        if predecessor == &c.operation_id {
            return Err(contract("connector claim cannot succeed itself"));
        }
    }
    token(&c.target, "target")
}
#[cfg(unix)]
fn claim_matches_parent(
    claim: &ConnectorClaim,
    parent: &OperationRecord,
    proof: &VerifiedHostBinding,
) -> Result<()> {
    if proof.host() != &parent.binding.host
        || claim.manifest_digest != parent.manifest_digest
        || claim.target != parent.target
    {
        return Err(ReleaseError::OperationConflict);
    }
    let BindingWorkload::ConnectorHost {
        connector_digest,
        connectors,
    } = &parent.binding.workload
    else {
        return Err(ReleaseError::OperationConflict);
    };
    let Some(binding) = connectors
        .iter()
        .find(|binding| binding.instance_id == claim.instance_id)
    else {
        return Err(ReleaseError::OperationConflict);
    };
    if claim.artifact != parent.artifact
        || claim.artifact.digest != *connector_digest
        || claim.adapter_kind != binding.adapter_kind
        || claim.handoff_digest != binding.handoff_digest
    {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}
#[cfg(unix)]
fn record_matches_manifest(record: &OperationRecord, manifest: &DeploymentManifest) -> Result<()> {
    manifest.manifest.validate()?;
    let expected = OperationRecord::planned(
        manifest,
        &record.target,
        &record.operation_id,
        record.predecessor_operation_id.clone(),
    )?;
    if operation_identity_digest(record)? != operation_identity_digest(&expected)? {
        return Err(ReleaseError::OperationConflict);
    }
    Ok(())
}
#[cfg(unix)]
fn ownership_fence(target: &str, host: &HostTuple) -> Result<String> {
    token(target, "ownership target")?;
    host.validate()?;
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&(
        target, host,
    ))?)))
}
#[cfg(unix)]
fn is_target_owner_projection_filename(name: &str) -> bool {
    name.strip_prefix(TARGET_OWNER_PREFIX)
        .and_then(|value| value.strip_suffix(".json"))
        .is_some_and(|fence| {
            fence.len() == 64
                && fence
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
}
#[cfg(unix)]
fn serialize_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    if bytes.len() <= 1 || bytes.len() as u64 > MAX_BYTES {
        return Err(contract(
            "durable state serialization is empty or oversized",
        ));
    }
    Ok(bytes)
}
fn require_safe_file(path: &Path, max: u64) -> Result<()> {
    let m = fs::symlink_metadata(path).map_err(io_error(path))?;
    if m.file_type().is_symlink() || !m.is_file() || m.len() == 0 || m.len() > max {
        return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
    }
    Ok(())
}
#[cfg(all(unix, test))]
fn require_secure_state_file(path: &Path, max: u64) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
    let file: File = fd.into();
    let metadata = file.metadata().map_err(io_error(path))?;
    if !metadata.is_file() || metadata.len() > max {
        return Err(ReleaseError::StateUnsafe(path.to_path_buf()));
    }
    let parent = path
        .parent()
        .ok_or_else(|| ReleaseError::StateUnsafe(path.to_path_buf()))?;
    let expected_owner = fs::metadata(parent).map_err(io_error(parent))?.uid();
    validate_state_metadata(metadata.mode(), metadata.uid(), expected_owner)
}
#[cfg(all(unix, test))]
fn validate_state_metadata(mode: u32, owner: u32, expected_owner: u32) -> Result<()> {
    if mode & 0o777 != 0o600 || owner != expected_owner {
        return Err(ReleaseError::StateUnsafe(PathBuf::from("state metadata")));
    }
    Ok(())
}
#[cfg(not(unix))]
fn durable_state_unsupported() -> ReleaseError {
    contract("durable deployment state is unsupported off Unix")
}
fn contract(s: &str) -> ReleaseError {
    ReleaseError::Deployment(s.to_owned())
}
fn token(s: &str, name: &str) -> Result<()> {
    if s.is_empty()
        || s.len() > 128
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(contract(&format!("{name} is invalid")));
    }
    Ok(())
}
fn sha256(s: &str, name: &str) -> Result<()> {
    if s.len() != 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    {
        return Err(contract(&format!("{name} must be a SHA-256 hex digest")));
    }
    Ok(())
}
/// Validates lower-case canonical `UUIDv7` text with the RFC4122 variant.
///
/// # Errors
///
/// Returns an error when the UUID text is not canonical `UUIDv7` or uses a
/// non-RFC4122 variant.
pub fn require_canonical_uuid7(s: &str, name: &str) -> Result<()> {
    let b = s.as_bytes();
    if b.len() != 36
        || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-')
        || b[14] != b'7'
        || !matches!(b[19], b'8' | b'9' | b'a' | b'b')
        || b.iter().enumerate().any(|(i, b)| {
            !([8, 13, 18, 23].contains(&i) || b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        })
    {
        return Err(contract(&format!(
            "{name} must be a canonical RFC4122 UUIDv7"
        )));
    }
    Ok(())
}
fn uuid(s: &str, name: &str) -> Result<()> {
    require_canonical_uuid7(s, name)
}
fn identity_id(value: &str, name: &str) -> Result<()> {
    if value.len() != 57
        || !value.starts_with("dtxi1")
        || !value[5..]
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(contract(&format!("{name} must be a stable IdentityId")));
    }
    Ok(())
}
fn https_origin(s: &str) -> Result<()> {
    if !s.starts_with("https://") || s.len() > 256 {
        return Err(contract("target.origin must be canonical HTTPS DNS origin"));
    }
    let host = &s[8..];
    if host.is_empty()
        || host
            .bytes()
            .any(|b| !b.is_ascii() || b.is_ascii_whitespace())
        || host.contains(['/', '?', '#', '@', ':', '[', ']'])
        || host.starts_with('.')
        || host.ends_with('.')
        || host.ends_with(".localhost")
        || host == "localhost"
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return Err(contract("target.origin must be canonical HTTPS DNS origin"));
    }
    let labels = host.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(contract("target.origin must be canonical HTTPS DNS origin"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const ID: &str = "018f856e-e0bd-71d2-9428-58d50cf77eaf";
    const SECOND_ID: &str = "018f856e-e0bd-77d2-9428-58d50cf77eaf";
    const THIRD_ID: &str = "018f856e-e0bd-78d2-9428-58d50cf77eaf";
    const OWNER: &str = "dtxi1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn artifact() -> ImmutableArtifact {
        ImmutableArtifact {
            version: "1.0.0".into(),
            digest: DIGEST.into(),
        }
    }

    fn record() -> OperationRecord {
        let artifact = artifact();
        OperationRecord {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            artifact: artifact.clone(),
            binding: OperationBinding {
                target: "node-a".into(),
                host: HostTuple {
                    tenant_id: ID.into(),
                    host_id: ID.into(),
                    owner_id: OWNER.into(),
                    host_credential_id: ID.into(),
                },
                artifact,
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node],
                },
            },
            target: "node-a".into(),
            predecessor_operation_id: None,
            phase: OperationPhase::Planned,
            last_proven_phase: OperationPhase::Planned,
            last_failure: None,
            integrity_digest: String::new(),
        }
    }
    fn proof() -> VerifiedHostBinding {
        VerifiedHostBinding(record().binding.host)
    }

    fn connector_record() -> OperationRecord {
        let mut value = record();
        value.binding.workload = BindingWorkload::ConnectorHost {
            connector_digest: DIGEST.into(),
            connectors: vec![BoundConnector {
                instance_id: "018f856e-e0bd-72d2-9428-58d50cf77eaf".into(),
                adapter_kind: AdapterKind::Codex,
                handoff_digest: DIGEST.into(),
            }],
        };
        value
    }

    fn manifest_for_record(record: &OperationRecord) -> DeploymentManifest {
        let target = match &record.binding.workload {
            BindingWorkload::Node {
                origin, services, ..
            } => DeploymentTarget::Node {
                id: record.target.clone(),
                origin: origin.clone(),
                services: services.clone(),
                host: record.binding.host.clone(),
            },
            BindingWorkload::ConnectorHost { connectors, .. } => DeploymentTarget::ConnectorHost {
                id: record.target.clone(),
                host: record.binding.host.clone(),
                connectors: connectors
                    .iter()
                    .map(|binding| ConnectorBinding {
                        instance_id: binding.instance_id.clone(),
                        adapter_kind: binding.adapter_kind,
                        handoff_digest: binding.handoff_digest.clone(),
                    })
                    .collect(),
            },
        };
        DeploymentManifest {
            manifest: DeploymentContract {
                schema_version: 1,
                server: record.artifact.clone(),
                connector: record.artifact.clone(),
                targets: vec![target],
            },
            digest: record.manifest_digest.clone(),
        }
    }

    fn claim_operation(
        store: &DeploymentStateStore,
        record: &OperationRecord,
        proof: &VerifiedHostBinding,
    ) -> Result<OperationRecord> {
        store.claim(&manifest_for_record(record), record, proof)
    }

    fn connector_manifest_for(instance_ids: &[&str], digest: &str) -> DeploymentManifest {
        let host = record().binding.host;
        DeploymentManifest {
            manifest: DeploymentContract {
                schema_version: 1,
                server: artifact(),
                connector: artifact(),
                targets: vec![DeploymentTarget::ConnectorHost {
                    id: "node-a".into(),
                    host,
                    connectors: instance_ids
                        .iter()
                        .map(|instance_id| ConnectorBinding {
                            instance_id: (*instance_id).into(),
                            adapter_kind: if *instance_id == "018f856e-e0bd-72d2-9428-58d50cf77eaf"
                            {
                                AdapterKind::Codex
                            } else {
                                AdapterKind::Rig
                            },
                            handoff_digest: DIGEST.into(),
                        })
                        .collect(),
                }],
            },
            digest: digest.into(),
        }
    }

    #[test]
    fn connector_execution_lease_serializes_and_recovers_fsynced_progress() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let parent = connector_record();
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        store
            .claim(&manifest_for_record(&parent), &parent, &proof)
            .expect("parent claim");
        let instance = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        assert!(
            store
                .read_connector_claim(parent.operation_id(), instance)
                .expect("no claim read")
                .is_none()
        );
        let claim = ConnectorClaim::prepared(&parent, instance, None).expect("connector claim");
        store
            .claim_connector(&claim, &proof)
            .expect("claim connector");
        let first = store
            .lock_connector_execution(parent.operation_id(), instance)
            .expect("first lease");
        first
            .write(&serde_json::json!({"phase":"claimed"}))
            .expect("durable progress");
        assert!(matches!(
            store.lock_connector_execution(parent.operation_id(), instance),
            Err(ReleaseError::OperationLocked)
        ));
        drop(first);
        let recovered = store
            .lock_connector_execution(parent.operation_id(), instance)
            .expect("recovered lease");
        assert_eq!(
            recovered.read().expect("read").expect("record"),
            b"{\"phase\":\"claimed\"}\n"
        );
    }

    fn claim_connector_parent(
        store: &DeploymentStateStore,
        manifest: &DeploymentManifest,
        operation_id: &str,
        predecessor_operation_id: Option<String>,
    ) -> OperationRecord {
        let parent =
            OperationRecord::planned(manifest, "node-a", operation_id, predecessor_operation_id)
                .expect("connector parent plan");
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        store
            .claim(manifest, &parent, &proof)
            .expect("connector parent claim");
        parent
    }

    fn release_connectors_and_complete(
        store: &DeploymentStateStore,
        parent: &OperationRecord,
        predecessors: &[(&str, Option<&str>)],
    ) {
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        for (instance_id, predecessor) in predecessors {
            let claim =
                ConnectorClaim::prepared(parent, instance_id, predecessor.map(str::to_owned))
                    .expect("prepared connector");
            store
                .claim_connector(&claim, &proof)
                .expect("connector claim");
            store
                .observe_connector_handoff(instance_id)
                .expect("handoff evidence");
            store
                .release_connector_claim(instance_id)
                .expect("release evidence");
        }
        for phase in [
            OperationPhase::Claimed,
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
            OperationPhase::ServicesConverged,
            OperationPhase::ReadinessVerified,
            OperationPhase::Completed,
        ] {
            store
                .advance(&parent.operation_id, phase)
                .expect("connector parent completion");
        }
    }

    #[test]
    fn expired_unclaimed_bootstrap_is_replayable_and_allows_only_exact_successor() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let parent = connector_record();
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        store
            .claim(&manifest_for_record(&parent), &parent, &proof)
            .expect("parent claim");
        let instance = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        let claim = ConnectorClaim::prepared(&parent, instance, None).expect("connector claim");
        store
            .claim_connector(&claim, &proof)
            .expect("claim connector");
        for phase in [
            OperationPhase::Claimed,
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
        ] {
            store
                .advance(parent.operation_id(), phase)
                .expect("pre-effect phase");
        }
        let terminal_claim = store
            .expire_unclaimed_connector_claim(instance)
            .expect("terminal claim");
        assert_eq!(
            terminal_claim.phase(),
            ConnectorClaimPhase::ExpiredUnclaimed
        );
        assert_eq!(
            store
                .expire_unclaimed_connector_claim(instance)
                .expect("claim replay")
                .phase(),
            ConnectorClaimPhase::ExpiredUnclaimed
        );
        assert_eq!(
            store
                .expire_unclaimed_operation(parent.operation_id(), instance)
                .expect("terminal operation")
                .phase(),
            OperationPhase::ExpiredUnclaimed
        );
        assert_eq!(
            store
                .expire_unclaimed_operation(parent.operation_id(), instance)
                .expect("operation replay")
                .phase(),
            OperationPhase::ExpiredUnclaimed
        );

        let mut successor = connector_record();
        successor.operation_id = SECOND_ID.into();
        successor.predecessor_operation_id = Some(ID.into());
        let claimed = store
            .claim(&manifest_for_record(&successor), &successor, &proof)
            .expect("exact successor operation");
        let successor_claim = store
            .prepare_connector_claim(&claimed, instance)
            .expect("successor connector preparation");
        assert_eq!(successor_claim.predecessor_operation_id(), Some(ID));
        store
            .claim_connector(&successor_claim, &proof)
            .expect("exact successor connector claim");

        let mut wrong = connector_record();
        wrong.operation_id = THIRD_ID.into();
        wrong.predecessor_operation_id = Some(ID.into());
        assert!(matches!(
            store.claim(&manifest_for_record(&wrong), &wrong, &proof),
            Err(ReleaseError::OperationConflict)
        ));
    }

    fn manifest() -> DeploymentContract {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: "018f856e-e0bd-72d2-9428-58d50cf77eaf".into(),
            owner_id: OWNER.into(),
            host_credential_id: "018f856e-e0bd-74d2-9428-58d50cf77eaf".into(),
        };
        DeploymentContract {
            schema_version: 1,
            server: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            connector: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            },
            targets: vec![
                DeploymentTarget::Node {
                    id: "node-a".into(),
                    origin: "https://node.example.invalid".into(),
                    services: vec![NodeService::Node, NodeService::AgentControl],
                    host: host.clone(),
                },
                DeploymentTarget::ConnectorHost {
                    id: "connector-host-a".into(),
                    host,
                    connectors: vec![
                        ConnectorBinding {
                            instance_id: "018f856e-e0bd-75d2-9428-58d50cf77eaf".into(),
                            adapter_kind: AdapterKind::Codex,
                            handoff_digest:
                                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                                    .into(),
                        },
                        ConnectorBinding {
                            instance_id: "018f856e-e0bd-76d2-9428-58d50cf77eaf".into(),
                            adapter_kind: AdapterKind::Rig,
                            handoff_digest:
                                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                                    .into(),
                        },
                    ],
                },
            ],
        }
    }

    impl DeploymentTarget {
        fn id_mut(&mut self) -> &mut String {
            match self {
                Self::Node { id, .. } | Self::ConnectorHost { id, .. } => id,
            }
        }

        fn host_mut(&mut self) -> &mut HostTuple {
            match self {
                Self::Node { host, .. } | Self::ConnectorHost { host, .. } => host,
            }
        }

        fn node_services_mut(&mut self) -> &mut Vec<NodeService> {
            match self {
                Self::Node { services, .. } => services,
                Self::ConnectorHost { .. } => panic!("not a node target"),
            }
        }

        fn connector_bindings_mut(&mut self) -> &mut Vec<ConnectorBinding> {
            match self {
                Self::ConnectorHost { connectors, .. } => connectors,
                Self::Node { .. } => panic!("not a connector target"),
            }
        }
    }

    #[test]
    fn manifest_v1_accepts_repeated_host_tuple_and_two_connectors() {
        assert!(manifest().validate().is_ok());
    }

    #[test]
    fn host_owner_is_strict_stable_identity_not_uuid() {
        let mut host = record().binding.host;
        assert!(host.validate().is_ok());
        host.owner_id = ID.into();
        assert!(host.validate().is_err());
        host.owner_id = "dtxi1AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(host.validate().is_err());
    }

    #[test]
    fn canonical_uuid7_rejects_ncs_variant() {
        assert!(require_canonical_uuid7(ID, "id").is_ok());
        let mut ncs = ID.to_owned();
        ncs.replace_range(19..20, "0");
        assert!(require_canonical_uuid7(&ncs, "id").is_err());
    }

    #[test]
    #[cfg(unix)]
    fn protected_manifest_metadata_rejects_hardlinks() {
        assert!(protected_manifest_metadata_valid(true, 1, 0, 0o600, 1));
        assert!(!protected_manifest_metadata_valid(true, 2, 0, 0o600, 1));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn manifest_v1_validation_failure_matrix_is_fail_closed() {
        type ManifestCase = (&'static str, Box<dyn Fn(&mut DeploymentContract)>);
        let cases: [ManifestCase; 16] = [
            ("schema_version", Box::new(|m| m.schema_version = 2)),
            (
                "invalid semver",
                Box::new(|m| m.server.version = "not-semver".into()),
            ),
            (
                "invalid connector semver",
                Box::new(|m| m.connector.version = "not-semver".into()),
            ),
            (
                "uppercase sha256",
                Box::new(|m| m.server.digest = "A".repeat(64)),
            ),
            ("bad sha256", Box::new(|m| m.server.digest = "z".repeat(64))),
            (
                "uppercase connector handoff sha256",
                Box::new(|m| {
                    if let DeploymentTarget::ConnectorHost { connectors, .. } = &mut m.targets[1] {
                        connectors[0].handoff_digest = "A".repeat(64);
                    }
                }),
            ),
            (
                "bad connector handoff sha256",
                Box::new(|m| {
                    if let DeploymentTarget::ConnectorHost { connectors, .. } = &mut m.targets[1] {
                        connectors[0].handoff_digest = "z".repeat(64);
                    }
                }),
            ),
            (
                "noncanonical uuid",
                Box::new(|m| m.targets[0].host_mut().tenant_id = ID.to_uppercase()),
            ),
            (
                "non-v7 uuid",
                Box::new(|m| m.targets[0].host_mut().host_id.replace_range(14..15, "6")),
            ),
            (
                "wrong uuid variant",
                Box::new(|m| m.targets[0].host_mut().host_id.replace_range(19..20, "7")),
            ),
            (
                "empty target id",
                Box::new(|m| m.targets[0].id_mut().clear()),
            ),
            (
                "duplicate target id",
                Box::new(|m| {
                    let id = m.targets[0].id().to_owned();
                    m.targets[1].id_mut().clone_from(&id);
                }),
            ),
            (
                "duplicate node origin",
                Box::new(|m| {
                    let mut target = m.targets[0].clone();
                    target.id_mut().push_str("-copy");
                    m.targets.push(target);
                }),
            ),
            (
                "empty node services",
                Box::new(|m| m.targets[0].node_services_mut().clear()),
            ),
            (
                "duplicate node services",
                Box::new(|m| m.targets[0].node_services_mut().push(NodeService::Node)),
            ),
            (
                "missing node service",
                Box::new(|m| *m.targets[0].node_services_mut() = vec![NodeService::AgentControl]),
            ),
        ];
        for (name, mutate) in cases {
            let mut candidate = manifest();
            mutate(&mut candidate);
            assert!(candidate.validate().is_err(), "{name}");
        }

        let mut empty_bindings = manifest();
        empty_bindings.targets[1].connector_bindings_mut().clear();
        assert!(
            empty_bindings.validate().is_err(),
            "empty connector bindings"
        );

        let mut duplicate_connector = manifest();
        let mut second_host = duplicate_connector.targets[1].clone();
        second_host.id_mut().push_str("-copy");
        duplicate_connector.targets.push(second_host);
        assert!(
            duplicate_connector.validate().is_err(),
            "duplicate connector instance across targets"
        );

        for (name, divergent) in [
            ("tenant_id", "018f856e-e0bd-77d2-9428-58d50cf77eaf"),
            ("owner_id", "018f856e-e0bd-78d2-9428-58d50cf77eaf"),
            ("host_credential_id", "018f856e-e0bd-79d2-9428-58d50cf77eaf"),
        ] {
            let mut candidate = manifest();
            match name {
                "tenant_id" => candidate.targets[1].host_mut().tenant_id = divergent.into(),
                "owner_id" => candidate.targets[1].host_mut().owner_id = divergent.into(),
                "host_credential_id" => {
                    candidate.targets[1].host_mut().host_credential_id = divergent.into();
                }
                _ => unreachable!(),
            }
            assert!(candidate.validate().is_err(), "divergent {name}");
        }
    }

    #[test]
    fn manifest_v1_rejects_unknown_fields_at_every_contract_layer() {
        let mut root = serde_json::to_value(manifest()).expect("manifest json");
        let cases = [
            ("root", "extra_root", None),
            ("artifact", "extra_artifact", Some(("server", 0))),
            ("target", "extra_target", Some(("targets", 0))),
            ("host", "extra_host", Some(("targets", 0))),
            ("connector", "extra_connector", Some(("targets", 1))),
        ];
        for (name, field, location) in cases {
            let mut candidate = root.clone();
            match location {
                None => {
                    candidate[field] = true.into();
                }
                Some(("server", _)) => {
                    candidate["server"][field] = true.into();
                }
                Some(("targets", 0)) if name == "target" => {
                    candidate["targets"][0][field] = true.into();
                }
                Some(("targets", 0)) => {
                    candidate["targets"][0]["host"][field] = true.into();
                }
                Some(("targets", 1)) => {
                    candidate["targets"][1]["connectors"][0][field] = true.into();
                }
                _ => unreachable!(),
            }
            assert!(
                serde_json::from_value::<DeploymentContract>(candidate).is_err(),
                "unknown {name} field accepted"
            );
        }
        root["connector"]["extra_artifact"] = true.into();
        assert!(serde_json::from_value::<DeploymentContract>(root).is_err());
    }
    #[test]
    fn durable_claim_replay_conflict_and_transitions_are_strict() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        assert_eq!(
            claim_operation(&store, &record(), &proof())
                .expect("claim")
                .phase,
            OperationPhase::Planned
        );
        assert_eq!(
            claim_operation(&store, &record(), &proof())
                .expect("replay")
                .phase,
            OperationPhase::Planned
        );
        let mut conflicting = record();
        conflicting.target = "node-b".into();
        conflicting.binding.target = "node-b".into();
        assert!(matches!(
            claim_operation(&store, &conflicting, &proof()),
            Err(ReleaseError::OperationConflict)
        ));
        let mut service_conflict = record();
        if let BindingWorkload::Node { services, .. } = &mut service_conflict.binding.workload {
            services.push(NodeService::AgentControl);
        }
        assert!(matches!(
            claim_operation(&store, &service_conflict, &proof()),
            Err(ReleaseError::OperationConflict)
        ));
        assert!(store.advance(ID, OperationPhase::HostBound).is_err());
        assert_eq!(
            store
                .advance(ID, OperationPhase::Claimed)
                .expect("advance")
                .phase,
            OperationPhase::Claimed
        );
    }

    #[test]
    fn claim_rejects_same_uuid_on_another_target_without_publishing_owner() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first = record();
        let mut second = record();
        second.target = "node-b".into();
        second.binding.target = "node-b".into();
        let second_proof = VerifiedHostBinding(second.binding.host.clone());
        claim_operation(&store, &first, &proof()).expect("first claim");
        assert!(matches!(
            store.claim(&manifest_for_record(&second), &second, &second_proof),
            Err(ReleaseError::OperationConflict)
        ));
        let fence = ownership_fence(&second.target, &second.binding.host).expect("fence");
        assert!(
            !temp
                .path()
                .join("state")
                .join(format!("target-owner-{fence}.json"))
                .exists()
        );
    }

    #[test]
    fn claim_serializes_same_uuid_across_targets() {
        use std::sync::{Arc, Barrier};

        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("state");
        let first = record();
        let mut second = record();
        second.target = "node-b".into();
        second.binding.target = "node-b".into();
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let second_barrier = Arc::clone(&barrier);
        let first_root = root.clone();
        let second_root = root.clone();
        let first_thread = std::thread::spawn(move || {
            first_barrier.wait();
            let store = DeploymentStateStore::for_test(first_root);
            let proof = VerifiedHostBinding(first.binding.host.clone());
            store.claim(&manifest_for_record(&first), &first, &proof)
        });
        let second_thread = std::thread::spawn(move || {
            second_barrier.wait();
            let store = DeploymentStateStore::for_test(second_root);
            let proof = VerifiedHostBinding(second.binding.host.clone());
            store.claim(&manifest_for_record(&second), &second, &proof)
        });
        barrier.wait();
        let first = first_thread.join().expect("first thread");
        let second = second_thread.join().expect("second thread");
        assert_ne!(first.is_ok(), second.is_ok());
    }

    #[test]
    fn claim_repairs_operation_present_owner_absent_on_exact_replay() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let planned = record();
        let record = planned.clone().seal().expect("seal");
        let manifest = manifest_for_record(&planned);
        store.ensure_root().expect("state root");
        store
            .write_path(&store.record_path(ID).expect("record path"), &record)
            .expect("orphan operation");
        let recovered = store
            .claim(&manifest, &planned, &proof())
            .expect("replay repairs owner");
        assert_eq!(recovered, record);
        let fence = ownership_fence(&record.target, &record.binding.host).expect("fence");
        assert!(
            temp.path()
                .join("state")
                .join(format!("target-owner-{fence}.json"))
                .exists()
        );
    }

    #[test]
    fn claim_repairs_legacy_owner_present_operation_absent_on_exact_replay() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let planned = record();
        let record = planned.clone().seal().expect("seal");
        let ownership = TargetOwnership::from_record(&record).expect("ownership");
        let fence = ownership_fence(&record.target, &record.binding.host).expect("fence");
        let owner_path = temp
            .path()
            .join("state")
            .join(format!("target-owner-{fence}.json"));
        store.ensure_root().expect("state root");
        store
            .write_path(&owner_path, &ownership)
            .expect("legacy owner");
        assert_eq!(
            store
                .claim(&manifest_for_record(&planned), &planned, &proof())
                .expect("exact legacy repair"),
            record
        );
        assert_eq!(
            DeploymentStateStore::read_owner(&owner_path).expect("owner"),
            ownership
        );
    }

    #[test]
    fn legacy_owner_for_absent_uuid_blocks_cross_target_claim_until_exact_replay() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let planned = record();
        let sealed = planned.clone().seal().expect("seal");
        let ownership = TargetOwnership::from_record(&sealed).expect("ownership");
        let first_fence = ownership_fence(&planned.target, &planned.binding.host).expect("fence");
        let first_owner = temp
            .path()
            .join("state")
            .join(format!("target-owner-{first_fence}.json"));
        store.ensure_root().expect("state root");
        for index in 0..=MAX_STATE_ROOT_ENTRIES {
            drop(
                store
                    .lock(&format!("unrelated-{index:04x}"))
                    .expect("unrelated valid lock"),
            );
        }
        store
            .write_path(&first_owner, &ownership)
            .expect("legacy owner");

        let mut competing = record();
        competing.target = "node-b".into();
        competing.binding.target = "node-b".into();
        let competing_proof = VerifiedHostBinding(competing.binding.host.clone());
        assert!(matches!(
            store.claim(
                &manifest_for_record(&competing),
                &competing,
                &competing_proof
            ),
            Err(ReleaseError::OperationConflict)
        ));
        assert!(!store.record_path(ID).expect("record path").exists());
        assert_eq!(
            DeploymentStateStore::read_owner(&first_owner).expect("owner"),
            ownership
        );

        assert_eq!(
            store
                .claim(&manifest_for_record(&planned), &planned, &proof())
                .expect("exact recovery"),
            sealed
        );
    }

    #[test]
    fn multiple_legacy_owner_projections_for_absent_uuid_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let planned = record();
        let sealed = planned.clone().seal().expect("seal");
        let ownership = TargetOwnership::from_record(&sealed).expect("ownership");
        let fence = ownership_fence(&planned.target, &planned.binding.host).expect("fence");
        store.ensure_root().expect("state root");
        store
            .write_path(
                &temp
                    .path()
                    .join("state")
                    .join(format!("target-owner-{fence}.json")),
                &ownership,
            )
            .expect("first owner");
        store
            .write_path(
                &temp
                    .path()
                    .join("state")
                    .join(format!("target-owner-{}.json", "e".repeat(64))),
                &ownership,
            )
            .expect("duplicate owner");
        assert!(matches!(
            store.claim(&manifest_for_record(&planned), &planned, &proof()),
            Err(ReleaseError::OperationConflict)
        ));
        assert!(!store.record_path(ID).expect("record path").exists());
    }
    #[test]
    fn connector_binding_replay_and_canonical_facts_are_strict() {
        let mut value = record();
        value.binding.workload = BindingWorkload::ConnectorHost {
            connector_digest: DIGEST.into(),
            connectors: vec![
                BoundConnector {
                    instance_id: "018f856e-e0bd-72d2-9428-58d50cf77eaf".into(),
                    adapter_kind: AdapterKind::Codex,
                    handoff_digest: DIGEST.into(),
                },
                BoundConnector {
                    instance_id: "018f856e-e0bd-73d2-9428-58d50cf77eaf".into(),
                    adapter_kind: AdapterKind::Rig,
                    handoff_digest: DIGEST.into(),
                },
            ],
        };
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let proof = VerifiedHostBinding(value.binding.host.clone());
        assert!(claim_operation(&store, &value, &proof).is_ok());
        assert!(claim_operation(&store, &value, &proof).is_ok());
        let mut adapter = value.clone();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut adapter.binding.workload {
            connectors[0].adapter_kind = AdapterKind::Rig;
        }
        assert!(matches!(
            claim_operation(&store, &adapter, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        let mut handoff = value.clone();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut handoff.binding.workload {
            connectors[0].handoff_digest =
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        }
        assert!(matches!(
            claim_operation(&store, &handoff, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        let mut reverse = value.clone();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut reverse.binding.workload {
            connectors.reverse();
        }
        assert!(valid_record(&reverse).is_err());
        let mut duplicate = value.clone();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut duplicate.binding.workload {
            connectors[1].instance_id = connectors[0].instance_id.clone();
        }
        assert!(valid_record(&duplicate).is_err());
    }
    #[test]
    fn connector_claims_are_independent_and_exact() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let mut parent = connector_record();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut parent.binding.workload {
            connectors.push(BoundConnector {
                instance_id: "018f856e-e0bd-73d2-9428-58d50cf77eaf".into(),
                adapter_kind: AdapterKind::Rig,
                handoff_digest: DIGEST.into(),
            });
        }
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        claim_operation(&store, &parent, &proof).expect("parent claim");
        let claim = ConnectorClaim::prepared(&parent, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
            .expect("prepared");
        store.claim_connector(&claim, &proof).expect("claim");
        assert_eq!(
            store
                .observe_connector_handoff(&claim.instance_id)
                .expect("start")
                .phase,
            ConnectorClaimPhase::HandoffObserved
        );
        let other = ConnectorClaim::prepared(&parent, "018f856e-e0bd-73d2-9428-58d50cf77eaf", None)
            .expect("second prepared");
        assert!(store.claim_connector(&other, &proof).is_ok());
        let mut divergent = claim.clone();
        divergent.target = "node-b".into();
        assert!(matches!(
            store.claim_connector(&divergent, &proof),
            Err(ReleaseError::OperationConflict)
        ));
    }
    #[test]
    fn receipt_tampering_and_untrusted_host_evidence_fail_closed() {
        let temp = TempDir::new().expect("temp");
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let path = temp.path().join("host.json");
        fs::write(&path, b"{}").expect("write");
        assert!(validate_host_evidence_at(&path, &host).is_err());
        let base = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![ServiceReceiptEvidence {
                service: ReceiptService::Node {
                    service: NodeService::Node,
                },
                service_revision_digest: DIGEST.into(),
                config_digest: DIGEST.into(),
                unit_digest: DIGEST.into(),
                readiness_digest: DIGEST.into(),
                entrypoint_digest: DIGEST.into(),
                runtime_uid: 1,
                runtime_gid: 1,
            }],
            forward_migration: Some(ForwardMigrationEvidence {
                from_version: 0,
                to_version: 1,
                before_digest: DIGEST.into(),
                after_digest: DIGEST.into(),
                migration_artifact_digest: DIGEST.into(),
            }),
            integrity_digest: String::new(),
        };
        let receipt = base.clone().seal().expect("seal");
        assert!(receipt.verify().is_ok());
        let mut bad = receipt;
        bad.binding.target = "changed".into();
        assert!(bad.verify().is_err());
    }
    #[test]
    fn completed_multi_service_node_receipt_seals_and_verifies() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let evidence = |service| ServiceReceiptEvidence {
            service: ReceiptService::Node { service },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let receipt = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node, NodeService::AgentControl],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![
                evidence(NodeService::Node),
                evidence(NodeService::AgentControl),
            ],
            forward_migration: Some(ForwardMigrationEvidence {
                from_version: 0,
                to_version: 1,
                before_digest: DIGEST.into(),
                after_digest: DIGEST.into(),
                migration_artifact_digest: DIGEST.into(),
            }),
            integrity_digest: String::new(),
        }
        .seal()
        .expect("seal");
        assert!(receipt.verify().is_ok());
    }
    #[test]
    fn completed_two_connector_receipt_seals_and_verifies() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let first = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        let second = "018f856e-e0bd-73d2-9428-58d50cf77eaf";
        let evidence = |instance_id: &str, adapter_kind| ServiceReceiptEvidence {
            service: ReceiptService::Connector {
                instance_id: instance_id.into(),
                adapter_kind,
            },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let receipt = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "host-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::ConnectorHost {
                    connector_digest: DIGEST.into(),
                    connectors: vec![
                        BoundConnector {
                            instance_id: first.into(),
                            adapter_kind: AdapterKind::Codex,
                            handoff_digest: DIGEST.into(),
                        },
                        BoundConnector {
                            instance_id: second.into(),
                            adapter_kind: AdapterKind::Rig,
                            handoff_digest: DIGEST.into(),
                        },
                    ],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![
                evidence(first, AdapterKind::Codex),
                evidence(second, AdapterKind::Rig),
            ],
            forward_migration: None,
            integrity_digest: String::new(),
        }
        .seal()
        .expect("seal");
        assert!(receipt.verify().is_ok());

        let mut wrong_adapter = receipt.clone();
        if let ReceiptService::Connector { adapter_kind, .. } =
            &mut wrong_adapter.services[0].service
        {
            *adapter_kind = AdapterKind::Eino;
        }
        assert!(wrong_adapter.seal().is_err());

        let mut duplicate = receipt.clone();
        duplicate.services[1] = duplicate.services[0].clone();
        assert!(duplicate.seal().is_err());

        let mut reversed = receipt.clone();
        reversed.services.reverse();
        assert!(reversed.seal().is_err());

        let mut migration = receipt.clone();
        migration.forward_migration = Some(ForwardMigrationEvidence {
            from_version: 0,
            to_version: 1,
            before_digest: DIGEST.into(),
            after_digest: DIGEST.into(),
            migration_artifact_digest: DIGEST.into(),
        });
        assert!(migration.seal().is_err());

        let mut failed_migration_phase = receipt.clone();
        failed_migration_phase.phase = OperationPhase::FailedRecoverable;
        failed_migration_phase.last_proven_phase = OperationPhase::MigrationApplied;
        failed_migration_phase.outcome = ReceiptOutcome::FailedRecoverable;
        assert!(failed_migration_phase.seal().is_err());

        let mut unknown = receipt;
        if let ReceiptService::Connector { instance_id, .. } = &mut unknown.services[1].service {
            *instance_id = "018f856e-e0bd-74d2-9428-58d50cf77eaf".into();
        }
        assert!(unknown.seal().is_err());
    }
    #[test]
    fn receipt_rejects_missing_node_migration_and_artifact_mismatch() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let evidence = ServiceReceiptEvidence {
            service: ReceiptService::Node {
                service: NodeService::Node,
            },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let mut receipt = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![evidence],
            forward_migration: None,
            integrity_digest: String::new(),
        };
        assert!(receipt.clone().seal().is_err());
        receipt.forward_migration = Some(ForwardMigrationEvidence {
            from_version: 0,
            to_version: 1,
            before_digest: DIGEST.into(),
            after_digest: DIGEST.into(),
            migration_artifact_digest:
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        });
        assert!(receipt.clone().seal().is_err());
        receipt.forward_migration = Some(ForwardMigrationEvidence {
            from_version: 0,
            to_version: 1,
            before_digest: DIGEST.into(),
            after_digest: DIGEST.into(),
            migration_artifact_digest: DIGEST.into(),
        });
        receipt.artifact.version = "2.0.0".into();
        assert!(receipt.seal().is_err());
    }
    #[test]
    fn receipt_rejects_bad_completed_service_identity() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let e = |service| ServiceReceiptEvidence {
            service: ReceiptService::Node { service },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let base = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node, NodeService::AgentControl],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![e(NodeService::Node), e(NodeService::AgentControl)],
            forward_migration: Some(ForwardMigrationEvidence {
                from_version: 0,
                to_version: 1,
                before_digest: DIGEST.into(),
                after_digest: DIGEST.into(),
                migration_artifact_digest: DIGEST.into(),
            }),
            integrity_digest: String::new(),
        };
        let mut missing = base.clone();
        missing.services.pop();
        assert!(missing.seal().is_err());
        let mut reversed = base.clone();
        reversed.services.reverse();
        assert!(reversed.seal().is_err());
        let mut duplicate = base.clone();
        duplicate.services[1] = duplicate.services[0].clone();
        assert!(duplicate.seal().is_err());
        let mut unplanned = base.clone();
        unplanned.services[1].service = ReceiptService::Node {
            service: NodeService::RealtimeGateway,
        };
        assert!(unplanned.seal().is_err());
        let mut artifact = base;
        artifact.artifact.digest =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
        assert!(artifact.seal().is_err());
    }
    #[test]
    fn failed_node_receipt_subset_and_migration_timing() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let e = |service| ServiceReceiptEvidence {
            service: ReceiptService::Node { service },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let base = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node, NodeService::AgentControl],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::FailedRecoverable,
            last_proven_phase: OperationPhase::ConfigsWritten,
            outcome: ReceiptOutcome::FailedRecoverable,
            services: vec![e(NodeService::Node), e(NodeService::AgentControl)],
            forward_migration: None,
            integrity_digest: String::new(),
        };
        assert!(base.clone().seal().is_ok());
        let mut duplicate = base.clone();
        duplicate.services[1] = duplicate.services[0].clone();
        assert!(duplicate.seal().is_err());
        let mut reverse = base.clone();
        reverse.services.reverse();
        assert!(reverse.seal().is_err());
        let migration = ForwardMigrationEvidence {
            from_version: 0,
            to_version: 1,
            before_digest: DIGEST.into(),
            after_digest: DIGEST.into(),
            migration_artifact_digest: DIGEST.into(),
        };
        let mut early = base.clone();
        early.forward_migration = Some(migration.clone());
        assert!(early.seal().is_err());
        let mut applied = base.clone();
        applied.last_proven_phase = OperationPhase::MigrationApplied;
        assert!(applied.clone().seal().is_err());
        applied.forward_migration = Some(migration);
        assert!(applied.seal().is_ok());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn node_rollback_outcomes_require_retained_migration() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let service = ServiceReceiptEvidence {
            service: ReceiptService::Node {
                service: NodeService::Node,
            },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let migration = ForwardMigrationEvidence {
            from_version: 0,
            to_version: 1,
            before_digest: DIGEST.into(),
            after_digest: DIGEST.into(),
            migration_artifact_digest: DIGEST.into(),
        };
        let base = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![service],
            forward_migration: Some(migration),
            integrity_digest: String::new(),
        };
        assert!(base.clone().seal().is_ok());
        for (outcome, phase) in [
            (
                ReceiptOutcome::RollbackConverged,
                OperationPhase::RollbackConverged,
            ),
            (
                ReceiptOutcome::RollbackBlocked,
                OperationPhase::RollbackBlocked,
            ),
        ] {
            let mut receipt = base.clone();
            receipt.outcome = outcome;
            receipt.phase = phase;
            assert!(receipt.clone().seal().is_ok());
            receipt.forward_migration = None;
            assert!(receipt.seal().is_err());
        }
        let cases = [
            (
                ReceiptOutcome::Succeeded,
                OperationPhase::ReadinessVerified,
                OperationPhase::Completed,
            ),
            (
                ReceiptOutcome::Succeeded,
                OperationPhase::Completed,
                OperationPhase::ReadinessVerified,
            ),
            (
                ReceiptOutcome::FailedRecoverable,
                OperationPhase::Completed,
                OperationPhase::Completed,
            ),
            (
                ReceiptOutcome::FailedRecoverable,
                OperationPhase::FailedRecoverable,
                OperationPhase::Completed,
            ),
            (
                ReceiptOutcome::RollbackConverged,
                OperationPhase::RollbackBlocked,
                OperationPhase::Completed,
            ),
            (
                ReceiptOutcome::RollbackBlocked,
                OperationPhase::RollbackConverged,
                OperationPhase::Completed,
            ),
        ];
        for (outcome, phase, last) in cases {
            let mut receipt = base.clone();
            receipt.outcome = outcome;
            receipt.phase = phase;
            receipt.last_proven_phase = last;
            assert!(receipt.seal().is_err());
        }
    }
    #[test]
    fn receipt_structural_fields_fail_closed() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let service = ServiceReceiptEvidence {
            service: ReceiptService::Node {
                service: NodeService::Node,
            },
            service_revision_digest: DIGEST.into(),
            config_digest: DIGEST.into(),
            unit_digest: DIGEST.into(),
            readiness_digest: DIGEST.into(),
            entrypoint_digest: DIGEST.into(),
            runtime_uid: 1,
            runtime_gid: 1,
        };
        let base = DeploymentReceipt {
            schema_version: 1,
            operation_id: ID.into(),
            manifest_digest: DIGEST.into(),
            binding: OperationBinding {
                target: "node-a".into(),
                host,
                artifact: artifact(),
                workload: BindingWorkload::Node {
                    origin: "https://node.example.invalid".into(),
                    server_digest: DIGEST.into(),
                    services: vec![NodeService::Node],
                },
            },
            artifact: ImmutableArtifact {
                version: "1.0.0".into(),
                digest: DIGEST.into(),
            },
            phase: OperationPhase::Completed,
            last_proven_phase: OperationPhase::Completed,
            outcome: ReceiptOutcome::Succeeded,
            services: vec![service],
            forward_migration: Some(ForwardMigrationEvidence {
                from_version: 1,
                to_version: 2,
                before_digest: DIGEST.into(),
                after_digest: DIGEST.into(),
                migration_artifact_digest: DIGEST.into(),
            }),
            integrity_digest: String::new(),
        };
        let mut schema = base.clone();
        schema.schema_version = 2;
        assert!(schema.seal().is_err());
        let mut uuid = base.clone();
        uuid.operation_id = "018F856E-e0bd-71d2-9428-58d50cf77eaf".into();
        assert!(uuid.seal().is_err());
        let mut digest = base.clone();
        digest.manifest_digest =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(digest.seal().is_err());
        let mut zero_uid = base.clone();
        zero_uid.services[0].runtime_uid = 0;
        assert!(zero_uid.seal().is_err());
        let mut bad_version = base.clone();
        bad_version.artifact.version = "not-semver".into();
        assert!(bad_version.seal().is_err());
        let mut artifact_digest = base.clone();
        artifact_digest.artifact.digest =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(artifact_digest.seal().is_err());
        let mut service_digest = base.clone();
        service_digest.services[0].config_digest =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(service_digest.seal().is_err());
        let mut root_group = base.clone();
        root_group.services[0].runtime_gid = 0;
        assert!(root_group.seal().is_err());
        let mut bad_migration_digest = base.clone();
        bad_migration_digest
            .forward_migration
            .as_mut()
            .expect("migration")
            .before_digest =
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into();
        assert!(bad_migration_digest.seal().is_err());
        let mut migration = base;
        migration
            .forward_migration
            .as_mut()
            .expect("migration")
            .to_version = 0;
        assert!(migration.seal().is_err());
    }
    #[test]
    fn tagged_receipt_json_rejects_unknown_fields() {
        let workload = serde_json::json!({"kind":"node","origin":"https://node.example.invalid","server_digest":DIGEST,"services":["node"]});
        assert!(serde_json::from_value::<BindingWorkload>(workload.clone()).is_ok());
        let mut extra = workload;
        extra["extra"] = true.into();
        assert!(serde_json::from_value::<BindingWorkload>(extra).is_err());
        let service = serde_json::json!({"kind":"node","service":"node"});
        assert!(serde_json::from_value::<ReceiptService>(service.clone()).is_ok());
        let mut extra_service = service;
        extra_service["extra"] = true.into();
        assert!(serde_json::from_value::<ReceiptService>(extra_service).is_err());
        let root = serde_json::json!({"schema_version":1,"operation_id":ID,"manifest_digest":DIGEST,"binding":{"target":"node-a","host":{"tenant_id":ID,"host_id":ID,"owner_id":OWNER,"host_credential_id":ID},"workload":{"kind":"node","origin":"https://node.example.invalid","server_digest":DIGEST,"services":["node"]}},"artifact":{"version":"1.0.0","digest":DIGEST},"phase":"completed","last_proven_phase":"completed","outcome":"succeeded","services":[],"forward_migration":null,"integrity_digest":""});
        let mut extra_root = root;
        extra_root["extra"] = true.into();
        assert!(serde_json::from_value::<DeploymentReceipt>(extra_root).is_err());
    }
    #[test]
    fn https_origin_is_canonical_public_dns() {
        for value in ["https://x3.dirextalk.ai", "https://xn--demo-9ta.example"] {
            assert!(https_origin(value).is_ok());
        }
        for value in [
            "HTTPS://x3.dirextalk.ai",
            "http://x3.dirextalk.ai",
            "https://localhost",
            "https://a.localhost",
            "https://127.0.0.1",
            "https://[::1]",
            "https://x3.dirextalk.ai:443",
            "https://u@x3.dirextalk.ai",
            "https://x3.dirextalk.ai/a",
            "https://x3.dirextalk.ai?x",
            "https://x3.dirextalk.ai#x",
            "https://x3..dirextalk.ai",
            "https://x3.dirextalk.ai.",
            "https://x_3.dirextalk.ai",
            "https://-x.dirextalk.ai",
            "https://",
            "https://single",
            "https://X3.dirextalk.ai",
            "https://.leading.example",
            "https://x-.dirextalk.ai",
            "https://x3. dirextalk.ai",
            "https://éxample.ai",
        ] {
            assert!(https_origin(value).is_err(), "{value}");
        }
        let long_label = format!("https://{}.example", "a".repeat(64));
        assert!(https_origin(&long_label).is_err());
        let long_origin = format!("https://{}.example", "a".repeat(250));
        assert!(https_origin(&long_origin).is_err());
    }

    #[test]
    fn manifest_rejects_tagged_contract_failures() {
        let bad = serde_json::json!({"schema_version":1,"server":{"version":"bad","digest":DIGEST},"connector":{"version":"1.0.0","digest":DIGEST},"targets":[]});
        let contract: DeploymentContract = serde_json::from_value(bad).expect("shape");
        assert!(contract.validate().is_err());
        assert!(uuid("018F856E-e0bd-71d2-9428-58d50cf77eaf", "id").is_err());
        assert!(https_origin("https://localhost").is_err());
        assert!(https_origin("http://example.invalid").is_err());
    }

    #[test]
    fn failure_resume_and_rollback_edges_are_fenced() {
        let mut record = record();
        record.advance(OperationPhase::Claimed).expect("claimed");
        record
            .fail(OperationFailureEvidence {
                service_revision_digest: None,
                config_digest: None,
                unit_digest: None,
                readiness_digest: None,
                runtime_uid: None,
                runtime_gid: None,
                entrypoint_digest: None,
            })
            .expect("fail");
        assert!(record.advance(OperationPhase::ArtifactsVerified).is_err());
        record.phase = record.last_proven_phase;
        record.last_failure = None;
        record.advance(OperationPhase::HostBound).expect("resume");
        for phase in [
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
            OperationPhase::MigrationApplied,
            OperationPhase::ServicesConverged,
            OperationPhase::ReadinessVerified,
            OperationPhase::Completed,
        ] {
            record.advance(phase).expect("edge");
        }
        record
            .rollback_service_only(OperationPhase::RollbackFenced)
            .expect("fence");
        record
            .finish_rollback(OperationPhase::RollbackConverged)
            .expect("converge");
        assert!(
            record
                .finish_rollback(OperationPhase::RollbackBlocked)
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn secure_state_file_rejects_world_readable_and_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().expect("temp");
        let path = temp.path().join("state");
        fs::write(&path, b"x").expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(require_secure_state_file(&path, MAX_BYTES).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(require_secure_state_file(&path, MAX_BYTES).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn secure_state_root_symlink_fails_closed() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("root");
        symlink(temp.path(), &root).expect("link");
        assert!(matches!(
            claim_operation(&DeploymentStateStore::for_test(root), &record(), &proof()),
            Err(ReleaseError::StateUnsafe(_))
        ));
    }
    #[cfg(unix)]
    #[test]
    fn owner_metadata_seam_accepts_matching_and_rejects_mismatch() {
        assert!(validate_state_metadata(0o100_600, 42, 42).is_ok());
        assert!(validate_state_metadata(0o100_600, 42, 7).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn nofollow_host_reader_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().expect("temp");
        let target = temp.path().join("host.json");
        fs::write(&target, b"{}").expect("file");
        let link = temp.path().join("link.json");
        symlink(&target, &link).expect("link");
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        assert!(validate_host_evidence_at(&link, &host).is_err());
    }
    #[test]
    fn host_evidence_parser_accepts_exact_and_rejects_schema() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"tenant_id":ID,"host_id":ID,"owner_id":OWNER,"host_credential_id":ID})).expect("json");
        assert!(parse_host_evidence(&bytes, &host).is_ok());
        assert!(parse_host_evidence(br#"{"schema_version":2}"#, &host).is_err());
    }
    #[test]
    fn host_metadata_seam_is_strict() {
        assert!(validate_host_metadata(true, 0, 0o100_600, 1).is_ok());
        assert!(validate_host_metadata(false, 0, 0o100_600, 1).is_err());
        assert!(validate_host_metadata(true, 1, 0o100_600, 1).is_err());
        assert!(validate_host_metadata(true, 0, 0o100_644, 1).is_err());
        assert!(validate_host_metadata(true, 0, 0o100_600, 0).is_err());
        assert!(validate_host_metadata(true, 0, 0o100_600, MAX_BYTES + 1).is_err());
    }
    #[test]
    fn host_parser_mismatches_do_not_invoke_observer() {
        let host = HostTuple {
            tenant_id: ID.into(),
            host_id: ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: ID.into(),
        };
        for field in ["tenant_id", "host_id", "owner_id", "host_credential_id"] {
            let mut value = serde_json::json!({"schema_version":1,"tenant_id":ID,"host_id":ID,"owner_id":OWNER,"host_credential_id":ID});
            value[field] = "018f856e-e0bd-72d2-9428-58d50cf77eaf".into();
            let mut calls = 0;
            assert!(
                validate_then(
                    parse_host_evidence(&serde_json::to_vec(&value).expect("json"), &host),
                    |_| { calls += 1 }
                )
                .is_err()
            );
            assert_eq!(calls, 0);
        }
        let mut calls = 0;
        assert!(validate_then(parse_host_evidence(&serde_json::to_vec(&serde_json::json!({"schema_version":1,"tenant_id":ID,"host_id":ID,"owner_id":OWNER,"host_credential_id":ID})).expect("json"),&host), |_| { calls+=1 }).is_ok());
        assert_eq!(calls, 1);
    }
    #[test]
    fn invalid_proof_does_not_create_state_root() {
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("absent");
        let store = DeploymentStateStore::for_test(root.clone());
        let host = proof().0;
        let mut calls = 0;
        assert!(
            validate_then(parse_host_evidence(br"{}", &host), |_| {
                calls += 1;
                claim_operation(&store, &record(), &proof())
            })
            .is_err()
        );
        assert_eq!(calls, 0);
        assert!(!root.exists());
        let bytes=serde_json::to_vec(&serde_json::json!({"schema_version":1,"tenant_id":ID,"host_id":ID,"owner_id":OWNER,"host_credential_id":ID})).expect("json");
        let valid = parse_host_evidence(&bytes, &host).expect("proof");
        claim_operation(&store, &record(), &valid).expect("claim");
        assert!(root.exists());
    }
    #[cfg(unix)]
    #[test]
    fn secure_file_rejects_symlink_and_directory_substitutions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = TempDir::new().expect("temp");
        let target = temp.path().join("target");
        fs::write(&target, b"x").expect("write");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("mode");
        let link = temp.path().join("link");
        symlink(&target, &link).expect("link");
        assert!(require_secure_state_file(&link, MAX_BYTES).is_err());
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).expect("directory");
        assert!(require_secure_state_file(&directory, MAX_BYTES).is_err());
    }
    #[cfg(unix)]
    #[test]
    fn stale_secure_lock_file_is_recovered() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        store.ensure_root().expect("root");
        let lock = store.root.join(format!("operation-{ID}.lock"));
        fs::write(&lock, b"").expect("stale");
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).expect("mode");
        assert!(store.lock(ID).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn real_record_and_claim_mode_downgrade_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        claim_operation(&store, &record(), &proof()).expect("record");
        let path = store.record_path(ID).expect("path");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(store.read(ID).is_err());
        let parent = connector_record();
        let parent_proof = VerifiedHostBinding(parent.binding.host.clone());
        let claim = ConnectorClaim::prepared(&parent, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
            .expect("prepared");
        let second = DeploymentStateStore::for_test(temp.path().join("claim-state"));
        claim_operation(&second, &parent, &parent_proof).expect("parent");
        second
            .claim_connector(&claim, &parent_proof)
            .expect("claim");
        let claim_path = second
            .connector_claim_path(&claim.instance_id, &claim.operation_id)
            .expect("claim path");
        fs::set_permissions(&claim_path, fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(
            second
                .observe_connector_handoff(&claim.instance_id)
                .is_err()
        );
    }
    #[test]
    fn connector_claim_requires_exact_parent_and_verified_host_proof() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let parent = connector_record();
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        let claim = ConnectorClaim::prepared(&parent, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
            .expect("prepared");
        assert!(
            store.claim_connector(&claim, &proof).is_err(),
            "missing parent"
        );
        claim_operation(&store, &parent, &proof).expect("parent");
        let wrong_proof = VerifiedHostBinding(HostTuple {
            tenant_id: "018f856e-e0bd-73d2-9428-58d50cf77eaf".into(),
            ..parent.binding.host.clone()
        });
        assert!(matches!(
            store.claim_connector(&claim, &wrong_proof),
            Err(ReleaseError::OperationConflict)
        ));
        for mutate in [
            Box::new(|c: &mut ConnectorClaim| c.manifest_digest = "b".repeat(64))
                as Box<dyn Fn(&mut ConnectorClaim)>,
            Box::new(|c| c.target = "other".into()),
            Box::new(|c| c.artifact.digest = "b".repeat(64)),
            Box::new(|c| c.adapter_kind = AdapterKind::Rig),
            Box::new(|c| c.handoff_digest = "b".repeat(64)),
        ] {
            let mut divergent = claim.clone();
            mutate(&mut divergent);
            assert!(matches!(
                store.claim_connector(&divergent, &proof),
                Err(ReleaseError::OperationConflict)
            ));
        }
        assert!(store.claim_connector(&claim, &proof).is_ok());
    }
    #[test]
    fn held_lock_releases_and_secure_stale_temp_does_not_block_write() {
        use std::sync::atomic::Ordering;
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("state");
        let first = DeploymentStateStore::for_test(root.clone());
        claim_operation(&first, &record(), &proof()).expect("claim");
        let value = record();
        let fence = ownership_fence(&value.target, &value.binding.host).expect("fence");
        let held = first.lock(&format!("target-{fence}")).expect("held lock");
        let second = DeploymentStateStore::for_test(root.clone());
        assert!(matches!(
            second.advance(ID, OperationPhase::Claimed),
            Err(ReleaseError::OperationLocked)
        ));
        drop(held);
        assert_eq!(
            second
                .advance(ID, OperationPhase::Claimed)
                .expect("released")
                .phase,
            OperationPhase::Claimed
        );
        let path = second.record_path(ID).expect("record path");
        let next = TEMP_SEQUENCE.load(Ordering::Relaxed);
        let stale = path.with_extension(format!("tmp.{}.{}", std::process::id(), next));
        fs::write(&stale, b"stale").expect("stale temp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).expect("mode");
        }
        assert_eq!(
            second
                .advance(ID, OperationPhase::HostBound)
                .expect("retry temp")
                .phase,
            OperationPhase::HostBound
        );
        assert!(
            stale.exists(),
            "no durable artifact is deleted during recovery"
        );
    }
    #[test]
    fn simultaneous_exact_connector_claims_converge_without_cross_instance_state() {
        use std::sync::{Arc, Barrier};
        let temp = TempDir::new().expect("temp");
        let root = temp.path().join("state");
        let setup = DeploymentStateStore::for_test(root.clone());
        let parent = connector_record();
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        claim_operation(&setup, &parent, &proof).expect("parent");
        let claim = ConnectorClaim::prepared(&parent, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
            .expect("prepared");
        let barrier = Arc::new(Barrier::new(2));
        std::thread::scope(|scope| {
            let child_barrier = Arc::clone(&barrier);
            let child_root = root.clone();
            let child_claim = claim.clone();
            let child_proof = proof.clone();
            let child = scope.spawn(move || {
                child_barrier.wait();
                DeploymentStateStore::for_test(child_root)
                    .claim_connector(&child_claim, &child_proof)
            });
            barrier.wait();
            let local = DeploymentStateStore::for_test(root).claim_connector(&claim, &proof);
            let remote = child.join().expect("child claim");
            assert!(local.is_ok() || remote.is_ok());
            assert!(
                local.is_ok() || matches!(&local, Err(ReleaseError::OperationLocked)),
                "local claim outcome"
            );
            assert!(
                remote.is_ok() || matches!(&remote, Err(ReleaseError::OperationLocked)),
                "remote claim outcome"
            );
        });
        assert!(
            setup.claim_connector(&claim, &proof).is_ok(),
            "replay after lock"
        );
        assert_eq!(
            setup
                .observe_connector_handoff(&claim.instance_id)
                .expect("state")
                .phase,
            ConnectorClaimPhase::HandoffObserved
        );
    }
    #[test]
    fn durable_phase_failure_resume_and_rollback_transitions_are_persisted() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        claim_operation(&store, &record(), &proof()).expect("claim");
        assert!(store.advance(ID, OperationPhase::HostBound).is_err());
        store.advance(ID, OperationPhase::Claimed).expect("claimed");
        let failed = store
            .fail(
                ID,
                OperationFailureEvidence {
                    service_revision_digest: Some(DIGEST.into()),
                    config_digest: None,
                    unit_digest: None,
                    readiness_digest: None,
                    runtime_uid: None,
                    runtime_gid: None,
                    entrypoint_digest: None,
                },
            )
            .expect("fail");
        assert_eq!(failed.phase, OperationPhase::FailedRecoverable);
        assert!(
            store
                .read(ID)
                .expect("failure persisted")
                .last_failure
                .is_some()
        );
        assert!(
            store.advance(ID, OperationPhase::HostBound).is_err(),
            "failed state requires explicit resume"
        );
        assert_eq!(
            store.resume(ID).expect("resume").phase,
            OperationPhase::Claimed
        );
        for phase in [
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
            OperationPhase::MigrationApplied,
            OperationPhase::ServicesConverged,
            OperationPhase::ReadinessVerified,
            OperationPhase::Completed,
        ] {
            store.advance(ID, phase).expect("forward phase");
        }
        assert!(
            store
                .fail(
                    ID,
                    OperationFailureEvidence {
                        service_revision_digest: None,
                        config_digest: None,
                        unit_digest: None,
                        readiness_digest: None,
                        runtime_uid: None,
                        runtime_gid: None,
                        entrypoint_digest: None,
                    },
                )
                .is_err()
        );
        store.rollback_fence(ID).expect("fence");
        assert!(
            store
                .finish_rollback(ID, OperationPhase::Completed)
                .is_err()
        );
        assert_eq!(
            store
                .finish_rollback(ID, OperationPhase::RollbackConverged)
                .expect("rollback")
                .phase,
            OperationPhase::RollbackConverged
        );
        assert_eq!(
            store
                .read(ID)
                .expect("rollback persisted")
                .last_proven_phase,
            OperationPhase::Completed
        );
    }
    #[test]
    fn target_ownership_requires_terminal_predecessor_and_fences_superseded_mutation() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first = record();
        let manifest = manifest_for_record(&first);
        let proof = VerifiedHostBinding(first.binding.host.clone());
        store.claim(&manifest, &first, &proof).expect("first");

        let no_predecessor =
            OperationRecord::planned(&manifest, &first.target, SECOND_ID, None).expect("candidate");
        assert!(matches!(
            store.claim(&manifest, &no_predecessor, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        for phase in [
            OperationPhase::Claimed,
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
            OperationPhase::MigrationApplied,
            OperationPhase::ServicesConverged,
            OperationPhase::ReadinessVerified,
            OperationPhase::Completed,
        ] {
            store.advance(ID, phase).expect("first completion");
        }
        let successor =
            OperationRecord::planned(&manifest, &first.target, SECOND_ID, Some(ID.into()))
                .expect("successor");
        assert_eq!(
            store
                .claim(&manifest, &successor, &proof)
                .expect("successor claim")
                .phase,
            OperationPhase::Planned
        );
        assert_eq!(
            store
                .claim(&manifest, &successor, &proof)
                .expect("successor replay")
                .operation_id,
            SECOND_ID
        );
        assert!(matches!(
            store.rollback_fence(ID),
            Err(ReleaseError::OperationConflict)
        ));
        let sibling = OperationRecord::planned(&manifest, &first.target, THIRD_ID, Some(ID.into()))
            .expect("sibling");
        assert!(matches!(
            store.claim(&manifest, &sibling, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        store
            .advance(SECOND_ID, OperationPhase::Claimed)
            .expect("current owner mutation");
    }
    #[test]
    fn ownership_pointer_first_crash_replay_repairs_without_competing_owner() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let planned = record();
        let manifest = manifest_for_record(&planned);
        let proof = VerifiedHostBinding(planned.binding.host.clone());
        let sealed = planned.clone().seal().expect("sealed");
        let owner = TargetOwnership::from_record(&sealed).expect("owner");
        store.ensure_root().expect("root");
        let fence = ownership_fence(&planned.target, &planned.binding.host).expect("fence");
        store
            .write_path(
                &store.root.join(format!("target-owner-{fence}.json")),
                &owner,
            )
            .expect("crash-window owner");
        assert!(!store.record_path(ID).expect("path").exists());

        let competing = OperationRecord::planned(&manifest, &planned.target, SECOND_ID, None)
            .expect("competing");
        assert!(matches!(
            store.claim(&manifest, &competing, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        assert_eq!(
            store
                .claim(&manifest, &planned, &proof)
                .expect("repair")
                .operation_id,
            ID
        );
    }
    #[test]
    fn connector_successor_retains_history_and_rejects_sibling_promotion() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first = connector_record();
        let manifest = manifest_for_record(&first);
        let proof = VerifiedHostBinding(first.binding.host.clone());
        store
            .claim(&manifest, &first, &proof)
            .expect("first parent");
        let first_claim =
            ConnectorClaim::prepared(&first, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
                .expect("first claim");
        store
            .claim_connector(&first_claim, &proof)
            .expect("claim connector");
        store
            .observe_connector_handoff(&first_claim.instance_id)
            .expect("start evidence");
        store
            .release_connector_claim(&first_claim.instance_id)
            .expect("release evidence");
        for phase in [
            OperationPhase::Claimed,
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
            OperationPhase::ServicesConverged,
            OperationPhase::ReadinessVerified,
            OperationPhase::Completed,
        ] {
            store
                .advance(ID, phase)
                .expect("connector parent completion");
        }
        let successor =
            OperationRecord::planned(&manifest, &first.target, SECOND_ID, Some(ID.into()))
                .expect("successor parent");
        store
            .claim(&manifest, &successor, &proof)
            .expect("promote parent");
        let successor_claim =
            ConnectorClaim::prepared(&successor, &first_claim.instance_id, Some(ID.into()))
                .expect("successor claim");
        store
            .claim_connector(&successor_claim, &proof)
            .expect("promote connector");
        assert_eq!(
            DeploymentStateStore::read_claim(
                &store
                    .connector_claim_path(&first_claim.instance_id, ID)
                    .expect("historical path")
            )
            .expect("historical evidence")
            .phase,
            ConnectorClaimPhase::Released
        );
        let sibling = OperationRecord::planned(&manifest, &first.target, THIRD_ID, Some(ID.into()))
            .expect("sibling parent");
        assert!(matches!(
            store.claim(&manifest, &sibling, &proof),
            Err(ReleaseError::OperationConflict)
        ));
    }
    #[test]
    fn connector_added_by_successor_requires_no_connector_predecessor() {
        const CONNECTOR_A: &str = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        const CONNECTOR_B: &str = "018f856e-e0bd-73d2-9428-58d50cf77eaf";
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first_manifest = connector_manifest_for(&[CONNECTOR_B], DIGEST);
        let first = claim_connector_parent(&store, &first_manifest, ID, None);
        release_connectors_and_complete(&store, &first, &[(CONNECTOR_B, None)]);

        let second_manifest = connector_manifest_for(&[CONNECTOR_A, CONNECTOR_B], &"b".repeat(64));
        let second = claim_connector_parent(&store, &second_manifest, SECOND_ID, Some(ID.into()));
        let proof = VerifiedHostBinding(second.binding.host.clone());
        let wrong = ConnectorClaim::prepared(&second, CONNECTOR_A, Some(ID.into()))
            .expect("syntactically valid but wrong predecessor");
        assert!(matches!(
            store.claim_connector(&wrong, &proof),
            Err(ReleaseError::OperationConflict)
        ));
        let added = ConnectorClaim::prepared(&second, CONNECTOR_A, None).expect("new connector");
        assert_eq!(added.predecessor_operation_id(), None);
        store
            .claim_connector(&added, &proof)
            .expect("new connector claim");
        let upgraded =
            ConnectorClaim::prepared(&second, CONNECTOR_B, Some(ID.into())).expect("upgrade");
        assert_eq!(upgraded.predecessor_operation_id(), Some(ID));
        store
            .claim_connector(&upgraded, &proof)
            .expect("existing connector upgrade");
    }
    #[test]
    fn connector_removal_preserves_released_history_without_current_parent_binding() {
        const CONNECTOR_A: &str = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        const CONNECTOR_B: &str = "018f856e-e0bd-73d2-9428-58d50cf77eaf";
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first_manifest = connector_manifest_for(&[CONNECTOR_A, CONNECTOR_B], DIGEST);
        let first = claim_connector_parent(&store, &first_manifest, ID, None);
        release_connectors_and_complete(
            &store,
            &first,
            &[(CONNECTOR_A, None), (CONNECTOR_B, None)],
        );

        let second_manifest = connector_manifest_for(&[CONNECTOR_B], &"b".repeat(64));
        let second = claim_connector_parent(&store, &second_manifest, SECOND_ID, Some(ID.into()));
        release_connectors_and_complete(&store, &second, &[(CONNECTOR_B, Some(ID))]);
        let historical = DeploymentStateStore::read_claim(
            &store
                .connector_claim_path(CONNECTOR_A, ID)
                .expect("historical path"),
        )
        .expect("historical claim");
        assert_eq!(historical.phase, ConnectorClaimPhase::Released);
        assert_eq!(historical.predecessor_operation_id(), None);
        assert!(matches!(
            &second.binding.workload,
            BindingWorkload::ConnectorHost { connectors, .. }
                if connectors.iter().all(|binding| binding.instance_id != CONNECTOR_A)
        ));
    }
    #[test]
    fn connector_reintroduced_after_manifest_gap_starts_new_predecessor_chain() {
        const CONNECTOR_A: &str = "018f856e-e0bd-72d2-9428-58d50cf77eaf";
        const CONNECTOR_B: &str = "018f856e-e0bd-73d2-9428-58d50cf77eaf";
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let first_manifest = connector_manifest_for(&[CONNECTOR_A, CONNECTOR_B], DIGEST);
        let first = claim_connector_parent(&store, &first_manifest, ID, None);
        release_connectors_and_complete(
            &store,
            &first,
            &[(CONNECTOR_A, None), (CONNECTOR_B, None)],
        );
        let gap_manifest = connector_manifest_for(&[CONNECTOR_B], &"b".repeat(64));
        let gap = claim_connector_parent(&store, &gap_manifest, SECOND_ID, Some(ID.into()));
        release_connectors_and_complete(&store, &gap, &[(CONNECTOR_B, Some(ID))]);

        let reintroduced_manifest =
            connector_manifest_for(&[CONNECTOR_A, CONNECTOR_B], &"c".repeat(64));
        let reintroduced = claim_connector_parent(
            &store,
            &reintroduced_manifest,
            THIRD_ID,
            Some(SECOND_ID.into()),
        );
        let proof = VerifiedHostBinding(reintroduced.binding.host.clone());
        for wrong_predecessor in [ID, SECOND_ID] {
            let wrong = ConnectorClaim::prepared(
                &reintroduced,
                CONNECTOR_A,
                Some(wrong_predecessor.into()),
            )
            .expect("syntactically valid predecessor");
            assert!(matches!(
                store.claim_connector(&wrong, &proof),
                Err(ReleaseError::OperationConflict)
            ));
        }
        let fresh =
            ConnectorClaim::prepared(&reintroduced, CONNECTOR_A, None).expect("reintroduced");
        store
            .claim_connector(&fresh, &proof)
            .expect("fresh reintroduction");
        assert_eq!(fresh.predecessor_operation_id(), None);
        let owner = DeploymentStateStore::read_connector_owner(
            &store.connector_owner_path(CONNECTOR_A).expect("owner path"),
        )
        .expect("connector owner");
        assert_eq!(owner.current_operation_id, THIRD_ID);
        assert_eq!(owner.predecessor_operation_id, None);
        assert_eq!(
            DeploymentStateStore::read_claim(
                &store
                    .connector_claim_path(CONNECTOR_A, ID)
                    .expect("historical path")
            )
            .expect("historical claim")
            .phase,
            ConnectorClaimPhase::Released
        );
    }
    #[test]
    fn connector_owner_pointer_first_crash_is_exactly_repairable() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let parent = connector_record();
        let proof = VerifiedHostBinding(parent.binding.host.clone());
        claim_operation(&store, &parent, &proof).expect("parent");
        let claim = ConnectorClaim::prepared(&parent, "018f856e-e0bd-72d2-9428-58d50cf77eaf", None)
            .expect("claim");
        let owner = ConnectorOwnership::from_claim(&claim).expect("owner");
        store
            .write_path(
                &store
                    .connector_owner_path(&claim.instance_id)
                    .expect("owner path"),
                &owner,
            )
            .expect("crash-window owner");
        let claim_path = store
            .connector_claim_path(&claim.instance_id, &claim.operation_id)
            .expect("claim path");
        assert!(!claim_path.exists());
        assert_eq!(
            store
                .claim_connector(&claim, &proof)
                .expect("repair connector")
                .phase,
            ConnectorClaimPhase::Prepared
        );
        assert!(claim_path.exists());
    }
    #[test]
    fn planned_record_and_claim_reject_manifest_artifact_and_workload_divergence() {
        let manifest = DeploymentManifest::load(Path::new("deployment.example.json"))
            .expect("deployment manifest");
        let planned = OperationRecord::planned(&manifest, "control", ID, None).expect("planned");
        assert_eq!(planned.artifact, manifest.manifest.server);
        let proof = VerifiedHostBinding(planned.binding.host.clone());
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));

        let mut candidates = Vec::new();
        let mut version = planned.clone();
        version.artifact.version = "0.2.0".into();
        version.binding.artifact.version = "0.2.0".into();
        candidates.push(version);
        let mut digest = planned.clone();
        digest.artifact.digest = "c".repeat(64);
        digest.binding.artifact.digest = "c".repeat(64);
        if let BindingWorkload::Node { server_digest, .. } = &mut digest.binding.workload {
            *server_digest = "c".repeat(64);
        }
        candidates.push(digest);
        let mut origin = planned.clone();
        if let BindingWorkload::Node { origin, .. } = &mut origin.binding.workload {
            *origin = "https://other.example.invalid".into();
        }
        candidates.push(origin);
        let mut target = planned.clone();
        target.target = "other".into();
        target.binding.target = "other".into();
        candidates.push(target);
        let mut services = planned.clone();
        if let BindingWorkload::Node { services, .. } = &mut services.binding.workload {
            services[1] = NodeService::RealtimeGateway;
        }
        candidates.push(services);
        for candidate in candidates {
            assert!(store.claim(&manifest, &candidate, &proof).is_err());
        }

        let connector = OperationRecord::planned(&manifest, "connector-host-a", SECOND_ID, None)
            .expect("connector planned");
        let connector_proof = VerifiedHostBinding(connector.binding.host.clone());
        let mut divergent = connector.clone();
        if let BindingWorkload::ConnectorHost { connectors, .. } = &mut divergent.binding.workload {
            connectors[0].adapter_kind = AdapterKind::Rig;
        }
        assert!(
            store
                .claim(&manifest, &divergent, &connector_proof)
                .is_err()
        );
        assert!(!store.root.exists(), "rejected claims create no state");
    }
    #[test]
    fn connector_forward_phases_skip_migration_and_persist() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let record = connector_record();
        let proof = VerifiedHostBinding(record.binding.host.clone());
        claim_operation(&store, &record, &proof).expect("claim");
        for phase in [
            OperationPhase::Claimed,
            OperationPhase::HostBound,
            OperationPhase::ArtifactsVerified,
            OperationPhase::MaterialPrepared,
            OperationPhase::ConfigsWritten,
        ] {
            store.advance(ID, phase).expect("connector phase");
        }
        assert!(store.advance(ID, OperationPhase::MigrationApplied).is_err());
        assert_eq!(
            store
                .advance(ID, OperationPhase::ServicesConverged)
                .expect("skip migration")
                .phase,
            OperationPhase::ServicesConverged
        );
        assert_eq!(
            store.read(ID).expect("persisted").phase,
            OperationPhase::ServicesConverged
        );
    }
    #[cfg(unix)]
    #[test]
    fn serialization_and_oversize_fail_before_any_temporary_file_creation() {
        use serde::Serializer;

        struct Failing;
        impl Serialize for Failing {
            fn serialize<S>(&self, _serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                Err(serde::ser::Error::custom(
                    "intentional serialization failure",
                ))
            }
        }

        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        store.ensure_root().expect("root");
        assert!(
            store
                .write_path(&store.root.join("failed.json"), &Failing)
                .is_err()
        );
        assert!(
            store
                .write_path(
                    &store.root.join("oversized.json"),
                    &vec![0_u8; usize::try_from(MAX_BYTES).expect("test bound")],
                )
                .is_err()
        );
        assert!(
            fs::read_dir(&store.root)
                .expect("state entries")
                .next()
                .is_none(),
            "serialization failures leave no files or temporary artifacts"
        );
    }
    #[test]
    fn shuffled_node_services_have_identical_steps() {
        let first =
            DeploymentManifest::load(Path::new("deployment.example.json")).expect("example");
        let mut second = first.clone();
        for target in &mut second.manifest.targets {
            if let DeploymentTarget::Node { services, .. } = target {
                services.reverse();
            }
        }
        assert_eq!(
            DeploymentPlan::create(&first).actions,
            DeploymentPlan::create(&second).actions
        );
    }
    #[test]
    fn shuffled_connectors_have_canonical_enrollment_order() {
        let mut first =
            DeploymentManifest::load(Path::new("deployment.example.json")).expect("example");
        for target in &mut first.manifest.targets {
            if let DeploymentTarget::ConnectorHost { connectors, .. } = target {
                let mut other = connectors[0].clone();
                other.instance_id = "018f856e-e0bd-76d2-9428-58d50cf77eaf".into();
                connectors.push(other);
            }
        }
        let mut second = first.clone();
        for target in &mut second.manifest.targets {
            if let DeploymentTarget::ConnectorHost { connectors, .. } = target {
                connectors.reverse();
            }
        }
        let plan = DeploymentPlan::create(&first);
        assert_eq!(plan.actions, DeploymentPlan::create(&second).actions);
        let steps = plan.actions.get("connector-host-a").expect("steps");
        let claims: Vec<_> = steps
            .iter()
            .filter_map(|step| {
                if step.action == DeploymentAction::RecordConnectorClaim {
                    if let PlanSubject::Connector { instance_id, .. } = &step.subject {
                        Some(instance_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(
            claims,
            vec![
                "018f856e-e0bd-75d2-9428-58d50cf77eaf",
                "018f856e-e0bd-76d2-9428-58d50cf77eaf"
            ]
        );
        assert!(
            !steps
                .iter()
                .any(|step| step.action == DeploymentAction::ForwardMigration)
        );
    }
}
