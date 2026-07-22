//! Root-only creation of the durable operation consumed by Connector apply.

use std::path::PathBuf;

use crate::{
    deployment::{
        DeploymentManifest, DeploymentStateStore, DeploymentTarget, HostTuple, OperationRecord,
        VerifiedHostBinding, require_canonical_uuid7, validate_host_evidence,
    },
    error::{ReleaseError, Result},
};
#[cfg(unix)]
use rustix::process::geteuid;

pub struct ConnectorClaimInputs {
    pub operation_id: String,
    pub manifest: PathBuf,
    pub target: String,
    pub predecessor_operation_id: Option<String>,
}

/// Creates or exactly replays the durable operation for one Connector host.
///
/// # Errors
///
/// Returns an error unless the caller is root, the manifest and fixed host
/// evidence are protected and exact, and the state-store ownership fence accepts
/// the canonical operation identity.
pub fn claim(inputs: &ConnectorClaimInputs) -> Result<OperationRecord> {
    require_root()?;
    let store = DeploymentStateStore::fixed()?;
    let manifest = DeploymentManifest::load_protected(&inputs.manifest)?;
    let expected_host = connector_host(&manifest, &inputs.target)?;
    let proof = validate_host_evidence(&expected_host)?;
    claim_with(inputs, &manifest, &store, &proof)
}

fn claim_with(
    inputs: &ConnectorClaimInputs,
    manifest: &DeploymentManifest,
    store: &DeploymentStateStore,
    proof: &VerifiedHostBinding,
) -> Result<OperationRecord> {
    require_canonical_uuid7(&inputs.operation_id, "operation_id")?;
    if let Some(predecessor) = &inputs.predecessor_operation_id {
        require_canonical_uuid7(predecessor, "predecessor_operation_id")?;
    }
    let _ = connector_host(manifest, &inputs.target)?;
    let record = OperationRecord::planned(
        manifest,
        &inputs.target,
        &inputs.operation_id,
        inputs.predecessor_operation_id.clone(),
    )?;
    store.claim(manifest, &record, proof)
}

fn connector_host(manifest: &DeploymentManifest, target: &str) -> Result<HostTuple> {
    match manifest
        .contract()
        .targets
        .iter()
        .find(|candidate| candidate.id() == target)
    {
        Some(DeploymentTarget::ConnectorHost { host, .. }) => Ok(host.clone()),
        Some(DeploymentTarget::Node { .. }) => Err(deployment(
            "connector claim target must be a connector host",
        )),
        None => Err(deployment(
            "connector claim target is absent from deployment manifest",
        )),
    }
}

fn require_root() -> Result<()> {
    #[cfg(unix)]
    if geteuid().as_raw() == 0 {
        return Ok(());
    }
    Err(deployment("deployment-connector-claim requires Unix root"))
}

fn deployment(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.to_owned())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::deployment::verified_host_binding_for_test;
    use tempfile::TempDir;

    const ID: &str = "018f856e-e0bd-71d2-9428-58d50cf77eaf";
    const NEXT_ID: &str = "018f856e-e0bd-77d2-9428-58d50cf77eaf";
    const THIRD_ID: &str = "018f856e-e0bd-78d2-9428-58d50cf77eaf";
    const OWNER: &str = "dtxi1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn manifest() -> DeploymentManifest {
        DeploymentManifest::from_bytes(
            format!(
                r#"{{"schema_version":1,"server":{{"version":"1.0.0","digest":"{DIGEST}"}},"connector":{{"version":"1.0.0","digest":"{DIGEST}"}},"targets":[{{"kind":"connector_host","id":"connector-a","host":{{"tenant_id":"{ID}","host_id":"{ID}","owner_id":"{OWNER}","host_credential_id":"{ID}"}},"connectors":[{{"instance_id":"{NEXT_ID}","adapter_kind":"codex","handoff_digest":"{DIGEST}"}}]}}]}}"#
            )
            .as_bytes(),
        )
        .expect("manifest")
    }

    fn inputs(id: &str, predecessor: Option<&str>) -> ConnectorClaimInputs {
        ConnectorClaimInputs {
            operation_id: id.into(),
            manifest: PathBuf::from("unused-injected-test-manifest"),
            target: "connector-a".into(),
            predecessor_operation_id: predecessor.map(str::to_owned),
        }
    }

    fn proof(manifest: &DeploymentManifest) -> VerifiedHostBinding {
        verified_host_binding_for_test(connector_host(manifest, "connector-a").expect("host"))
    }

    #[test]
    fn claim_exactly_replays_and_requires_terminal_predecessor() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let manifest = manifest();
        let proof = proof(&manifest);
        let first = claim_with(&inputs(ID, None), &manifest, &store, &proof).expect("claim");
        let replay = claim_with(&inputs(ID, None), &manifest, &store, &proof).expect("replay");
        assert_eq!(first, replay);
        assert!(claim_with(&inputs(NEXT_ID, Some(ID)), &manifest, &store, &proof).is_err());
    }

    #[test]
    fn claim_rejects_wrong_evidence_before_store_mutation_and_node_target() {
        let temp = TempDir::new().expect("temp");
        let store = DeploymentStateStore::for_test(temp.path().join("state"));
        let manifest = manifest();
        let wrong = verified_host_binding_for_test(HostTuple {
            tenant_id: THIRD_ID.into(),
            host_id: THIRD_ID.into(),
            owner_id: OWNER.into(),
            host_credential_id: THIRD_ID.into(),
        });
        assert!(claim_with(&inputs(ID, None), &manifest, &store, &wrong).is_err());
        assert!(!temp.path().join("state").exists());

        let node = DeploymentManifest::from_bytes(
            format!(
                r#"{{"schema_version":1,"server":{{"version":"1.0.0","digest":"{DIGEST}"}},"connector":{{"version":"1.0.0","digest":"{DIGEST}"}},"targets":[{{"kind":"node","id":"connector-a","origin":"https://node.example.invalid","services":["node"],"host":{{"tenant_id":"{ID}","host_id":"{ID}","owner_id":"{OWNER}","host_credential_id":"{ID}"}}}}]}}"#
            )
            .as_bytes(),
        )
        .expect("node manifest");
        assert!(connector_host(&node, "connector-a").is_err());
    }
}
