use std::net::Ipv4Addr;

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use super::{
    AwsEc2Manifest, Ec2State,
    bundle::{BundleFacts, canonical_json, digest, hash},
    contract, domain, exact_image,
};
use crate::Result;

const MAX_PROVISION: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisionRequest {
    pub schema: String,
    pub schema_version: u32,
    pub target: String,
    pub domain: String,
    pub tenant_id: String,
    pub indexer_id: String,
    pub private_ipv4: String,
    pub release_version: String,
    pub bundle_sha256: String,
    pub compose_sha256: String,
    pub server_image: String,
    pub migrator_image: String,
    pub postgres_image: String,
    pub caddy_image: String,
    pub probe_image: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostReadyReceipt {
    pub schema: String,
    pub schema_version: u32,
    pub state: String,
    pub request_sha256: String,
    pub target: String,
    pub domain: String,
    pub tenant_id: String,
    pub indexer_id: String,
    pub release_version: String,
    pub bundle_sha256: String,
    pub compose_sha256: String,
    pub receipt_sha256: String,
}

impl ProvisionRequest {
    pub fn new(manifest: &AwsEc2Manifest, state: &Ec2State, facts: &BundleFacts) -> Result<Self> {
        if manifest.target != state.target || manifest.domain != state.domain {
            return Err(contract(
                "host provision request manifest/state identity mismatch",
            ));
        }
        let request = Self {
            schema: "dirextalk.vnext-host-provision".into(),
            schema_version: 1,
            target: state.target.clone(),
            domain: state.domain.clone(),
            tenant_id: state.tenant_id.clone(),
            indexer_id: state.indexer_id.clone(),
            private_ipv4: state
                .private_ipv4
                .clone()
                .ok_or_else(|| contract("private IPv4 is absent from instance state"))?,
            release_version: facts.manifest.version.clone(),
            bundle_sha256: facts.bundle_sha256.clone(),
            compose_sha256: facts.compose_sha256.clone(),
            server_image: facts.manifest.server_image.clone(),
            migrator_image: facts.manifest.migrator_image.clone(),
            postgres_image: manifest.postgres_image.clone(),
            caddy_image: manifest.caddy_image.clone(),
            probe_image: manifest.probe_image.clone(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = canonical_json(self)?;
        if bytes.len() > MAX_PROVISION {
            return Err(contract("host provision request exceeds the fixed limit"));
        }
        Ok(bytes)
    }

    pub fn sha256(&self) -> Result<String> {
        Ok(hash(&self.canonical_bytes()?))
    }

    pub fn parse_and_verify(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PROVISION {
            return Err(contract("host provision request size is invalid"));
        }
        let request: Self = serde_json::from_slice(bytes)?;
        request.validate()?;
        if bytes != request.canonical_bytes()? {
            return Err(contract("host provision request is not canonical"));
        }
        Ok(request)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "dirextalk.vnext-host-provision"
            || self.schema_version != 1
            || !matches!(self.target.as_str(), "x6" | "x7" | "x8")
            || Version::parse(&self.release_version).is_err()
            || self.tenant_id == self.indexer_id
            || !self
                .private_ipv4
                .parse::<Ipv4Addr>()
                .is_ok_and(|address| address.is_private())
        {
            return Err(contract("host provision request facts are invalid"));
        }
        domain(&self.domain)?;
        for id in [&self.tenant_id, &self.indexer_id] {
            if Uuid::parse_str(id)
                .ok()
                .is_none_or(|uuid| uuid.get_version_num() != 7)
            {
                return Err(contract("host provision request UUID is invalid"));
            }
        }
        for value in [&self.bundle_sha256, &self.compose_sha256] {
            digest(value, "host provision request")?;
        }
        exact_image(
            &self.server_image,
            "dirextalk/vnet-server",
            "host provision server image",
        )?;
        exact_image(
            &self.migrator_image,
            "dirextalk/vnet-server",
            "host provision migrator image",
        )?;
        exact_image(
            &self.postgres_image,
            "postgres",
            "host provision postgres image",
        )?;
        exact_image(&self.caddy_image, "caddy", "host provision caddy image")?;
        exact_image(
            &self.probe_image,
            "curlimages/curl",
            "host provision probe image",
        )?;
        Ok(())
    }
}

impl HostReadyReceipt {
    pub fn parse_and_verify(bytes: &[u8], request: &ProvisionRequest) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_PROVISION {
            return Err(contract("host ready receipt size is invalid"));
        }
        let receipt: Self = serde_json::from_slice(bytes)?;
        if receipt.schema != "dirextalk.vnext-host-provision-ready"
            || receipt.schema_version != 1
            || receipt.state != "ready"
            || receipt.request_sha256 != request.sha256()?
            || receipt.target != request.target
            || receipt.domain != request.domain
            || receipt.tenant_id != request.tenant_id
            || receipt.indexer_id != request.indexer_id
            || receipt.release_version != request.release_version
            || receipt.bundle_sha256 != request.bundle_sha256
            || receipt.compose_sha256 != request.compose_sha256
        {
            return Err(contract("host ready receipt binding mismatch"));
        }
        digest(&receipt.receipt_sha256, "host ready receipt")?;
        let mut body: Value = serde_json::to_value(&receipt)?;
        body.as_object_mut()
            .ok_or_else(|| contract("host ready receipt is not an object"))?
            .remove("receipt_sha256");
        if hash(&canonical_json(&body)?) != receipt.receipt_sha256
            || bytes != canonical_json(&receipt)?
        {
            return Err(contract(
                "host ready receipt is not canonical or self-authenticating",
            ));
        }
        Ok(receipt)
    }
}
