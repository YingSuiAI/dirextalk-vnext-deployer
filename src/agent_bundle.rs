//! Strict, digest-bound Agent Bundle contract for production Connector targets.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{ReleaseError, Result, strict_json};

const MAX_COMPONENT_SIZE: u64 = 64 * 1024 * 1024;
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;
const REQUIRED_ROLES: [&str; 3] = ["connector", "agent_device", "runtime_launcher"];

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentBundle {
    pub schema: String,
    pub schema_version: u32,
    pub target: String,
    pub acceptance_profile: String,
    pub bundle_digest: String,
    pub protocol: AgentBundleProtocol,
    pub components: Vec<AgentBundleComponent>,
    pub runtime: RuntimeBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentBundleComponent {
    pub role: String,
    pub identity: String,
    pub version: String,
    pub source_commit: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentControlBounds {
    pub major: u32,
    pub minimum_minor: u32,
    pub maximum_minor: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AgentBundleProtocol {
    pub agent_control: AgentControlBounds,
    pub sidecar_route: RequiredCapability,
    pub sidecar_approval: RequiredCapability,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequiredCapability {
    pub required: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeBinding {
    pub kind: String,
    pub adapter: String,
    pub profile: String,
    pub launcher_component: String,
    pub required_options: BTreeMap<String, String>,
    pub required_capabilities: Vec<String>,
}

impl AgentBundle {
    /// Decode one canonical JSON bundle and verify its self-digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the JSON is non-canonical, violates the closed
    /// contract, or its digest does not match.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BUNDLE_BYTES {
            return Err(contract("agent bundle bytes are invalid"));
        }
        let bundle: Self = serde_json::from_value(strict_json::parse_value(bytes)?)?;
        bundle.validate()?;
        if bundle.canonical_bytes()? != bytes {
            return Err(contract("agent bundle JSON is not canonical"));
        }
        bundle.verify_digest()?;
        Ok(bundle)
    }

    /// Validate all fixed values and digest shape.
    ///
    /// # Errors
    ///
    /// Returns an error when any field falls outside the production profile.
    pub fn validate(&self) -> Result<()> {
        if self.schema != "dirextalk.agent-bundle" || self.schema_version != 1 {
            return Err(contract("agent bundle schema/version is unsupported"));
        }
        if self.target != "linux-amd64" {
            return Err(contract("agent bundle target must be linux-amd64"));
        }
        if self.acceptance_profile != "codex-app-server-safe-v1" {
            return Err(contract("agent bundle acceptance profile is unsupported"));
        }
        if self.components.len() != REQUIRED_ROLES.len() {
            return Err(contract("agent bundle requires exactly three components"));
        }
        let mut roles = BTreeSet::new();
        for (component, expected_role) in self.components.iter().zip(REQUIRED_ROLES) {
            if component.role != expected_role || !roles.insert(component.role.as_str()) {
                return Err(contract(
                    "agent bundle components must be sorted and unique",
                ));
            }
            validate_component(component)?;
        }
        if self.protocol.agent_control
            != (AgentControlBounds {
                major: 1,
                minimum_minor: 2,
                maximum_minor: 5,
            })
        {
            return Err(contract("Agent Control protocol bounds are unsupported"));
        }
        if self.protocol.sidecar_route.required != "agent-route-bootstrap-v1"
            || self.protocol.sidecar_approval.required != "runtime.approval.v1"
        {
            return Err(contract(
                "agent bundle required sidecar routes are unsupported",
            ));
        }
        self.runtime.validate()?;
        Ok(())
    }

    /// Verify the self-excluding canonical digest after structural validation.
    ///
    /// # Errors
    ///
    /// Returns an error when the digest is malformed or does not match the
    /// canonical bundle body.
    pub fn verify_digest(&self) -> Result<()> {
        if !is_digest(&self.bundle_digest) {
            return Err(contract("agent bundle digest is not lowercase SHA-256"));
        }
        if self.computed_digest()? != self.bundle_digest {
            return Err(contract("agent bundle digest mismatch"));
        }
        Ok(())
    }

    /// Canonical project JSON: sorted object keys and a single trailing LF.
    ///
    /// # Errors
    ///
    /// Returns an error when the bundle cannot be represented as JSON.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(self)?;
        canonical_value(&value)
    }

    /// Compute the digest over canonical JSON with `bundle_digest` omitted.
    ///
    /// # Errors
    ///
    /// Returns an error when canonical JSON serialization fails.
    pub fn computed_digest(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| contract("agent bundle is not a JSON object"))?;
        object.remove("bundle_digest");
        Ok(hex::encode(Sha256::digest(canonical_value(&value)?)))
    }

    #[must_use]
    pub fn component_metadata(&self) -> Vec<AgentBundleComponent> {
        self.components.clone()
    }
}

impl RuntimeBinding {
    fn validate(&self) -> Result<()> {
        if self.kind != "codex"
            || self.adapter != "codex-app-server"
            || self.profile != "safe"
            || self.launcher_component != "runtime_launcher"
            || self.required_options
                != BTreeMap::from([
                    ("app_server_url".into(), "stdio".into()),
                    ("backend".into(), "app_server".into()),
                    ("mode".into(), "suggest".into()),
                ])
            || self.required_capabilities != ["runtime.execute", "runtime.approval.v1"]
        {
            return Err(contract(
                "runtime binding is outside the closed production profile",
            ));
        }
        for capability in &self.required_capabilities {
            if capability.contains('/') || capability.contains('\\') || capability.contains(' ') {
                return Err(contract("runtime capability is invalid"));
            }
        }
        Ok(())
    }
}

fn validate_component(component: &AgentBundleComponent) -> Result<()> {
    token(&component.identity, "component.identity")?;
    if semver::Version::parse(&component.version).is_err() {
        return Err(contract("component.version must be SemVer"));
    }
    if !is_commit(&component.source_commit) {
        return Err(contract(
            "component.source_commit must be lowercase Git object id",
        ));
    }
    if !is_digest(&component.sha256) {
        return Err(contract("component.sha256 must be lowercase SHA-256"));
    }
    if component.size == 0 || component.size > MAX_COMPONENT_SIZE {
        return Err(contract(
            "component.size must be positive and safely bounded",
        ));
    }
    Ok(())
}

fn canonical_value(value: &Value) -> Result<Vec<u8>> {
    // serde_json's default Map is ordered by key. Rebuilding recursively also
    // makes this independent of the input object's insertion order.
    let normalized = normalize(value)?;
    let mut bytes = serde_json::to_vec(&normalized)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn normalize(value: &Value) -> Result<Value> {
    match value {
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort_unstable();
            for key in keys {
                sorted.insert(key.clone(), normalize(&map[key])?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Array(values) => Ok(Value::Array(
            values.iter().map(normalize).collect::<Result<Vec<_>>>()?,
        )),
        _ => Ok(value.clone()),
    }
}

fn token(value: &str, name: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
    {
        return Err(contract(&format!("{name} is invalid")));
    }
    Ok(())
}

fn is_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn positive() -> AgentBundle {
        let mut bundle = AgentBundle {
            schema: "dirextalk.agent-bundle".into(),
            schema_version: 1,
            target: "linux-amd64".into(),
            acceptance_profile: "codex-app-server-safe-v1".into(),
            bundle_digest: String::new(),
            protocol: AgentBundleProtocol {
                agent_control: AgentControlBounds {
                    major: 1,
                    minimum_minor: 2,
                    maximum_minor: 5,
                },
                sidecar_route: RequiredCapability {
                    required: "agent-route-bootstrap-v1".into(),
                },
                sidecar_approval: RequiredCapability {
                    required: "runtime.approval.v1".into(),
                },
            },
            components: REQUIRED_ROLES
                .iter()
                .map(|role| AgentBundleComponent {
                    role: (*role).into(),
                    identity: format!("dirextalk-{role}"),
                    version: "1.0.0".into(),
                    source_commit: "a".repeat(40),
                    sha256: "b".repeat(64),
                    size: 1,
                })
                .collect(),
            runtime: RuntimeBinding {
                kind: "codex".into(),
                adapter: "codex-app-server".into(),
                profile: "safe".into(),
                launcher_component: "runtime_launcher".into(),
                required_options: BTreeMap::from([
                    ("app_server_url".into(), "stdio".into()),
                    ("backend".into(), "app_server".into()),
                    ("mode".into(), "suggest".into()),
                ]),
                required_capabilities: vec!["runtime.execute".into(), "runtime.approval.v1".into()],
            },
        };
        bundle.bundle_digest = bundle.computed_digest().expect("digest");
        bundle
    }

    #[test]
    fn canonical_positive_vector_round_trips() {
        let bundle = positive();
        let bytes = bundle.canonical_bytes().expect("canonical");
        assert_eq!(AgentBundle::from_bytes(&bytes).expect("round trip"), bundle);
        let fixture = include_bytes!("../tests/fixtures/agent-bundle-v1-canonical.json");
        assert_eq!(AgentBundle::from_bytes(fixture).expect("fixture"), bundle);
    }

    #[test]
    fn every_public_coordinate_tamper_fails() {
        let bundle = positive();
        let bytes = bundle.canonical_bytes().expect("canonical");
        for needle in [
            "linux-amd64",
            "codex-app-server-safe-v1",
            "agent-route-bootstrap-v1",
            "runtime.approval.v1",
            "runtime_launcher",
            "runtime.execute",
        ] {
            let changed = String::from_utf8(bytes.clone())
                .expect("utf8")
                .replacen(needle, "tampered", 1);
            assert!(
                AgentBundle::from_bytes(changed.as_bytes()).is_err(),
                "{needle}"
            );
        }
    }

    #[test]
    fn stale_digest_rejects_well_shaped_component_tamper() {
        let mut bundle = positive();
        bundle.components[0].size = 2;
        assert!(bundle.validate().is_ok());
        assert!(bundle.verify_digest().is_err());
        let mut bytes = bundle.canonical_bytes().expect("canonical");
        assert!(AgentBundle::from_bytes(&bytes).is_err());
        bytes.extend_from_slice(b" ");
        assert!(AgentBundle::from_bytes(&bytes).is_err());
    }

    #[test]
    fn raw_duplicate_and_reordered_nested_bundle_json_fails_before_collapse() {
        let fixture = include_bytes!("../tests/fixtures/agent-bundle-v1-canonical.json");
        let fixture = String::from_utf8(fixture.to_vec()).expect("utf8");
        for changed in [
            fixture.replacen(
                "\"backend\":\"app_server\"",
                "\"backend\":\"app_server\",\"backend\":\"app_server\"",
                1,
            ),
            fixture.replacen(
                "\"role\":\"connector\"",
                "\"role\":\"connector\",\"role\":\"connector\"",
                1,
            ),
            fixture.replacen(
                "\"bundle_digest\":\"14daade12ac140eb29529dd60b5af73c3bd5f7364159c93a63b9bc7bae27fbc6\"",
                "\"bundle_digest\":\"14daade12ac140eb29529dd60b5af73c3bd5f7364159c93a63b9bc7bae27fbc6\",\"bundle_digest\":\"14daade12ac140eb29529dd60b5af73c3bd5f7364159c93a63b9bc7bae27fbc6\"",
                1,
            ),
            fixture.replacen(
                "\"runtime\":{\"adapter\":\"codex-app-server\",\"kind\":\"codex\"",
                "\"runtime\":{\"kind\":\"codex\",\"adapter\":\"codex-app-server\"",
                1,
            ),
        ] {
            assert!(AgentBundle::from_bytes(changed.as_bytes()).is_err());
        }
    }
}
