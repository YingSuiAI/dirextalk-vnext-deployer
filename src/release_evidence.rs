//! Strict, local-only release evidence contract.
//!
//! Release evidence is a proof index, not a publisher or a signer.  Loading
//! it verifies the canonical JSON representation and the bytes named by the
//! evidence records.  Optional attestation records are digest-bound references
//! only; this module intentionally does not perform cryptographic verification
//! or network access.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::{
    digest::{FileIdentity, verify_regular_file_descriptor},
    error::{ReleaseError, Result, io_error},
    manifest::LoadedManifest,
    source::verify_source_root,
    strict_json,
};

const MAX_EVIDENCE_BYTES: u64 = 1024 * 1024;
const MAX_REFERENCED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 256;
const REQUIRED_COMPONENTS: [&str; 5] = [
    "server",
    "client-android",
    "connector",
    "agent-device-sidecar",
    "deployer",
];

/// The required components in the stable contract order.
pub const REQUIRED_RELEASE_COMPONENTS: &[&str] = &REQUIRED_COMPONENTS;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseEvidenceV1 {
    pub schema: String,
    pub schema_version: u32,
    pub release: EvidenceRelease,
    pub components: Vec<EvidenceComponent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AttestationReference>,
}

/// Alias kept short for callers that do not need to spell the version.
pub type ReleaseEvidence = ReleaseEvidenceV1;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRelease {
    pub version: String,
    pub source_date_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceComponent {
    #[serde(alias = "name")]
    pub component: String,
    pub source_commit: String,
    pub target: String,
    pub toolchain: String,
    #[serde(alias = "build-recipe")]
    pub build_recipe: String,
    pub artifact: ArtifactEvidence,
    pub sbom: FileEvidence,
    pub third_party_notice: FileEvidence,
    pub license: FileEvidence,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attestations: Vec<AttestationReference>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidence {
    #[serde(alias = "id", alias = "name")]
    pub identity: String,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEvidence {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AttestationReference {
    pub kind: AttestationKind,
    pub component: String,
    pub target: String,
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    #[serde(alias = "subject_sha256")]
    pub artifact_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AttestationKind {
    Dsse,
    #[serde(alias = "in_toto")]
    InToto,
    Slsa,
    #[serde(alias = "detached_signature")]
    DetachedSignature,
}

impl ReleaseEvidenceV1 {
    /// Load and verify one evidence file relative to its containing directory.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe evidence files, non-canonical JSON, invalid
    /// contract fields, missing references, or digest/size mismatches.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_EVIDENCE_BYTES
        {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        let bytes = fs::read(path).map_err(io_error(path))?;
        let evidence = Self::from_bytes(&bytes)?;
        let root = path
            .parent()
            .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?;
        evidence.validate_files(root)?;
        Ok(evidence)
    }

    /// Decode only; file records are checked by [`Self::validate_files`].
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, duplicate-key, non-canonical, or
    /// contract-invalid JSON.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() as u64 > MAX_EVIDENCE_BYTES {
            return Err(contract("release evidence bytes are invalid"));
        }
        let evidence: Self = serde_json::from_value(strict_json::parse_value(bytes)?)?;
        evidence.validate_contract()?;
        if evidence.canonical_bytes()? != bytes {
            return Err(contract("release evidence JSON is not canonical"));
        }
        Ok(evidence)
    }

    /// Validate schema, identities, source pin shape, and digest shape.
    ///
    /// # Errors
    ///
    /// Returns an error when any release evidence field violates the contract.
    pub fn validate(&self) -> Result<()> {
        self.validate_contract()
    }

    /// Validate all referenced regular files against their recorded size and
    /// SHA-256. `root` is the only path resolution base and is never accessed
    /// through a shell or a network.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe paths, non-regular files, oversize files, or
    /// digest/size mismatches.
    pub fn validate_files(&self, root: &Path) -> Result<()> {
        require_directory_root(root)?;
        let mut artifact_ids = BTreeSet::new();
        let mut evidence_paths = BTreeSet::new();
        let mut evidence_identities = BTreeSet::new();
        let mut attestation_paths = BTreeSet::new();
        for component in &self.components {
            verify_file(
                root,
                &component.artifact.path,
                component.artifact.size,
                &component.artifact.sha256,
                "artifact",
                &mut evidence_paths,
                &mut evidence_identities,
            )?;
            if !artifact_ids.insert(component.artifact.identity.clone()) {
                return Err(contract("duplicate artifact identity"));
            }
            for (label, file) in [
                ("sbom", &component.sbom),
                ("third_party_notice", &component.third_party_notice),
                ("license", &component.license),
            ] {
                verify_file(
                    root,
                    &file.path,
                    file.size,
                    &file.sha256,
                    label,
                    &mut evidence_paths,
                    &mut evidence_identities,
                )?;
            }
            for attestation in &component.attestations {
                verify_attestation(
                    root,
                    component,
                    attestation,
                    &mut attestation_paths,
                    &mut evidence_paths,
                    &mut evidence_identities,
                )?;
            }
        }
        for attestation in &self.attestations {
            let component = self
                .components
                .iter()
                .find(|component| {
                    component.component == attestation.component
                        && component.target == attestation.target
                })
                .ok_or_else(|| contract("attestation component/target is not present"))?;
            verify_attestation(
                root,
                component,
                attestation,
                &mut attestation_paths,
                &mut evidence_paths,
                &mut evidence_identities,
            )?;
        }
        Ok(())
    }

    /// Validate supplied source repositories. Only supplied roots are checked;
    /// omitted roots do not cause Git commands to run.
    ///
    /// # Errors
    ///
    /// Returns an error for unknown roots, source mismatches, dirty worktrees,
    /// or Git command failures.
    pub fn validate_source_roots(&self, roots: &BTreeMap<String, PathBuf>) -> Result<()> {
        let known: BTreeSet<_> = self
            .components
            .iter()
            .map(|component| component.component.as_str())
            .collect();
        for (component, root) in roots {
            if !known.contains(component.as_str()) {
                return Err(contract("source root names an unknown component"));
            }
            let Some(expected) = self
                .components
                .iter()
                .find(|entry| entry.component == *component)
                .map(|entry| entry.source_commit.as_str())
            else {
                return Err(contract("source root names an unknown component"));
            };
            verify_source_root(root, expected)?;
        }
        Ok(())
    }

    /// Cross-check the release version and the source pins already present in
    /// an existing strict release manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the release version or a configured source commit
    /// differs from this evidence.
    pub fn cross_check_manifest(&self, manifest: &LoadedManifest) -> Result<()> {
        if self.release.version != manifest.manifest.release.version {
            return Err(contract("release evidence version mismatches manifest"));
        }
        if self.release.source_date_epoch != manifest.manifest.release.source_date_epoch {
            return Err(contract(
                "release evidence source_date_epoch mismatches manifest",
            ));
        }
        for (component, configured) in [
            ("server", manifest.manifest.server.source_commit.as_deref()),
            (
                "connector",
                manifest.manifest.connector.source_commit.as_deref(),
            ),
            (
                "deployer",
                manifest.manifest.deployer.source_commit.as_deref(),
            ),
        ] {
            if let Some(configured) = configured {
                let Some(evidence) = self
                    .components
                    .iter()
                    .find(|entry| entry.component == component)
                    .map(|entry| entry.source_commit.as_str())
                else {
                    return Err(contract("release evidence component is missing"));
                };
                if !configured.eq_ignore_ascii_case(evidence) {
                    return Err(contract(
                        "release evidence source commit mismatches manifest",
                    ));
                }
            }
        }
        let mut covered_targets = BTreeSet::new();
        for component in &self.components {
            let target = manifest.manifest.targets.iter().find(|target| {
                target.id == component.target
                    || format!("{}-{}", target.goos, target.goarch) == component.target
                    || format!("{}-{}", target.node_platform, target.node_arch) == component.target
                    || target.rust_target == component.target
            });
            if let Some(target) = target {
                if let Some(toolchain) = &target.rust_toolchain
                    && component.toolchain != *toolchain
                {
                    return Err(contract(
                        "release evidence toolchain mismatches manifest target",
                    ));
                }
                covered_targets.insert(target.id.as_str());
                continue;
            }
            if component.component == "server"
                && manifest
                    .manifest
                    .server
                    .platforms
                    .iter()
                    .any(|platform| platform.replace('/', "-") == component.target)
            {
                continue;
            }
            return Err(contract(
                "release evidence target is not a manifest member or server platform",
            ));
        }
        if covered_targets.len() < manifest.manifest.targets.len() {
            return Err(contract(
                "release evidence does not cover every manifest target",
            ));
        }
        Ok(())
    }

    /// Canonical JSON uses sorted object keys and one trailing LF.
    ///
    /// # Errors
    ///
    /// Returns an error when the value cannot be serialized as JSON.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical_json(&serde_json::to_value(self)?)
    }

    fn validate_contract(&self) -> Result<()> {
        if self.schema != "dirextalk.release-evidence" || self.schema_version != 1 {
            return Err(contract("release evidence schema/version is unsupported"));
        }
        if Version::parse(&self.release.version).is_err() {
            return Err(contract("release evidence version must be SemVer"));
        }
        if self.release.source_date_epoch == 0 {
            return Err(contract(
                "release evidence source_date_epoch must be non-zero",
            ));
        }
        if self.components.len() != REQUIRED_COMPONENTS.len() {
            return Err(contract(
                "release evidence requires exactly five components",
            ));
        }
        let mut components = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut artifacts = BTreeSet::new();
        let mut evidence_paths = BTreeSet::new();
        let mut attestation_paths = BTreeSet::new();
        for component in &self.components {
            if !REQUIRED_COMPONENTS.contains(&component.component.as_str())
                || !components.insert(component.component.clone())
            {
                return Err(contract(
                    "release evidence components are incomplete or duplicated",
                ));
            }
            validate_lower_token(&component.component, "component")?;
            validate_lower_token(&component.target, "target")?;
            validate_identity(&component.toolchain, "toolchain")?;
            validate_identity(&component.build_recipe, "build_recipe")?;
            if !targets.insert((component.component.clone(), component.target.clone())) {
                return Err(contract("duplicate component/target identity"));
            }
            if !artifacts.insert(component.artifact.identity.clone()) {
                return Err(contract("duplicate artifact identity"));
            }
            insert_contract_path(&mut evidence_paths, &component.artifact.path, "artifact")?;
            if !is_commit(&component.source_commit) {
                return Err(contract("source_commit must be lowercase 40-hex"));
            }
            validate_artifact_identity(&component.artifact.identity)?;
            validate_artifact_shape(&component.artifact)?;
            validate_file_shape(&component.sbom, "sbom")?;
            validate_file_shape(&component.third_party_notice, "third_party_notice")?;
            validate_file_shape(&component.license, "license")?;
            insert_contract_path(&mut evidence_paths, &component.sbom.path, "sbom")?;
            insert_contract_path(
                &mut evidence_paths,
                &component.third_party_notice.path,
                "third_party_notice",
            )?;
            insert_contract_path(&mut evidence_paths, &component.license.path, "license")?;
            validate_attestations(&component.attestations, component)?;
            for attestation in &component.attestations {
                insert_contract_path(&mut evidence_paths, &attestation.path, "attestation")?;
                if !attestation_paths.insert(attestation.path.clone()) {
                    return Err(contract("duplicate attestation path"));
                }
            }
        }
        if components
            != REQUIRED_COMPONENTS
                .iter()
                .copied()
                .map(str::to_owned)
                .collect()
        {
            return Err(contract(
                "release evidence required components are incomplete",
            ));
        }
        validate_attestation_list(&self.attestations, self)?;
        for attestation in &self.attestations {
            insert_contract_path(&mut evidence_paths, &attestation.path, "attestation")?;
            if !attestation_paths.insert(attestation.path.clone()) {
                return Err(contract("duplicate attestation path"));
            }
        }
        Ok(())
    }
}

impl ArtifactEvidence {
    fn as_file(&self) -> FileEvidence {
        FileEvidence {
            path: self.path.clone(),
            size: self.size,
            sha256: self.sha256.clone(),
        }
    }
}

fn validate_attestation_list(
    attestations: &[AttestationReference],
    evidence: &ReleaseEvidenceV1,
) -> Result<()> {
    let mut paths = BTreeSet::new();
    for attestation in attestations {
        let component = evidence
            .components
            .iter()
            .find(|component| {
                component.component == attestation.component
                    && component.target == attestation.target
            })
            .ok_or_else(|| contract("attestation component/target is not present"))?;
        validate_attestation(attestation, component)?;
        if !paths.insert(attestation.path.clone()) {
            return Err(contract("duplicate attestation path"));
        }
    }
    Ok(())
}

fn validate_attestations(
    attestations: &[AttestationReference],
    component: &EvidenceComponent,
) -> Result<()> {
    let mut paths = BTreeSet::new();
    for attestation in attestations {
        validate_attestation(attestation, component)?;
        if !paths.insert(attestation.path.clone()) {
            return Err(contract("duplicate attestation path"));
        }
    }
    Ok(())
}

fn validate_attestation(
    attestation: &AttestationReference,
    component: &EvidenceComponent,
) -> Result<()> {
    if attestation.component != component.component || attestation.target != component.target {
        return Err(contract("attestation component/target binding mismatch"));
    }
    if attestation.artifact_sha256 != component.artifact.sha256 {
        return Err(contract("attestation artifact digest binding mismatch"));
    }
    if !is_digest(&attestation.sha256) || !is_digest(&attestation.artifact_sha256) {
        return Err(contract("attestation digest is not lowercase SHA-256"));
    }
    validate_path(&attestation.path, "attestation.path")?;
    if attestation.size == 0 || attestation.size > MAX_REFERENCED_FILE_BYTES {
        return Err(contract("attestation size is out of bounds"));
    }
    Ok(())
}

fn verify_attestation(
    root: &Path,
    component: &EvidenceComponent,
    attestation: &AttestationReference,
    paths: &mut BTreeSet<PathBuf>,
    evidence_paths: &mut BTreeSet<PathBuf>,
    evidence_identities: &mut BTreeSet<FileIdentity>,
) -> Result<()> {
    validate_attestation(attestation, component)?;
    if !paths.insert(attestation.path.clone()) {
        return Err(contract("duplicate attestation path"));
    }
    verify_file(
        root,
        &attestation.path,
        attestation.size,
        &attestation.sha256,
        "attestation",
        evidence_paths,
        evidence_identities,
    )
}

fn validate_file_shape(file: &FileEvidence, label: &str) -> Result<()> {
    validate_path(&file.path, &format!("{label}.path"))?;
    if file.size == 0 || file.size > MAX_REFERENCED_FILE_BYTES {
        return Err(contract(&format!("{label}.size is out of bounds")));
    }
    if !is_digest(&file.sha256) {
        return Err(contract(&format!(
            "{label}.sha256 is not lowercase SHA-256"
        )));
    }
    Ok(())
}

fn validate_artifact_shape(file: &ArtifactEvidence) -> Result<()> {
    validate_file_shape(&file.as_file(), "artifact")
}

fn verify_file(
    root: &Path,
    relative: &Path,
    size: u64,
    digest: &str,
    label: &str,
    evidence_paths: &mut BTreeSet<PathBuf>,
    evidence_identities: &mut BTreeSet<FileIdentity>,
) -> Result<()> {
    validate_path(relative, "file.path")?;
    if !evidence_paths.insert(relative.to_path_buf()) {
        return Err(contract(&format!("duplicate evidence path for {label}")));
    }
    let identity =
        verify_regular_file_descriptor(root, relative, size, digest, MAX_REFERENCED_FILE_BYTES)
            .map_err(|_| contract(&format!("{label} is missing, unsafe, or changed")))?;
    if !evidence_identities.insert(identity) {
        return Err(contract(&format!(
            "duplicate opened evidence file for {label}"
        )));
    }
    Ok(())
}

fn validate_path(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.as_os_str().to_string_lossy().len() > MAX_PATH_BYTES
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir))
    {
        return Err(contract(&format!("{field} must be a safe relative path")));
    }
    Ok(())
}

fn require_directory_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root).map_err(io_error(root))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseError::InvalidPath(root.to_path_buf()));
    }
    Ok(())
}

fn validate_artifact_identity(value: &str) -> Result<()> {
    validate_identity(value, "artifact.identity")
}

fn insert_contract_path(paths: &mut BTreeSet<PathBuf>, path: &Path, label: &str) -> Result<()> {
    if !paths.insert(path.to_path_buf()) {
        return Err(contract(&format!("duplicate evidence path for {label}")));
    }
    Ok(())
}

fn validate_lower_token(value: &str, label: &str) -> Result<()> {
    validate_identity(value, label)?;
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(contract(&format!("{label} must be lowercase")));
    }
    Ok(())
}

fn validate_identity(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
    {
        return Err(contract(&format!("{label} identity is invalid")));
    }
    Ok(())
}

fn is_commit(value: &str) -> bool {
    value.len() == 40
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

fn canonical_json(value: &Value) -> Result<Vec<u8>> {
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

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Manifest(format!("release evidence: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;
    use tempfile::TempDir;

    fn fixture() -> (TempDir, ReleaseEvidenceV1) {
        let root = TempDir::new().expect("temp root");
        let mut components = Vec::new();
        for component in REQUIRED_COMPONENTS {
            let dir = root.path().join(component);
            fs::create_dir_all(&dir).expect("component dir");
            let artifact = dir.join("artifact.bin");
            let sbom = dir.join("sbom.json");
            let notice = dir.join("NOTICE");
            let license = dir.join("LICENSE");
            for (path, bytes) in [
                (&artifact, b"artifact".as_slice()),
                (&sbom, b"{}\n".as_slice()),
                (&notice, b"notice\n".as_slice()),
                (&license, b"MIT\n".as_slice()),
            ] {
                fs::write(path, bytes).expect("file");
            }
            let file = |path: &Path| {
                let bytes = fs::read(path).expect("read");
                FileEvidence {
                    path: path
                        .strip_prefix(root.path())
                        .expect("relative")
                        .to_path_buf(),
                    size: bytes.len() as u64,
                    sha256: hex::encode(Sha256::digest(bytes)),
                }
            };
            let artifact_file = file(&artifact);
            components.push(EvidenceComponent {
                component: component.to_owned(),
                source_commit: "a".repeat(40),
                target: "linux-amd64".into(),
                toolchain: "stable-1.97.0".into(),
                build_recipe: "recipe-v1".into(),
                artifact: ArtifactEvidence {
                    identity: format!("{component}-linux-amd64"),
                    path: artifact_file.path,
                    size: artifact_file.size,
                    sha256: artifact_file.sha256,
                },
                sbom: file(&sbom),
                third_party_notice: file(&notice),
                license: file(&license),
                attestations: Vec::new(),
            });
        }
        (
            root,
            ReleaseEvidenceV1 {
                schema: "dirextalk.release-evidence".into(),
                schema_version: 1,
                release: EvidenceRelease {
                    version: "1.2.3".into(),
                    source_date_epoch: 1,
                },
                components,
                attestations: Vec::new(),
            },
        )
    }

    #[test]
    fn canonical_round_trip_and_file_digests() {
        let (root, evidence) = fixture();
        let bytes = evidence.canonical_bytes().expect("canonical");
        let decoded = ReleaseEvidenceV1::from_bytes(&bytes).expect("decode");
        decoded.validate_files(root.path()).expect("files");
    }

    #[test]
    fn duplicate_keys_and_unknown_fields_are_rejected() {
        let (root, evidence) = fixture();
        let bytes = evidence.canonical_bytes().expect("canonical");
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(ReleaseEvidenceV1::from_bytes(
            text.replacen("\"schema\":\"dirextalk.release-evidence\"", "\"schema\":\"dirextalk.release-evidence\",\"schema\":\"dirextalk.release-evidence\"", 1).as_bytes()
        )
        .is_err());
        let mut value: Value = serde_json::from_str(&text).expect("json");
        value["extra"] = Value::Bool(true);
        assert!(ReleaseEvidenceV1::from_bytes(&canonical_json(&value).expect("json")).is_err());
        evidence
            .validate_files(root.path())
            .expect("fixture remains valid");
    }

    #[cfg(unix)]
    #[test]
    fn hardlink_aliases_are_rejected_across_evidence_roles() {
        let (root, mut evidence) = fixture();
        let component = evidence
            .components
            .iter_mut()
            .find(|component| component.component == "server")
            .expect("server");
        let artifact = root.path().join(&component.artifact.path);
        let license = root.path().join(&component.license.path);
        fs::remove_file(&license).expect("remove license");
        fs::hard_link(&artifact, &license).expect("hardlink");
        component.license.size = component.artifact.size;
        component.license.sha256 = component.artifact.sha256.clone();
        assert!(evidence.validate_files(root.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_replacement_is_rejected_without_following() {
        let (root, evidence) = fixture();
        let component = evidence
            .components
            .iter()
            .find(|component| component.component == "server")
            .expect("server");
        let artifact = root.path().join(&component.artifact.path);
        let replacement = root.path().join("replacement");
        fs::write(&replacement, b"artifact").expect("replacement");
        fs::remove_file(&artifact).expect("remove artifact");
        std::os::unix::fs::symlink(&replacement, &artifact).expect("symlink");
        assert!(evidence.validate_files(root.path()).is_err());
    }

    #[test]
    fn manifest_cross_check_covers_epoch_target_and_toolchain() {
        let (evidence_root, mut evidence) = fixture();
        let manifest_root = TempDir::new().expect("manifest root");
        for directory in ["server/docker/release", "deployer", "connector"] {
            fs::create_dir_all(manifest_root.path().join(directory)).expect("manifest directory");
        }
        fs::write(
            manifest_root.path().join("server/Cargo.toml"),
            b"[workspace]\n",
        )
        .expect("server cargo");
        fs::write(
            manifest_root
                .path()
                .join("server/docker/release/Dockerfile"),
            b"FROM scratch\n",
        )
        .expect("dockerfile");
        fs::write(
            manifest_root.path().join("deployer/Cargo.toml"),
            b"[package]\n",
        )
        .expect("deployer cargo");
        fs::write(manifest_root.path().join("deployer/LICENSE"), b"MIT\n")
            .expect("deployer license");
        fs::write(
            manifest_root.path().join("connector/go.mod"),
            b"module example.invalid/connector\n",
        )
        .expect("go mod");
        fs::write(manifest_root.path().join("connector/LICENSE"), b"MIT\n")
            .expect("connector license");
        fs::write(manifest_root.path().join("connector/NOTICE"), b"NOTICE\n")
            .expect("connector notice");
        let manifest_path = manifest_root.path().join("release.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": 1,
                "release": {"version": "1.2.3", "source_date_epoch": 1},
                "server": {"repository": "server", "dockerfile": "docker/release/Dockerfile", "image": "dirextalk/vent", "platforms": ["linux/amd64"]},
                "deployer": {"repository": "deployer", "package": "dirextalk-vnext-deployer", "binary": "dirextalk-vnext-deployer"},
                "connector": {"repository": "connector", "module": "./cmd/dirextalk-agent-connector", "binary": "dirextalk-agent-connector"},
                "targets": [{"id": "linux-x64", "rust_target": "x86_64-unknown-linux-gnu", "goos": "linux", "goarch": "amd64", "node_platform": "linux", "node_arch": "x64", "archive": "tar_gz"}],
                "npm": {"package": "@dirextalk/vnext-deployer", "access": "public"},
                "github": {"repository": "YingSuiAI/dirextalk-vnext-deployer", "tag_prefix": "v"}
            }))
            .expect("manifest json"),
        )
        .expect("manifest");
        let manifest = LoadedManifest::load(&manifest_path).expect("manifest load");
        evidence
            .cross_check_manifest(&manifest)
            .expect("overlapping facts match");
        evidence.release.source_date_epoch = 2;
        assert!(evidence.cross_check_manifest(&manifest).is_err());
        evidence.release.source_date_epoch = 1;
        evidence.components[0].target = "windows-x64".into();
        assert!(evidence.cross_check_manifest(&manifest).is_err());
        drop(evidence_root);
    }
}
