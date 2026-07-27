//! Fresh-only Internal Test Alpha deployment contract.
//!
//! This module deliberately has no reader for an earlier schema. It validates
//! one canonical schema-3 package, binds every local artifact by digest, and
//! owns the exact durable Alpha lifecycle.

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    error::{ReleaseError, Result, io_error},
    strict_json,
};

const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const ALPHA_SCHEMA: &str = "dirextalk.internal-test-alpha-deployment";
const ALPHA_SCENARIO: &str = "dirextalk.internal-test-alpha.v1";
#[cfg(unix)]
const ALPHA_STATE_DIR: &str = "/var/lib/dirextalk-vnext-deployer/alpha";

#[derive(Clone, Debug)]
pub struct AlphaManifest {
    contract: AlphaContract,
    digest: String,
}

#[allow(clippy::missing_errors_doc)]
impl AlphaManifest {
    /// Loads and validates one canonical, duplicate-key-free schema-3 manifest.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES as u64
        {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        Self::from_bytes(&fs::read(path).map_err(io_error(path))?)
    }

    /// Parses only the active schema-3 contract.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
            return Err(alpha_error("manifest bytes are invalid"));
        }
        let value = strict_json::parse_value(bytes)?;
        if strict_json::canonical_bytes(&value, false)? != bytes {
            return Err(alpha_error("manifest must be canonical JSON"));
        }
        let contract: AlphaContract = serde_json::from_value(value)?;
        contract.validate()?;
        Ok(Self {
            contract,
            digest: prefixed_digest(bytes),
        })
    }

    #[must_use]
    pub const fn contract(&self) -> &AlphaContract {
        &self.contract
    }

    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Verifies every package-local artifact and returns one exact package digest.
    pub fn verify_package(&self, package_root: &Path) -> Result<VerifiedAlphaPackage> {
        let root = package_root
            .canonicalize()
            .map_err(io_error(package_root))?;
        if !root.is_dir() {
            return Err(ReleaseError::InvalidPath(package_root.to_path_buf()));
        }
        let artifacts = [
            ("client.apk", &self.contract.client.apk),
            ("client.test_apk", &self.contract.client.test_apk),
            ("connector.binary", &self.contract.connector.binary),
            ("config", &self.contract.config),
        ];
        let mut material = Vec::new();
        append_part(&mut material, self.digest.as_bytes());
        for (name, artifact) in artifacts {
            let path = root.join(&artifact.path);
            let canonical = path.canonicalize().map_err(io_error(&path))?;
            if !canonical.starts_with(&root) {
                return Err(ReleaseError::InvalidPath(path));
            }
            let metadata = fs::symlink_metadata(&canonical).map_err(io_error(&canonical))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() == 0
                || metadata.len() > MAX_ARTIFACT_BYTES
            {
                return Err(ReleaseError::MissingArtifact(canonical));
            }
            let actual = prefixed_digest(&fs::read(&canonical).map_err(io_error(&canonical))?);
            if actual != artifact.sha256 {
                return Err(ReleaseError::SourceMismatch(canonical));
            }
            append_part(&mut material, name.as_bytes());
            append_part(&mut material, actual.as_bytes());
        }
        Ok(VerifiedAlphaPackage {
            manifest_digest: self.digest.clone(),
            package_digest: prefixed_digest(&material),
            component_digests: ComponentDigests::from_contract(&self.contract),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaContract {
    pub schema: String,
    pub schema_version: u32,
    pub fresh_only: bool,
    pub target: AlphaTarget,
    pub server: ImageComponent,
    pub client: ClientComponent,
    pub connector: ConnectorComponent,
    pub sidecar: ImageComponent,
    pub deployer: SourceComponent,
    pub config: PackageArtifact,
}

impl AlphaContract {
    fn validate(&self) -> Result<()> {
        if self.schema != ALPHA_SCHEMA || self.schema_version != 3 || !self.fresh_only {
            return Err(alpha_error(
                "only fresh-only dirextalk Internal Test Alpha schema 3 is accepted",
            ));
        }
        self.target.validate()?;
        self.server.validate("server")?;
        self.client.validate()?;
        self.connector.validate()?;
        self.sidecar.validate("sidecar")?;
        self.deployer.validate("deployer")?;
        self.config.validate("config")?;
        if self.client.apk.path == self.client.test_apk.path {
            return Err(alpha_error("client APK and test APK must be distinct"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AlphaTarget {
    pub id: String,
}

impl AlphaTarget {
    fn validate(&self) -> Result<()> {
        if !matches!(
            self.id.as_str(),
            "x3.dirextalk.ai" | "x4.dirextalk.ai" | "x5.dirextalk.ai"
        ) {
            return Err(alpha_error("target.id must be x3, x4, or x5"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceComponent {
    pub source_commit: String,
}

impl SourceComponent {
    fn validate(&self, name: &str) -> Result<()> {
        commit(&self.source_commit, &format!("{name}.source_commit"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageComponent {
    pub source_commit: String,
    pub image: String,
}

impl ImageComponent {
    fn validate(&self, name: &str) -> Result<()> {
        commit(&self.source_commit, &format!("{name}.source_commit"))?;
        image(&self.image, &format!("{name}.image"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientComponent {
    pub source_commit: String,
    pub apk: PackageArtifact,
    pub test_apk: PackageArtifact,
}

impl ClientComponent {
    fn validate(&self) -> Result<()> {
        commit(&self.source_commit, "client.source_commit")?;
        self.apk.validate("client.apk")?;
        self.test_apk.validate("client.test_apk")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorComponent {
    pub source_commit: String,
    pub binary: PackageArtifact,
}

impl ConnectorComponent {
    fn validate(&self) -> Result<()> {
        commit(&self.source_commit, "connector.source_commit")?;
        self.binary.validate("connector.binary")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageArtifact {
    pub path: PathBuf,
    pub sha256: String,
}

impl PackageArtifact {
    fn validate(&self, name: &str) -> Result<()> {
        safe_relative(&self.path, name)?;
        digest(&self.sha256, &format!("{name}.sha256"))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ComponentDigests {
    pub server_image: String,
    pub client_apk: String,
    pub client_test_apk: String,
    pub connector_binary: String,
    pub sidecar_image: String,
    pub config: String,
}

impl ComponentDigests {
    fn from_contract(contract: &AlphaContract) -> Self {
        Self {
            server_image: contract.server.image.clone(),
            client_apk: contract.client.apk.sha256.clone(),
            client_test_apk: contract.client.test_apk.sha256.clone(),
            connector_binary: contract.connector.binary.sha256.clone(),
            sidecar_image: contract.sidecar.image.clone(),
            config: contract.config.sha256.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct VerifiedAlphaPackage {
    pub manifest_digest: String,
    pub package_digest: String,
    pub component_digests: ComponentDigests,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorFence {
    pub connector_id: String,
    pub generation: u64,
    pub lease_id: String,
    pub lease_epoch: u64,
}

impl ConnectorFence {
    fn validate(&self) -> Result<()> {
        uuid_v7(&self.connector_id, "connector_id")?;
        uuid_v7(&self.lease_id, "connector_lease_id")?;
        positive(self.generation, "connector_generation")?;
        positive(self.lease_epoch, "connector_lease_epoch")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationFence {
    pub operation_id: String,
    pub epoch: u64,
}

impl OperationFence {
    fn validate(&self) -> Result<()> {
        uuid_v7(&self.operation_id, "operation_id")?;
        positive(self.epoch, "operation_epoch")
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum AlphaLifecycle {
    Planned,
    Installed,
    Started,
    ReadinessVerified,
    AcceptanceObserved,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ReadinessFacts {
    pub server_ready: bool,
    pub client_ready: bool,
    pub connector_ready: bool,
    pub sidecar_ready: bool,
}

#[allow(clippy::missing_errors_doc)]
impl ReadinessFacts {
    pub fn load(path: &Path) -> Result<Self> {
        load_canonical(path)
    }

    fn validate(&self) -> Result<()> {
        if !(self.server_ready && self.client_ready && self.connector_ready && self.sidecar_ready) {
            return Err(alpha_error("all four readiness facts must be true"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceObservation {
    pub scenario: String,
    pub target_id: String,
    pub manifest_digest: String,
    pub package_digest: String,
    pub connector_fence: ConnectorFence,
    pub operation_fence: OperationFence,
    pub receipt_digest: String,
    pub signer_identity: String,
    pub signature_verified: bool,
}

#[allow(clippy::missing_errors_doc)]
impl AcceptanceObservation {
    pub fn load(path: &Path) -> Result<Self> {
        load_canonical(path)
    }

    fn validate_for(&self, record: &AlphaLifecycleRecord) -> Result<()> {
        self.connector_fence.validate()?;
        self.operation_fence.validate()?;
        digest(&self.receipt_digest, "receipt_digest")?;
        if self.scenario != ALPHA_SCENARIO
            || self.target_id != record.target_id
            || self.manifest_digest != record.manifest_digest
            || self.package_digest != record.package_digest
            || self.connector_fence != record.connector_fence
            || self.operation_fence != record.operation_fence
            || !self.signature_verified
            || self.signer_identity.is_empty()
            || self.signer_identity.len() > 128
            || !self.signer_identity.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':')
            })
        {
            return Err(alpha_error(
                "acceptance receipt does not match the exact Alpha operation",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AlphaLifecycleRecord {
    pub schema: String,
    pub schema_version: u32,
    pub target_id: String,
    pub manifest_digest: String,
    pub package_digest: String,
    pub component_digests: ComponentDigests,
    pub connector_fence: ConnectorFence,
    pub operation_fence: OperationFence,
    pub state: AlphaLifecycle,
    pub readiness: Option<ReadinessFacts>,
    pub receipt_digest: Option<String>,
    pub receipt_signer_identity: Option<String>,
    pub integrity_digest: String,
}

#[allow(clippy::missing_errors_doc)]
impl AlphaLifecycleRecord {
    pub fn planned(
        manifest: &AlphaManifest,
        package: &VerifiedAlphaPackage,
        connector_fence: ConnectorFence,
        operation_fence: OperationFence,
    ) -> Result<Self> {
        connector_fence.validate()?;
        operation_fence.validate()?;
        if package.manifest_digest != manifest.digest {
            return Err(alpha_error("verified package does not match manifest"));
        }
        Self {
            schema: ALPHA_SCHEMA.to_owned(),
            schema_version: 3,
            target_id: manifest.contract.target.id.clone(),
            manifest_digest: package.manifest_digest.clone(),
            package_digest: package.package_digest.clone(),
            component_digests: package.component_digests.clone(),
            connector_fence,
            operation_fence,
            state: AlphaLifecycle::Planned,
            readiness: None,
            receipt_digest: None,
            receipt_signer_identity: None,
            integrity_digest: String::new(),
        }
        .seal()
    }

    pub fn advance(
        &self,
        next: AlphaLifecycle,
        readiness: Option<ReadinessFacts>,
        acceptance: Option<AcceptanceObservation>,
    ) -> Result<Self> {
        self.verify()?;
        let expected = match self.state {
            AlphaLifecycle::Planned => AlphaLifecycle::Installed,
            AlphaLifecycle::Installed => AlphaLifecycle::Started,
            AlphaLifecycle::Started => AlphaLifecycle::ReadinessVerified,
            AlphaLifecycle::ReadinessVerified => AlphaLifecycle::AcceptanceObserved,
            AlphaLifecycle::AcceptanceObserved => AlphaLifecycle::Completed,
            AlphaLifecycle::Completed => {
                return Err(alpha_error("completed Alpha operation is immutable"));
            }
        };
        if next != expected {
            return Err(alpha_error("invalid Alpha lifecycle transition"));
        }
        let mut record = self.clone();
        record.state = next;
        match next {
            AlphaLifecycle::ReadinessVerified => {
                let facts = readiness.ok_or_else(|| alpha_error("readiness facts are required"))?;
                facts.validate()?;
                record.readiness = Some(facts);
            }
            AlphaLifecycle::AcceptanceObserved => {
                let observation =
                    acceptance.ok_or_else(|| alpha_error("acceptance receipt is required"))?;
                observation.validate_for(self)?;
                record.receipt_digest = Some(observation.receipt_digest);
                record.receipt_signer_identity = Some(observation.signer_identity);
            }
            AlphaLifecycle::Completed => {
                if record.readiness.is_none()
                    || record.receipt_digest.is_none()
                    || record.receipt_signer_identity.is_none()
                {
                    return Err(alpha_error(
                        "completed Alpha record lacks acceptance evidence",
                    ));
                }
            }
            AlphaLifecycle::Planned | AlphaLifecycle::Installed | AlphaLifecycle::Started => {}
        }
        record.seal()
    }

    fn seal(mut self) -> Result<Self> {
        self.integrity_digest.clear();
        self.integrity_digest = prefixed_digest(&serde_json::to_vec(&self)?);
        Ok(self)
    }

    pub fn verify(&self) -> Result<()> {
        if self.schema != ALPHA_SCHEMA || self.schema_version != 3 {
            return Err(alpha_error("invalid Alpha lifecycle schema"));
        }
        self.connector_fence.validate()?;
        self.operation_fence.validate()?;
        digest(&self.manifest_digest, "manifest_digest")?;
        digest(&self.package_digest, "package_digest")?;
        let mut copy = self.clone();
        let expected = std::mem::take(&mut copy.integrity_digest);
        if expected != prefixed_digest(&serde_json::to_vec(&copy)?) {
            return Err(alpha_error("Alpha lifecycle integrity mismatch"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AlphaStateStore {
    root: PathBuf,
}

#[allow(clippy::missing_errors_doc)]
impl AlphaStateStore {
    #[cfg(unix)]
    pub fn fixed() -> Result<Self> {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(alpha_error("fixed Alpha state requires root"));
        }
        Ok(Self {
            root: PathBuf::from(ALPHA_STATE_DIR),
        })
    }

    #[cfg(not(unix))]
    pub fn fixed() -> Result<Self> {
        Err(ReleaseError::UnsupportedPlatform(
            "Internal Test Alpha deployment requires Unix",
        ))
    }

    #[cfg(test)]
    fn for_test(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn create(&self, record: &AlphaLifecycleRecord) -> Result<AlphaLifecycleRecord> {
        record.verify()?;
        if record.state != AlphaLifecycle::Planned {
            return Err(alpha_error("new Alpha state must be Planned"));
        }
        self.ensure_root()?;
        let path = self.record_path(&record.operation_fence.operation_id)?;
        if path.exists() {
            let existing = self.read(&record.operation_fence.operation_id)?;
            return if existing == *record {
                Ok(existing)
            } else {
                Err(ReleaseError::OperationConflict)
            };
        }
        Self::write_new(&path, record)?;
        Ok(record.clone())
    }

    pub fn read(&self, operation_id: &str) -> Result<AlphaLifecycleRecord> {
        uuid_v7(operation_id, "operation_id")?;
        let path = self.record_path(operation_id)?;
        let record: AlphaLifecycleRecord = load_canonical(&path)?;
        record.verify()?;
        if record.operation_fence.operation_id != operation_id {
            return Err(ReleaseError::OperationConflict);
        }
        Ok(record)
    }

    pub fn advance(
        &self,
        operation_id: &str,
        next: AlphaLifecycle,
        readiness: Option<ReadinessFacts>,
        acceptance: Option<AcceptanceObservation>,
    ) -> Result<AlphaLifecycleRecord> {
        let current = self.read(operation_id)?;
        let next_record = current.advance(next, readiness, acceptance)?;
        let path = self.record_path(operation_id)?;
        self.replace(&path, &next_record)?;
        Ok(next_record)
    }

    fn ensure_root(&self) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(io_error(&self.root))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))
                .map_err(io_error(&self.root))?;
            let metadata = fs::symlink_metadata(&self.root).map_err(io_error(&self.root))?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o777 != 0o700
            {
                return Err(ReleaseError::StateUnsafe(self.root.clone()));
            }
        }
        Ok(())
    }

    fn record_path(&self, operation_id: &str) -> Result<PathBuf> {
        uuid_v7(operation_id, "operation_id")?;
        Ok(self.root.join(format!("{operation_id}.json")))
    }

    fn write_new(path: &Path, record: &AlphaLifecycleRecord) -> Result<()> {
        use std::io::Write as _;

        let value = serde_json::to_value(record)?;
        let bytes = strict_json::canonical_bytes(&value, false)?;
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path).map_err(io_error(path))?;
        file.write_all(&bytes).map_err(io_error(path))?;
        file.sync_all().map_err(io_error(path))
    }

    fn replace(&self, path: &Path, record: &AlphaLifecycleRecord) -> Result<()> {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?;
        let temp = self.root.join(format!(".{file_name}.new"));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_error(&temp)(error)),
        }
        Self::write_new(&temp, record)?;
        fs::rename(&temp, path).map_err(io_error(path))?;
        let directory = fs::File::open(&self.root).map_err(io_error(&self.root))?;
        directory.sync_all().map_err(io_error(&self.root))
    }
}

fn safe_relative(path: &Path, name: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(_))
                || component
                    .as_os_str()
                    .to_str()
                    .is_none_or(|value| value.is_empty() || value.len() > 255)
        })
    {
        return Err(alpha_error(&format!("{name}.path must be safe-relative")));
    }
    Ok(())
}

fn commit(value: &str, name: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(alpha_error(&format!(
            "{name} must be a lowercase 40-hex commit"
        )));
    }
    Ok(())
}

fn image(value: &str, name: &str) -> Result<()> {
    let Some((repository, digest_value)) = value.rsplit_once("@sha256:") else {
        return Err(alpha_error(&format!(
            "{name} must be an immutable image digest"
        )));
    };
    if repository.is_empty() || repository.contains(char::is_whitespace) {
        return Err(alpha_error(&format!("{name} has an invalid repository")));
    }
    digest(&format!("sha256:{digest_value}"), name)
}

fn digest(value: &str, name: &str) -> Result<()> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(alpha_error(&format!("{name} must use sha256")));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(alpha_error(&format!("{name} must be lowercase sha256")));
    }
    Ok(())
}

fn uuid_v7(value: &str, name: &str) -> Result<()> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| alpha_error(&format!("{name} must be UUIDv7")))?;
    if parsed.get_version_num() != 7 || parsed.to_string() != value {
        return Err(alpha_error(&format!("{name} must be canonical UUIDv7")));
    }
    Ok(())
}

fn positive(value: u64, name: &str) -> Result<()> {
    if value == 0 || value > 9_007_199_254_740_991 {
        return Err(alpha_error(&format!("{name} is out of range")));
    }
    Ok(())
}

fn prefixed_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn append_part(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn load_canonical<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
{
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_MANIFEST_BYTES as u64
    {
        return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
    }
    let bytes = fs::read(path).map_err(io_error(path))?;
    let value = strict_json::parse_value(&bytes)?;
    if strict_json::canonical_bytes(&value, false)? != bytes {
        return Err(alpha_error(
            "Alpha evidence or state must be canonical JSON",
        ));
    }
    Ok(serde_json::from_value(value)?)
}

fn alpha_error(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.to_owned())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const IMAGE: &str = "registry.example/dirextalk@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CONNECTOR_ID: &str = "019fa57f-848c-789c-a039-129d0b457ced";
    const LEASE_ID: &str = "019fa599-0000-7000-8000-000000000001";
    const OPERATION_ID: &str = "019fa599-0000-7000-8000-000000000002";

    fn package() -> (TempDir, Vec<u8>) {
        let temp = TempDir::new().expect("temp");
        for (path, body) in [
            ("client.apk", b"client".as_slice()),
            ("client-test.apk", b"test".as_slice()),
            ("connector", b"connector".as_slice()),
            ("config.json", b"config".as_slice()),
        ] {
            fs::write(temp.path().join(path), body).expect("fixture");
        }
        let artifact = |path: &str| {
            serde_json::json!({
                "path": path,
                "sha256": prefixed_digest(&fs::read(temp.path().join(path)).expect("read"))
            })
        };
        let value = serde_json::json!({
            "client": {
                "apk": artifact("client.apk"),
                "source_commit": COMMIT,
                "test_apk": artifact("client-test.apk")
            },
            "config": artifact("config.json"),
            "connector": {"binary": artifact("connector"), "source_commit": COMMIT},
            "deployer": {"source_commit": COMMIT},
            "fresh_only": true,
            "schema": ALPHA_SCHEMA,
            "schema_version": 3,
            "server": {"image": IMAGE, "source_commit": COMMIT},
            "sidecar": {"image": IMAGE, "source_commit": COMMIT},
            "target": {"id": "x4.dirextalk.ai"}
        });
        (
            temp,
            strict_json::canonical_bytes(&value, false).expect("canonical"),
        )
    }

    #[test]
    fn schema3_package_and_lifecycle_complete_exactly_once() {
        let (temp, bytes) = package();
        let manifest = AlphaManifest::from_bytes(&bytes).expect("manifest");
        let package = manifest.verify_package(temp.path()).expect("package");
        let connector_fence = ConnectorFence {
            connector_id: CONNECTOR_ID.into(),
            generation: 1,
            lease_id: LEASE_ID.into(),
            lease_epoch: 13,
        };
        let operation_fence = OperationFence {
            operation_id: OPERATION_ID.into(),
            epoch: 1,
        };
        let planned = AlphaLifecycleRecord::planned(
            &manifest,
            &package,
            connector_fence.clone(),
            operation_fence.clone(),
        )
        .expect("planned");
        let installed = planned
            .advance(AlphaLifecycle::Installed, None, None)
            .expect("installed");
        let started = installed
            .advance(AlphaLifecycle::Started, None, None)
            .expect("started");
        let readiness = ReadinessFacts {
            server_ready: true,
            client_ready: true,
            connector_ready: true,
            sidecar_ready: true,
        };
        let ready = started
            .advance(AlphaLifecycle::ReadinessVerified, Some(readiness), None)
            .expect("ready");
        let observation = AcceptanceObservation {
            scenario: ALPHA_SCENARIO.into(),
            target_id: "x4.dirextalk.ai".into(),
            manifest_digest: package.manifest_digest.clone(),
            package_digest: package.package_digest.clone(),
            connector_fence,
            operation_fence,
            receipt_digest: format!("sha256:{}", "b".repeat(64)),
            signer_identity: "x4.internal-acceptance".into(),
            signature_verified: true,
        };
        let observed = ready
            .advance(AlphaLifecycle::AcceptanceObserved, None, Some(observation))
            .expect("observed");
        let completed = observed
            .advance(AlphaLifecycle::Completed, None, None)
            .expect("completed");
        completed.verify().expect("sealed");
        assert_eq!(completed.state, AlphaLifecycle::Completed);
        assert!(
            completed
                .advance(AlphaLifecycle::Completed, None, None)
                .is_err()
        );
    }

    #[test]
    fn rejects_all_other_schemas_and_noncanonical_json() {
        let (_, bytes) = package();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        value["schema_version"] = 2.into();
        let old = strict_json::canonical_bytes(&value, false).expect("canonical");
        assert!(AlphaManifest::from_bytes(&old).is_err());
        let pretty = serde_json::to_vec_pretty(
            &serde_json::from_slice::<serde_json::Value>(&bytes).expect("json"),
        )
        .expect("pretty");
        assert!(AlphaManifest::from_bytes(&pretty).is_err());
        assert!(AlphaManifest::from_bytes(br#"{"schema":1,"schema":1}"#).is_err());
    }

    #[test]
    fn rejects_digest_drift_and_transition_skips() {
        let (temp, bytes) = package();
        let manifest = AlphaManifest::from_bytes(&bytes).expect("manifest");
        fs::write(temp.path().join("connector"), b"changed").expect("change");
        assert!(manifest.verify_package(temp.path()).is_err());
        fs::write(temp.path().join("connector"), b"connector").expect("restore");
        let package = manifest.verify_package(temp.path()).expect("package");
        let planned = AlphaLifecycleRecord::planned(
            &manifest,
            &package,
            ConnectorFence {
                connector_id: CONNECTOR_ID.into(),
                generation: 1,
                lease_id: LEASE_ID.into(),
                lease_epoch: 1,
            },
            OperationFence {
                operation_id: OPERATION_ID.into(),
                epoch: 1,
            },
        )
        .expect("planned");
        assert!(
            planned
                .advance(AlphaLifecycle::Started, None, None)
                .is_err()
        );
    }

    #[test]
    fn state_store_persists_each_exact_transition() {
        let (package_root, bytes) = package();
        let manifest = AlphaManifest::from_bytes(&bytes).expect("manifest");
        let package = manifest
            .verify_package(package_root.path())
            .expect("package");
        let store_root = TempDir::new().expect("state");
        let store = AlphaStateStore::for_test(store_root.path().join("alpha"));
        let planned = AlphaLifecycleRecord::planned(
            &manifest,
            &package,
            ConnectorFence {
                connector_id: CONNECTOR_ID.into(),
                generation: 1,
                lease_id: LEASE_ID.into(),
                lease_epoch: 1,
            },
            OperationFence {
                operation_id: OPERATION_ID.into(),
                epoch: 1,
            },
        )
        .expect("planned");
        store.create(&planned).expect("create");
        assert_eq!(
            store.read(OPERATION_ID).expect("read").state,
            AlphaLifecycle::Planned
        );
        store
            .advance(OPERATION_ID, AlphaLifecycle::Installed, None, None)
            .expect("installed");
        assert_eq!(
            store.read(OPERATION_ID).expect("read").state,
            AlphaLifecycle::Installed
        );
        assert!(store.create(&planned).is_err());
    }
}
