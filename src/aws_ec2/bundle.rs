use std::{
    collections::BTreeMap,
    fs,
    io::{Cursor, Read},
    path::{Component, Path},
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ReleaseError, Result, error::io_error};

const MAX_BUNDLE: u64 = 512 * 1024 * 1024;
const MAX_EXPANDED: u64 = 1024 * 1024 * 1024;
const MAX_ENTRY: u64 = 256 * 1024 * 1024;
const ROOT: &str = "dirextalk-vnext-stack/";
const MANIFEST_PATH: &str = "dirextalk-vnext-stack/manifest.json";
const INSTALLER_PATH: &str = "dirextalk-vnext-stack/usr/local/libexec/dirextalk/install-vnext";
const RECEIPT_READER_PATH: &str =
    "dirextalk-vnext-stack/usr/local/libexec/dirextalk/read-vnext-receipt";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackManifest {
    pub schema: String,
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub server: String,
    pub migrator: String,
    pub installer_sha256: String,
    pub files: Vec<StackFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackFile {
    pub path: String,
    pub sha256: String,
    pub mode: u32,
}

#[derive(Clone, Debug)]
pub struct BundleFacts {
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub manifest: StackManifest,
    pub installer: Vec<u8>,
    pub receipt_reader: Vec<u8>,
    pub receipt_reader_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub schema: String,
    pub schema_version: u32,
    pub target: String,
    pub domain: String,
    pub version: String,
    pub source_commit: String,
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub server_image: String,
    pub migrator_image: String,
    #[serde(default)]
    pub previous_receipt_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstalledReceipt {
    pub schema: String,
    pub schema_version: u32,
    pub state: ReceiptState,
    pub target: String,
    pub domain: String,
    pub version: String,
    pub source_commit: String,
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub server_image: String,
    pub migrator_image: String,
    #[serde(default)]
    pub previous_receipt_sha256: Option<String>,
    pub installed_at_ms: u64,
    pub receipt_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    Installed,
    RolledBack,
}

pub fn load_bundle(path: &Path, expected_sha256: &str) -> Result<BundleFacts> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BUNDLE {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    let encoded = fs::read(path).map_err(io_error(path))?;
    let actual_bundle = hash(&encoded);
    if actual_bundle != expected_sha256 {
        return Err(ReleaseError::SourceMismatch(path.to_owned()));
    }
    let tar_bytes = if encoded.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        let mut decoder = zstd::stream::read::Decoder::new(Cursor::new(encoded))
            .map_err(|_| deployment("bundle zstd header is invalid"))?;
        let mut expanded = Vec::new();
        decoder
            .by_ref()
            .take(MAX_EXPANDED + 1)
            .read_to_end(&mut expanded)
            .map_err(io_error(path))?;
        if expanded.len() as u64 > MAX_EXPANDED {
            return Err(deployment("expanded bundle exceeds the fixed limit"));
        }
        expanded
    } else {
        encoded
    };
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let mut entries = BTreeMap::<String, (u32, Vec<u8>)>::new();
    for entry in archive.entries().map_err(io_error(path))? {
        let mut entry = entry.map_err(io_error(path))?;
        let header = entry.header();
        if !header.entry_type().is_file() {
            return Err(deployment("bundle contains a non-regular entry"));
        }
        let path_value = entry.path().map_err(io_error(path))?.into_owned();
        validate_archive_path(&path_value)?;
        let name = path_value
            .to_str()
            .ok_or_else(|| deployment("bundle path is not UTF-8"))?
            .to_owned();
        if !name.starts_with(ROOT) || name.ends_with('/') || entries.contains_key(&name) {
            return Err(deployment("bundle root or entry uniqueness is invalid"));
        }
        let size = entry.size();
        if size == 0 || size > MAX_ENTRY {
            return Err(deployment("bundle entry size is invalid"));
        }
        let mode = entry.header().mode().map_err(io_error(path))? & 0o7777;
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
        entry
            .by_ref()
            .take(MAX_ENTRY + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        if bytes.len() as u64 != size {
            return Err(deployment("bundle entry length mismatch"));
        }
        entries.insert(name, (mode, bytes));
    }
    let (manifest_mode, manifest_bytes) = entries
        .remove(MANIFEST_PATH)
        .ok_or_else(|| deployment("bundle manifest is missing"))?;
    if manifest_mode != 0o444 && manifest_mode != 0o644 {
        return Err(deployment("bundle manifest mode must be 0444 or 0644"));
    }
    let manifest: StackManifest = serde_json::from_slice(&manifest_bytes)?;
    validate_manifest(&manifest, &entries)?;
    let installer = entries
        .get(INSTALLER_PATH)
        .map(|(_, bytes)| bytes.clone())
        .ok_or_else(|| deployment("fixed installer is absent from bundle"))?;
    let receipt_reader = entries
        .get(RECEIPT_READER_PATH)
        .map(|(_, bytes)| bytes.clone())
        .ok_or_else(|| deployment("fixed receipt reader is absent from bundle"))?;
    let reader_sha = hash(&receipt_reader);
    Ok(BundleFacts {
        bundle_sha256: actual_bundle,
        manifest_sha256: hash(&manifest_bytes),
        manifest,
        installer,
        receipt_reader,
        receipt_reader_sha256: reader_sha,
    })
}

fn validate_archive_path(path: &Path) -> Result<()> {
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(deployment("bundle contains an unsafe path"));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &StackManifest,
    entries: &BTreeMap<String, (u32, Vec<u8>)>,
) -> Result<()> {
    if manifest.schema != "dirextalk.vnext-stack-bundle" || manifest.schema_version != 1 {
        return Err(deployment("bundle manifest schema is unsupported"));
    }
    Version::parse(&manifest.version).map_err(|_| deployment("bundle version must be SemVer"))?;
    if manifest.target != "linux-amd64" {
        return Err(deployment("bundle target must be linux-amd64"));
    }
    commit(&manifest.source_commit)?;
    image(&manifest.server, "bundle server")?;
    image(&manifest.migrator, "bundle migrator")?;
    digest(&manifest.installer_sha256, "bundle installer")?;
    if manifest.files.len() != entries.len() {
        return Err(deployment("bundle file index is not exhaustive"));
    }
    let mut previous = None::<&str>;
    for file in &manifest.files {
        validate_string_path(&file.path)?;
        if previous.is_some_and(|old| old >= file.path.as_str()) {
            return Err(deployment("bundle file index must be strictly sorted"));
        }
        previous = Some(&file.path);
        digest(&file.sha256, "bundle file")?;
        if file.mode != 0o444 && file.mode != 0o555 {
            return Err(deployment("bundle file mode is outside the fixed policy"));
        }
        let (mode, bytes) = entries
            .get(&file.path)
            .ok_or_else(|| deployment("bundle file index references a missing entry"))?;
        if *mode != file.mode || hash(bytes) != file.sha256 {
            return Err(deployment("bundle file metadata or digest mismatch"));
        }
    }
    let installer = manifest
        .files
        .iter()
        .find(|file| file.path == INSTALLER_PATH)
        .ok_or_else(|| deployment("bundle file index omits the fixed installer"))?;
    if installer.mode != 0o555 || installer.sha256 != manifest.installer_sha256 {
        return Err(deployment("fixed installer binding is invalid"));
    }
    let reader = manifest
        .files
        .iter()
        .find(|file| file.path == RECEIPT_READER_PATH)
        .ok_or_else(|| deployment("bundle file index omits the fixed receipt reader"))?;
    if reader.mode != 0o555 {
        return Err(deployment("fixed receipt reader mode must be 0555"));
    }
    Ok(())
}

fn validate_string_path(path: &str) -> Result<()> {
    validate_archive_path(Path::new(path))?;
    if !path.starts_with(ROOT) || path == MANIFEST_PATH || path.ends_with('/') {
        return Err(deployment("bundle file index path is invalid"));
    }
    Ok(())
}

impl InstallRequest {
    pub fn new(
        target: &str,
        domain: &str,
        facts: &BundleFacts,
        previous_receipt_sha256: Option<String>,
    ) -> Self {
        Self {
            schema: "dirextalk.vnext-install-request".into(),
            schema_version: 1,
            target: target.into(),
            domain: domain.into(),
            version: facts.manifest.version.clone(),
            source_commit: facts.manifest.source_commit.clone(),
            bundle_sha256: facts.bundle_sha256.clone(),
            manifest_sha256: facts.manifest_sha256.clone(),
            server_image: facts.manifest.server.clone(),
            migrator_image: facts.manifest.migrator.clone(),
            previous_receipt_sha256,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)?;
        if bytes.len() > 64 * 1024 {
            return Err(deployment("install request exceeds the fixed limit"));
        }
        Ok(bytes)
    }
}

impl InstalledReceipt {
    pub fn parse_and_verify(
        bytes: &[u8],
        expected: &InstallRequest,
        expected_state: ReceiptState,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(deployment("installed receipt size is invalid"));
        }
        let receipt: Self = serde_json::from_slice(bytes)?;
        if receipt.schema != "dirextalk.vnext-installed-release"
            || receipt.schema_version != 1
            || receipt.state != expected_state
            || receipt.target != expected.target
            || receipt.domain != expected.domain
            || receipt.version != expected.version
            || receipt.source_commit != expected.source_commit
            || receipt.bundle_sha256 != expected.bundle_sha256
            || receipt.manifest_sha256 != expected.manifest_sha256
            || receipt.server_image != expected.server_image
            || receipt.migrator_image != expected.migrator_image
            || receipt.previous_receipt_sha256 != expected.previous_receipt_sha256
            || receipt.installed_at_ms == 0
        {
            return Err(deployment("installed receipt binding mismatch"));
        }
        digest(&receipt.receipt_sha256, "installed receipt")?;
        let mut canonical: Value = serde_json::to_value(&receipt)?;
        canonical
            .as_object_mut()
            .ok_or_else(|| deployment("installed receipt is not an object"))?
            .remove("receipt_sha256");
        if hash(&serde_json::to_vec(&canonical)?) != receipt.receipt_sha256 {
            return Err(deployment("installed receipt integrity mismatch"));
        }
        Ok(receipt)
    }
}

pub fn installer_base64(facts: &BundleFacts) -> String {
    STANDARD.encode(&facts.installer)
}

pub fn receipt_reader_base64(facts: &BundleFacts) -> String {
    STANDARD.encode(&facts.receipt_reader)
}

pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn digest(value: &str, name: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(deployment(&format!("{name} must be canonical SHA-256")));
    }
    Ok(())
}

pub fn image(value: &str, name: &str) -> Result<()> {
    let Some((repository, sha)) = value.split_once("@sha256:") else {
        return Err(deployment(&format!("{name} must be repository@sha256")));
    };
    if repository.is_empty() || repository.contains(char::is_whitespace) || repository.contains(':')
    {
        return Err(deployment(&format!("{name} repository is invalid")));
    }
    digest(sha, name)
}

pub fn commit(value: &str) -> Result<()> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(deployment("source_commit must be canonical lowercase hex"));
    }
    Ok(())
}

fn deployment(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.into())
}
