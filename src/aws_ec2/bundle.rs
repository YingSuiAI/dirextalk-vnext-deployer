use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Cursor, Read},
    path::{Component, Path},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ReleaseError, Result, error::io_error};

const MAX_BUNDLE: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_HELPER: u64 = 1024 * 1024;
const MAX_MEMBERS: usize = 256;
const ROOT_NAME: &str = "dirextalk-vnext-stack";
const ROOT: &str = "dirextalk-vnext-stack/";
const MANIFEST_PATH: &str = "dirextalk-vnext-stack/manifest.json";
const STACK_INSTALLER_PATH: &str = "scripts/production-stack/install.sh";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackManifest {
    pub schema: String,
    pub schema_version: u32,
    pub version: String,
    pub source_commit: String,
    pub target: String,
    pub server_image: String,
    pub migrator_image: String,
    pub installer_sha256: String,
    pub files: Vec<StackFile>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StackFile {
    pub path: String,
    pub sha256: String,
    pub mode: String,
}

#[derive(Clone, Debug)]
pub struct BundleFacts {
    pub bundle_sha256: String,
    pub manifest_sha256: String,
    pub compose_sha256: String,
    pub manifest: StackManifest,
    pub host_installer: Vec<u8>,
    pub host_installer_sha256: String,
    pub host_provisioner: Vec<u8>,
    pub host_provisioner_sha256: String,
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

#[allow(clippy::too_many_arguments)]
pub fn load_bundle(
    path: &Path,
    expected_sha256: &str,
    host_installer_path: &Path,
    expected_host_installer_sha256: &str,
    host_provisioner_path: &Path,
    expected_host_provisioner_sha256: &str,
    receipt_reader_path: &Path,
    expected_receipt_reader_sha256: &str,
) -> Result<BundleFacts> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BUNDLE {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    let encoded = fs::read(path).map_err(io_error(path))?;
    let actual_bundle = hash(&encoded);
    if actual_bundle != expected_sha256 {
        return Err(ReleaseError::SourceMismatch(path.to_owned()));
    }
    let mut archive = tar::Archive::new(Cursor::new(encoded));
    let mut entries = BTreeMap::<String, (String, Vec<u8>)>::new();
    let mut directories = BTreeSet::new();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    let mut member_count = 0_usize;
    for entry in archive.entries().map_err(io_error(path))? {
        let mut entry = entry.map_err(io_error(path))?;
        member_count += 1;
        if member_count > MAX_MEMBERS {
            return Err(deployment("bundle contains too many members"));
        }
        let header = entry.header();
        if header.as_ustar().is_none()
            || header.uid().map_err(io_error(path))? != 0
            || header.gid().map_err(io_error(path))? != 0
            || header.mtime().map_err(io_error(path))? != 0
        {
            return Err(deployment(
                "bundle member metadata is not deterministic USTAR",
            ));
        }
        let path_value = entry.path().map_err(io_error(path))?.into_owned();
        let raw_name = path_value
            .to_str()
            .ok_or_else(|| deployment("bundle path is not UTF-8"))?
            .to_owned();
        let name = raw_name.trim_end_matches('/');
        validate_archive_name(name)?;
        if !seen.insert(name.to_owned()) {
            return Err(deployment("bundle member path is duplicated"));
        }
        let size = entry.size();
        let mode = header.mode().map_err(io_error(path))? & 0o7777;
        if header.entry_type().is_dir() {
            if raw_name != format!("{name}/") || size != 0 || mode != 0o555 {
                return Err(deployment("bundle directory metadata is invalid"));
            }
            directories.insert(name.to_owned());
        } else if header.entry_type().is_file() {
            if raw_name != name || !matches!(mode, 0o444 | 0o555) || size > MAX_BUNDLE {
                return Err(deployment("bundle file metadata is invalid"));
            }
            total = total
                .checked_add(size)
                .ok_or_else(|| deployment("bundle payload size overflow"))?;
            if total > MAX_BUNDLE {
                return Err(deployment("bundle payload exceeds the fixed limit"));
            }
            let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or_default());
            entry
                .by_ref()
                .take(size + 1)
                .read_to_end(&mut bytes)
                .map_err(io_error(path))?;
            if bytes.len() as u64 != size {
                return Err(deployment("bundle entry length mismatch"));
            }
            entries.insert(name.to_owned(), (format!("{mode:04o}"), bytes));
        } else {
            return Err(deployment("bundle contains a link or special member"));
        }
    }
    let (manifest_mode, manifest_bytes) = entries
        .remove(MANIFEST_PATH)
        .ok_or_else(|| deployment("bundle manifest is missing"))?;
    if manifest_mode != "0444" || manifest_bytes.len() as u64 > MAX_MANIFEST {
        return Err(deployment("bundle manifest mode or size is invalid"));
    }
    let manifest: StackManifest = serde_json::from_slice(&manifest_bytes)?;
    if canonical_json(&manifest)? != manifest_bytes {
        return Err(deployment("bundle manifest is not canonical JSON"));
    }
    validate_manifest(&manifest, &entries, &directories)?;
    let compose_sha256 = manifest
        .files
        .iter()
        .find(|file| file.path == "docker/production/docker-compose.yml")
        .map(|file| file.sha256.clone())
        .ok_or_else(|| deployment("bundle omits the fixed production compose file"))?;
    let host_installer = read_hash_bound_helper(
        host_installer_path,
        expected_host_installer_sha256,
        "host installer",
    )?;
    let receipt_reader = read_hash_bound_helper(
        receipt_reader_path,
        expected_receipt_reader_sha256,
        "receipt reader",
    )?;
    let host_provisioner = read_hash_bound_helper(
        host_provisioner_path,
        expected_host_provisioner_sha256,
        "host provisioner",
    )?;
    Ok(BundleFacts {
        bundle_sha256: actual_bundle,
        manifest_sha256: hash(&manifest_bytes),
        compose_sha256,
        manifest,
        host_installer,
        host_installer_sha256: expected_host_installer_sha256.to_owned(),
        host_provisioner,
        host_provisioner_sha256: expected_host_provisioner_sha256.to_owned(),
        receipt_reader,
        receipt_reader_sha256: expected_receipt_reader_sha256.to_owned(),
    })
}

fn validate_archive_name(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || (value != ROOT_NAME && !value.starts_with(ROOT))
    {
        return Err(deployment("bundle contains an unsafe path"));
    }
    Ok(())
}

fn validate_manifest(
    manifest: &StackManifest,
    entries: &BTreeMap<String, (String, Vec<u8>)>,
    directories: &BTreeSet<String>,
) -> Result<()> {
    if manifest.schema != "dirextalk.vnext-stack-bundle" || manifest.schema_version != 1 {
        return Err(deployment("bundle manifest schema is unsupported"));
    }
    Version::parse(&manifest.version).map_err(|_| deployment("bundle version must be SemVer"))?;
    if manifest.target != "linux-amd64" {
        return Err(deployment("bundle target must be linux-amd64"));
    }
    commit(&manifest.source_commit)?;
    exact_server_image(&manifest.server_image, "bundle server_image")?;
    exact_server_image(&manifest.migrator_image, "bundle migrator_image")?;
    digest(&manifest.installer_sha256, "bundle installer")?;
    if manifest.files.len() != entries.len() {
        return Err(deployment("bundle file index is not exhaustive"));
    }
    let mut previous = None::<&str>;
    for file in &manifest.files {
        validate_relative_path(&file.path)?;
        if previous.is_some_and(|old| old >= file.path.as_str()) {
            return Err(deployment("bundle file index must be strictly sorted"));
        }
        previous = Some(&file.path);
        digest(&file.sha256, "bundle file")?;
        if file.mode != "0444" && file.mode != "0555" {
            return Err(deployment("bundle file mode is outside the fixed policy"));
        }
        let archive_path = format!("{ROOT}{}", file.path);
        let (mode, bytes) = entries
            .get(&archive_path)
            .ok_or_else(|| deployment("bundle file index references a missing entry"))?;
        if mode != &file.mode || hash(bytes) != file.sha256 {
            return Err(deployment("bundle file metadata or digest mismatch"));
        }
    }
    let expected_files = manifest
        .files
        .iter()
        .map(|file| format!("{ROOT}{}", file.path))
        .collect::<BTreeSet<_>>();
    if entries.keys().cloned().collect::<BTreeSet<_>>() != expected_files {
        return Err(deployment("bundle file set differs from its manifest"));
    }
    if required_directories(&expected_files) != *directories {
        return Err(deployment("bundle directory set differs from its manifest"));
    }
    let installer = manifest
        .files
        .iter()
        .find(|file| file.path == STACK_INSTALLER_PATH)
        .ok_or_else(|| deployment("bundle file index omits the fixed installer"))?;
    if installer.mode != "0555" || installer.sha256 != manifest.installer_sha256 {
        return Err(deployment("fixed installer binding is invalid"));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<()> {
    let path = Path::new(value);
    if value.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || value.ends_with('/')
    {
        return Err(deployment("bundle file index path is invalid"));
    }
    Ok(())
}

fn required_directories(files: &BTreeSet<String>) -> BTreeSet<String> {
    let mut result = BTreeSet::from([ROOT_NAME.to_owned()]);
    for file in files {
        let mut current = Path::new(file).parent();
        while let Some(directory) = current {
            let value = directory.to_string_lossy();
            if value == "." || value.is_empty() {
                break;
            }
            result.insert(value.into_owned());
            if directory == Path::new(ROOT_NAME) {
                break;
            }
            current = directory.parent();
        }
    }
    result
}

pub(super) fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&serde_json::to_value(value)?)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn exact_server_image(value: &str, name: &str) -> Result<()> {
    image(value, name)?;
    if !value.starts_with("dirextalk/vnet-server@sha256:") {
        return Err(deployment(&format!("{name} repository is not allowed")));
    }
    Ok(())
}

fn read_hash_bound_helper(path: &Path, expected_sha256: &str, name: &str) -> Result<Vec<u8>> {
    digest(expected_sha256, name)?;
    let before = fs::symlink_metadata(path).map_err(io_error(path))?;
    if !before.is_file() || before.len() == 0 || before.len() > MAX_HELPER {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    #[cfg(unix)]
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path);
    #[cfg(not(unix))]
    let opened = OpenOptions::new().read(true).open(path);
    let mut file = opened.map_err(io_error(path))?;
    let opened_metadata = file.metadata().map_err(io_error(path))?;
    if !opened_metadata.is_file() || opened_metadata.len() != before.len() {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    #[cfg(unix)]
    if (opened_metadata.dev(), opened_metadata.ino()) != (before.dev(), before.ino()) {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_HELPER + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(path))?;
    let after = file.metadata().map_err(io_error(path))?;
    if bytes.is_empty()
        || bytes.len() as u64 > MAX_HELPER
        || after.len() != opened_metadata.len()
        || hash(&bytes) != expected_sha256
    {
        return Err(ReleaseError::SourceMismatch(path.to_owned()));
    }
    Ok(bytes)
}

impl InstallRequest {
    pub fn new(domain: &str, facts: &BundleFacts, previous_receipt_sha256: Option<String>) -> Self {
        Self {
            schema: "dirextalk.vnext-install-request".into(),
            schema_version: 1,
            target: facts.manifest.target.clone(),
            domain: domain.into(),
            version: facts.manifest.version.clone(),
            source_commit: facts.manifest.source_commit.clone(),
            bundle_sha256: facts.bundle_sha256.clone(),
            manifest_sha256: facts.manifest_sha256.clone(),
            server_image: facts.manifest.server_image.clone(),
            migrator_image: facts.manifest.migrator_image.clone(),
            previous_receipt_sha256,
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = canonical_json(self)?;
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
        {
            return Err(deployment("installed receipt binding mismatch"));
        }
        digest(&receipt.receipt_sha256, "installed receipt")?;
        let mut canonical: Value = serde_json::to_value(&receipt)?;
        canonical
            .as_object_mut()
            .ok_or_else(|| deployment("installed receipt is not an object"))?
            .remove("receipt_sha256");
        if hash(&canonical_json(&canonical)?) != receipt.receipt_sha256
            || bytes != canonical_json(&receipt)?
        {
            return Err(deployment("installed receipt integrity mismatch"));
        }
        Ok(receipt)
    }
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
