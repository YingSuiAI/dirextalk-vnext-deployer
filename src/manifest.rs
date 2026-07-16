use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use semver::Version;
use serde::{Deserialize, Serialize};

use crate::error::{ReleaseError, Result, io_error};

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct LoadedManifest {
    pub manifest: ReleaseManifest,
    pub manifest_path: PathBuf,
    pub root: PathBuf,
}

impl LoadedManifest {
    /// Load a strict manifest and validate its referenced source roots.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe files, malformed contracts, invalid fields,
    /// or missing source inputs.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        let bytes = fs::read(path).map_err(io_error(path))?;
        let manifest: ReleaseManifest = serde_json::from_slice(&bytes)?;
        manifest.validate()?;
        let absolute = absolute_path(path)?;
        let root = absolute
            .parent()
            .ok_or_else(|| ReleaseError::InvalidPath(absolute.clone()))?
            .to_path_buf();
        let loaded = Self {
            manifest,
            manifest_path: absolute,
            root,
        };
        loaded.validate_sources()?;
        Ok(loaded)
    }

    #[must_use]
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    #[must_use]
    pub fn server_repository(&self) -> PathBuf {
        self.resolve(&self.manifest.server.repository)
    }

    #[must_use]
    pub fn deployer_repository(&self) -> PathBuf {
        self.resolve(&self.manifest.deployer.repository)
    }

    #[must_use]
    pub fn connector_repository(&self) -> PathBuf {
        self.resolve(&self.manifest.connector.repository)
    }

    fn validate_sources(&self) -> Result<()> {
        let server = self.server_repository();
        require_directory(&server)?;
        require_regular_file(&server.join(&self.manifest.server.dockerfile))?;
        require_regular_file(&server.join("Cargo.toml"))?;

        let deployer = self.deployer_repository();
        require_directory(&deployer)?;
        require_regular_file(&deployer.join("Cargo.toml"))?;
        require_regular_file(&deployer.join("LICENSE"))?;

        let connector = self.connector_repository();
        require_directory(&connector)?;
        require_regular_file(&connector.join("go.mod"))?;
        require_regular_file(&connector.join("LICENSE"))?;
        require_regular_file(&connector.join("NOTICE"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifest {
    pub schema_version: u32,
    pub release: ReleaseIdentity,
    pub server: ServerArtifact,
    pub deployer: RustArtifact,
    pub connector: GoArtifact,
    pub targets: Vec<ReleaseTarget>,
    pub npm: NpmPackage,
    pub github: GitHubRelease,
}

impl ReleaseManifest {
    /// Validate the versioned manifest contract without resolving source Git state.
    ///
    /// # Errors
    ///
    /// Returns an error when any field violates the release contract.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != 1 {
            return Err(ReleaseError::Manifest(
                "schema_version must be exactly 1".to_owned(),
            ));
        }
        Version::parse(&self.release.version)
            .map_err(|_| ReleaseError::Manifest("release.version must be SemVer".to_owned()))?;
        if self.release.source_date_epoch == 0 {
            return Err(ReleaseError::Manifest(
                "release.source_date_epoch must be non-zero".to_owned(),
            ));
        }
        validate_relative_file(&self.server.dockerfile, "server.dockerfile")?;
        validate_image_repository(&self.server.image)?;
        validate_optional_source_commit(self.server.source_commit.as_deref())?;
        validate_optional_source_commit(self.deployer.source_commit.as_deref())?;
        validate_optional_source_commit(self.connector.source_commit.as_deref())?;
        if self.server.platforms.is_empty() {
            return Err(ReleaseError::Manifest(
                "server.platforms must not be empty".to_owned(),
            ));
        }
        let mut platforms = HashSet::new();
        for platform in &self.server.platforms {
            if !valid_platform(platform) || !platforms.insert(platform) {
                return Err(ReleaseError::Manifest(format!(
                    "invalid or duplicate server platform {platform:?}"
                )));
            }
        }
        validate_token(&self.deployer.package, "deployer.package")?;
        validate_binary_name(&self.deployer.binary, "deployer.binary")?;
        validate_relative_module(&self.connector.module)?;
        validate_binary_name(&self.connector.binary, "connector.binary")?;
        if self.deployer.binary == self.connector.binary {
            return Err(ReleaseError::Manifest(
                "deployer.binary and connector.binary must be distinct".to_owned(),
            ));
        }
        validate_npm_name(&self.npm.package)?;
        validate_github_repository(&self.github.repository)?;
        if self.github.tag_prefix.len() > 8
            || !self
                .github
                .tag_prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(ReleaseError::Manifest(
                "github.tag_prefix is invalid".to_owned(),
            ));
        }
        if self.targets.is_empty() {
            return Err(ReleaseError::Manifest(
                "targets must not be empty".to_owned(),
            ));
        }
        let mut ids = HashSet::new();
        let mut node_targets = HashSet::new();
        for target in &self.targets {
            validate_target(target)?;
            if !ids.insert(&target.id) {
                return Err(ReleaseError::Manifest(format!(
                    "duplicate target id {:?}",
                    target.id
                )));
            }
            if !node_targets.insert((&target.node_platform, &target.node_arch)) {
                return Err(ReleaseError::Manifest(format!(
                    "duplicate npm platform mapping {}/{}",
                    target.node_platform, target.node_arch
                )));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub version: String,
    pub source_date_epoch: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServerArtifact {
    pub repository: PathBuf,
    pub dockerfile: PathBuf,
    pub image: String,
    pub platforms: Vec<String>,
    #[serde(default)]
    pub source_commit: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RustArtifact {
    pub repository: PathBuf,
    pub package: String,
    pub binary: String,
    #[serde(default)]
    pub source_commit: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoArtifact {
    pub repository: PathBuf,
    pub module: String,
    pub binary: String,
    #[serde(default)]
    pub source_commit: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTarget {
    pub id: String,
    pub rust_target: String,
    #[serde(default)]
    pub rust_toolchain: Option<String>,
    #[serde(default)]
    pub rust_native: bool,
    pub goos: String,
    pub goarch: String,
    pub node_platform: String,
    pub node_arch: String,
    pub archive: ArchiveKind,
}

impl ReleaseTarget {
    #[must_use]
    pub fn executable_suffix(&self) -> &'static str {
        if self.goos == "windows" { ".exe" } else { "" }
    }

    #[must_use]
    pub fn npm_key(&self) -> String {
        format!("{}-{}", self.node_platform, self.node_arch)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveKind {
    Zip,
    TarGz,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NpmPackage {
    pub package: String,
    pub access: NpmAccess,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmAccess {
    Public,
    Restricted,
}

impl NpmAccess {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Restricted => "restricted",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubRelease {
    pub repository: String,
    pub tag_prefix: String,
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map_err(io_error("."))
            .map(|directory| directory.join(path))
    }
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}

/// Require a non-symlink regular file.
///
/// # Errors
///
/// Returns an error when metadata cannot be read or the path is not safe.
pub fn require_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
    }
    Ok(())
}

fn validate_relative_file(path: &Path, field: &str) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ReleaseError::Manifest(format!(
            "{field} must be a safe relative path"
        )));
    }
    Ok(())
}

fn validate_relative_module(module: &str) -> Result<()> {
    if !module.starts_with("./")
        || module.len() > 256
        || module.contains("..")
        || module.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ReleaseError::Manifest(
            "connector.module must be a bounded ./ relative Go package".to_owned(),
        ));
    }
    Ok(())
}

fn validate_binary_name(value: &str, field: &str) -> Result<()> {
    validate_token(value, field)?;
    if value.contains('.') || value.contains('/') || value.contains('\\') {
        return Err(ReleaseError::Manifest(format!(
            "{field} must be a bare binary name without an extension"
        )));
    }
    Ok(())
}

fn validate_token(value: &str, field: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ReleaseError::Manifest(format!("{field} is invalid")));
    }
    Ok(())
}

fn validate_target(target: &ReleaseTarget) -> Result<()> {
    for (value, field) in [
        (&target.id, "target.id"),
        (&target.rust_target, "target.rust_target"),
        (&target.goos, "target.goos"),
        (&target.goarch, "target.goarch"),
        (&target.node_platform, "target.node_platform"),
        (&target.node_arch, "target.node_arch"),
    ] {
        validate_token(value, field)?;
    }
    if let Some(toolchain) = &target.rust_toolchain {
        validate_token(toolchain, "target.rust_toolchain")?;
    }
    if target.id.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(ReleaseError::Manifest(
            "target.id must be lowercase".to_owned(),
        ));
    }
    let expected_node_platform = match target.goos.as_str() {
        "windows" => "win32",
        "linux" => "linux",
        "darwin" => "darwin",
        _ => {
            return Err(ReleaseError::Manifest(format!(
                "unsupported target goos {:?}",
                target.goos
            )));
        }
    };
    if target.node_platform != expected_node_platform {
        return Err(ReleaseError::Manifest(format!(
            "target {} has inconsistent Go and Node platforms",
            target.id
        )));
    }
    let expected_node_arch = match target.goarch.as_str() {
        "amd64" => "x64",
        "arm64" => "arm64",
        _ => {
            return Err(ReleaseError::Manifest(format!(
                "unsupported target goarch {:?}",
                target.goarch
            )));
        }
    };
    if target.node_arch != expected_node_arch {
        return Err(ReleaseError::Manifest(format!(
            "target {} has inconsistent Go and Node architectures",
            target.id
        )));
    }
    let expected_rust_architecture = match target.goarch.as_str() {
        "amd64" => "x86_64-",
        "arm64" => "aarch64-",
        _ => unreachable!("Go architecture was validated above"),
    };
    let rust_os_matches = match target.goos.as_str() {
        "windows" => target.rust_target.contains("windows"),
        "linux" => target.rust_target.contains("linux"),
        "darwin" => target.rust_target.contains("apple-darwin"),
        _ => unreachable!("Go operating system was validated above"),
    };
    if !target.rust_target.starts_with(expected_rust_architecture) || !rust_os_matches {
        return Err(ReleaseError::Manifest(format!(
            "target {} has inconsistent Rust and Go platforms",
            target.id
        )));
    }
    Ok(())
}

fn valid_platform(value: &str) -> bool {
    let Some((os, architecture)) = value.split_once('/') else {
        return false;
    };
    os == "linux" && matches!(architecture, "amd64" | "arm64")
}

fn validate_image_repository(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.contains('@')
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(ReleaseError::Manifest(
            "server.image must be an untagged OCI repository".to_owned(),
        ));
    }
    let tail = value.rsplit('/').next().unwrap_or(value);
    if tail.contains(':') || !value.contains('/') {
        return Err(ReleaseError::Manifest(
            "server.image must be an untagged namespace/repository value".to_owned(),
        ));
    }
    Ok(())
}

fn validate_npm_name(value: &str) -> Result<()> {
    let valid = value
        .strip_prefix('@')
        .and_then(|remaining| remaining.split_once('/'))
        .is_some_and(|(scope, name)| {
            !scope.is_empty()
                && !name.is_empty()
                && value.len() <= 214
                && scope.bytes().all(valid_package_byte)
                && name.bytes().all(valid_package_byte)
        });
    if !valid {
        return Err(ReleaseError::Manifest(
            "npm.package must be a lowercase scoped package".to_owned(),
        ));
    }
    Ok(())
}

fn valid_package_byte(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
}

fn validate_github_repository(value: &str) -> Result<()> {
    let valid = value.split_once('/').is_some_and(|(owner, repository)| {
        !owner.is_empty()
            && !repository.is_empty()
            && !repository.contains('/')
            && value.len() <= 200
            && value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/')
            })
    });
    if !valid {
        return Err(ReleaseError::Manifest(
            "github.repository must be owner/repository".to_owned(),
        ));
    }
    Ok(())
}

fn valid_source_commit(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Validate an optional full Git object identifier.
///
/// # Errors
///
/// Returns an error when the configured value is not 40 or 64 hexadecimal bytes.
pub fn validate_optional_source_commit(value: Option<&str>) -> Result<()> {
    if value.is_some_and(|commit| !valid_source_commit(commit)) {
        return Err(ReleaseError::Manifest(
            "source_commit must be a full hexadecimal Git object id".to_owned(),
        ));
    }
    Ok(())
}
