use std::{
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{ReleaseError, Result},
    manifest::{LoadedManifest, validate_optional_source_commit},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceRevisions {
    pub server: String,
    pub deployer: String,
    pub connector: String,
}

impl SourceRevisions {
    /// Resolve exact source commits from manifest pins or repository `HEAD`.
    ///
    /// # Errors
    ///
    /// Returns an error when a configured or resolved commit is invalid.
    pub fn resolve(loaded: &LoadedManifest) -> Result<Self> {
        Ok(Self {
            server: resolve_one(
                &loaded.server_repository(),
                loaded.manifest.server.source_commit.as_deref(),
            )?,
            deployer: resolve_one(
                &loaded.deployer_repository(),
                loaded.manifest.deployer.source_commit.as_deref(),
            )?,
            connector: resolve_one(
                &loaded.connector_repository(),
                loaded.manifest.connector.source_commit.as_deref(),
            )?,
        })
    }

    /// Verify that every source remains clean and exactly matches this release.
    ///
    /// # Errors
    ///
    /// Returns an error for a dirty worktree, revision mismatch, or Git failure.
    pub fn verify_publishable(&self, loaded: &LoadedManifest) -> Result<()> {
        Self::verify_repositories([
            (loaded.server_repository(), self.server.as_str()),
            (loaded.deployer_repository(), self.deployer.as_str()),
            (loaded.connector_repository(), self.connector.as_str()),
        ])
    }

    pub(crate) fn verify_binary_sources(&self, loaded: &LoadedManifest) -> Result<()> {
        Self::verify_repositories([
            (loaded.deployer_repository(), self.deployer.as_str()),
            (loaded.connector_repository(), self.connector.as_str()),
        ])
    }

    pub(crate) fn verify_server_source(&self, loaded: &LoadedManifest) -> Result<()> {
        Self::verify_repositories([(loaded.server_repository(), self.server.as_str())])
    }

    fn verify_repositories<const N: usize>(repositories: [(PathBuf, &str); N]) -> Result<()> {
        for (repository, expected) in repositories {
            let actual = git_output(&repository, &["rev-parse", "HEAD"])?;
            if !actual.eq_ignore_ascii_case(expected) {
                return Err(ReleaseError::SourceMismatch(repository));
            }
            let status = git_output(
                &repository,
                &["status", "--porcelain=v1", "--untracked-files=normal"],
            )?;
            if !status.is_empty() {
                return Err(ReleaseError::DirtyRepository(repository));
            }
        }
        Ok(())
    }
}

/// Verify one externally supplied source root against an exact release commit.
///
/// This is deliberately read-only: it only invokes `git rev-parse` and
/// `git status`, and never fetches, checks out, or mutates the repository.
pub(crate) fn verify_source_root(repository: &Path, expected: &str) -> Result<()> {
    let metadata =
        std::fs::symlink_metadata(repository).map_err(crate::error::io_error(repository))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseError::InvalidPath(repository.to_path_buf()));
    }
    let identity = source_root_identity(&metadata);
    let actual = git_output(repository, &["rev-parse", "HEAD"])?;
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(ReleaseError::SourceMismatch(repository.to_path_buf()));
    }
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    if !status.is_empty() {
        return Err(ReleaseError::DirtyRepository(repository.to_path_buf()));
    }
    let after =
        std::fs::symlink_metadata(repository).map_err(crate::error::io_error(repository))?;
    if after.file_type().is_symlink() || !after.is_dir() || source_root_identity(&after) != identity
    {
        return Err(ReleaseError::SourceMismatch(repository.to_path_buf()));
    }
    Ok(())
}

fn source_root_identity(metadata: &std::fs::Metadata) -> (u64, u64, u64, u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        (
            metadata.dev(),
            metadata.ino(),
            metadata.mtime().cast_unsigned(),
            metadata.mtime_nsec().cast_unsigned(),
        )
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |value| value.as_nanos() as u64);
        (0, 0, metadata.len(), modified)
    }
}

fn resolve_one(repository: &Path, configured: Option<&str>) -> Result<String> {
    validate_optional_source_commit(configured)?;
    if let Some(configured) = configured {
        return Ok(configured.to_ascii_lowercase());
    }
    let revision = git_output(repository, &["rev-parse", "HEAD"])?;
    validate_optional_source_commit(Some(&revision))?;
    Ok(revision.to_ascii_lowercase())
}

fn git_output(repository: &Path, arguments: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(repository)
        .output()
        .map_err(|_| ReleaseError::CommandStart("git".to_owned()))?;
    if !output.status.success() {
        return Err(ReleaseError::CommandFailed {
            program: "git".to_owned(),
            status: output.status,
        });
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|_| ReleaseError::Manifest("Git returned non-UTF-8 output".to_owned()))
}
