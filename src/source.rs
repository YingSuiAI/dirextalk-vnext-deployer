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
