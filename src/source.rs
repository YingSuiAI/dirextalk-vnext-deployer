use std::{
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(unix)]
use std::fs::{File, OpenOptions};

#[cfg(unix)]
use fs2::FileExt;

use serde::{Deserialize, Serialize};

use crate::{
    error::{ReleaseError, Result},
    manifest::{LoadedManifest, validate_optional_source_commit},
};

#[cfg(unix)]
use crate::digest::sha256_file;

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct SourceEvidenceGuard {
    repository: PathBuf,
    lock: File,
    before: SourceSnapshot,
}

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceSnapshot {
    head: String,
    tree: String,
    index_digest: String,
    index_size: u64,
    status: String,
}

#[cfg(unix)]
impl SourceEvidenceGuard {
    pub(crate) fn begin(repository: &Path) -> Result<Self> {
        let (git_dir, common_dir) = resolve_git_dirs(repository)?;
        let lock_path = common_dir.join("dirextalk-release-evidence.lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(crate::error::io_error(&lock_path))?;
        lock.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ReleaseError::OperationLocked
            } else {
                crate::error::io_error(&lock_path)(error)
            }
        })?;
        let before = snapshot(repository, &git_dir)?;
        Ok(Self {
            repository: repository.to_path_buf(),
            lock,
            before,
        })
    }

    pub(crate) fn verify_expected(&self, expected: &str) -> Result<()> {
        if !self.before.head.eq_ignore_ascii_case(expected) {
            return Err(ReleaseError::SourceMismatch(self.repository.clone()));
        }
        if !self.before.status.is_empty() {
            return Err(ReleaseError::DirtyRepository(self.repository.clone()));
        }
        Ok(())
    }

    pub(crate) fn repository(&self) -> &Path {
        &self.repository
    }

    /// The immutable tree object observed while the cooperative guard is held.
    pub(crate) fn head_tree(&self) -> &str {
        &self.before.tree
    }

    pub(crate) fn finish(self) -> Result<()> {
        let (git_dir, _) = resolve_git_dirs(&self.repository)?;
        let after = snapshot(&self.repository, &git_dir)?;
        if after != self.before {
            return Err(ReleaseError::SourceMismatch(self.repository));
        }
        let _ = self.lock.unlock();
        Ok(())
    }
}

#[cfg(unix)]
fn resolve_git_dirs(repository: &Path) -> Result<(PathBuf, PathBuf)> {
    let git_dir = git_output(repository, &["rev-parse", "--git-dir"])?;
    let common_dir = git_output(repository, &["rev-parse", "--git-common-dir"])?;
    let git_dir = resolve_git_path(repository, &git_dir)?;
    let common_dir = resolve_git_path(repository, &common_dir)?;
    for path in [&git_dir, &common_dir] {
        let metadata = std::fs::symlink_metadata(path).map_err(crate::error::io_error(path))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ReleaseError::InvalidPath(path.clone()));
        }
    }
    Ok((git_dir, common_dir))
}

#[cfg(unix)]
fn resolve_git_path(repository: &Path, value: &str) -> Result<PathBuf> {
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        repository.join(path)
    };
    std::fs::canonicalize(&path).map_err(crate::error::io_error(path))
}

#[cfg(unix)]
fn snapshot(repository: &Path, _git_dir: &Path) -> Result<SourceSnapshot> {
    let head = git_output(repository, &["rev-parse", "HEAD"])?;
    let tree = git_output(repository, &["rev-parse", "HEAD^{tree}"])?;
    let status = git_output(
        repository,
        &["status", "--porcelain=v1", "--untracked-files=normal"],
    )?;
    let index_value = git_output(repository, &["rev-parse", "--git-path", "index"])?;
    let index_path = resolve_git_path(repository, &index_value)?;
    let metadata =
        std::fs::symlink_metadata(&index_path).map_err(crate::error::io_error(&index_path))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReleaseError::UnsafeFile(index_path));
    }
    Ok(SourceSnapshot {
        head,
        tree,
        index_digest: sha256_file(&index_path)?,
        index_size: metadata.len(),
        status,
    })
}

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
#[cfg(unix)]
pub(crate) fn verify_source_root(repository: &Path, expected: &str) -> Result<()> {
    let guard = SourceEvidenceGuard::begin(repository)?;
    guard.verify_expected(expected)?;
    guard.finish()
}

#[cfg(not(unix))]
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

#[cfg(not(unix))]
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command;
    use tempfile::TempDir;

    fn git(repository: &Path, arguments: &[&str]) {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .output()
            .expect("git starts");
        assert!(output.status.success(), "git failed: {arguments:?}");
    }

    #[test]
    fn snapshot_guard_detects_tracked_mutation_and_cooperates_with_lock() {
        let root = TempDir::new().expect("root");
        fs::write(root.path().join("tracked"), b"before\n").expect("tracked");
        git(root.path(), &["init", "-b", "main"]);
        git(
            root.path(),
            &["config", "user.email", "evidence@example.invalid"],
        );
        git(root.path(), &["config", "user.name", "Evidence Test"]);
        git(root.path(), &["add", "tracked"]);
        git(root.path(), &["commit", "-m", "fixture"]);
        let expected = git_output(root.path(), &["rev-parse", "HEAD"]).expect("head");
        let guard = SourceEvidenceGuard::begin(root.path()).expect("guard");
        guard.verify_expected(&expected).expect("clean start");
        assert!(matches!(
            SourceEvidenceGuard::begin(root.path()),
            Err(ReleaseError::OperationLocked)
        ));
        fs::write(root.path().join("tracked"), b"after\n").expect("mutate");
        assert!(guard.finish().is_err());
    }
}
