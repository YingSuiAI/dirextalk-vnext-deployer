use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

#[cfg(unix)]
use rustix::fs::{Mode, OFlags, open, openat};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ReleaseError, Result, io_error};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileDigest {
    pub sha256: String,
    pub size: u64,
}

pub(crate) fn digest_regular_file(path: &Path, maximum_size: u64) -> Result<FileDigest> {
    let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(ReleaseError::MissingArtifact(path.to_path_buf()));
    }
    Ok(FileDigest {
        sha256: sha256_file(path)?,
        size: metadata.len(),
    })
}

pub(crate) fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).map_err(io_error(path))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).map_err(io_error(path))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Identity of the opened inode used to reject aliases and hardlinks across
/// one evidence document. It is intentionally derived from the descriptor,
/// not a path lookup.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    pub device: u64,
    #[cfg(unix)]
    pub inode: u64,
    #[cfg(not(unix))]
    pub path: std::path::PathBuf,
}

/// Verify one bounded regular file through a no-follow descriptor.
///
/// On Unix this opens every path component relative to an `O_NOFOLLOW` root
/// descriptor and hashes the opened file. The opened descriptor is checked for
/// regular type, a single hardlink, bounded growth, and unchanged device,
/// inode, size, and mtime before/after reading. Other platforms fail closed
/// rather than falling back to a check-then-open race.
#[cfg(unix)]
pub(crate) fn verify_regular_file_descriptor(
    root: &Path,
    relative: &Path,
    expected_size: u64,
    expected_sha256: &str,
    maximum_size: u64,
) -> Result<FileIdentity> {
    let file = open_relative_nofollow(root, relative)?;
    let before = file.metadata().map_err(io_error(relative))?;
    validate_open_metadata(&before, maximum_size, relative)?;
    if before.len() != expected_size {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    let mut file = file;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file.read(&mut buffer).map_err(io_error(relative))?;
        if count == 0 {
            break;
        }
        bytes_read = bytes_read.saturating_add(count as u64);
        if bytes_read > maximum_size {
            return Err(ReleaseError::MissingArtifact(relative.to_path_buf()));
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata().map_err(io_error(relative))?;
    if !same_open_metadata(&before, &after)
        || bytes_read != expected_size
        || hex::encode(hasher.finalize()) != expected_sha256
    {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    Ok(FileIdentity {
        device: before.dev(),
        inode: before.ino(),
    })
}

/// Non-Unix builds deliberately fail closed because std cannot express a
/// descriptor-relative no-follow open portably.
#[cfg(not(unix))]
pub(crate) fn verify_regular_file_descriptor(
    _root: &Path,
    relative: &Path,
    _expected_size: u64,
    _expected_sha256: &str,
    _maximum_size: u64,
) -> Result<FileIdentity> {
    Err(ReleaseError::Manifest(format!(
        "release evidence file verification is unsupported on this platform: {}",
        relative.display()
    )))
}

#[cfg(unix)]
fn open_relative_nofollow(root: &Path, relative: &Path) -> Result<File> {
    let components: Vec<_> = relative.components().collect();
    let (last, parents) = components
        .split_last()
        .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error(root)(std::io::Error::from(error)))?;
    let mut directory = root_fd;
    for component in parents {
        let std::path::Component::Normal(name) = component else {
            return Err(ReleaseError::InvalidPath(relative.to_path_buf()));
        };
        let name = name
            .to_str()
            .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
        directory = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
    }
    let std::path::Component::Normal(name) = last else {
        return Err(ReleaseError::InvalidPath(relative.to_path_buf()));
    };
    let name = name
        .to_str()
        .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
    openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| io_error(relative)(std::io::Error::from(error)))
}

#[cfg(unix)]
fn validate_open_metadata(
    metadata: &std::fs::Metadata,
    maximum_size: u64,
    path: &Path,
) -> Result<()> {
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > maximum_size
    {
        return Err(ReleaseError::MissingArtifact(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn same_open_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.is_file()
        && after.is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
}
