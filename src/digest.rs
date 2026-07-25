use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

#[cfg(unix)]
use std::{
    os::fd::{BorrowedFd, OwnedFd},
    os::unix::fs::MetadataExt,
};

#[cfg(unix)]
use rustix::fs::{AtFlags, Mode, OFlags, open, openat, statat};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{ReleaseError, Result, io_error};

#[cfg(test)]
use std::sync::{Arc, Barrier};

#[cfg(test)]
thread_local! {
    static AFTER_MATERIAL_READ: std::cell::RefCell<Option<Arc<Barrier>>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_after_material_read_barrier(barrier: Option<Arc<Barrier>>) {
    AFTER_MATERIAL_READ.with(|slot| *slot.borrow_mut() = barrier);
}

#[cfg(test)]
fn after_material_read() {
    let barrier = AFTER_MATERIAL_READ.with(|slot| slot.borrow_mut().take());
    if let Some(barrier) = barrier {
        barrier.wait();
        barrier.wait();
    }
}

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

#[cfg(unix)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StableFileMetadata {
    pub device: u64,
    pub inode: u64,
    pub mode: u32,
    pub nlink: u64,
    pub size: u64,
    pub mtime: i64,
    pub mtime_nsec: u64,
    pub ctime: i64,
    pub ctime_nsec: u64,
}

#[cfg(unix)]
fn stable_metadata(metadata: &std::fs::Metadata) -> StableFileMetadata {
    StableFileMetadata {
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        nlink: metadata.nlink(),
        size: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec().cast_unsigned(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec().cast_unsigned(),
    }
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
    read_regular_file_relative_descriptor(
        root,
        relative,
        expected_size,
        Some(expected_sha256),
        maximum_size,
    )
    .map(|(_, identity)| identity)
}

/// Read a bounded regular file through a descriptor-relative no-follow path.
/// The bytes and identity come from the same stable opened descriptor, so
/// callers can safely copy pre-generated release material after validating it.
#[cfg(unix)]
pub(crate) fn read_regular_file_relative_descriptor(
    root: &Path,
    relative: &Path,
    expected_size: u64,
    expected_sha256: Option<&str>,
    maximum_size: u64,
) -> Result<(Vec<u8>, FileIdentity)> {
    let mut opened = open_relative_nofollow(root, relative)?;
    let before = opened.file.metadata().map_err(io_error(relative))?;
    validate_open_metadata(&before, maximum_size, relative)?;
    if before.len() != expected_size {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    let mut bytes = Vec::new();
    opened
        .file
        .by_ref()
        .take(maximum_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error(relative))?;
    let bytes_read = bytes.len() as u64;
    #[cfg(test)]
    after_material_read();
    let after = opened.file.metadata().map_err(io_error(relative))?;
    let path_stat = statat(&opened.directory, &opened.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
    if !same_open_metadata(&before, &after)
        || !same_path_stat(&before, &path_stat)
        || bytes_read != expected_size
        || expected_sha256.is_some_and(|expected| hex::encode(Sha256::digest(&bytes)) != expected)
    {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    Ok((
        bytes,
        FileIdentity {
            device: before.dev(),
            inode: before.ino(),
        },
    ))
}

/// Read a bounded regular file relative to an already-retained directory fd.
/// This is the fd-root counterpart to `read_regular_file_relative_descriptor`;
/// it never re-resolves the root path.
#[cfg(unix)]
pub(crate) fn read_regular_file_fd_relative_descriptor(
    root: BorrowedFd<'_>,
    relative: &Path,
    expected_size: u64,
    expected_sha256: Option<&str>,
    maximum_size: u64,
) -> Result<(Vec<u8>, FileIdentity)> {
    read_regular_file_fd_relative_descriptor_with_metadata(
        root,
        relative,
        expected_size,
        expected_sha256,
        maximum_size,
    )
    .map(|(bytes, identity, _)| (bytes, identity))
}

/// Read a bounded regular file and retain the descriptor's authoritative
/// metadata baseline alongside the bytes and inode identity.
#[cfg(unix)]
pub(crate) fn read_regular_file_fd_relative_descriptor_with_metadata(
    root: BorrowedFd<'_>,
    relative: &Path,
    expected_size: u64,
    expected_sha256: Option<&str>,
    maximum_size: u64,
) -> Result<(Vec<u8>, FileIdentity, StableFileMetadata)> {
    let mut opened = open_fd_relative_nofollow(root, relative)?;
    let before = opened.file.metadata().map_err(io_error(relative))?;
    validate_open_metadata(&before, maximum_size, relative)?;
    if before.len() != expected_size {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    let mut bytes = Vec::new();
    opened
        .file
        .by_ref()
        .take(maximum_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error(relative))?;
    let bytes_read = bytes.len() as u64;
    #[cfg(test)]
    after_material_read();
    let after = opened.file.metadata().map_err(io_error(relative))?;
    let path_stat = statat(&opened.directory, &opened.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
    if !same_open_metadata(&before, &after)
        || !same_path_stat(&before, &path_stat)
        || bytes_read != expected_size
        || expected_sha256.is_some_and(|expected| hex::encode(Sha256::digest(&bytes)) != expected)
    {
        return Err(ReleaseError::SourceMismatch(relative.to_path_buf()));
    }
    Ok((
        bytes,
        FileIdentity {
            device: before.dev(),
            inode: before.ino(),
        },
        stable_metadata(&before),
    ))
}

/// Read one bounded regular file through the same stable descriptor path used
/// for evidence members. This is used for the evidence JSON document itself.
#[cfg(unix)]
pub(crate) fn read_regular_file_descriptor(path: &Path, maximum_size: u64) -> Result<Vec<u8>> {
    let root = path
        .parent()
        .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?;
    let relative = path
        .file_name()
        .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?;
    let relative = Path::new(relative);
    let mut opened = open_relative_nofollow(root, relative)?;
    let before = opened.file.metadata().map_err(io_error(path))?;
    validate_open_metadata(&before, maximum_size, path)?;
    let mut bytes = Vec::new();
    opened
        .file
        .by_ref()
        .take(maximum_size.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error(path))?;
    let after = opened.file.metadata().map_err(io_error(path))?;
    let path_stat = statat(&opened.directory, &opened.name, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
    if bytes.is_empty()
        || bytes.len() as u64 > maximum_size
        || !same_open_metadata(&before, &after)
        || !same_path_stat(&before, &path_stat)
    {
        return Err(ReleaseError::SourceMismatch(path.to_path_buf()));
    }
    Ok(bytes)
}

#[cfg(not(unix))]
pub(crate) fn read_regular_file_descriptor(path: &Path, _maximum_size: u64) -> Result<Vec<u8>> {
    Err(ReleaseError::Manifest(format!(
        "release evidence file verification is unsupported on this platform: {}",
        path.display()
    )))
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
#[cfg(unix)]
struct OpenedFile {
    file: File,
    directory: OwnedFd,
    name: String,
}

#[cfg(unix)]
fn open_relative_nofollow(root: &Path, relative: &Path) -> Result<OpenedFile> {
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
    let file = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
    Ok(OpenedFile {
        file,
        directory,
        name: name.to_owned(),
    })
}

#[cfg(unix)]
fn open_fd_relative_nofollow(root: BorrowedFd<'_>, relative: &Path) -> Result<OpenedFile> {
    let components: Vec<_> = relative.components().collect();
    let (last, parents) = components
        .split_last()
        .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
    let mut directory = openat(
        root,
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
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
    let file = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
    Ok(OpenedFile {
        file,
        directory,
        name: name.to_owned(),
    })
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
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(unix)]
fn same_path_stat(before: &std::fs::Metadata, path_stat: &rustix::fs::Stat) -> bool {
    (path_stat.st_mode & libc::S_IFMT) == libc::S_IFREG
        && path_stat.st_dev == before.dev()
        && path_stat.st_ino == before.ino()
        && path_stat.st_nlink == before.nlink()
        && path_stat.st_size >= 0
        && path_stat.st_size.cast_unsigned() == before.len()
        && path_stat.st_mtime == before.mtime()
        && path_stat.st_mtime_nsec == before.mtime_nsec().cast_unsigned()
        && path_stat.st_ctime == before.ctime()
        && path_stat.st_ctime_nsec == before.ctime_nsec().cast_unsigned()
}
