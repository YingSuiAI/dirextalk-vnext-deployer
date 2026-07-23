use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use fs2::FileExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Serialize, de::DeserializeOwned};

use crate::{ReleaseError, Result, error::io_error};

const MAX_STATE: u64 = 4 * 1024 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Store {
    root: PathBuf,
    target: String,
    _lock: OperationLock,
}

struct OperationLock {
    #[cfg(unix)]
    file: File,
}

impl Store {
    pub fn lock(root: &Path, target: &str) -> Result<Self> {
        validate_token(target)?;
        ensure_root(root)?;
        #[cfg(not(unix))]
        {
            let _ = root;
            return Err(ReleaseError::Deployment(
                "AWS lifecycle durable locking is unsupported off Unix".into(),
            ));
        }
        #[cfg(unix)]
        {
            let lock_path = root.join(format!("{target}.lock"));
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&lock_path)
                .map_err(io_error(&lock_path))?;
            validate_file(&lock_path, &file, MAX_STATE)?;
            file.try_lock_exclusive().map_err(|error| {
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    ReleaseError::OperationLocked
                } else {
                    io_error(&lock_path)(error)
                }
            })?;
            Ok(Self {
                root: root.to_owned(),
                target: target.into(),
                _lock: OperationLock { file },
            })
        }
    }

    pub fn state_path(&self) -> PathBuf {
        self.root.join(format!("{}.json", self.target))
    }

    pub fn artifact_path(&self, suffix: &str) -> Result<PathBuf> {
        validate_suffix(suffix)?;
        Ok(self.root.join(format!("{}.{}", self.target, suffix)))
    }

    #[allow(dead_code)]
    pub fn read<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        self.read_with_bytes()
            .map(|value| value.map(|(decoded, _)| decoded))
    }

    pub fn read_with_bytes<T: DeserializeOwned>(&self) -> Result<Option<(T, Vec<u8>)>> {
        let path = self.state_path();
        let Some(bytes) = read_secure(&path, MAX_STATE)? else {
            return Ok(None);
        };
        Ok(Some((serde_json::from_slice(&bytes)?, bytes)))
    }

    pub fn write<T: Serialize>(&self, value: &T) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        if bytes.len() as u64 > MAX_STATE {
            return Err(ReleaseError::StateUnsafe(self.state_path()));
        }
        self.write_bytes(&self.state_path(), &bytes, 0o600)
    }

    pub fn write_artifact(&self, suffix: &str, bytes: &[u8], mode: u32) -> Result<PathBuf> {
        let path = self.artifact_path(suffix)?;
        self.write_bytes(&path, bytes, mode)?;
        Ok(path)
    }

    pub fn copy_artifact(
        &self,
        suffix: &str,
        source: &Path,
        expected_sha256: &str,
    ) -> Result<PathBuf> {
        let metadata = fs::symlink_metadata(source).map_err(io_error(source))?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
            return Err(ReleaseError::UnsafeFile(source.to_owned()));
        }
        let bytes = fs::read(source).map_err(io_error(source))?;
        if crate::aws_ec2::bundle::hash(&bytes) != expected_sha256 {
            return Err(ReleaseError::SourceMismatch(source.to_owned()));
        }
        self.write_artifact(suffix, &bytes, 0o600)
    }

    pub fn read_artifact(&self, suffix: &str, max: u64) -> Result<Vec<u8>> {
        let path = self.artifact_path(suffix)?;
        read_secure(&path, max)?.ok_or(ReleaseError::MissingArtifact(path))
    }

    pub fn remove_artifact(&self, suffix: &str) -> Result<()> {
        let path = self.artifact_path(suffix)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&path).map_err(io_error(&path))?;
                sync_dir(&self.root)
            }
            Ok(_) => Err(ReleaseError::StateUnsafe(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_error(&path)(error)),
        }
    }

    fn write_bytes(&self, path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
        if let Ok(metadata) = fs::symlink_metadata(path)
            && !metadata.is_file()
        {
            return Err(ReleaseError::StateUnsafe(path.to_owned()));
        }
        let mut created = None;
        for _ in 0..64 {
            let temp = path.with_extension(format!(
                "tmp.{}.{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            #[cfg(unix)]
            let opened = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(mode)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temp);
            #[cfg(not(unix))]
            let opened = OpenOptions::new().write(true).create_new(true).open(&temp);
            match opened {
                Ok(file) => {
                    created = Some((temp, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(io_error(&temp)(error)),
            }
        }
        let (temp, mut file) = created.ok_or_else(|| {
            ReleaseError::Deployment("state temporary-name collision limit exceeded".into())
        })?;
        let result = file.write_all(bytes).and_then(|()| file.sync_all());
        if let Err(error) = result {
            let _ = fs::remove_file(&temp);
            return Err(io_error(&temp)(error));
        }
        if let Err(error) = fs::rename(&temp, path) {
            let _ = fs::remove_file(&temp);
            return Err(io_error(path)(error));
        }
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(io_error(path))?;
        sync_dir(&self.root)
    }
}

#[cfg(unix)]
impl Drop for OperationLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn ensure_root(root: &Path) -> Result<()> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if !metadata.is_dir() => {
            return Err(ReleaseError::StateUnsafe(root.to_owned()));
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(root).map_err(io_error(root))?;
        }
        Err(error) => return Err(io_error(root)(error)),
    }
    #[cfg(unix)]
    {
        fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(io_error(root))?;
        let metadata = fs::symlink_metadata(root).map_err(io_error(root))?;
        if !metadata.is_dir()
            || metadata.mode() & 0o777 != 0o700
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(ReleaseError::StateUnsafe(root.to_owned()));
        }
    }
    Ok(())
}

fn read_secure(path: &Path, max: u64) -> Result<Option<Vec<u8>>> {
    #[cfg(unix)]
    let opened = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path);
    #[cfg(not(unix))]
    let opened = OpenOptions::new().read(true).open(path);
    let file = match opened {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_error(path)(error)),
    };
    #[cfg(unix)]
    validate_file(path, &file, max)?;
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error(path))?;
    if bytes.len() as u64 > max {
        return Err(ReleaseError::StateUnsafe(path.to_owned()));
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn validate_file(path: &Path, file: &File, max: u64) -> Result<()> {
    let metadata = file.metadata().map_err(io_error(path))?;
    if !metadata.is_file()
        || metadata.len() > max
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(ReleaseError::StateUnsafe(path.to_owned()));
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io_error(path))
}

fn validate_token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ReleaseError::Deployment(
            "state target token is invalid".into(),
        ));
    }
    Ok(())
}

fn validate_suffix(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ReleaseError::Deployment(
            "state artifact suffix is invalid".into(),
        ));
    }
    Ok(())
}
