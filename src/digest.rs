use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

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
