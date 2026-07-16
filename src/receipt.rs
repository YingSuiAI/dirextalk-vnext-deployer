use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    digest::{FileDigest, digest_regular_file},
    error::{ReleaseError, Result, io_error},
    source::SourceRevisions,
};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BinarySourceRevisions {
    pub deployer: String,
    pub connector: String,
}

impl From<&SourceRevisions> for BinarySourceRevisions {
    fn from(sources: &SourceRevisions) -> Self {
        Self {
            deployer: sources.deployer.clone(),
            connector: sources.connector.clone(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReceipt {
    pub schema_version: u32,
    pub version: String,
    pub target: String,
    pub sources: BinarySourceRevisions,
    pub binaries: BTreeMap<String, FileDigest>,
}

impl BuildReceipt {
    /// Write a per-target receipt that binds both binaries to source revisions.
    ///
    /// # Errors
    ///
    /// Returns an error when either binary is unsafe or the receipt cannot be written.
    pub fn write(
        path: &Path,
        version: &str,
        target: &str,
        sources: &SourceRevisions,
        binaries: &[(&str, &Path)],
    ) -> Result<Self> {
        let binaries = binaries
            .iter()
            .map(|(name, binary)| {
                Ok((
                    (*name).to_owned(),
                    digest_regular_file(binary, MAX_BINARY_BYTES)?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let receipt = Self {
            schema_version: 1,
            version: version.to_owned(),
            target: target.to_owned(),
            sources: sources.into(),
            binaries,
        };
        let mut encoded = serde_json::to_vec_pretty(&receipt)?;
        encoded.push(b'\n');
        fs::write(path, encoded).map_err(io_error(path))?;
        Ok(receipt)
    }

    pub(crate) fn load_and_verify(
        path: &Path,
        version: &str,
        target: &str,
        sources: &SourceRevisions,
        binaries: &[(&str, &Path)],
    ) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > MAX_RECEIPT_BYTES
        {
            return Err(ReleaseError::MissingArtifact(path.to_path_buf()));
        }
        let receipt: Self = serde_json::from_slice(&fs::read(path).map_err(io_error(path))?)?;
        if receipt.schema_version != 1
            || receipt.version != version
            || receipt.target != target
            || receipt.sources != BinarySourceRevisions::from(sources)
            || receipt.binaries.len() != binaries.len()
        {
            return Err(ReleaseError::SourceMismatch(path.to_path_buf()));
        }
        for (name, binary) in binaries {
            let expected = receipt
                .binaries
                .get(*name)
                .ok_or_else(|| ReleaseError::MissingArtifact(path.to_path_buf()))?;
            let actual = digest_regular_file(binary, MAX_BINARY_BYTES)?;
            if expected != &actual {
                return Err(ReleaseError::SourceMismatch(binary.to_path_buf()));
            }
        }
        Ok(receipt)
    }
}
