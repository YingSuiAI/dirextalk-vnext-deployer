//! Local-only import of an AWS access-key CSV.
//!
//! The credential values in this module are deliberately non-serializable,
//! non-cloneable, redacted from diagnostics, and zeroized on drop.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{ReleaseError, Result, error::io_error};

const MAX_ROOTKEY_CSV_BYTES: u64 = 16 * 1024;
const ACCESS_KEY_ID_HEADERS: [&str; 2] = ["AWSAccessKeyId", "Access key ID"];
const SECRET_ACCESS_KEY_HEADERS: [&str; 2] = ["AWSSecretKey", "Secret access key"];
const OPTIONAL_HEADERS: [&str; 2] = ["User name", "Session token"];

/// In-memory AWS credentials loaded from the user-selected `rootkey.csv`.
pub struct AwsRootKey {
    access_key_id: Zeroizing<String>,
    secret_access_key: Zeroizing<String>,
    session_token: Option<Zeroizing<String>>,
}

impl AwsRootKey {
    /// Loads exactly one credential row from a safe, bounded local CSV.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is not a safe regular file, the file is
    /// too large, or the CSV does not contain exactly one supported credential
    /// record.
    pub fn load(path: &Path) -> Result<Self> {
        let mut file = open_rootkey(path)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref()
            .take(MAX_ROOTKEY_CSV_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(io_error(path))?;
        if bytes.is_empty() || bytes.len() as u64 > MAX_ROOTKEY_CSV_BYTES {
            return Err(ReleaseError::UnsafeFile(path.to_owned()));
        }
        parse_csv(&bytes)
    }

    /// Returns a non-secret digest used only to recognize the key used for a deployment.
    #[must_use]
    pub fn access_key_id_sha256(&self) -> String {
        hex::encode(Sha256::digest(self.access_key_id.as_bytes()))
    }

    /// Returns only the final four identifier characters for an operator reminder.
    #[must_use]
    pub fn access_key_id_suffix(&self) -> &str {
        let length = self.access_key_id.len();
        &self.access_key_id[length.saturating_sub(4)..]
    }

    /// Exposes credential strings only for the duration of an AWS request setup.
    pub(crate) fn expose<R>(
        &self,
        use_credentials: impl FnOnce(&str, &str, Option<&str>) -> R,
    ) -> R {
        use_credentials(
            self.access_key_id.as_str(),
            self.secret_access_key.as_str(),
            self.session_token.as_deref().map(String::as_str),
        )
    }
}

impl fmt::Debug for AwsRootKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AwsRootKey")
            .field("access_key_id", &"[REDACTED]")
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

fn parse_csv(bytes: &[u8]) -> Result<AwsRootKey> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut reader = csv::ReaderBuilder::new()
        .flexible(false)
        .trim(csv::Trim::All)
        .from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|_| contract("rootkey.csv header is invalid"))?
        .clone();
    if headers.is_empty() {
        return Err(contract("rootkey.csv header is empty"));
    }

    let mut indexes = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (index, header) in headers.iter().enumerate() {
        if header.is_empty() || !seen.insert(header.to_owned()) {
            return Err(contract(
                "rootkey.csv contains an empty or duplicate header",
            ));
        }
        let supported = ACCESS_KEY_ID_HEADERS.contains(&header)
            || SECRET_ACCESS_KEY_HEADERS.contains(&header)
            || OPTIONAL_HEADERS.contains(&header);
        if !supported {
            return Err(contract("rootkey.csv contains an unsupported header"));
        }
        indexes.insert(header.to_owned(), index);
    }

    let access_key_index = exactly_one_header(&indexes, &ACCESS_KEY_ID_HEADERS, "access key ID")?;
    let secret_key_index =
        exactly_one_header(&indexes, &SECRET_ACCESS_KEY_HEADERS, "secret access key")?;
    let session_token_index = indexes.get("Session token").copied();

    let mut records = reader.records();
    let record = records
        .next()
        .transpose()
        .map_err(|_| contract("rootkey.csv credential row is invalid"))?
        .ok_or_else(|| contract("rootkey.csv credential row is missing"))?;
    if records.next().is_some() {
        return Err(contract(
            "rootkey.csv must contain exactly one credential row",
        ));
    }

    let access_key_id = required_field(&record, access_key_index, "access key ID")?;
    let secret_access_key = required_field(&record, secret_key_index, "secret access key")?;
    validate_access_key_id(access_key_id)?;
    validate_secret(secret_access_key, "secret access key")?;
    let session_token = session_token_index
        .and_then(|index| record.get(index))
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_secret(value, "session token")?;
            Ok::<Zeroizing<String>, ReleaseError>(Zeroizing::new(value.to_owned()))
        })
        .transpose()?;

    Ok(AwsRootKey {
        access_key_id: Zeroizing::new(access_key_id.to_owned()),
        secret_access_key: Zeroizing::new(secret_access_key.to_owned()),
        session_token,
    })
}

fn exactly_one_header(
    indexes: &BTreeMap<String, usize>,
    candidates: &[&str],
    name: &str,
) -> Result<usize> {
    let matches = candidates
        .iter()
        .filter_map(|header| indexes.get(*header).copied())
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(contract(&format!(
            "rootkey.csv must contain exactly one {name} header"
        )));
    }
    Ok(matches[0])
}

fn required_field<'a>(record: &'a csv::StringRecord, index: usize, name: &str) -> Result<&'a str> {
    record
        .get(index)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| contract(&format!("rootkey.csv {name} is empty")))
}

fn validate_access_key_id(value: &str) -> Result<()> {
    if !(16..=128).contains(&value.len()) || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(contract("rootkey.csv access key ID is malformed"));
    }
    Ok(())
}

fn validate_secret(value: &str, name: &str) -> Result<()> {
    if value.len() < 16
        || value.len() > 4096
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(contract(&format!("rootkey.csv {name} is malformed")));
    }
    Ok(())
}

fn open_rootkey(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err(ReleaseError::InvalidPath(path.to_owned()));
    }
    #[cfg(unix)]
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(io_error(path))?;
    #[cfg(not(unix))]
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(io_error(path))?;

    let metadata = file.metadata().map_err(io_error(path))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ROOTKEY_CSV_BYTES {
        return Err(ReleaseError::UnsafeFile(path.to_owned()));
    }
    #[cfg(unix)]
    {
        if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
            return Err(ReleaseError::UnsafeFile(path.to_owned()));
        }
    }
    Ok(file)
}

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.to_owned())
}

impl Drop for AwsRootKey {
    fn drop(&mut self) {
        // `Zeroizing` handles the allocations. Explicitly zeroize the option
        // container as a defense against future field-shape changes.
        self.session_token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write, path::PathBuf};

    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use tempfile::TempDir;

    use super::*;

    fn write_csv(bytes: &[u8]) -> (TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("rootkey.csv");
        #[cfg(unix)]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .expect("rootkey file");
        #[cfg(not(unix))]
        let mut file = File::create(&path).expect("rootkey file");
        file.write_all(bytes).expect("rootkey bytes");
        (directory, path)
    }

    #[test]
    fn parses_legacy_rootkey_csv_without_exposing_debug_values() {
        let (_directory, path) = write_csv(
            b"AWSAccessKeyId,AWSSecretKey\nTESTACCESSKEY0000001,test-secret-value-not-real-0000000001\n",
        );
        let rootkey = AwsRootKey::load(&path).expect("valid rootkey");
        assert_eq!(rootkey.access_key_id_suffix(), "0001");
        let debug = format!("{rootkey:?}");
        assert!(!debug.contains("AKIA"));
        assert!(!debug.contains("wJalr"));
    }

    #[test]
    fn parses_current_csv_with_bom_and_optional_columns() {
        let (_directory, path) = write_csv(
            b"\xef\xbb\xbfUser name,Access key ID,Secret access key,Session token\nroot,TESTACCESSKEY0000002,test-secret-value-not-real-0000000002,temporary-token-value\n",
        );
        let rootkey = AwsRootKey::load(&path).expect("valid rootkey");
        assert_eq!(rootkey.access_key_id_suffix(), "0002");
    }

    #[test]
    fn rejects_multiple_rows_unknown_headers_and_relative_paths() {
        let (_directory, multiple) = write_csv(
            b"AWSAccessKeyId,AWSSecretKey\nTESTACCESSKEY0000003,test-secret-value-not-real-0000000003\nTESTACCESSKEY0000004,test-secret-value-not-real-0000000004\n",
        );
        assert!(AwsRootKey::load(&multiple).is_err());

        let (_directory, unknown) = write_csv(
            b"AWSAccessKeyId,AWSSecretKey,Extra\nTESTACCESSKEY0000005,test-secret-value-not-real-0000000005,x\n",
        );
        assert!(AwsRootKey::load(&unknown).is_err());
        assert!(AwsRootKey::load(Path::new("rootkey.csv")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_and_symlink_files() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let (directory, path) = write_csv(
            b"AWSAccessKeyId,AWSSecretKey\nTESTACCESSKEY0000006,test-secret-value-not-real-0000000006\n",
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("permissions");
        assert!(AwsRootKey::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let link = directory.path().join("rootkey-link.csv");
        symlink(&path, &link).expect("symlink");
        assert!(AwsRootKey::load(&link).is_err());
    }
}
