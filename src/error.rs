use std::{io, path::PathBuf, process::ExitStatus};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReleaseError {
    #[error("manifest error: {0}")]
    Manifest(String),
    #[error("invalid path: {0}")]
    InvalidPath(PathBuf),
    #[error("required file is missing or unsafe: {0}")]
    UnsafeFile(PathBuf),
    #[error("output directory must be new or empty: {0}")]
    OutputNotEmpty(PathBuf),
    #[error("artifact is missing or unsafe: {0}")]
    MissingArtifact(PathBuf),
    #[error("build step {step} requires host {required}, current host is {current}")]
    BuildHostMismatch {
        step: String,
        required: String,
        current: String,
    },
    #[error("source repository is not clean: {0}")]
    DirtyRepository(PathBuf),
    #[error("source revision does not match the assembled release: {0}")]
    SourceMismatch(PathBuf),
    #[error("no publication destination was selected")]
    NoPublicationSelected,
    #[error("publication requires --execute")]
    PublicationNotConfirmed,
    #[error("{0} credentials are not available")]
    CredentialsUnavailable(&'static str),
    #[error("external command {program} failed with {status}")]
    CommandFailed { program: String, status: ExitStatus },
    #[error("external command {0} could not be started")]
    CommandStart(String),
    #[error("I/O operation failed for {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("JSON operation failed")]
    Json(#[from] serde_json::Error),
    #[error("archive operation failed")]
    Zip(#[from] zip::result::ZipError),
}

pub type Result<T> = std::result::Result<T, ReleaseError>;

pub fn io_error(path: impl Into<PathBuf>) -> impl FnOnce(io::Error) -> ReleaseError {
    let path = path.into();
    move |source| ReleaseError::Io { path, source }
}
