#![forbid(unsafe_code)]

pub mod archive;
pub mod aws_ec2;
pub mod cli;
#[cfg(unix)]
pub mod connector_apply;
#[cfg(not(unix))]
#[path = "connector_apply_unsupported.rs"]
pub mod connector_apply;
pub mod connector_claim;
pub mod deployment;
mod digest;
pub mod error;
pub mod manifest;
pub mod plan;
pub mod publish;
pub mod receipt;
pub mod source;

pub use cli::{Cli, run};
pub use error::{ReleaseError, Result};
