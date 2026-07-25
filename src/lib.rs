#![forbid(unsafe_code)]

pub mod agent_bundle;
pub mod archive;
pub mod aws_ec2;
pub mod cli;
#[cfg(unix)]
pub mod client_binding;
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
mod strict_json;

pub use cli::{Cli, run};
pub use error::{ReleaseError, Result};
