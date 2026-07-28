#![forbid(unsafe_code)]

pub mod agent_bundle;
pub mod alpha_deployment;
pub mod archive;
pub mod aws_ec2;
mod aws_sdk;
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
#[cfg(unix)]
pub mod deployment_binding;
mod digest;
pub mod error;
pub mod manifest;
pub mod plan;
pub mod publish;
pub mod receipt;
pub mod release_evidence;
#[cfg(unix)]
pub mod release_materials;
pub mod rootkey;
pub mod source;
mod strict_json;
pub mod user_deployment;

pub use cli::{Cli, run};
pub use error::{ReleaseError, Result};
