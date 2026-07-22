use std::path::PathBuf;

use serde::Serialize;

use crate::{ReleaseError, Result};

pub struct ConnectorApplyInputs {
    pub operation_id: String,
    pub manifest: PathBuf,
    pub target: String,
    pub plan: PathBuf,
    pub handoff: PathBuf,
    pub config: PathBuf,
    pub enrollment_ca: PathBuf,
    pub control_ca: PathBuf,
    pub issuer_ca: PathBuf,
}

#[derive(Serialize)]
pub struct ApplyResult {
    pub operation_id: String,
    pub lifecycle_operation_id: String,
    pub state: String,
}

/// Fails closed because Host Control is Linux/Unix-only.
///
/// # Errors
/// Always returns an unsupported-platform error.
pub fn apply(_inputs: &ConnectorApplyInputs) -> Result<ApplyResult> {
    Err(ReleaseError::Deployment(
        "deployment-connector-apply is unsupported off Unix".into(),
    ))
}
