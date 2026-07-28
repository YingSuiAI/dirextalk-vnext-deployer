//! New-user deployment orchestration layered over the durable provider
//! lifecycles.

#![allow(clippy::missing_errors_doc, clippy::too_many_lines)]

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    ReleaseError, Result,
    aws_ec2::{
        self, AwsEc2Manifest, AwsExecutor, Ec2State, FixedCommand, RootKeyAwsExecutor,
        StatusReport, VerifyReport, store::Store,
    },
    rootkey::AwsRootKey,
};

const ONBOARDING_SUFFIX: &str = "onboarding.json";
const MAX_ONBOARDING_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRotationState {
    pub schema: String,
    pub schema_version: u32,
    pub target: String,
    pub operation_id: String,
    pub aws_account_id: String,
    pub access_key_id_sha256: String,
    pub access_key_id_suffix: String,
    pub rotation_required: bool,
    pub integrity_sha256: String,
}

impl CredentialRotationState {
    fn new(state: &Ec2State, rootkey: &AwsRootKey) -> Result<Self> {
        let account_id = state
            .account_id
            .clone()
            .ok_or_else(|| contract("AWS account identity was not persisted"))?;
        Self {
            schema: "dirextalk.user-deployment-credentials".to_owned(),
            schema_version: 1,
            target: state.target.clone(),
            operation_id: state.operation_id.clone(),
            aws_account_id: account_id,
            access_key_id_sha256: rootkey.access_key_id_sha256(),
            access_key_id_suffix: rootkey.access_key_id_suffix().to_owned(),
            rotation_required: true,
            integrity_sha256: String::new(),
        }
        .seal()
    }

    fn seal(mut self) -> Result<Self> {
        self.integrity_sha256.clear();
        self.integrity_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(&self)?));
        Ok(self)
    }

    fn verify(&self) -> Result<()> {
        if self.schema != "dirextalk.user-deployment-credentials"
            || self.schema_version != 1
            || self.target.is_empty()
            || self.aws_account_id.len() != 12
            || !self
                .aws_account_id
                .bytes()
                .all(|byte| byte.is_ascii_digit())
            || self.access_key_id_sha256.len() != 64
            || self.access_key_id_suffix.len() != 4
        {
            return Err(ReleaseError::StateUnsafe(
                Path::new(ONBOARDING_SUFFIX).into(),
            ));
        }
        let mut copy = self.clone();
        let digest = std::mem::take(&mut copy.integrity_sha256);
        if digest != hex::encode(Sha256::digest(serde_json::to_vec(&copy)?)) {
            return Err(ReleaseError::StateUnsafe(
                Path::new(ONBOARDING_SUFFIX).into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct OnboardReport {
    pub aws_identity: AwsIdentity,
    pub region: String,
    pub planned_resources: Vec<&'static str>,
    pub rootkey_risk_notice: &'static str,
    pub deployment: Ec2State,
    pub credential_rotation: Option<CredentialRotationReminder>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AwsIdentity {
    pub account_id: String,
    pub principal_type: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CredentialRotationReminder {
    pub required: bool,
    pub access_key_id_suffix: String,
    pub message: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct UserDeploymentStatus {
    pub deployment: StatusReport,
    pub credential_rotation: Option<CredentialRotationReminder>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RotationVerification {
    pub target: String,
    pub aws_account_id: String,
    pub previous_key_inactive_or_deleted: bool,
    pub replacement_key_verified: bool,
    pub reminder_cleared: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct OwnedAwsInventory {
    pub aws_identity: AwsIdentity,
    pub region: String,
    pub targets: Vec<String>,
    pub instances: Vec<Value>,
    pub elastic_ips: Vec<Value>,
    pub security_groups: Vec<Value>,
    pub volumes: Vec<Value>,
    pub key_pairs: Vec<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LightsailCatalog {
    pub aws_identity: AwsIdentity,
    pub region: String,
    pub regions: Vec<Value>,
    pub blueprints: Vec<Value>,
    pub bundles: Vec<Value>,
}

pub fn onboard_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    max_monthly_usd: u32,
    execute: bool,
    rootkey: &AwsRootKey,
) -> Result<OnboardReport> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    let aws_identity = identify_aws_account(&executor)?;
    let state = aws_ec2::apply(manifest, state_dir, max_monthly_usd, execute, &executor)?;
    let credential_rotation = if execute {
        let rotation = CredentialRotationState::new(&state, rootkey)?;
        write_rotation_state(state_dir, &state.target, &rotation)?;
        Some(reminder(&rotation))
    } else {
        None
    };
    Ok(OnboardReport {
        aws_identity,
        region: manifest.region.clone(),
        planned_resources: ec2_planned_resources(),
        rootkey_risk_notice: rootkey_risk_notice(),
        deployment: state,
        credential_rotation,
    })
}

pub fn resume_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    max_monthly_usd: u32,
    execute: bool,
    rootkey: &AwsRootKey,
) -> Result<OnboardReport> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    let aws_identity = identify_aws_account(&executor)?;
    let state = aws_ec2::resume(manifest, state_dir, max_monthly_usd, execute, &executor)?;
    let credential_rotation = read_rotation_state(state_dir, &state.target)?
        .as_ref()
        .map(reminder);
    Ok(OnboardReport {
        aws_identity,
        region: manifest.region.clone(),
        planned_resources: ec2_planned_resources(),
        rootkey_risk_notice: rootkey_risk_notice(),
        deployment: state,
        credential_rotation,
    })
}

pub fn status_ec2(manifest: &AwsEc2Manifest, state_dir: &Path) -> Result<UserDeploymentStatus> {
    let deployment = aws_ec2::status(manifest, state_dir)?;
    let credential_rotation = read_rotation_state(state_dir, &manifest.target)?
        .as_ref()
        .map(reminder);
    Ok(UserDeploymentStatus {
        deployment,
        credential_rotation,
    })
}

pub fn verify_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    rootkey: &AwsRootKey,
) -> Result<VerifyReport> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    aws_ec2::verify(manifest, state_dir, &executor)
}

pub fn update_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    rootkey: &AwsRootKey,
) -> Result<Ec2State> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    aws_ec2::update(manifest, state_dir, execute, &executor)
}

pub fn rebind_operator_cidr_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    expected_old_cidr: &str,
    execute: bool,
    rootkey: &AwsRootKey,
) -> Result<Ec2State> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    aws_ec2::rebind_operator_cidr(manifest, state_dir, expected_old_cidr, execute, &executor)
}

pub fn destroy_ec2(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    execute: bool,
    purge_volume: bool,
    purge_volume_id: Option<&str>,
    rootkey: &AwsRootKey,
) -> Result<Ec2State> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    aws_ec2::destroy(
        manifest,
        state_dir,
        execute,
        purge_volume,
        purge_volume_id,
        &executor,
    )
}

pub fn verify_rotation(
    manifest: &AwsEc2Manifest,
    state_dir: &Path,
    replacement: &AwsRootKey,
) -> Result<RotationVerification> {
    let mut rotation = read_rotation_state(state_dir, &manifest.target)?
        .ok_or_else(|| contract("credential rotation state is missing"))?;
    if replacement.access_key_id_sha256() == rotation.access_key_id_sha256 {
        return Err(contract(
            "replacement rootkey.csv still contains the original access key",
        ));
    }
    let executor = RootKeyAwsExecutor::new(replacement)?;
    let identity = identify_aws_account(&executor)?;
    if identity.account_id != rotation.aws_account_id {
        return Err(contract(
            "replacement rootkey.csv belongs to a different AWS account",
        ));
    }
    let keys = aws_json(
        &executor,
        FixedCommand::new(
            "verify-rotation-old-key-status",
            "aws",
            ["iam", "list-access-keys", "--output", "json"],
            false,
            30,
        ),
    )?;
    let old_active = keys["AccessKeyMetadata"]
        .as_array()
        .ok_or_else(|| contract("IAM response is missing AccessKeyMetadata"))?
        .iter()
        .any(|entry| {
            entry["AccessKeyId"].as_str().is_some_and(|value| {
                hex::encode(Sha256::digest(value.as_bytes())) == rotation.access_key_id_sha256
            }) && entry["Status"].as_str() == Some("Active")
        });
    if old_active {
        return Err(contract("original AWS root access key is still active"));
    }
    rotation.rotation_required = false;
    rotation = rotation.seal()?;
    write_rotation_state(state_dir, &manifest.target, &rotation)?;
    Ok(RotationVerification {
        target: manifest.target.clone(),
        aws_account_id: identity.account_id,
        previous_key_inactive_or_deleted: true,
        replacement_key_verified: true,
        reminder_cleared: true,
    })
}

pub fn identify_rootkey(rootkey: &AwsRootKey) -> Result<AwsIdentity> {
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    identify_aws_account(&executor)
}

pub fn lightsail_catalog(region: &str, rootkey: &AwsRootKey) -> Result<LightsailCatalog> {
    if region.is_empty()
        || region.len() > 32
        || !region
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(contract("Lightsail region is invalid"));
    }
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    let aws_identity = identify_aws_account(&executor)?;
    let command = |id, action| {
        FixedCommand::new(
            id,
            "aws",
            ["lightsail", action, "--region", region, "--output", "json"],
            false,
            45,
        )
    };
    let regions = aws_array(
        &executor,
        command("lightsail-catalog-regions", "get-regions"),
        "regions",
    )?;
    let blueprints = aws_array(
        &executor,
        command("lightsail-catalog-blueprints", "get-blueprints"),
        "blueprints",
    )?;
    let bundles = aws_array(
        &executor,
        command("lightsail-catalog-bundles", "get-bundles"),
        "bundles",
    )?;
    Ok(LightsailCatalog {
        aws_identity,
        region: region.to_owned(),
        regions,
        blueprints,
        bundles,
    })
}

pub fn inventory_owned_ec2(
    region: &str,
    targets: &[String],
    rootkey: &AwsRootKey,
) -> Result<OwnedAwsInventory> {
    if targets.is_empty()
        || targets.len() > 32
        || targets.iter().any(|target| {
            target.is_empty()
                || target.len() > 63
                || !target
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(contract("inventory targets are invalid"));
    }
    let executor = RootKeyAwsExecutor::new(rootkey)?;
    let aws_identity = identify_aws_account(&executor)?;
    let target_filter = format!("Name=tag:DirextalkTarget,Values={}", targets.join(","));
    let managed_filter = "Name=tag:DirextalkManaged,Values=true";
    let instances = aws_array(
        &executor,
        FixedCommand::new(
            "inventory-owned-instances",
            "aws",
            [
                "ec2",
                "describe-instances",
                "--region",
                region,
                "--filters",
                managed_filter,
                target_filter.as_str(),
                "--output",
                "json",
            ],
            false,
            45,
        ),
        "Reservations",
    )?
    .into_iter()
    .flat_map(|reservation| {
        reservation["Instances"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    })
    .collect();
    let elastic_ips = aws_array(
        &executor,
        FixedCommand::new(
            "inventory-owned-eips",
            "aws",
            [
                "ec2",
                "describe-addresses",
                "--region",
                region,
                "--filters",
                managed_filter,
                target_filter.as_str(),
                "--output",
                "json",
            ],
            false,
            45,
        ),
        "Addresses",
    )?;
    let security_groups = aws_array(
        &executor,
        FixedCommand::new(
            "inventory-owned-security-groups",
            "aws",
            [
                "ec2",
                "describe-security-groups",
                "--region",
                region,
                "--filters",
                managed_filter,
                target_filter.as_str(),
                "--output",
                "json",
            ],
            false,
            45,
        ),
        "SecurityGroups",
    )?;
    let volumes = aws_array(
        &executor,
        FixedCommand::new(
            "inventory-owned-volumes",
            "aws",
            [
                "ec2",
                "describe-volumes",
                "--region",
                region,
                "--filters",
                managed_filter,
                target_filter.as_str(),
                "--output",
                "json",
            ],
            false,
            45,
        ),
        "Volumes",
    )?;
    let key_pairs = aws_array(
        &executor,
        FixedCommand::new(
            "inventory-owned-key-pairs",
            "aws",
            [
                "ec2",
                "describe-key-pairs",
                "--region",
                region,
                "--filters",
                managed_filter,
                target_filter.as_str(),
                "--output",
                "json",
            ],
            false,
            45,
        ),
        "KeyPairs",
    )?;
    Ok(OwnedAwsInventory {
        aws_identity,
        region: region.to_owned(),
        targets: targets.to_vec(),
        instances,
        elastic_ips,
        security_groups,
        volumes,
        key_pairs,
    })
}

fn identify_aws_account(executor: &RootKeyAwsExecutor) -> Result<AwsIdentity> {
    let identity = aws_json(
        executor,
        FixedCommand::new(
            "identify-rootkey-account",
            "aws",
            ["sts", "get-caller-identity", "--output", "json"],
            false,
            30,
        ),
    )?;
    let account_id = identity["Account"]
        .as_str()
        .filter(|value| value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .ok_or_else(|| contract("STS response is missing Account"))?
        .to_owned();
    let arn = identity["Arn"]
        .as_str()
        .ok_or_else(|| contract("STS response is missing Arn"))?;
    let principal_type = if arn.ends_with(":root") {
        "root"
    } else if arn.contains(":user/") {
        "iam-user"
    } else if arn.contains(":assumed-role/") {
        "assumed-role"
    } else {
        "other"
    };
    Ok(AwsIdentity {
        account_id,
        principal_type,
    })
}

fn ec2_planned_resources() -> Vec<&'static str> {
    vec![
        "EC2 key pair",
        "security group",
        "EC2 instance and encrypted gp3 volume",
        "Elastic IP",
        "Route53 A record",
    ]
}

const fn rootkey_risk_notice() -> &'static str {
    "AWS RootKey has account-wide authority. --execute confirms this plan; after deployment, verify a replacement key and immediately deactivate or delete the original key."
}

#[allow(clippy::needless_pass_by_value)]
fn aws_json(executor: &dyn AwsExecutor, command: FixedCommand) -> Result<Value> {
    let output = executor.run(&command)?;
    if output.status != 0 {
        return Err(contract("AWS credential verification failed"));
    }
    serde_json::from_str(&output.stdout).map_err(Into::into)
}

fn aws_array(executor: &dyn AwsExecutor, command: FixedCommand, field: &str) -> Result<Vec<Value>> {
    aws_json(executor, command)?[field]
        .as_array()
        .cloned()
        .ok_or_else(|| contract("AWS inventory response is malformed"))
}

fn reminder(state: &CredentialRotationState) -> CredentialRotationReminder {
    CredentialRotationReminder {
        required: state.rotation_required,
        access_key_id_suffix: state.access_key_id_suffix.clone(),
        message: if state.rotation_required {
            "Deployment succeeded. Create a replacement AWS root access key, verify it, then deactivate or delete the original key."
        } else {
            "Replacement AWS root access key verified and the original key is inactive or deleted."
        },
    }
}

fn read_rotation_state(state_dir: &Path, target: &str) -> Result<Option<CredentialRotationState>> {
    let store = Store::lock(state_dir, target)?;
    let bytes = match store.read_artifact(ONBOARDING_SUFFIX, MAX_ONBOARDING_BYTES) {
        Ok(bytes) => bytes,
        Err(ReleaseError::MissingArtifact(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let state: CredentialRotationState = serde_json::from_slice(&bytes)?;
    state.verify()?;
    Ok(Some(state))
}

fn write_rotation_state(
    state_dir: &Path,
    target: &str,
    state: &CredentialRotationState,
) -> Result<()> {
    state.verify()?;
    let store = Store::lock(state_dir, target)?;
    store.write_artifact(ONBOARDING_SUFFIX, &serde_json::to_vec_pretty(state)?, 0o600)?;
    Ok(())
}

fn contract(message: &str) -> ReleaseError {
    ReleaseError::Deployment(message.to_owned())
}
