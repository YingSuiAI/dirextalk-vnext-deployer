use std::path::PathBuf;

#[cfg(unix)]
use std::collections::BTreeMap;

use clap::{Parser, Subcommand};
use serde_json::json;

#[cfg(unix)]
use crate::client_binding::ClientBindingStore;
use crate::{
    alpha_deployment::{
        AcceptanceObservation, AlphaLifecycle, AlphaLifecycleRecord, AlphaManifest,
        AlphaStateStore, ConnectorFence, OperationFence, ReadinessFacts,
    },
    archive::assemble,
    aws_ec2::{self, AwsEc2Manifest, ProductionAwsExecutor, ProductionRegistryExecutor},
    connector_apply::{ConnectorApplyInputs, apply},
    connector_claim::{ConnectorClaimInputs, claim},
    deployment::{DeploymentManifest, DeploymentPlan, DeploymentStateStore, DeploymentTarget},
    error::Result,
    manifest::LoadedManifest,
    plan::ReleasePlan,
    publish::{PublicationPlan, PublicationSelection},
    rootkey::AwsRootKey,
    user_deployment,
};

#[cfg(unix)]
use crate::release_evidence::ReleaseEvidenceV1;
#[cfg(unix)]
use crate::release_materials;

#[derive(Debug, Parser)]
#[command(
    name = "dirextalk-vnext-deployer",
    version = env!("DTX_RELEASE_VERSION"),
    long_version = concat!(env!("DTX_RELEASE_VERSION"), " (", env!("DTX_SOURCE_COMMIT"), ")"),
    about = "Typed Dirextalk vNext release and deployment CLI"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum DeployCommands {
    /// Plan and, with --execute, complete a new-user EC2 deployment.
    Onboard {
        /// Strict deployment configuration. The file must never contain AWS credentials.
        #[arg(long)]
        config: PathBuf,
        /// Absolute path to the user-selected AWS root access-key CSV.
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        max_monthly_usd: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Read-only inventory of deployment-tagged EC2 resources.
    Inventory {
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long)]
        region: String,
        #[arg(long = "target", required = true)]
        targets: Vec<String>,
    },
    /// Query the live Lightsail region, Ubuntu blueprint, and bundle catalog.
    Catalog {
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long)]
        region: String,
    },
    /// Resume an interrupted deployment using a freshly selected rootkey.csv.
    Resume {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        max_monthly_usd: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Read redacted deployment and credential-rotation state.
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
    },
    /// Verify live deployment health using a freshly selected rootkey.csv.
    Verify {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
    },
    /// Apply an authenticated forward update.
    Update {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Replace only the deployment-owned operator SSH /32 after the public IP changes.
    RebindSsh {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        expected_old_cidr: String,
        #[arg(long)]
        execute: bool,
    },
    /// Destroy only resources recorded as owned by this deployment.
    Destroy {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        purge_volume: bool,
        #[arg(long, requires = "purge_volume")]
        purge_volume_id: Option<String>,
    },
    /// Client binding issuance and status.
    Binding {
        #[command(subcommand)]
        command: DeployBindingCommands,
    },
    /// Root-key replacement verification.
    Credentials {
        #[command(subcommand)]
        command: DeployCredentialCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DeployBindingCommands {
    /// Issue a short-lived deployment binding after the server is verified.
    Issue {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        execute: bool,
        /// Return after issuance instead of waiting for the App to consume the ticket.
        #[arg(long)]
        no_wait: bool,
    },
    /// Query one issued ticket and clean the fallback file after consumption.
    Status {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DeployCredentialCommands {
    /// Validate rootkey.csv and display only the redacted STS account identity.
    Identify {
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
    },
    /// Verify a replacement root key and clear the post-deployment reminder.
    VerifyRotation {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        aws_rootkey_csv: PathBuf,
        #[arg(long, default_value_os_t = default_user_state_dir())]
        state_dir: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// New-user deployment, lifecycle, binding, and credential rotation.
    Deploy {
        #[command(subcommand)]
        command: DeployCommands,
    },
    /// Strictly validate a release manifest and its source paths.
    Validate {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Read-only validate a canonical local release-evidence contract.
    #[command(
        name = "release-evidence-validate",
        aliases = ["evidence-validate", "validate-evidence"]
    )]
    ReleaseEvidenceValidate {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        manifest: Option<PathBuf>,
        /// Optional `component=repository` roots for clean/source checks.
        #[arg(long = "source-root", alias = "root")]
        source_roots: Vec<String>,
    },
    /// Atomically bind pre-generated local release material into immutable evidence.
    /// Run this on a dedicated release-operator UID: every output-parent path
    /// component must be owned by that UID or root, and never group/other writable.
    #[command(name = "release-evidence-assemble")]
    ReleaseEvidenceAssemble {
        #[arg(long)]
        inputs: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long = "source-root")]
        source_roots: Vec<String>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Compose five canonical component fragments into release-inputs material.
    #[command(name = "release-inputs-compose")]
    ReleaseInputsCompose {
        #[arg(long = "fragment", required = true)]
        fragments: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read-only verify one finalized, self-contained release-materials directory.
    #[command(name = "release-materials-validate")]
    ReleaseMaterialsValidate { directory: PathBuf },
    /// Print the immutable local build plan without executing it.
    Plan {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output_dir: PathBuf,
        #[arg(long = "target")]
        targets: Vec<String>,
        #[arg(long)]
        without_server_image: bool,
    },
    /// Build selected local artifacts. This is a dry run without --execute.
    Build {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output_dir: PathBuf,
        #[arg(long = "target")]
        targets: Vec<String>,
        #[arg(long)]
        server_image: bool,
        #[arg(long)]
        execute: bool,
    },
    /// Package prebuilt Rust/Go binaries and generate npm/GitHub metadata.
    Assemble {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "artifacts")]
        artifacts_dir: PathBuf,
        #[arg(long, default_value = "dist")]
        output_dir: PathBuf,
    },
    /// Publish selected destinations. This is a dry run without --execute.
    Publish {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = "dist")]
        release_dir: PathBuf,
        #[arg(long)]
        push_image: bool,
        #[arg(long)]
        publish_npm: bool,
        #[arg(long)]
        publish_github: bool,
        #[arg(long)]
        execute: bool,
    },
    /// Strictly validate the offline deployment contract; never contacts a host.
    DeploymentValidate {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Print the deterministic offline deployment action plan.
    DeploymentPlan {
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Read one durable offline operation record from the fixed local state directory.
    DeploymentStatus {
        #[arg(long)]
        operation_id: String,
    },
    /// Validate the sole fresh-only Internal Test Alpha schema-3 package.
    DeploymentAlphaValidate {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        package_root: PathBuf,
    },
    /// Create the exact Alpha Planned record; dry-run unless --execute is present.
    DeploymentAlphaPlan {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        package_root: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        operation_epoch: u64,
        #[arg(long)]
        connector_id: String,
        #[arg(long)]
        connector_generation: u64,
        #[arg(long)]
        connector_lease_id: String,
        #[arg(long)]
        connector_lease_epoch: u64,
        #[arg(long)]
        execute: bool,
    },
    /// Advance exactly one durable Alpha lifecycle edge.
    DeploymentAlphaAdvance {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        readiness: Option<PathBuf>,
        #[arg(long)]
        receipt: Option<PathBuf>,
        #[arg(long)]
        execute: bool,
    },
    /// Read one redacted schema-3 Alpha lifecycle record.
    DeploymentAlphaStatus {
        #[arg(long)]
        operation_id: String,
    },
    /// Apply one Server-issued Connector bootstrap plan on this Connector host.
    DeploymentConnectorApply {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        handoff: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        enrollment_ca: PathBuf,
        #[arg(long)]
        control_ca: PathBuf,
        #[arg(long)]
        issuer_ca: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Create or exactly replay one local Connector-host deployment operation.
    DeploymentConnectorClaim {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        target: String,
        #[arg(long)]
        predecessor_operation_id: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Issue one short-lived client binding through a verified EC2 deployment.
    #[cfg(unix)]
    Ec2ClientBindingIssue {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Recover only the admitted 0.1.1-to-0.1.4 false-runtime incident.
    #[command(
        name = "ec2-recover-runtime-011-to-014",
        alias = "ec2-recover-runtime011-to014"
    )]
    Ec2RecoverRuntime011To014 {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        recovery_helper: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Plan one immutable AWS EC2 vNext node (dry run).
    Ec2Plan {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        max_monthly_usd: Option<u32>,
    },
    /// Apply or resume one AWS EC2 node; requires explicit --execute.
    Ec2Apply {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        max_monthly_usd: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Resume an interrupted AWS EC2 apply.
    Ec2Resume {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        max_monthly_usd: u32,
        #[arg(long)]
        execute: bool,
    },
    /// Read redacted AWS EC2 ownership state.
    Ec2Status {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
    },
    /// Verify DNS/TLS/health and the immutable release receipt.
    Ec2Verify {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
    },
    /// Apply or resume the authenticated forward update; dry-run unless --execute.
    Ec2Update {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Rebind only the exact operator SSH /32 on one owned security group.
    Ec2RebindOperatorCidr {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        expected_old_cidr: String,
        #[arg(long)]
        execute: bool,
    },
    /// Destroy only recorded owned EC2 resources.
    Ec2Destroy {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
        #[arg(long)]
        execute: bool,
        #[arg(long)]
        purge_volume: bool,
        #[arg(long, requires = "purge_volume")]
        purge_volume_id: Option<String>,
    },
}

/// Execute a parsed CLI command.
///
/// # Errors
///
/// Returns an error when validation, planning, local artifact work, or an
/// explicitly confirmed publication fails.
#[allow(clippy::too_many_lines)]
pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Deploy { command } => match command {
            DeployCommands::Catalog {
                aws_rootkey_csv,
                region,
            } => {
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::lightsail_catalog(&region, &rootkey)?)?;
            }
            DeployCommands::Inventory {
                aws_rootkey_csv,
                region,
                targets,
            } => {
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::inventory_owned_ec2(
                    &region, &targets, &rootkey,
                )?)?;
            }
            DeployCommands::Onboard {
                config,
                aws_rootkey_csv,
                state_dir,
                max_monthly_usd,
                execute,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::onboard_ec2(
                    &manifest,
                    &state_dir,
                    max_monthly_usd,
                    execute,
                    &rootkey,
                )?)?;
            }
            DeployCommands::Resume {
                config,
                aws_rootkey_csv,
                state_dir,
                max_monthly_usd,
                execute,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::resume_ec2(
                    &manifest,
                    &state_dir,
                    max_monthly_usd,
                    execute,
                    &rootkey,
                )?)?;
            }
            DeployCommands::Status { config, state_dir } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                print_json(&user_deployment::status_ec2(&manifest, &state_dir)?)?;
            }
            DeployCommands::Verify {
                config,
                aws_rootkey_csv,
                state_dir,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::verify_ec2(
                    &manifest, &state_dir, &rootkey,
                )?)?;
            }
            DeployCommands::Update {
                config,
                aws_rootkey_csv,
                state_dir,
                execute,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::update_ec2(
                    &manifest, &state_dir, execute, &rootkey,
                )?)?;
            }
            DeployCommands::RebindSsh {
                config,
                aws_rootkey_csv,
                state_dir,
                expected_old_cidr,
                execute,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::rebind_operator_cidr_ec2(
                    &manifest,
                    &state_dir,
                    &expected_old_cidr,
                    execute,
                    &rootkey,
                )?)?;
            }
            DeployCommands::Destroy {
                config,
                aws_rootkey_csv,
                state_dir,
                execute,
                purge_volume,
                purge_volume_id,
            } => {
                let manifest = AwsEc2Manifest::load(&config)?;
                let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                print_json(&user_deployment::destroy_ec2(
                    &manifest,
                    &state_dir,
                    execute,
                    purge_volume,
                    purge_volume_id.as_deref(),
                    &rootkey,
                )?)?;
            }
            DeployCommands::Binding { command } => match command {
                DeployBindingCommands::Issue {
                    config,
                    state_dir,
                    output,
                    execute,
                    no_wait,
                } => {
                    #[cfg(not(unix))]
                    {
                        let _ = (config, state_dir, output, execute, no_wait);
                        return Err(crate::ReleaseError::UnsupportedPlatform(
                            "client binding issuance requires Unix",
                        ));
                    }
                    #[cfg(unix)]
                    {
                        if !execute {
                            return Err(crate::ReleaseError::Deployment(
                                "deploy binding-issue requires --execute".into(),
                            ));
                        }
                        let manifest = AwsEc2Manifest::load(&config)?;
                        print_json(&crate::deployment_binding::issue_ec2(
                            &manifest,
                            &state_dir,
                            &output,
                            &ProductionAwsExecutor,
                        )?)?;
                        if !no_wait {
                            print_json(&crate::deployment_binding::wait_ec2(
                                &manifest, &state_dir, &output,
                            )?)?;
                        }
                    }
                }
                DeployBindingCommands::Status {
                    config,
                    state_dir,
                    output,
                } => {
                    #[cfg(not(unix))]
                    {
                        let _ = (config, state_dir, output);
                        return Err(crate::ReleaseError::UnsupportedPlatform(
                            "deployment binding status requires Unix",
                        ));
                    }
                    #[cfg(unix)]
                    {
                        let manifest = AwsEc2Manifest::load(&config)?;
                        print_json(&crate::deployment_binding::status_ec2(
                            &manifest, &state_dir, &output,
                        )?)?;
                    }
                }
            },
            DeployCommands::Credentials { command } => match command {
                DeployCredentialCommands::Identify { aws_rootkey_csv } => {
                    let rootkey = AwsRootKey::load(&aws_rootkey_csv)?;
                    print_json(&user_deployment::identify_rootkey(&rootkey)?)?;
                }
                DeployCredentialCommands::VerifyRotation {
                    config,
                    aws_rootkey_csv,
                    state_dir,
                } => {
                    let manifest = AwsEc2Manifest::load(&config)?;
                    let replacement = AwsRootKey::load(&aws_rootkey_csv)?;
                    print_json(&user_deployment::verify_rotation(
                        &manifest,
                        &state_dir,
                        &replacement,
                    )?)?;
                }
            },
        },
        Commands::Validate { manifest } => {
            let loaded = LoadedManifest::load(&manifest)?;
            print_json(&json!({
                "valid": true,
                "schema_version": loaded.manifest.schema_version,
                "version": loaded.manifest.release.version,
                "image": loaded.manifest.server.image,
                "targets": loaded.manifest.targets.iter().map(|target| &target.id).collect::<Vec<_>>()
            }))?;
        }
        Commands::ReleaseEvidenceValidate {
            evidence,
            manifest,
            source_roots,
        } => {
            #[cfg(not(unix))]
            {
                let _ = (evidence, manifest, source_roots);
                return Err(crate::error::ReleaseError::UnsupportedPlatform(
                    "release-evidence-validate requires a Unix release host",
                ));
            }
            #[cfg(unix)]
            {
                let roots = parse_source_roots(&source_roots)?;
                let loaded = if roots.is_empty() {
                    ReleaseEvidenceV1::load(&evidence)?
                } else {
                    ReleaseEvidenceV1::load_with_source_roots(&evidence, &roots)?
                };
                if let Some(manifest_path) = manifest.as_deref() {
                    let release_manifest = LoadedManifest::load(manifest_path)?;
                    loaded.cross_check_manifest(&release_manifest)?;
                }
                print_json(&json!({
                    "valid": true,
                    "schema": &loaded.schema,
                    "schema_version": loaded.schema_version,
                    "version": &loaded.release.version,
                    "source_date_epoch": loaded.release.source_date_epoch,
                    "components": loaded.components.iter().map(|component| &component.component).collect::<Vec<_>>(),
                    "source_roots_checked": roots.keys().collect::<Vec<_>>(),
                    "manifest_checked": manifest.is_some(),
                    "attestations": loaded.attestations.len()
                        + loaded.components.iter().map(|component| component.attestations.len()).sum::<usize>(),
                }))?;
            }
        }
        Commands::ReleaseEvidenceAssemble {
            inputs,
            manifest,
            source_roots,
            output,
        } => {
            #[cfg(not(unix))]
            {
                let _ = (inputs, manifest, source_roots, output);
                return Err(crate::error::ReleaseError::UnsupportedPlatform(
                    "release-evidence-assemble requires a Unix release host",
                ));
            }
            #[cfg(unix)]
            {
                let roots = parse_source_roots(&source_roots)?;
                let evidence = release_materials::assemble(&inputs, &manifest, &roots, &output)?;
                print_json(&json!({
                    "assembled": true,
                    "output": output,
                    "schema": evidence.schema,
                    "schema_version": evidence.schema_version,
                    "components": evidence.components.iter().map(|component| &component.component).collect::<Vec<_>>(),
                }))?;
            }
        }
        Commands::ReleaseInputsCompose { fragments, output } => {
            #[cfg(not(unix))]
            {
                let _ = (fragments, output);
                return Err(crate::error::ReleaseError::UnsupportedPlatform(
                    "release-inputs-compose requires a Unix release host",
                ));
            }
            #[cfg(unix)]
            {
                let inputs = release_materials::compose(&fragments, &output)?;
                print_json(&json!({
                    "composed": true,
                    "output": output,
                    "schema": inputs.schema,
                    "schema_version": inputs.schema_version,
                    "components": inputs.components.iter().map(|component| &component.component).collect::<Vec<_>>(),
                }))?;
            }
        }
        Commands::ReleaseMaterialsValidate { directory } => {
            #[cfg(not(unix))]
            {
                let _ = directory;
                return Err(crate::error::ReleaseError::UnsupportedPlatform(
                    "release-materials-validate requires a Unix release host",
                ));
            }
            #[cfg(unix)]
            {
                release_materials::ReleaseMaterialsV1::validate_dir(&directory)?;
            }
        }
        Commands::Plan {
            manifest,
            artifacts_dir,
            output_dir,
            targets,
            without_server_image,
        } => {
            let loaded = LoadedManifest::load(&manifest)?;
            let plan = ReleasePlan::create(
                &loaded,
                &artifacts_dir,
                &output_dir,
                &targets,
                !without_server_image,
            )?;
            print_json(&plan)?;
        }
        Commands::Build {
            manifest,
            artifacts_dir,
            output_dir,
            targets,
            server_image,
            execute,
        } => {
            let loaded = LoadedManifest::load(&manifest)?;
            let plan =
                ReleasePlan::create(&loaded, &artifacts_dir, &output_dir, &targets, server_image)?;
            if execute {
                plan.execute(&loaded)?;
            }
            print_json(&plan)?;
        }
        Commands::Assemble {
            manifest,
            artifacts_dir,
            output_dir,
        } => {
            let loaded = LoadedManifest::load(&manifest)?;
            let release = assemble(&loaded, &artifacts_dir, &output_dir)?;
            print_json(&release)?;
        }
        Commands::Publish {
            manifest,
            release_dir,
            push_image,
            publish_npm,
            publish_github,
            execute,
        } => {
            let loaded = LoadedManifest::load(&manifest)?;
            let selection = PublicationSelection {
                image: push_image,
                npm: publish_npm,
                github: publish_github,
            };
            let plan = PublicationPlan::create(&loaded, &release_dir, selection)?;
            if execute {
                plan.execute(&loaded)?;
            }
            print_json(&plan)?;
        }
        Commands::DeploymentValidate { manifest } => {
            let loaded = DeploymentManifest::load(&manifest)?;
            print_json(
                &json!({"valid": true, "schema_version": loaded.contract().schema_version,
                "manifest_digest": loaded.digest(), "targets": loaded.contract().targets.iter().map(DeploymentTarget::id).collect::<Vec<_>>() }),
            )?;
        }
        Commands::DeploymentPlan { manifest } => {
            let loaded = DeploymentManifest::load(&manifest)?;
            print_json(&DeploymentPlan::create(&loaded))?;
        }
        Commands::DeploymentStatus { operation_id } => {
            print_json(&DeploymentStateStore::fixed()?.read(&operation_id)?)?;
        }
        Commands::DeploymentAlphaValidate {
            manifest,
            package_root,
        } => {
            let manifest = AlphaManifest::load(&manifest)?;
            let package = manifest.verify_package(&package_root)?;
            print_json(&json!({
                "valid": true,
                "schema_version": manifest.contract().schema_version,
                "target": &manifest.contract().target.id,
                "manifest_digest": package.manifest_digest,
                "package_digest": package.package_digest,
                "component_digests": package.component_digests,
            }))?;
        }
        Commands::DeploymentAlphaPlan {
            manifest,
            package_root,
            operation_id,
            operation_epoch,
            connector_id,
            connector_generation,
            connector_lease_id,
            connector_lease_epoch,
            execute,
        } => {
            let manifest = AlphaManifest::load(&manifest)?;
            let package = manifest.verify_package(&package_root)?;
            let record = AlphaLifecycleRecord::planned(
                &manifest,
                &package,
                ConnectorFence {
                    connector_id,
                    generation: connector_generation,
                    lease_id: connector_lease_id,
                    lease_epoch: connector_lease_epoch,
                },
                OperationFence {
                    operation_id,
                    epoch: operation_epoch,
                },
            )?;
            let record = if execute {
                AlphaStateStore::fixed()?.create(&record)?
            } else {
                record
            };
            print_json(&record)?;
        }
        Commands::DeploymentAlphaAdvance {
            operation_id,
            to,
            readiness,
            receipt,
            execute,
        } => {
            if !execute {
                return Err(crate::error::ReleaseError::Deployment(
                    "deployment-alpha-advance requires --execute".into(),
                ));
            }
            let next = parse_alpha_lifecycle(&to)?;
            let readiness = readiness.as_deref().map(ReadinessFacts::load).transpose()?;
            let acceptance = receipt
                .as_deref()
                .map(AcceptanceObservation::load)
                .transpose()?;
            let record =
                AlphaStateStore::fixed()?.advance(&operation_id, next, readiness, acceptance)?;
            print_json(&record)?;
        }
        Commands::DeploymentAlphaStatus { operation_id } => {
            print_json(&AlphaStateStore::fixed()?.read(&operation_id)?)?;
        }
        Commands::DeploymentConnectorApply {
            operation_id,
            manifest,
            target,
            plan,
            handoff,
            config,
            enrollment_ca,
            control_ca,
            issuer_ca,
            execute,
        } => {
            if !execute {
                return Err(crate::error::ReleaseError::Deployment(
                    "deployment-connector-apply requires --execute".into(),
                ));
            }
            let result = apply(&ConnectorApplyInputs {
                operation_id,
                manifest,
                target,
                plan,
                handoff,
                config,
                enrollment_ca,
                control_ca,
                issuer_ca,
            })?;
            print_json(&result)?;
        }
        Commands::DeploymentConnectorClaim {
            operation_id,
            manifest,
            target,
            predecessor_operation_id,
            execute,
        } => {
            if !execute {
                return Err(crate::error::ReleaseError::Deployment(
                    "deployment-connector-claim requires --execute".into(),
                ));
            }
            print_json(&claim(&ConnectorClaimInputs {
                operation_id,
                manifest,
                target,
                predecessor_operation_id,
            })?)?;
        }
        #[cfg(unix)]
        Commands::Ec2ClientBindingIssue {
            manifest,
            state_dir,
            output,
            execute,
        } => {
            if !execute {
                return Err(crate::error::ReleaseError::Deployment(
                    "ec2-client-binding-issue requires --execute".into(),
                ));
            }
            let manifest = AwsEc2Manifest::load(&manifest)?;
            let binding_store = ClientBindingStore::fixed()?;
            let result = crate::client_binding::issue_ec2(
                &manifest,
                &state_dir,
                &output,
                &binding_store,
                &crate::aws_ec2::ProductionAwsExecutor,
            )?;
            print_json(&result)?;
        }
        Commands::Ec2RecoverRuntime011To014 {
            manifest,
            state_dir,
            recovery_helper,
            execute,
        } => {
            let manifest = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::recover_runtime_011_to_014(
                &manifest,
                &state_dir,
                &recovery_helper,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2Plan {
            manifest,
            max_monthly_usd,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::plan(&m, max_monthly_usd)?)?;
        }
        Commands::Ec2Apply {
            manifest,
            state_dir,
            max_monthly_usd,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::apply(
                &m,
                &state_dir,
                max_monthly_usd,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2Resume {
            manifest,
            state_dir,
            max_monthly_usd,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::resume(
                &m,
                &state_dir,
                max_monthly_usd,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2Status {
            manifest,
            state_dir,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::status_with_registry(
                &m,
                &state_dir,
                &ProductionRegistryExecutor,
            )?)?;
        }
        Commands::Ec2Verify {
            manifest,
            state_dir,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::verify(&m, &state_dir, &ProductionAwsExecutor)?)?;
        }
        Commands::Ec2Update {
            manifest,
            state_dir,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::update(
                &m,
                &state_dir,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2RebindOperatorCidr {
            manifest,
            state_dir,
            expected_old_cidr,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::rebind_operator_cidr(
                &m,
                &state_dir,
                &expected_old_cidr,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2Destroy {
            manifest,
            state_dir,
            execute,
            purge_volume,
            purge_volume_id,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::destroy(
                &m,
                &state_dir,
                execute,
                purge_volume,
                purge_volume_id.as_deref(),
                &ProductionAwsExecutor,
            )?)?;
        }
    }
    Ok(())
}

fn default_user_state_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Some(root) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(root).join("Dirextalk").join("deployments");
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Some(root) = std::env::var_os("HOME") {
            return PathBuf::from(root)
                .join("Library")
                .join("Application Support")
                .join("Dirextalk")
                .join("deployments");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(root).join("dirextalk").join("deployments");
        }
        if let Some(root) = std::env::var_os("HOME") {
            return PathBuf::from(root)
                .join(".local")
                .join("state")
                .join("dirextalk")
                .join("deployments");
        }
    }
    PathBuf::from(".dirextalk-state")
}

fn parse_alpha_lifecycle(value: &str) -> Result<AlphaLifecycle> {
    match value {
        "installed" => Ok(AlphaLifecycle::Installed),
        "started" => Ok(AlphaLifecycle::Started),
        "readiness_verified" => Ok(AlphaLifecycle::ReadinessVerified),
        "acceptance_observed" => Ok(AlphaLifecycle::AcceptanceObserved),
        "completed" => Ok(AlphaLifecycle::Completed),
        _ => Err(crate::error::ReleaseError::Deployment(
            "invalid Alpha lifecycle target".into(),
        )),
    }
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(unix)]
fn parse_source_roots(values: &[String]) -> Result<BTreeMap<String, PathBuf>> {
    let mut roots = BTreeMap::new();
    for value in values {
        let Some((component, path)) = value.split_once('=') else {
            return Err(crate::error::ReleaseError::Manifest(
                "release evidence source root must be component=path".into(),
            ));
        };
        if component.is_empty()
            || path.is_empty()
            || roots
                .insert(component.to_owned(), PathBuf::from(path))
                .is_some()
        {
            return Err(crate::error::ReleaseError::Manifest(
                "release evidence source root is empty or duplicated".into(),
            ));
        }
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn connector_claim_cli_requires_explicit_execute() {
        let cli = Cli::try_parse_from([
            "dirextalk-vnext-deployer",
            "deployment-connector-claim",
            "--operation-id",
            "018f856e-e0bd-71d2-9428-58d50cf77eaf",
            "--manifest",
            "deployment.json",
            "--target",
            "connector-a",
        ])
        .expect("claim command parses");
        assert!(matches!(
            &cli.command,
            Commands::DeploymentConnectorClaim { execute: false, .. }
        ));
        assert!(run(cli).is_err());
    }

    #[test]
    fn runtime_recovery_cli_uses_documented_canonical_name_and_hidden_legacy_alias() {
        let arguments = [
            "--manifest",
            "aws-ec2.json",
            "--recovery-helper",
            "install-vnext",
        ];
        for command in [
            "ec2-recover-runtime-011-to-014",
            "ec2-recover-runtime011-to014",
        ] {
            let cli = Cli::try_parse_from(
                ["dirextalk-vnext-deployer", command]
                    .into_iter()
                    .chain(arguments),
            )
            .expect("runtime recovery command parses");
            assert!(matches!(
                cli.command,
                Commands::Ec2RecoverRuntime011To014 { execute: false, .. }
            ));
        }

        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("ec2-recover-runtime-011-to-014"));
        assert!(!help.contains("ec2-recover-runtime011-to014"));
        assert!(
            include_str!("../COMMANDS.md").contains("ec2-recover-runtime-011-to-014 --manifest")
        );
    }
}
