use std::path::PathBuf;

use clap::{Parser, Subcommand};
use serde_json::json;

use crate::{
    archive::assemble,
    aws_ec2::{self, AwsEc2Manifest, ProductionAwsExecutor, ProductionRegistryExecutor},
    connector_apply::{ConnectorApplyInputs, apply},
    deployment::{DeploymentManifest, DeploymentPlan, DeploymentStateStore, DeploymentTarget},
    error::Result,
    manifest::LoadedManifest,
    plan::ReleasePlan,
    publish::{PublicationPlan, PublicationSelection},
};

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
enum Commands {
    /// Strictly validate a release manifest and its source paths.
    Validate {
        #[arg(long)]
        manifest: PathBuf,
    },
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
    /// Apply one Server-issued Connector bootstrap plan on this Connector host.
    DeploymentConnectorApply {
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
    /// Plan one immutable AWS EC2 vNext node (dry run).
    Ec2Plan {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
    },
    /// Apply or resume one AWS EC2 node; requires explicit --execute.
    Ec2Apply {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
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
    /// Update the exact bundle digest with a rollback receipt.
    Ec2Update {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long, default_value = ".dirextalk-ec2-state")]
        state_dir: PathBuf,
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
        Commands::DeploymentConnectorApply {
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
            let result = apply(ConnectorApplyInputs {
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
        Commands::Ec2Plan { manifest, .. } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::plan(&m)?)?;
        }
        Commands::Ec2Apply {
            manifest,
            state_dir,
            execute,
        }
        | Commands::Ec2Resume {
            manifest,
            state_dir,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::apply(
                &m,
                &state_dir,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
        Commands::Ec2Status {
            manifest,
            state_dir,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::status_with_executor(
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
            print_json(&aws_ec2::verify(&m, &state_dir)?)?;
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
                &ProductionRegistryExecutor,
            )?)?;
        }
        Commands::Ec2Destroy {
            manifest,
            state_dir,
            execute,
        } => {
            let m = AwsEc2Manifest::load(&manifest)?;
            print_json(&aws_ec2::destroy(
                &m,
                &state_dir,
                execute,
                &ProductionAwsExecutor,
            )?)?;
        }
    }
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
