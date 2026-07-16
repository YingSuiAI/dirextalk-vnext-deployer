use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde::{Deserialize, Serialize};

use crate::{
    error::{ReleaseError, Result, io_error},
    manifest::{LoadedManifest, ReleaseTarget},
    receipt::BuildReceipt,
    source::SourceRevisions,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePlan {
    pub schema_version: u32,
    pub version: String,
    pub tag: String,
    pub image: String,
    pub artifacts_directory: PathBuf,
    pub release_directory: PathBuf,
    pub sources: SourceRevisions,
    pub commands: Vec<PlannedCommand>,
    pub collections: Vec<ArtifactCollection>,
    pub receipts: Vec<BuildReceiptPlan>,
}

impl ReleasePlan {
    /// Resolve source identities and produce a non-publishing build plan.
    ///
    /// # Errors
    ///
    /// Returns an error when Git identity resolution or target selection fails.
    pub fn create(
        loaded: &LoadedManifest,
        artifacts_dir: &Path,
        output_dir: &Path,
        selected_targets: &[String],
        include_server_image: bool,
    ) -> Result<Self> {
        let sources = SourceRevisions::resolve(loaded)?;
        let artifacts_dir = absolute_from_manifest(loaded, artifacts_dir);
        let output_dir = absolute_from_manifest(loaded, output_dir);
        let targets = select_targets(loaded, selected_targets)?;
        let mut commands = Vec::new();
        let mut collections = Vec::new();
        let mut receipts = Vec::new();

        if include_server_image {
            commands.push(server_build_command(
                loaded,
                &sources,
                &artifacts_dir.join("server"),
                false,
            ));
        }

        for target in targets {
            let suffix = target.executable_suffix();
            let target_dir = artifacts_dir.join(&target.id);
            let deployer_destination =
                target_dir.join(format!("{}{suffix}", loaded.manifest.deployer.binary));
            let connector_destination =
                target_dir.join(format!("{}{suffix}", loaded.manifest.connector.binary));
            let mut rust_release_directory = loaded.deployer_repository().join("target");
            if !target.rust_native {
                rust_release_directory.push(&target.rust_target);
            }
            rust_release_directory.push("release");

            commands.push(rust_build_command(loaded, target, &sources));
            collections.push(ArtifactCollection {
                source: rust_release_directory
                    .join(format!("{}{suffix}", loaded.manifest.deployer.binary)),
                destination: deployer_destination.clone(),
            });
            commands.push(go_build_command(
                loaded,
                target,
                &sources,
                &connector_destination,
            ));
            receipts.push(BuildReceiptPlan {
                target: target.id.clone(),
                path: target_dir.join("build-receipt.json"),
                deployer_name: format!("{}{suffix}", loaded.manifest.deployer.binary),
                deployer_path: deployer_destination,
                connector_name: format!("{}{suffix}", loaded.manifest.connector.binary),
                connector_path: connector_destination,
            });
        }

        Ok(Self {
            schema_version: 1,
            version: loaded.manifest.release.version.clone(),
            tag: format!(
                "{}{}",
                loaded.manifest.github.tag_prefix, loaded.manifest.release.version
            ),
            image: format!(
                "{}:{}",
                loaded.manifest.server.image, loaded.manifest.release.version
            ),
            artifacts_directory: artifacts_dir,
            release_directory: output_dir,
            sources,
            commands,
            collections,
            receipts,
        })
    }

    /// Execute only the local build and collection actions in this plan.
    ///
    /// # Errors
    ///
    /// Returns an error when an external builder fails or an output cannot be
    /// safely collected.
    pub fn execute(&self, loaded: &LoadedManifest) -> Result<()> {
        self.sources.verify_binary_sources(loaded)?;
        if self
            .commands
            .iter()
            .any(|command| command.id == "build-server-image")
        {
            self.sources.verify_server_source(loaded)?;
        }
        fs::create_dir_all(&self.artifacts_directory)
            .map_err(io_error(&self.artifacts_directory))?;
        for collection in &self.collections {
            let parent = collection
                .destination
                .parent()
                .ok_or_else(|| ReleaseError::InvalidPath(collection.destination.clone()))?;
            fs::create_dir_all(parent).map_err(io_error(parent))?;
        }
        for command in &self.commands {
            if command.id.starts_with("build-connector-")
                && let Some(output) = command
                    .arguments
                    .windows(2)
                    .find_map(|pair| (pair[0] == "-o").then(|| PathBuf::from(&pair[1])))
            {
                let parent = output
                    .parent()
                    .ok_or_else(|| ReleaseError::InvalidPath(output.clone()))?;
                fs::create_dir_all(parent).map_err(io_error(parent))?;
            }
            if command.id == "build-server-image" {
                let server_dir = self.artifacts_directory.join("server");
                fs::create_dir_all(&server_dir).map_err(io_error(&server_dir))?;
            }
        }
        for planned in &self.commands {
            planned.execute()?;
        }
        for collection in &self.collections {
            let parent = collection
                .destination
                .parent()
                .ok_or_else(|| ReleaseError::InvalidPath(collection.destination.clone()))?;
            fs::create_dir_all(parent).map_err(io_error(parent))?;
            let metadata =
                fs::symlink_metadata(&collection.source).map_err(io_error(&collection.source))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ReleaseError::MissingArtifact(collection.source.clone()));
            }
            fs::copy(&collection.source, &collection.destination)
                .map_err(io_error(&collection.destination))?;
        }
        for receipt in &self.receipts {
            BuildReceipt::write(
                &receipt.path,
                &self.version,
                &receipt.target,
                &self.sources,
                &[
                    (&receipt.deployer_name, &receipt.deployer_path),
                    (&receipt.connector_name, &receipt.connector_path),
                ],
            )?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedCommand {
    pub id: String,
    pub program: String,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub environment: BTreeMap<String, String>,
    pub required_host: Option<BuildHost>,
    pub mutation: MutationKind,
}

impl PlannedCommand {
    /// Execute this exact typed command without a shell.
    ///
    /// # Errors
    ///
    /// Returns an error when the process cannot start or exits unsuccessfully.
    pub fn execute(&self) -> Result<()> {
        if let Some(required) = &self.required_host {
            let current = BuildHost::current();
            if required != &current {
                return Err(ReleaseError::BuildHostMismatch {
                    step: self.id.clone(),
                    required: required.to_string(),
                    current: current.to_string(),
                });
            }
        }
        eprintln!("executing {} via {}", self.id, self.program);
        let status = Command::new(&self.program)
            .args(&self.arguments)
            .envs(&self.environment)
            .current_dir(&self.working_directory)
            .status()
            .map_err(|_| ReleaseError::CommandStart(self.program.clone()))?;
        if !status.success() {
            return Err(ReleaseError::CommandFailed {
                program: self.program.clone(),
                status,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BuildHost {
    pub os: String,
    pub architecture: String,
}

impl BuildHost {
    fn current() -> Self {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: os.to_owned(),
            architecture: architecture.to_owned(),
        }
    }
}

impl std::fmt::Display for BuildHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}/{}", self.os, self.architecture)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    LocalBuild,
    LocalArtifact,
    RemotePublish,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCollection {
    pub source: PathBuf,
    pub destination: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildReceiptPlan {
    pub target: String,
    pub path: PathBuf,
    pub deployer_name: String,
    pub deployer_path: PathBuf,
    pub connector_name: String,
    pub connector_path: PathBuf,
}

#[must_use]
pub fn server_build_command(
    loaded: &LoadedManifest,
    sources: &SourceRevisions,
    output_dir: &Path,
    push: bool,
) -> PlannedCommand {
    let repository = loaded.server_repository();
    let dockerfile = repository.join(&loaded.manifest.server.dockerfile);
    let image = format!(
        "{}:{}",
        loaded.manifest.server.image, loaded.manifest.release.version
    );
    let mut arguments = vec![
        "buildx".to_owned(),
        "build".to_owned(),
        "--file".to_owned(),
        dockerfile.display().to_string(),
        "--platform".to_owned(),
        loaded.manifest.server.platforms.join(","),
        "--tag".to_owned(),
        image,
        "--label".to_owned(),
        format!(
            "org.opencontainers.image.version={}",
            loaded.manifest.release.version
        ),
        "--label".to_owned(),
        format!("org.opencontainers.image.revision={}", sources.server),
    ];
    if push {
        arguments.push("--push".to_owned());
    } else {
        arguments.push("--output".to_owned());
        arguments.push(format!(
            "type=oci,dest={}",
            output_dir
                .join(format!(
                    "dirextalk-vent-{}.oci.tar",
                    loaded.manifest.release.version
                ))
                .display()
        ));
    }
    arguments.push(repository.display().to_string());
    PlannedCommand {
        id: if push {
            "publish-server-image".to_owned()
        } else {
            "build-server-image".to_owned()
        },
        program: "docker".to_owned(),
        arguments,
        working_directory: repository,
        environment: BTreeMap::new(),
        required_host: None,
        mutation: if push {
            MutationKind::RemotePublish
        } else {
            MutationKind::LocalArtifact
        },
    }
}

fn rust_build_command(
    loaded: &LoadedManifest,
    target: &ReleaseTarget,
    sources: &SourceRevisions,
) -> PlannedCommand {
    let mut environment = BTreeMap::new();
    environment.insert(
        "SOURCE_DATE_EPOCH".to_owned(),
        loaded.manifest.release.source_date_epoch.to_string(),
    );
    environment.insert(
        "DTX_RELEASE_VERSION".to_owned(),
        loaded.manifest.release.version.clone(),
    );
    environment.insert("DTX_SOURCE_COMMIT".to_owned(), sources.deployer.clone());
    let mut cargo_arguments = vec![
        "build".to_owned(),
        "--locked".to_owned(),
        "--release".to_owned(),
        "--package".to_owned(),
        loaded.manifest.deployer.package.clone(),
    ];
    if !target.rust_native {
        cargo_arguments.push("--target".to_owned());
        cargo_arguments.push(target.rust_target.clone());
    }
    let (program, arguments) = match &target.rust_toolchain {
        Some(toolchain) => {
            let mut arguments = vec!["run".to_owned(), toolchain.clone(), "cargo".to_owned()];
            arguments.extend(cargo_arguments);
            ("rustup".to_owned(), arguments)
        }
        None => ("cargo".to_owned(), cargo_arguments),
    };
    PlannedCommand {
        id: format!("build-deployer-{}", target.id),
        program,
        arguments,
        working_directory: loaded.deployer_repository(),
        environment,
        required_host: target.rust_native.then(|| BuildHost {
            os: target.goos.clone(),
            architecture: target.goarch.clone(),
        }),
        mutation: MutationKind::LocalBuild,
    }
}

fn go_build_command(
    loaded: &LoadedManifest,
    target: &ReleaseTarget,
    sources: &SourceRevisions,
    output: &Path,
) -> PlannedCommand {
    let mut environment = BTreeMap::new();
    environment.insert("CGO_ENABLED".to_owned(), "0".to_owned());
    environment.insert("GOOS".to_owned(), target.goos.clone());
    environment.insert("GOARCH".to_owned(), target.goarch.clone());
    let linker_flags = format!(
        "-s -w -X main.version={} -X main.commit={} -X main.buildTime={}",
        loaded.manifest.release.version,
        sources.connector,
        loaded.manifest.release.source_date_epoch
    );
    PlannedCommand {
        id: format!("build-connector-{}", target.id),
        program: "go".to_owned(),
        arguments: vec![
            "build".to_owned(),
            "-trimpath".to_owned(),
            "-buildvcs=true".to_owned(),
            "-ldflags".to_owned(),
            linker_flags,
            "-o".to_owned(),
            output.display().to_string(),
            loaded.manifest.connector.module.clone(),
        ],
        working_directory: loaded.connector_repository(),
        environment,
        required_host: None,
        mutation: MutationKind::LocalBuild,
    }
}

fn select_targets<'a>(
    loaded: &'a LoadedManifest,
    selected: &[String],
) -> Result<Vec<&'a ReleaseTarget>> {
    if selected.is_empty() {
        return Ok(loaded.manifest.targets.iter().collect());
    }
    let mut targets = Vec::with_capacity(selected.len());
    for id in selected {
        let target = loaded
            .manifest
            .targets
            .iter()
            .find(|target| target.id == *id)
            .ok_or_else(|| ReleaseError::Manifest(format!("unknown target id {id:?}")))?;
        if targets
            .iter()
            .any(|existing: &&ReleaseTarget| existing.id == target.id)
        {
            return Err(ReleaseError::Manifest(format!(
                "duplicate selected target {id:?}"
            )));
        }
        targets.push(target);
    }
    Ok(targets)
}

fn absolute_from_manifest(loaded: &LoadedManifest, path: &Path) -> PathBuf {
    loaded.resolve(path)
}
