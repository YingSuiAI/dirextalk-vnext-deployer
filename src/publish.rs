use std::{
    collections::{BTreeMap, HashSet},
    env, fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    archive::AssembledRelease,
    digest::digest_regular_file,
    error::{ReleaseError, Result, io_error},
    manifest::LoadedManifest,
    plan::{MutationKind, PlannedCommand, server_build_command},
};

#[derive(Clone, Copy, Debug, Default)]
pub struct PublicationSelection {
    pub image: bool,
    pub npm: bool,
    pub github: bool,
}

impl PublicationSelection {
    fn any(self) -> bool {
        self.image || self.npm || self.github
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPlan {
    pub schema_version: u32,
    pub version: String,
    pub release_directory: PathBuf,
    pub credentials: CredentialReadiness,
    pub commands: Vec<PlannedCommand>,
}

impl PublicationPlan {
    /// Build a read-only publication preview for explicitly selected destinations.
    ///
    /// # Errors
    ///
    /// Returns an error when no destination is selected or assembled artifacts
    /// do not match their hashes and release manifest.
    pub fn create(
        loaded: &LoadedManifest,
        release_dir: &Path,
        selection: PublicationSelection,
    ) -> Result<Self> {
        if !selection.any() {
            return Err(ReleaseError::NoPublicationSelected);
        }
        let release_dir = loaded.resolve(release_dir);
        let assembled_path = release_dir.join("github-assets.json");
        let assembled = AssembledRelease::load(&assembled_path)?;
        validate_assembled_release(loaded, &release_dir, &assembled)?;
        let credentials = CredentialReadiness::detect();
        let mut commands = Vec::new();
        if selection.image {
            commands.push(server_build_command(
                loaded,
                &assembled.sources,
                &release_dir,
                true,
            ));
        }
        if selection.npm {
            commands.push(npm_publish_command(loaded, &release_dir, &assembled));
        }
        if selection.github {
            commands.push(github_publish_command(loaded, &release_dir, &assembled));
        }
        Ok(Self {
            schema_version: 1,
            version: assembled.version,
            release_directory: release_dir,
            credentials,
            commands,
        })
    }

    /// Execute a previously previewed publication after credential/source checks.
    ///
    /// # Errors
    ///
    /// Returns an error when credentials are absent, source repositories are
    /// dirty or mismatched, artifacts are invalid, or a publisher fails.
    pub fn execute(&self, loaded: &LoadedManifest, selection: PublicationSelection) -> Result<()> {
        if selection.image && !self.credentials.docker {
            return Err(ReleaseError::CredentialsUnavailable("Docker registry"));
        }
        if selection.npm && !self.credentials.npm {
            return Err(ReleaseError::CredentialsUnavailable("npm"));
        }
        if selection.github && !self.credentials.github {
            return Err(ReleaseError::CredentialsUnavailable("GitHub"));
        }
        let release_dir = self.release_directory.clone();
        let assembled = AssembledRelease::load(&release_dir.join("github-assets.json"))?;
        assembled.sources.verify_publishable(loaded)?;
        validate_assembled_release(loaded, &release_dir, &assembled)?;
        for command in &self.commands {
            command.execute()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReadiness {
    pub docker: bool,
    pub npm: bool,
    pub github: bool,
}

impl CredentialReadiness {
    fn detect() -> Self {
        Self {
            docker: has_nonempty_env("DOCKER_AUTH_CONFIG") || docker_config_exists(),
            npm: has_nonempty_env("NPM_TOKEN") || has_nonempty_env("NODE_AUTH_TOKEN"),
            github: has_nonempty_env("GH_TOKEN") || has_nonempty_env("GITHUB_TOKEN"),
        }
    }
}

fn npm_publish_command(
    loaded: &LoadedManifest,
    release_dir: &Path,
    assembled: &AssembledRelease,
) -> PlannedCommand {
    let npm_directory = release_dir.join(&assembled.npm_directory);
    PlannedCommand {
        id: "publish-npm".to_owned(),
        program: "npm".to_owned(),
        arguments: vec![
            "publish".to_owned(),
            npm_directory.display().to_string(),
            "--access".to_owned(),
            loaded.manifest.npm.access.as_str().to_owned(),
        ],
        working_directory: npm_directory,
        environment: BTreeMap::new(),
        required_host: None,
        mutation: MutationKind::RemotePublish,
    }
}

fn github_publish_command(
    loaded: &LoadedManifest,
    release_dir: &Path,
    assembled: &AssembledRelease,
) -> PlannedCommand {
    let mut arguments = vec![
        "release".to_owned(),
        "create".to_owned(),
        assembled.tag.clone(),
        "--repo".to_owned(),
        loaded.manifest.github.repository.clone(),
        "--title".to_owned(),
        format!("Dirextalk vNext {}", assembled.version),
        "--generate-notes".to_owned(),
    ];
    arguments.extend(
        assembled
            .assets
            .iter()
            .map(|asset| release_dir.join(&asset.path).display().to_string()),
    );
    arguments.push(release_dir.join("github-assets.json").display().to_string());
    PlannedCommand {
        id: "publish-github".to_owned(),
        program: "gh".to_owned(),
        arguments,
        working_directory: loaded.deployer_repository(),
        environment: BTreeMap::new(),
        required_host: None,
        mutation: MutationKind::RemotePublish,
    }
}

fn validate_assembled_release(
    loaded: &LoadedManifest,
    release_dir: &Path,
    assembled: &AssembledRelease,
) -> Result<()> {
    if assembled.version != loaded.manifest.release.version
        || assembled.tag
            != format!(
                "{}{}",
                loaded.manifest.github.tag_prefix, loaded.manifest.release.version
            )
        || assembled.image.reference
            != format!(
                "{}:{}",
                loaded.manifest.server.image, loaded.manifest.release.version
            )
        || assembled.image.platforms != loaded.manifest.server.platforms
    {
        return Err(ReleaseError::Manifest(
            "assembled release does not match the release manifest".to_owned(),
        ));
    }
    let mut paths = HashSet::new();
    for asset in &assembled.assets {
        if asset.name != asset.path
            || !safe_single_component(&asset.path)
            || !paths.insert(&asset.path)
            || asset.sha256.len() != 64
            || !asset.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReleaseError::Manifest(
                "assembled release contains an invalid asset entry".to_owned(),
            ));
        }
        let path = release_dir.join(&asset.path);
        let metadata = fs::symlink_metadata(&path).map_err(io_error(&path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() != asset.size
            || digest_regular_file(&path, u64::MAX)?.sha256 != asset.sha256
        {
            return Err(ReleaseError::MissingArtifact(path));
        }
    }
    let npm_directory = release_dir.join(&assembled.npm_directory);
    if assembled.npm_directory != "npm" {
        return Err(ReleaseError::Manifest(
            "assembled npm directory is invalid".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(&npm_directory).map_err(io_error(&npm_directory))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ReleaseError::InvalidPath(npm_directory));
    }
    validate_npm_files(&npm_directory, assembled)?;
    Ok(())
}

fn validate_npm_files(npm_directory: &Path, assembled: &AssembledRelease) -> Result<()> {
    let mut expected_paths = HashSet::new();
    for file in &assembled.npm_files {
        if !safe_relative_path(&file.path)
            || !expected_paths.insert(file.path.clone())
            || file.sha256.len() != 64
            || !file.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ReleaseError::Manifest(
                "assembled release contains an invalid npm file entry".to_owned(),
            ));
        }
        let path = npm_directory.join(&file.path);
        let digest = digest_regular_file(&path, 512 * 1024 * 1024)?;
        if digest.size != file.size || digest.sha256 != file.sha256 {
            return Err(ReleaseError::MissingArtifact(path));
        }
    }
    let mut actual_paths = HashSet::new();
    collect_npm_files(npm_directory, npm_directory, 0, &mut actual_paths)?;
    if actual_paths != expected_paths {
        return Err(ReleaseError::Manifest(
            "npm package files do not match the assembled release manifest".to_owned(),
        ));
    }
    Ok(())
}

fn collect_npm_files(
    root: &Path,
    directory: &Path,
    depth: usize,
    output: &mut HashSet<String>,
) -> Result<()> {
    if depth > 8 {
        return Err(ReleaseError::InvalidPath(directory.to_path_buf()));
    }
    for entry in fs::read_dir(directory).map_err(io_error(directory))? {
        let entry = entry.map_err(io_error(directory))?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(io_error(&path))?;
        if file_type.is_symlink() {
            return Err(ReleaseError::InvalidPath(path));
        }
        if file_type.is_dir() {
            collect_npm_files(root, &path, depth + 1, output)?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| ReleaseError::InvalidPath(path.clone()))?;
            let encoded = relative
                .components()
                .map(|component| match component {
                    Component::Normal(value) => value
                        .to_str()
                        .map(str::to_owned)
                        .ok_or_else(|| ReleaseError::InvalidPath(path.clone())),
                    _ => Err(ReleaseError::InvalidPath(path.clone())),
                })
                .collect::<Result<Vec<_>>>()?
                .join("/");
            output.insert(encoded);
        } else {
            return Err(ReleaseError::InvalidPath(path));
        }
    }
    Ok(())
}

fn safe_single_component(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path.components().count() == 1
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn has_nonempty_env(name: &str) -> bool {
    env::var_os(name).is_some_and(|value| !value.is_empty())
}

fn docker_config_exists() -> bool {
    let configured = env::var_os("DOCKER_CONFIG").map(PathBuf::from);
    let default = home_directory().map(|home| home.join(".docker"));
    configured
        .or(default)
        .map(|directory| directory.join("config.json"))
        .and_then(|path| fs::metadata(path).ok())
        .is_some_and(|metadata| metadata.is_file() && metadata.len() > 2)
}

fn home_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}
