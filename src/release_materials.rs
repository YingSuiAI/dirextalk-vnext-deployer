//! Local, fail-closed assembly of pre-generated release materials.

#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use rustix::fs::{RenameFlags, renameat_with};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    digest::{FileIdentity, read_regular_file_descriptor, read_regular_file_relative_descriptor},
    error::{ReleaseError, Result, io_error},
    manifest::LoadedManifest,
    release_evidence::{
        ArtifactEvidence, AttestationKind, AttestationReference, EvidenceComponent,
        EvidenceRelease, FileEvidence, REQUIRED_RELEASE_COMPONENTS, ReleaseEvidenceV1,
    },
    source::SourceEvidenceGuard,
    strict_json,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_MATERIAL_BYTES: u64 = 64 * 1024 * 1024;

struct Stage {
    path: PathBuf,
    published: bool,
}
impl Stage {
    fn create(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".release-evidence-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&path).map_err(io_error(&path))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(io_error(&path))?;
        Ok(Self {
            path,
            published: false,
        })
    }
    fn publish(mut self, output: &Path) -> Result<()> {
        let parent = output
            .parent()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
        let stage_name = self
            .path
            .file_name()
            .ok_or_else(|| ReleaseError::InvalidPath(self.path.clone()))?;
        let output_name = output
            .file_name()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
        let directory = File::open(parent).map_err(io_error(parent))?;
        renameat_with(
            &directory,
            stage_name,
            &directory,
            output_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| io_error(output)(std::io::Error::from(error)))?;
        self.published = true;
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInputsV1 {
    pub schema: String,
    pub schema_version: u32,
    pub release: EvidenceRelease,
    pub components: Vec<ReleaseInputComponent>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInputComponent {
    pub component: String,
    pub source_commit: String,
    pub targets: Vec<String>,
    pub toolchain: String,
    pub build_recipe: InputFile,
    pub artifact: InputArtifact,
    pub sbom: InputFile,
    pub third_party_notice: InputFile,
    pub license: InputFile,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputArtifact {
    pub identity: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputFile {
    pub path: PathBuf,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalProvenanceV1 {
    schema: String,
    schema_version: u32,
    component: String,
    release_manifest_sha256: String,
    source_commit: String,
    source_tree: String,
    targets: Vec<String>,
    toolchain: String,
    build_recipe: FileEvidence,
    artifact: ArtifactEvidence,
    sbom: FileEvidence,
    third_party_notice: FileEvidence,
    license: FileEvidence,
}

impl ReleaseInputsV1 {
    /// Load one canonical release-inputs document.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe files, non-canonical JSON, duplicates, or
    /// a contract that does not name exactly the required components.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_file_descriptor(path, MAX_INPUT_BYTES)?;
        let value = strict_json::parse_value(&bytes)?;
        let inputs: Self = serde_json::from_value(value)?;
        inputs.validate()?;
        if inputs.canonical_bytes()? != bytes {
            return Err(contract("release inputs JSON is not canonical"));
        }
        Ok(inputs)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>> {
        strict_json::canonical_bytes(&serde_json::to_value(self)?, true)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != "dirextalk.release-inputs" || self.schema_version != 1 {
            return Err(contract("schema/version is unsupported"));
        }
        if self.release.source_date_epoch == 0
            || semver::Version::parse(&self.release.version).is_err()
        {
            return Err(contract("release is invalid"));
        }
        if self.components.len() != REQUIRED_RELEASE_COMPONENTS.len() {
            return Err(contract("requires exactly five components"));
        }
        let mut names = BTreeSet::new();
        let mut all_paths = BTreeSet::new();
        for component in &self.components {
            if !REQUIRED_RELEASE_COMPONENTS.contains(&component.component.as_str())
                || !names.insert(component.component.clone())
            {
                return Err(contract("components are incomplete or duplicated"));
            }
            token(&component.component)?;
            token(&component.toolchain)?;
            token(&component.artifact.identity)?;
            if !commit(&component.source_commit) || component.targets.is_empty() {
                return Err(contract("source commit or targets are invalid"));
            }
            let mut targets = BTreeSet::new();
            for target in &component.targets {
                token(target)?;
                if !targets.insert(target) {
                    return Err(contract("duplicate target"));
                }
            }
            for path in [
                &component.build_recipe.path,
                &component.artifact.path,
                &component.sbom.path,
                &component.third_party_notice.path,
                &component.license.path,
            ] {
                safe_relative(path)?;
                if !all_paths.insert(path.clone()) {
                    return Err(contract("input material paths must be unique"));
                }
            }
        }
        Ok(())
    }
}

/// Assemble an immutable directory without invoking a builder, shell, or network.
///
/// # Errors
///
/// Returns an error for a changing or dirty source repository, unsafe input,
/// invalid manifest coverage, existing output, or an atomic publish failure.
#[allow(clippy::too_many_lines)]
pub fn assemble(
    inputs_path: &Path,
    manifest_path: &Path,
    roots: &BTreeMap<String, PathBuf>,
    output: &Path,
) -> Result<ReleaseEvidenceV1> {
    if output.exists() {
        return Err(ReleaseError::OutputNotEmpty(output.to_path_buf()));
    }
    let inputs = ReleaseInputsV1::load(inputs_path)?;
    if roots.len() != REQUIRED_RELEASE_COMPONENTS.len()
        || roots
            .keys()
            .any(|name| !REQUIRED_RELEASE_COMPONENTS.contains(&name.as_str()))
    {
        return Err(contract(
            "requires exactly one source root for every component",
        ));
    }
    let manifest_bytes = read_regular_file_descriptor(manifest_path, MAX_INPUT_BYTES)?;
    let manifest = LoadedManifest::load(manifest_path)?;
    let manifest_digest = hex::encode(Sha256::digest(&manifest_bytes));
    let mut guards = Vec::new();
    for component in &inputs.components {
        let root = roots
            .get(&component.component)
            .ok_or_else(|| contract("missing source root"))?;
        let guard = SourceEvidenceGuard::begin(root)?;
        guard.verify_expected(&component.source_commit)?;
        guards.push((component.component.as_str(), guard));
    }
    let parent = output
        .parent()
        .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
    ensure_directory(parent)?;
    let output_candidate = fs::canonicalize(parent).map_err(io_error(parent))?.join(
        output
            .file_name()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?,
    );
    for path in std::iter::once(inputs_path)
        .chain(std::iter::once(manifest_path))
        .chain(roots.values().map(PathBuf::as_path))
    {
        if fs::canonicalize(path)
            .map_err(io_error(path))?
            .starts_with(&output_candidate)
        {
            return Err(contract("inputs must be outside output"));
        }
    }
    let stage = Stage::create(parent)?;
    let input_root = inputs_path
        .parent()
        .ok_or_else(|| ReleaseError::InvalidPath(inputs_path.to_path_buf()))?;
    ensure_directory(input_root)?;
    let mut identities = BTreeSet::new();
    let mut components = Vec::new();
    let mut attestations = Vec::new();
    for component in &inputs.components {
        let tree = guards
            .iter()
            .find(|(name, _)| *name == component.component)
            .ok_or_else(|| contract("missing source guard"))?
            .1
            .head_tree()
            .to_owned();
        let recipe = copy_material(
            &stage.path,
            input_root,
            &component.build_recipe.path,
            &format!("components/{}/build-recipe", component.component),
            &mut identities,
        )?;
        let artifact_file = copy_material(
            &stage.path,
            input_root,
            &component.artifact.path,
            &format!("components/{}/artifact", component.component),
            &mut identities,
        )?;
        let sbom = copy_material(
            &stage.path,
            input_root,
            &component.sbom.path,
            &format!("components/{}/sbom", component.component),
            &mut identities,
        )?;
        let notice = copy_material(
            &stage.path,
            input_root,
            &component.third_party_notice.path,
            &format!("components/{}/third-party-notice", component.component),
            &mut identities,
        )?;
        let license = copy_material(
            &stage.path,
            input_root,
            &component.license.path,
            &format!("components/{}/license", component.component),
            &mut identities,
        )?;
        let artifact = ArtifactEvidence {
            identity: component.artifact.identity.clone(),
            path: artifact_file.path.clone(),
            size: artifact_file.size,
            sha256: artifact_file.sha256.clone(),
        };
        let provenance = LocalProvenanceV1 {
            schema: "dirextalk.local-provenance".into(),
            schema_version: 1,
            component: component.component.clone(),
            release_manifest_sha256: manifest_digest.clone(),
            source_commit: component.source_commit.clone(),
            source_tree: tree,
            targets: component.targets.clone(),
            toolchain: component.toolchain.clone(),
            build_recipe: recipe,
            artifact: artifact.clone(),
            sbom: sbom.clone(),
            third_party_notice: notice.clone(),
            license: license.clone(),
        };
        let provenance_path = PathBuf::from(format!("provenance/{}.json", component.component));
        let provenance_bytes =
            strict_json::canonical_bytes(&serde_json::to_value(&provenance)?, true)?;
        write_new(&stage.path, &provenance_path, &provenance_bytes)?;
        let provenance_digest = digest(&provenance_bytes);
        attestations.push(AttestationReference {
            kind: AttestationKind::InToto,
            component: component.component.clone(),
            target: component.targets[0].clone(),
            path: provenance_path,
            size: provenance_bytes.len() as u64,
            sha256: provenance_digest,
            artifact_sha256: artifact.sha256.clone(),
        });
        components.push(EvidenceComponent {
            component: component.component.clone(),
            source_commit: component.source_commit.clone(),
            target: component.targets[0].clone(),
            targets: component.targets.clone(),
            toolchain: component.toolchain.clone(),
            build_recipe: format!("sha256:{}", provenance.build_recipe.sha256),
            artifact,
            sbom,
            third_party_notice: notice,
            license,
            attestations: Vec::new(),
        });
    }
    components.sort_by(|a, b| a.component.cmp(&b.component));
    attestations.sort_by(|a, b| a.component.cmp(&b.component));
    let evidence = ReleaseEvidenceV1 {
        schema: "dirextalk.release-evidence".into(),
        schema_version: 1,
        release: inputs.release,
        components,
        attestations,
    };
    evidence.cross_check_manifest(&manifest)?;
    let evidence_bytes = evidence.canonical_bytes()?;
    write_new(
        &stage.path,
        Path::new("release-evidence.json"),
        &evidence_bytes,
    )?;
    // Re-open every staged member through the existing no-follow validator
    // before the checksums and atomic publication make the directory visible.
    evidence.validate_files(&stage.path)?;
    let checksums = checksum_manifest(&stage.path)?;
    write_new(&stage.path, Path::new("SHA256SUMS"), &checksums)?;
    sync_tree(&stage.path)?;
    for (_, guard) in guards {
        guard.finish()?;
    }
    stage.publish(output)?;
    sync_dir(parent)?;
    Ok(evidence)
}

fn copy_material(
    stage: &Path,
    input_root: &Path,
    source: &Path,
    destination: &str,
    identities: &mut BTreeSet<FileIdentity>,
) -> Result<FileEvidence> {
    let expected = fs::symlink_metadata(input_root.join(source))
        .map_err(io_error(source))?
        .len();
    let (bytes, identity) = read_regular_file_relative_descriptor(
        input_root,
        source,
        expected,
        None,
        MAX_MATERIAL_BYTES,
    )?;
    if !identities.insert(identity) {
        return Err(contract("input roles must not share an inode"));
    }
    let path = PathBuf::from(destination);
    write_new(stage, &path, &bytes)?;
    Ok(FileEvidence {
        path,
        size: bytes.len() as u64,
        sha256: digest(&bytes),
    })
}

fn checksum_manifest(root: &Path) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort();
    let mut bytes = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(root)
            .map_err(|_| ReleaseError::InvalidPath(path.clone()))?;
        let value = fs::read(&path).map_err(io_error(&path))?;
        // SHA256SUMS is deliberately the only excluded member: including its
        // own digest would be recursive. Every other regular final member is
        // represented once as `sha256 size path`, sorted by its relative path.
        bytes.extend_from_slice(
            format!(
                "{} {} {}\n",
                digest(&value),
                value.len(),
                relative.display()
            )
            .as_bytes(),
        );
    }
    Ok(bytes)
}
fn collect_files(root: &Path, current: &Path, result: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(current).map_err(io_error(current))? {
        let path = entry.map_err(io_error(current))?.path();
        let meta = fs::symlink_metadata(&path).map_err(io_error(&path))?;
        if meta.file_type().is_symlink() {
            return Err(ReleaseError::UnsafeFile(path));
        }
        if meta.is_dir() {
            collect_files(root, &path, result)?;
        } else if meta.is_file() {
            result.push(path);
        } else {
            return Err(ReleaseError::UnsafeFile(path));
        }
    }
    let _ = root;
    Ok(())
}
fn write_new(root: &Path, relative: &Path, bytes: &[u8]) -> Result<()> {
    safe_relative(relative)?;
    let path = root.join(relative);
    let parent = path
        .parent()
        .ok_or_else(|| ReleaseError::InvalidPath(path.clone()))?;
    fs::create_dir_all(parent).map_err(io_error(parent))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(io_error(&path))?;
    file.write_all(bytes).map_err(io_error(&path))?;
    file.sync_all().map_err(io_error(&path))?;
    sync_dir(parent)?;
    Ok(())
}
fn sync_tree(path: &Path) -> Result<()> {
    for entry in fs::read_dir(path).map_err(io_error(path))? {
        let path = entry.map_err(io_error(path))?.path();
        if path.is_dir() {
            sync_tree(&path)?;
            sync_dir(&path)?;
        }
    }
    sync_dir(path)
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)
        .map_err(io_error(path))?
        .sync_all()
        .map_err(io_error(path))
}
fn ensure_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(io_error(path))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(ReleaseError::InvalidPath(path.to_path_buf()));
    }
    Ok(())
}
fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn safe_relative(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
                    | Component::CurDir
            )
        })
    {
        return Err(contract("paths must be safe relative paths"));
    }
    Ok(())
}
fn token(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'_' | b'.' | b'/' | b':' | b'@' | b'+')
        })
    {
        return Err(contract("identity is invalid"));
    }
    Ok(())
}
fn commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn contract(message: &str) -> ReleaseError {
    ReleaseError::Manifest(format!("release materials: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::process::Command;
    use tempfile::TempDir;

    fn inputs() -> ReleaseInputsV1 {
        ReleaseInputsV1 {
            schema: "dirextalk.release-inputs".into(),
            schema_version: 1,
            release: EvidenceRelease {
                version: "1.2.3".into(),
                source_date_epoch: 1,
            },
            components: REQUIRED_RELEASE_COMPONENTS
                .iter()
                .map(|component| ReleaseInputComponent {
                    component: (*component).into(),
                    source_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                    targets: vec!["linux-amd64".into()],
                    toolchain: "stable-1.97.0".into(),
                    build_recipe: InputFile {
                        path: format!("{component}/recipe").into(),
                    },
                    artifact: InputArtifact {
                        identity: format!("{component}-linux-amd64"),
                        path: format!("{component}/artifact").into(),
                    },
                    sbom: InputFile {
                        path: format!("{component}/sbom").into(),
                    },
                    third_party_notice: InputFile {
                        path: format!("{component}/notice").into(),
                    },
                    license: InputFile {
                        path: format!("{component}/license").into(),
                    },
                })
                .collect(),
        }
    }

    #[test]
    fn inputs_are_canonical_and_duplicate_key_free() {
        let root = TempDir::new().expect("temp");
        let path = root.path().join("inputs.json");
        let fixture = inputs();
        fs::write(&path, fixture.canonical_bytes().expect("canonical")).expect("write");
        assert_eq!(ReleaseInputsV1::load(&path).expect("load"), fixture);
        fs::write(
            &path,
            br#"{"schema":"dirextalk.release-inputs","schema":"dirextalk.release-inputs"}"#,
        )
        .expect("write");
        assert!(ReleaseInputsV1::load(&path).is_err());
    }

    #[test]
    fn aliases_between_roles_are_rejected_before_copy() {
        let root = TempDir::new().expect("temp");
        let source = root.path().join("one");
        fs::write(&source, b"material").expect("write");
        let mut seen = BTreeSet::new();
        let first = copy_material(
            root.path(),
            root.path(),
            Path::new("one"),
            "out/a",
            &mut seen,
        )
        .expect("first");
        assert_eq!(first.size, 8);
        assert!(
            copy_material(
                root.path(),
                root.path(),
                Path::new("one"),
                "out/b",
                &mut seen
            )
            .is_err()
        );
    }

    fn git(repository: &Path, arguments: &[&str]) {
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(repository)
                .args(arguments)
                .status()
                .expect("git")
                .success()
        );
    }
    fn repository(root: &Path, name: &str) -> (PathBuf, String) {
        let path = root.join(name);
        fs::create_dir(&path).expect("repo");
        git(&path, &["init", "-q"]);
        git(&path, &["config", "user.email", "test@example.invalid"]);
        git(&path, &["config", "user.name", "test"]);
        fs::write(path.join("README"), name).expect("readme");
        for file in ["Cargo.toml", "LICENSE", "NOTICE", "Dockerfile", "go.mod"] {
            fs::write(path.join(file), "fixture").expect("fixture file");
        }
        git(&path, &["add", "."]);
        git(&path, &["commit", "-qm", "fixture"]);
        let output = Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "HEAD"])
            .output()
            .expect("head");
        (
            path,
            String::from_utf8(output.stdout)
                .expect("utf8")
                .trim()
                .to_owned(),
        )
    }
    fn assembly_fixture(
        root: &Path,
    ) -> (PathBuf, PathBuf, BTreeMap<String, PathBuf>, ReleaseInputsV1) {
        let mut roots = BTreeMap::new();
        let mut commits = BTreeMap::new();
        for component in REQUIRED_RELEASE_COMPONENTS {
            let (path, commit) = repository(root, &format!("repo-{component}"));
            roots.insert((*component).into(), path);
            commits.insert(*component, commit);
        }
        let mut fixture = inputs();
        for component in &mut fixture.components {
            component.source_commit = commits[component.component.as_str()].clone();
            component.targets = if component.component == "server" {
                vec!["linux-amd64".into()]
            } else {
                vec!["linux-x64".into()]
            };
            for (path, bytes) in [
                (&component.build_recipe.path, b"recipe".as_slice()),
                (&component.artifact.path, b"artifact".as_slice()),
                (&component.sbom.path, b"sbom".as_slice()),
                (&component.third_party_notice.path, b"notice".as_slice()),
                (&component.license.path, b"license".as_slice()),
            ] {
                let full = root.join(path);
                fs::create_dir_all(full.parent().expect("parent")).expect("dir");
                fs::write(full, bytes).expect("material");
            }
        }
        let inputs_path = root.join("release-inputs.json");
        fs::write(&inputs_path, fixture.canonical_bytes().expect("inputs")).expect("inputs write");
        let manifest = serde_json::json!({"schema_version":1,"release":{"version":"1.2.3","source_date_epoch":1},"server":{"repository":"repo-server","dockerfile":"Dockerfile","image":"example/server","platforms":["linux/amd64"],"source_commit":commits["server"]},"deployer":{"repository":"repo-deployer","package":"deployer","binary":"deployer","source_commit":commits["deployer"]},"connector":{"repository":"repo-connector","module":"./cmd","binary":"connector","source_commit":commits["connector"]},"targets":[{"id":"linux-x64","rust_target":"x86_64-unknown-linux-gnu","rust_native":true,"goos":"linux","goarch":"amd64","node_platform":"linux","node_arch":"x64","archive":"tar_gz"}],"npm":{"package":"@example/release","access":"public"},"github":{"repository":"example/repo","tag_prefix":"v"}});
        let manifest_path = root.join("release.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("manifest"),
        )
        .expect("manifest write");
        (inputs_path, manifest_path, roots, fixture)
    }
    #[test]
    fn deterministic_assembly_round_trips_and_refuses_existing_output() {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let first = root.path().join("first");
        let second = root.path().join("second");
        assemble(&inputs_path, &manifest_path, &roots, &first).expect("first");
        assemble(&inputs_path, &manifest_path, &roots, &second).expect("second");
        for name in [
            "release-evidence.json",
            "SHA256SUMS",
            "provenance/server.json",
        ] {
            assert_eq!(
                fs::read(first.join(name)).expect("first bytes"),
                fs::read(second.join(name)).expect("second bytes")
            );
        }
        ReleaseEvidenceV1::load(&first.join("release-evidence.json")).expect("reopen");
        let checksums = String::from_utf8(fs::read(first.join("SHA256SUMS")).expect("checksums"))
            .expect("utf8");
        let entries: Vec<_> = checksums.lines().collect();
        assert_eq!(
            entries.len(),
            31,
            "every material, provenance file, and evidence file is covered once"
        );
        let paths: Vec<_> = entries
            .iter()
            .map(|entry| entry.splitn(3, ' ').nth(2).expect("path"))
            .collect();
        assert!(paths.windows(2).all(|pair| pair[0] < pair[1]));
        for entry in entries {
            let mut fields = entry.splitn(3, ' ');
            let hash = fields.next().expect("hash");
            let size: u64 = fields.next().expect("size").parse().expect("numeric size");
            let path = fields.next().expect("path");
            assert_ne!(path, "SHA256SUMS");
            let bytes = fs::read(first.join(path)).expect("covered file");
            assert_eq!(hash, digest(&bytes));
            assert_eq!(size, bytes.len() as u64);
        }
        assert!(assemble(&inputs_path, &manifest_path, &roots, &first).is_err());
    }
    #[test]
    fn failed_copy_cleans_stage_and_does_not_publish() {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, fixture) = assembly_fixture(root.path());
        fs::remove_file(root.path().join(&fixture.components[0].artifact.path)).expect("remove");
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        assert!(!output.exists());
        assert_eq!(
            fs::read_dir(root.path())
                .expect("dir")
                .filter_map(std::result::Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".release-evidence-"))
                .count(),
            0
        );
    }

    #[test]
    fn cli_assemble_then_validate_fixture() {
        let root = TempDir::new().expect("temp");
        let (inputs, manifest, roots, _) = assembly_fixture(root.path());
        let output = root.path().join("cli-output");
        let mut assemble = vec![
            "dirextalk-vnext-deployer".to_owned(),
            "release-evidence-assemble".to_owned(),
            "--inputs".to_owned(),
            inputs.display().to_string(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
            "--output".to_owned(),
            output.display().to_string(),
        ];
        for (component, path) in &roots {
            assemble.push("--source-root".to_owned());
            assemble.push(format!("{component}={}", path.display()));
        }
        crate::run(crate::Cli::try_parse_from(assemble).expect("assemble args"))
            .expect("assemble cli");
        let mut validate = vec![
            "dirextalk-vnext-deployer".to_owned(),
            "release-evidence-validate".to_owned(),
            "--evidence".to_owned(),
            output.join("release-evidence.json").display().to_string(),
            "--manifest".to_owned(),
            manifest.display().to_string(),
        ];
        for (component, path) in roots {
            validate.push("--source-root".to_owned());
            validate.push(format!("{component}={}", path.display()));
        }
        crate::run(crate::Cli::try_parse_from(validate).expect("validate args"))
            .expect("validate cli");
    }
}
