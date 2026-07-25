//! Local, fail-closed assembly of pre-generated release materials.

#![cfg(unix)]

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Read, Write},
    os::{
        fd::{AsFd, BorrowedFd, OwnedFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};

use fs2::FileExt;
use rustix::{
    fs::{
        AtFlags, FileType, Mode, OFlags, RawDir, RenameFlags, fchmod, fstat, fsync, mkdirat, open,
        openat, renameat_with, statat, unlinkat,
    },
    io::Errno,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    digest::{
        FileIdentity, read_regular_file_descriptor, read_regular_file_fd_relative_descriptor,
        read_regular_file_relative_descriptor,
    },
    error::{ReleaseError, Result, io_error},
    manifest::{LoadedManifest, ReleaseManifest},
    release_evidence::{
        ArtifactEvidence, AttestationKind, AttestationReference, EvidenceComponent,
        EvidenceRelease, FileEvidence, REQUIRED_RELEASE_COMPONENTS, ReleaseEvidenceV1,
    },
    source::SourceEvidenceGuard,
    strict_json,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024;
const MAX_MATERIAL_BYTES: u64 = 64 * 1024 * 1024;
const LOCAL_PROVENANCE_SCHEMA: &str = "dirextalk.local-provenance";
const LOCAL_PROVENANCE_SCHEMA_VERSION: u32 = 1;

#[cfg(test)]
mod test_seams {
    use std::sync::mpsc::{Receiver, Sender};
    use std::sync::{Arc, Barrier};
    use std::time::Duration;
    thread_local! {
        static BEFORE_PARENT_RERESOLVE: std::cell::RefCell<Option<Arc<Barrier>>> = const { std::cell::RefCell::new(None) };
        static BEFORE_FRAGMENT_COPY: std::cell::RefCell<Option<Arc<Barrier>>> = const { std::cell::RefCell::new(None) };
        static BEFORE_RENAME: std::cell::RefCell<Option<(Sender<()>, Receiver<()>)>> = const { std::cell::RefCell::new(None) };
        static FAIL_STAGE_INIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    pub(super) fn set_before_parent_reresolve(barrier: Option<Arc<Barrier>>) {
        BEFORE_PARENT_RERESOLVE.with(|slot| *slot.borrow_mut() = barrier);
    }
    pub(super) fn fail_stage_init_once() {
        FAIL_STAGE_INIT.with(|flag| flag.set(true));
    }
    pub(super) fn should_fail_stage_init() -> bool {
        FAIL_STAGE_INIT.with(|flag| flag.replace(false))
    }
    #[allow(dead_code)]
    pub(super) fn set_before_rename(seam: Option<(Sender<()>, Receiver<()>)>) {
        BEFORE_RENAME.with(|slot| *slot.borrow_mut() = seam);
    }
    pub(super) fn before_parent_reresolve() {
        let barrier = BEFORE_PARENT_RERESOLVE.with(|slot| slot.borrow_mut().take());
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
    }
    pub(super) fn set_before_fragment_copy(barrier: Option<Arc<Barrier>>) {
        BEFORE_FRAGMENT_COPY.with(|slot| *slot.borrow_mut() = barrier);
    }
    pub(super) fn before_fragment_copy() {
        let barrier = BEFORE_FRAGMENT_COPY.with(|slot| slot.borrow_mut().take());
        if let Some(barrier) = barrier {
            barrier.wait();
            barrier.wait();
        }
    }
    pub(super) fn before_rename() {
        let seam = BEFORE_RENAME.with(|slot| slot.borrow_mut().take());
        if let Some((entered, resume)) = seam {
            assert!(
                entered.send(()).is_ok(),
                "post-SHA seam receiver disappeared"
            );
            assert!(
                resume.recv_timeout(Duration::from_secs(5)).is_ok(),
                "post-SHA seam timed out"
            );
        }
    }
}

#[allow(clippy::struct_field_names)]
// The parent directory and lock define a trusted release-operator namespace.
// Processes with the same EUID are equally authoritative (they can alter
// memory or descriptors); ordinary Unix paths cannot isolate against them.
struct Stage {
    parent_path: PathBuf,
    parent_fd: OwnedFd,
    parent_chain: Vec<NamespaceIdentity>,
    stage_name: String,
    root_fd: OwnedFd,
    root_dev: u64,
    root_ino: u64,
    _lock_file: File,
    published: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NamespaceIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DirectoryIdentity {
    relative: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
    nlink: u64,
}

/// Owns a just-created staging name until its inode has been retained by
/// `Stage`.  This deliberately starts at the `mkdirat` success boundary: no
/// initialization error can strand a visible staging directory.
struct InitStage<'a> {
    parent: &'a OwnedFd,
    name: String,
    created: Option<rustix::fs::Stat>,
    armed: bool,
}
impl InitStage<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for InitStage<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(created) = &self.created {
            cleanup_created_stage(self.parent, &self.name, created);
        } else {
            // The namespace was checked owner-only before mkdirat.  Until an
            // identity is available, only remove the exact empty name we made.
            let _ = unlinkat(self.parent, &self.name, AtFlags::REMOVEDIR);
        }
    }
}

fn namespace_identity(stat: &rustix::fs::Stat) -> Result<NamespaceIdentity> {
    let uid = rustix::process::geteuid().as_raw();
    if stat.st_mode & 0o022 != 0 || (stat.st_uid != uid && stat.st_uid != 0) {
        return Err(contract(
            "output path components must be root/current-user owned and not group/other writable",
        ));
    }
    Ok(NamespaceIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        uid: stat.st_uid,
        mode: stat.st_mode,
    })
}

fn open_trusted_parent(parent: &Path) -> Result<(OwnedFd, Vec<NamespaceIdentity>)> {
    let absolute = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(io_error(parent))?
            .join(parent)
    };
    let root = open(
        Path::new("/"),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
    let root_stat = fstat(&root).map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
    let mut directory = root;
    let mut chain = vec![namespace_identity(&root_stat)?];
    for component in absolute.components() {
        let name = match component {
            Component::RootDir | Component::CurDir => continue,
            Component::Normal(name) => name,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ReleaseError::InvalidPath(parent.to_path_buf()));
            }
        };
        let name = name
            .to_str()
            .ok_or_else(|| ReleaseError::InvalidPath(parent.to_path_buf()))?;
        directory = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
        let stat =
            fstat(&directory).map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
        chain.push(namespace_identity(&stat)?);
    }
    Ok((directory, chain))
}

fn trusted_parent_matches(parent: &Path, expected: &[NamespaceIdentity]) -> Result<bool> {
    let (fd, actual) = open_trusted_parent(parent)?;
    let _ = fd;
    Ok(actual == expected)
}
impl Stage {
    #[allow(clippy::needless_continue)]
    fn create(parent: &Path) -> Result<Self> {
        let (parent_fd, parent_chain) = open_trusted_parent(parent)?;
        let parent_stat =
            fstat(&parent_fd).map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
        if parent_stat.st_uid != rustix::process::geteuid().as_raw()
            || parent_stat.st_mode & 0o022 != 0
        {
            return Err(contract(
                "output parent must be owner-only and owned by the current user",
            ));
        }
        let lock_fd = openat(
            &parent_fd,
            ".dirextalk-release.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|error| {
            io_error(parent.join(".dirextalk-release.lock"))(std::io::Error::from(error))
        })?;
        let lock_meta = lock_fd.metadata().map_err(io_error(parent))?;
        if !lock_meta.is_file()
            || lock_meta.nlink() != 1
            || lock_meta.uid() != rustix::process::geteuid().as_raw()
            || lock_meta.mode() & 0o077 != 0
        {
            return Err(contract("release lock is unsafe"));
        }
        lock_fd.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                contract("another release assembly holds the namespace lock")
            } else {
                io_error(parent)(error)
            }
        })?;
        for _ in 0..8 {
            let stage_name = format!(".release-evidence-{}", uuid::Uuid::new_v4());
            match mkdirat(&parent_fd, &stage_name, Mode::from_raw_mode(0o700)) {
                Ok(()) => {
                    let mut init = InitStage {
                        parent: &parent_fd,
                        name: stage_name.clone(),
                        created: None,
                        armed: true,
                    };
                    let created = statat(&parent_fd, &stage_name, AtFlags::SYMLINK_NOFOLLOW)
                        .map_err(|error| {
                            io_error(parent.join(&stage_name))(std::io::Error::from(error))
                        })?;
                    init.created = Some(created);
                    #[cfg(test)]
                    if test_seams::should_fail_stage_init() {
                        return Err(contract("injected staging initialization failure"));
                    }
                    let root_fd = openat(
                        &parent_fd,
                        &stage_name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                        Mode::empty(),
                    )
                    .map_err(|error| {
                        io_error(parent.join(&stage_name))(std::io::Error::from(error))
                    })?;
                    if let Err(error) = fchmod(&root_fd, Mode::from_raw_mode(0o700)) {
                        return Err(io_error(parent.join(&stage_name))(std::io::Error::from(
                            error,
                        )));
                    }
                    let root_stat = fstat(&root_fd).map_err(|error| {
                        io_error(parent.join(&stage_name))(std::io::Error::from(error))
                    })?;
                    if root_stat.st_dev != created.st_dev || root_stat.st_ino != created.st_ino {
                        return Err(contract("staging inode changed during initialization"));
                    }
                    init.disarm();
                    drop(init);
                    return Ok(Self {
                        parent_path: parent.to_path_buf(),
                        parent_fd,
                        parent_chain,
                        stage_name,
                        root_fd,
                        root_dev: root_stat.st_dev,
                        root_ino: root_stat.st_ino,
                        _lock_file: lock_fd,
                        published: false,
                    });
                }
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(io_error(parent)(std::io::Error::from(error))),
            }
        }
        Err(contract("staging-name collision limit exceeded"))
    }
    fn publish(self, output: &Path, inventory: &ValidatedInventory) -> Result<()> {
        self.publish_with_check(output, inventory, || Ok(()))
    }
    fn publish_with_check<F>(
        mut self,
        output: &Path,
        inventory: &ValidatedInventory,
        mut pre_publish: F,
    ) -> Result<()>
    where
        F: FnMut() -> Result<()>,
    {
        let parent = output
            .parent()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
        let output_name = output
            .file_name()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
        #[cfg(test)]
        test_seams::before_parent_reresolve();
        if !trusted_parent_matches(parent, &self.parent_chain)? {
            return Err(contract("output parent changed during assembly"));
        }
        if !self.stage_matches_root()? {
            return Err(contract("staging entry changed before publication"));
        }
        #[cfg(test)]
        test_seams::before_rename();
        pre_publish()?;
        validate_inventory_fd(self.root_fd.as_fd(), inventory)?;
        renameat_with(
            &self.parent_fd,
            &self.stage_name,
            &self.parent_fd,
            output_name,
            RenameFlags::NOREPLACE,
        )
        .map_err(|error| {
            if error == Errno::EXIST {
                ReleaseError::OutputNotEmpty(output.to_path_buf())
            } else {
                io_error(output)(std::io::Error::from(error))
            }
        })?;
        let output_fd = openat(
            &self.parent_fd,
            output_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(output)(std::io::Error::from(error)))?;
        let output_stat =
            fstat(&output_fd).map_err(|error| io_error(output)(std::io::Error::from(error)))?;
        self.published = true;
        if output_stat.st_dev != self.root_dev || output_stat.st_ino != self.root_ino {
            return Err(contract("published output does not match staged root"));
        }
        validate_inventory_fd(output_fd.as_fd(), inventory)?;
        if !trusted_parent_matches(parent, &self.parent_chain)? {
            return Err(contract("output parent changed after publication"));
        }
        fsync(&self.parent_fd).map_err(|error| io_error(parent)(std::io::Error::from(error)))?;
        Ok(())
    }
    fn stage_matches_root(&self) -> Result<bool> {
        let stat = match statat(&self.parent_fd, &self.stage_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(false),
            Err(error) => return Err(io_error(&self.stage_name)(std::io::Error::from(error))),
        };
        if stat.st_dev != self.root_dev || stat.st_ino != self.root_ino {
            return Ok(false);
        }
        let fd = openat(
            &self.parent_fd,
            &self.stage_name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(&self.stage_name)(std::io::Error::from(error)))?;
        let opened =
            fstat(&fd).map_err(|error| io_error(&self.stage_name)(std::io::Error::from(error)))?;
        Ok(opened.st_dev == self.root_dev && opened.st_ino == self.root_ino)
    }
    fn output_exists(&self, output: &Path) -> Result<bool> {
        let name = output
            .file_name()
            .ok_or_else(|| ReleaseError::InvalidPath(output.to_path_buf()))?;
        match statat(&self.parent_fd, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::NOENT) => Ok(false),
            Err(error) => Err(io_error(output)(std::io::Error::from(error))),
        }
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if !self.published && self.stage_matches_root().unwrap_or(false) {
            let _ = clear_dir_fd(&self.root_fd);
            let _ = unlinkat(&self.parent_fd, &self.stage_name, AtFlags::REMOVEDIR);
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

/// One canonical producer fragment for exactly one release component.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInputFragmentV1 {
    pub schema: String,
    pub schema_version: u32,
    pub release: EvidenceRelease,
    pub component: ReleaseInputComponent,
}
impl ReleaseInputFragmentV1 {
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe, non-canonical, or invalid fragments.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_file_descriptor(path, MAX_INPUT_BYTES)?;
        Self::from_bytes(&bytes)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = strict_json::parse_value(bytes)?;
        let fragment: Self = serde_json::from_value(value)?;
        if fragment.schema != "dirextalk.release-input-fragment" || fragment.schema_version != 1 {
            return Err(contract("fragment schema/version is unsupported"));
        }
        fragment.validate()?;
        if strict_json::canonical_bytes(&serde_json::to_value(&fragment)?, true)? != bytes {
            return Err(contract("fragment JSON is not canonical"));
        }
        Ok(fragment)
    }

    fn validate(&self) -> Result<()> {
        if self.release.source_date_epoch == 0
            || semver::Version::parse(&self.release.version).is_err()
        {
            return Err(contract("fragment release is invalid"));
        }
        validate_input_component(&self.component, &mut BTreeSet::new())
    }
}

#[derive(Clone, Debug)]
struct FragmentStat {
    device: u64,
    inode: u64,
    nlink: u64,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: u64,
}

struct FragmentSourceGuard {
    path: PathBuf,
    parent_path: PathBuf,
    parent_fd: OwnedFd,
    parent_chain: Vec<NamespaceIdentity>,
    name: String,
    stat: FragmentStat,
    fragment: ReleaseInputFragmentV1,
}

impl FragmentSourceGuard {
    fn load(path: &Path) -> Result<Self> {
        let parent_path = path
            .parent()
            .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| ReleaseError::InvalidPath(path.to_path_buf()))?
            .to_owned();
        safe_relative(Path::new(&name))?;
        let (parent_fd, parent_chain) = open_trusted_parent(parent_path)?;
        let raw = statat(&parent_fd, &name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error(path)(std::io::Error::from(error)))?;
        let stat = fragment_stat(&raw, path)?;
        let (bytes, _) = read_regular_file_fd_relative_descriptor(
            parent_fd.as_fd(),
            Path::new(&name),
            stat.size,
            None,
            MAX_INPUT_BYTES,
        )?;
        let fragment = ReleaseInputFragmentV1::from_bytes(&bytes)?;
        Ok(Self {
            path: path.to_path_buf(),
            parent_path: parent_path.to_path_buf(),
            parent_fd,
            parent_chain,
            name,
            stat,
            fragment,
        })
    }

    fn verify_path(&self) -> Result<()> {
        let (current_parent, current_chain) = open_trusted_parent(&self.parent_path)?;
        if current_chain != self.parent_chain {
            return Err(contract("fragment parent changed during composition"));
        }
        let current = statat(&current_parent, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error(&self.path)(std::io::Error::from(error)))?;
        let retained = statat(&self.parent_fd, &self.name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error(&self.path)(std::io::Error::from(error)))?;
        if !same_fragment_stat(&self.stat, &current) || !same_fragment_stat(&self.stat, &retained) {
            return Err(contract("fragment file changed during composition"));
        }
        Ok(())
    }
}

fn fragment_stat(stat: &rustix::fs::Stat, path: &Path) -> Result<FragmentStat> {
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size.cast_unsigned() > MAX_INPUT_BYTES
    {
        return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
    }
    Ok(FragmentStat {
        device: stat.st_dev,
        inode: stat.st_ino,
        nlink: stat.st_nlink,
        mode: stat.st_mode,
        size: stat.st_size.cast_unsigned(),
        mtime: stat.st_mtime,
        mtime_nsec: stat.st_mtime_nsec,
    })
}

fn same_fragment_stat(expected: &FragmentStat, actual: &rustix::fs::Stat) -> bool {
    expected.device == actual.st_dev
        && expected.inode == actual.st_ino
        && expected.nlink == actual.st_nlink
        && expected.mode == actual.st_mode
        && expected.size == actual.st_size.cast_unsigned()
        && expected.mtime == actual.st_mtime
        && expected.mtime_nsec == actual.st_mtime_nsec
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseInputComponent {
    pub component: String,
    pub source_commit: String,
    pub source_tree: String,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let inputs: Self = serde_json::from_value(strict_json::parse_value(bytes)?)?;
        inputs.validate()?;
        if inputs.canonical_bytes()? != bytes {
            return Err(contract("release inputs JSON is not canonical"));
        }
        Ok(inputs)
    }
    /// Load one canonical release-inputs document.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe files, non-canonical JSON, duplicates, or
    /// a contract that does not name exactly the required components.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = read_regular_file_descriptor(path, MAX_INPUT_BYTES)?;
        Self::from_bytes(&bytes)
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
            validate_input_component(component, &mut all_paths)?;
        }
        Ok(())
    }
}

fn validate_input_component(
    component: &ReleaseInputComponent,
    all_paths: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    if !REQUIRED_RELEASE_COMPONENTS.contains(&component.component.as_str()) {
        return Err(contract("component is not required"));
    }
    token(&component.component)?;
    token(&component.toolchain)?;
    token(&component.artifact.identity)?;
    if !commit(&component.source_commit)
        || !commit(&component.source_tree)
        || component.targets.is_empty()
    {
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
    Ok(())
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
    // The external file is an input only.  Publish a strict, canonical snapshot
    // so validation never depends on the original path or its formatting.
    let manifest_value = strict_json::parse_value(&manifest_bytes)?;
    let manifest_contract: ReleaseManifest = serde_json::from_value(manifest_value)?;
    manifest_contract.validate()?;
    let manifest_snapshot =
        strict_json::canonical_bytes(&serde_json::to_value(&manifest_contract)?, true)?;
    let manifest = LoadedManifest::load_from_bytes(manifest_path, &manifest_snapshot)?;
    let manifest_digest = digest(&manifest_snapshot);
    let mut guards = Vec::new();
    for component in &inputs.components {
        let root = roots
            .get(&component.component)
            .ok_or_else(|| contract("missing source root"))?;
        let guard = SourceEvidenceGuard::begin(root)?;
        guard.verify_expected(&component.source_commit)?;
        if guard.head_tree() != component.source_tree {
            return Err(contract("source tree mismatches release inputs"));
        }
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
    if stage.output_exists(output)? {
        return Err(ReleaseError::OutputNotEmpty(output.to_path_buf()));
    }
    let input_root = inputs_path
        .parent()
        .ok_or_else(|| ReleaseError::InvalidPath(inputs_path.to_path_buf()))?;
    ensure_directory(input_root)?;
    let inputs_snapshot = inputs.canonical_bytes()?;
    stage.write_new(Path::new("release-inputs.json"), &inputs_snapshot)?;
    stage.write_new(Path::new("release-manifest.json"), &manifest_snapshot)?;
    let mut identities = BTreeSet::new();
    let mut components = Vec::new();
    let mut attestations = Vec::new();
    for component in &inputs.components {
        let recipe = copy_material(
            &stage,
            input_root,
            &component.build_recipe.path,
            &format!("components/{}/build-recipe", component.component),
            &mut identities,
        )?;
        let artifact_file = copy_material(
            &stage,
            input_root,
            &component.artifact.path,
            &format!("components/{}/artifact", component.component),
            &mut identities,
        )?;
        let sbom = copy_material(
            &stage,
            input_root,
            &component.sbom.path,
            &format!("components/{}/sbom", component.component),
            &mut identities,
        )?;
        let notice = copy_material(
            &stage,
            input_root,
            &component.third_party_notice.path,
            &format!("components/{}/third-party-notice", component.component),
            &mut identities,
        )?;
        let license = copy_material(
            &stage,
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
            schema: LOCAL_PROVENANCE_SCHEMA.into(),
            schema_version: LOCAL_PROVENANCE_SCHEMA_VERSION,
            component: component.component.clone(),
            release_manifest_sha256: manifest_digest.clone(),
            source_commit: component.source_commit.clone(),
            source_tree: component.source_tree.clone(),
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
        stage.write_new(&provenance_path, &provenance_bytes)?;
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
    stage.write_new(Path::new("release-evidence.json"), &evidence_bytes)?;
    // Re-open every staged member through the existing no-follow validator
    // before the checksums and atomic publication make the directory visible.
    evidence.validate_files_fd(stage.root_fd.as_fd())?;
    let original_inventory = validated_inventory_fd(stage.root_fd.as_fd())?;
    let checksums = checksum_manifest(&original_inventory.files);
    stage.write_new(Path::new("SHA256SUMS"), &checksums)?;
    let inventory = validated_inventory_fd(stage.root_fd.as_fd())?;
    validate_original_inventory(&original_inventory, &inventory, &checksums)?;
    validate_inventory_fd(stage.root_fd.as_fd(), &inventory)?;
    sync_tree_fd(stage.root_fd.as_fd())?;
    for (_, guard) in guards {
        guard.finish()?;
    }
    stage.publish(output, &inventory)?;
    Ok(evidence)
}

/// Compose exactly one producer fragment for each required release component
/// into a self-contained release-inputs directory. This operation only copies
/// already-produced material; it never invokes a builder or network.
///
/// # Errors
///
/// Returns an error for malformed or mismatched fragments, unsafe/changing
/// material, an existing output, or an atomic publication failure.
#[allow(clippy::too_many_lines)]
pub fn compose(fragments: &[PathBuf], output: &Path) -> Result<ReleaseInputsV1> {
    if fragments.len() != REQUIRED_RELEASE_COMPONENTS.len() {
        return Err(contract("requires exactly five --fragment inputs"));
    }
    let mut loaded = Vec::with_capacity(fragments.len());
    let mut names = BTreeSet::new();
    let mut release: Option<EvidenceRelease> = None;
    for path in fragments {
        let guard = FragmentSourceGuard::load(path)?;
        let fragment = &guard.fragment;
        if !names.insert(fragment.component.component.clone()) {
            return Err(contract("fragment components are duplicated"));
        }
        if let Some(expected) = &release {
            if expected != &fragment.release {
                return Err(contract("fragment releases differ"));
            }
        } else {
            release = Some(fragment.release.clone());
        }
        loaded.push(guard);
    }
    if names.len() != REQUIRED_RELEASE_COMPONENTS.len()
        || REQUIRED_RELEASE_COMPONENTS
            .iter()
            .any(|name| !names.contains(*name))
    {
        return Err(contract("fragments must cover exactly five components"));
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
    for guard in &loaded {
        if fs::canonicalize(&guard.path)
            .map_err(io_error(&guard.path))?
            .starts_with(&output_candidate)
        {
            return Err(contract("fragments must be outside output"));
        }
    }
    let stage = Stage::create(parent)?;
    if stage.output_exists(output)? {
        return Err(ReleaseError::OutputNotEmpty(output.to_path_buf()));
    }
    let mut identities = BTreeSet::new();
    let mut components = Vec::with_capacity(loaded.len());
    #[cfg(test)]
    test_seams::before_fragment_copy();
    for guard in &loaded {
        let fragment = &guard.fragment;
        let name = fragment.component.component.clone();
        let base = format!("components/{name}");
        let recipe = copy_material_fd(
            &stage,
            guard.parent_fd.as_fd(),
            &fragment.component.build_recipe.path,
            &format!("{base}/build-recipe"),
            &mut identities,
        )?;
        let artifact = copy_material_fd(
            &stage,
            guard.parent_fd.as_fd(),
            &fragment.component.artifact.path,
            &format!("{base}/artifact"),
            &mut identities,
        )?;
        let sbom = copy_material_fd(
            &stage,
            guard.parent_fd.as_fd(),
            &fragment.component.sbom.path,
            &format!("{base}/sbom"),
            &mut identities,
        )?;
        let notice = copy_material_fd(
            &stage,
            guard.parent_fd.as_fd(),
            &fragment.component.third_party_notice.path,
            &format!("{base}/third-party-notice"),
            &mut identities,
        )?;
        let license = copy_material_fd(
            &stage,
            guard.parent_fd.as_fd(),
            &fragment.component.license.path,
            &format!("{base}/license"),
            &mut identities,
        )?;
        let mut component = fragment.component.clone();
        component.build_recipe.path = recipe.path;
        component.artifact.path = artifact.path;
        component.sbom.path = sbom.path;
        component.third_party_notice.path = notice.path;
        component.license.path = license.path;
        components.push(component);
    }
    components.sort_by(|a, b| a.component.cmp(&b.component));
    let inputs = ReleaseInputsV1 {
        schema: "dirextalk.release-inputs".into(),
        schema_version: 1,
        release: release.ok_or_else(|| contract("missing release"))?,
        components,
    };
    inputs.validate()?;
    stage.write_new(Path::new("release-inputs.json"), &inputs.canonical_bytes()?)?;
    let inventory = validated_inventory_fd(stage.root_fd.as_fd())?;
    validate_composed_inventory(&inventory, &inputs)?;
    sync_tree_fd(stage.root_fd.as_fd())?;
    stage.publish_with_check(output, &inventory, || {
        for guard in &loaded {
            guard.verify_path()?;
        }
        Ok(())
    })?;
    Ok(inputs)
}

fn validate_composed_inventory(
    inventory: &ValidatedInventory,
    inputs: &ReleaseInputsV1,
) -> Result<()> {
    let mut expected = BTreeSet::from([PathBuf::from("release-inputs.json")]);
    for component in &inputs.components {
        expected.extend([
            component.build_recipe.path.clone(),
            component.artifact.path.clone(),
            component.sbom.path.clone(),
            component.third_party_notice.path.clone(),
            component.license.path.clone(),
        ]);
    }
    let actual: BTreeSet<_> = inventory
        .files
        .iter()
        .map(|entry| entry.relative.clone())
        .collect();
    if actual != expected {
        return Err(contract("composed inventory does not match release inputs"));
    }
    let expected_directories: BTreeSet<PathBuf> = expected
        .iter()
        .flat_map(|path| path.ancestors().skip(1))
        .filter(|path| !path.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .collect();
    let actual_directories: BTreeSet<PathBuf> = inventory
        .directories
        .iter()
        .map(|entry| entry.relative.clone())
        .collect();
    if actual_directories != expected_directories {
        return Err(contract("composed directory layout is not exact"));
    }
    Ok(())
}

/// Strict read-only verifier for one finalized, self-contained v1 directory.
pub struct ReleaseMaterialsV1;
impl ReleaseMaterialsV1 {
    /// Verify a finalized directory without modifying it.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe, incomplete, non-canonical, tampered,
    /// or concurrently changing finalized directory.
    #[allow(clippy::too_many_lines)]
    pub fn validate_dir(directory: &Path) -> Result<()> {
        let (fd, chain) = open_trusted_parent(directory)?;
        let initial = validated_inventory_fd(fd.as_fd())?;
        let mut files = BTreeMap::new();
        for entry in &initial.files {
            files.insert(entry.relative.clone(), entry.bytes.as_slice());
        }
        let take = |name: &str| -> Result<&[u8]> {
            files
                .get(Path::new(name))
                .copied()
                .ok_or_else(|| contract("finalized directory member is missing"))
        };
        let inputs_bytes = take("release-inputs.json")?;
        let inputs = ReleaseInputsV1::from_bytes(inputs_bytes)?;
        let manifest_bytes = take("release-manifest.json")?;
        let manifest_value = strict_json::parse_value(manifest_bytes)?;
        let manifest_contract: ReleaseManifest = serde_json::from_value(manifest_value)?;
        manifest_contract.validate()?;
        if strict_json::canonical_bytes(&serde_json::to_value(&manifest_contract)?, true)?
            != manifest_bytes
        {
            return Err(contract("release manifest JSON is not canonical"));
        }
        let evidence = ReleaseEvidenceV1::from_bytes(take("release-evidence.json")?)?;
        evidence.validate_files_fd(fd.as_fd())?;
        let loaded = LoadedManifest {
            manifest: manifest_contract,
            manifest_path: directory.join("release-manifest.json"),
            root: directory.to_path_buf(),
        };
        evidence.cross_check_manifest(&loaded)?;
        if evidence.release != inputs.release {
            return Err(contract("release inputs and evidence differ"));
        }
        let manifest_digest = digest(manifest_bytes);
        let mut expected = BTreeSet::from([
            PathBuf::from("release-inputs.json"),
            PathBuf::from("release-manifest.json"),
            PathBuf::from("release-evidence.json"),
            PathBuf::from("SHA256SUMS"),
        ]);
        let mut input_by_component = BTreeMap::new();
        for component in &inputs.components {
            input_by_component.insert(component.component.as_str(), component);
        }
        for component in &evidence.components {
            let input = input_by_component
                .get(component.component.as_str())
                .ok_or_else(|| contract("evidence component is absent from inputs"))?;
            let base = PathBuf::from(format!("components/{}", component.component));
            let recipe_path = base.join("build-recipe");
            let artifact_path = base.join("artifact");
            let sbom_path = base.join("sbom");
            let notice_path = base.join("third-party-notice");
            let license_path = base.join("license");
            let check_file = |file: &FileEvidence, path: &Path| -> Result<()> {
                let bytes = files
                    .get(path)
                    .copied()
                    .ok_or_else(|| contract("fixed role file is missing"))?;
                if file.path != path
                    || file.size != bytes.len() as u64
                    || file.sha256 != digest(bytes)
                {
                    return Err(contract("fixed role file mismatches evidence"));
                }
                Ok(())
            };
            if component.source_commit != input.source_commit
                || component.toolchain != input.toolchain
                || component.targets != input.targets
                || component.target != input.targets[0]
                || component.artifact.identity != input.artifact.identity
                || component.artifact.path != artifact_path
            {
                return Err(contract("evidence component mismatches inputs"));
            }
            check_file(
                &FileEvidence {
                    path: component.artifact.path.clone(),
                    size: component.artifact.size,
                    sha256: component.artifact.sha256.clone(),
                },
                &artifact_path,
            )?;
            check_file(&component.sbom, &sbom_path)?;
            check_file(&component.third_party_notice, &notice_path)?;
            check_file(&component.license, &license_path)?;
            for path in [
                &recipe_path,
                &artifact_path,
                &sbom_path,
                &notice_path,
                &license_path,
            ] {
                expected.insert(path.clone());
            }
            let provenance_path = PathBuf::from(format!("provenance/{}.json", component.component));
            let provenance: LocalProvenanceV1 = serde_json::from_value(strict_json::parse_value(
                files
                    .get(&provenance_path)
                    .copied()
                    .ok_or_else(|| contract("provenance is missing"))?,
            )?)?;
            let provenance_bytes = files[&provenance_path];
            if strict_json::canonical_bytes(&serde_json::to_value(&provenance)?, true)?
                != provenance_bytes
                || provenance.schema != LOCAL_PROVENANCE_SCHEMA
                || provenance.schema_version != LOCAL_PROVENANCE_SCHEMA_VERSION
                || provenance.component != component.component
                || provenance.source_commit != component.source_commit
                || !commit(&provenance.source_tree)
                || provenance.source_tree != input.source_tree
                || provenance.targets != input.targets
                || provenance.toolchain != component.toolchain
                || provenance.release_manifest_sha256 != manifest_digest
                || provenance.artifact != component.artifact
                || provenance.sbom != component.sbom
                || provenance.third_party_notice != component.third_party_notice
                || provenance.license != component.license
                || component.build_recipe != format!("sha256:{}", provenance.build_recipe.sha256)
            {
                return Err(contract("provenance mismatches finalized evidence"));
            }
            check_file(&provenance.build_recipe, &recipe_path)?;
            let expected_attestation = AttestationReference {
                kind: AttestationKind::InToto,
                component: component.component.clone(),
                target: input.targets[0].clone(),
                path: provenance_path.clone(),
                size: provenance_bytes.len() as u64,
                sha256: digest(provenance_bytes),
                artifact_sha256: component.artifact.sha256.clone(),
            };
            if !component.attestations.is_empty()
                || evidence
                    .attestations
                    .iter()
                    .filter(|entry| entry.component == component.component)
                    .count()
                    != 1
                || !evidence.attestations.contains(&expected_attestation)
            {
                return Err(contract(
                    "global attestation does not bind component provenance",
                ));
            }
            expected.insert(provenance_path);
        }
        for attestation in &evidence.attestations {
            expected.insert(attestation.path.clone());
        }
        let actual: BTreeSet<_> = initial
            .files
            .iter()
            .map(|entry| entry.relative.clone())
            .collect();
        if actual != expected {
            return Err(contract("finalized directory layout is not exact"));
        }
        let expected_directories: BTreeSet<PathBuf> = expected
            .iter()
            .flat_map(|path| path.ancestors().skip(1))
            .filter(|path| !path.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .collect();
        let actual_directories: BTreeSet<PathBuf> = initial
            .directories
            .iter()
            .map(|entry| entry.relative.clone())
            .collect();
        if actual_directories != expected_directories {
            return Err(contract(
                "finalized directory aliases or extra directories are present",
            ));
        }
        let sums = take("SHA256SUMS")?;
        let covered: Vec<_> = initial
            .files
            .iter()
            .filter(|entry| entry.relative != Path::new("SHA256SUMS"))
            .cloned()
            .collect();
        if checksum_manifest(&covered) != sums {
            return Err(contract(
                "SHA256SUMS is not canonical or does not cover final files",
            ));
        }
        let final_scan = validated_inventory_fd(fd.as_fd())?;
        if initial.directories != final_scan.directories
            || initial.files.len() != final_scan.files.len()
            || initial.files.iter().zip(&final_scan.files).any(|(a, b)| {
                a.relative != b.relative
                    || a.identity != b.identity
                    || a.nlink != b.nlink
                    || a.mode != b.mode
                    || a.size != b.size
                    || a.mtime != b.mtime
                    || a.mtime_nsec != b.mtime_nsec
                    || digest(&a.bytes) != digest(&b.bytes)
            })
        {
            return Err(contract("finalized directory changed during validation"));
        }
        if !trusted_parent_matches(directory, &chain)? {
            return Err(contract(
                "finalized directory path changed during validation",
            ));
        }
        Ok(())
    }
}

fn copy_material(
    stage: &Stage,
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
    stage.write_new(&path, &bytes)?;
    Ok(FileEvidence {
        path,
        size: bytes.len() as u64,
        sha256: digest(&bytes),
    })
}

fn copy_material_fd(
    stage: &Stage,
    input_root: BorrowedFd<'_>,
    source: &Path,
    destination: &str,
    identities: &mut BTreeSet<FileIdentity>,
) -> Result<FileEvidence> {
    safe_relative(source)?;
    let stat = statat(input_root, source, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|error| io_error(source)(std::io::Error::from(error)))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_nlink != 1
        || stat.st_size <= 0
        || stat.st_size.cast_unsigned() > MAX_MATERIAL_BYTES
    {
        return Err(ReleaseError::UnsafeFile(source.to_path_buf()));
    }
    let (bytes, identity) = read_regular_file_fd_relative_descriptor(
        input_root,
        source,
        stat.st_size.cast_unsigned(),
        None,
        MAX_MATERIAL_BYTES,
    )?;
    if !identities.insert(identity) {
        return Err(contract("input roles must not share an inode"));
    }
    let path = PathBuf::from(destination);
    stage.write_new(&path, &bytes)?;
    Ok(FileEvidence {
        path,
        size: bytes.len() as u64,
        sha256: digest(&bytes),
    })
}

#[derive(Clone)]
struct InventoryEntry {
    relative: PathBuf,
    bytes: Vec<u8>,
    identity: FileIdentity,
    nlink: u64,
    mode: u32,
    size: u64,
    mtime: i64,
    mtime_nsec: u64,
}

struct ValidatedInventory {
    files: Vec<InventoryEntry>,
    directories: BTreeSet<DirectoryIdentity>,
}

fn validated_inventory_fd(root: impl AsFd) -> Result<ValidatedInventory> {
    let mut files = Vec::new();
    collect_files_fd(root.as_fd(), PathBuf::new(), &mut files)?;
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    let mut directories = BTreeSet::new();
    collect_directories_fd(root.as_fd(), PathBuf::new(), &mut directories)?;
    Ok(ValidatedInventory { files, directories })
}

fn validate_inventory_fd(root: impl AsFd, expected: &ValidatedInventory) -> Result<()> {
    let actual = validated_inventory_fd(root.as_fd())?;
    if actual.directories != expected.directories
        || actual.files.len() != expected.files.len()
        || actual
            .files
            .iter()
            .zip(&expected.files)
            .any(|(actual, expected)| {
                actual.relative != expected.relative
                    || actual.identity != expected.identity
                    || actual.nlink != expected.nlink
                    || actual.mode != expected.mode
                    || actual.size != expected.size
                    || actual.mtime != expected.mtime
                    || actual.mtime_nsec != expected.mtime_nsec
                    || digest(&actual.bytes) != digest(&expected.bytes)
            })
    {
        return Err(contract("staged inventory changed during publication"));
    }
    Ok(())
}

fn validate_original_inventory(
    original: &ValidatedInventory,
    final_inventory: &ValidatedInventory,
    checksums: &[u8],
) -> Result<()> {
    if final_inventory.directories != original.directories
        || final_inventory.files.len() != original.files.len() + 1
    {
        return Err(contract(
            "final inventory differs from original release set",
        ));
    }
    for (actual, expected) in final_inventory
        .files
        .iter()
        .filter(|entry| entry.relative != Path::new("SHA256SUMS"))
        .zip(&original.files)
    {
        if actual.relative != expected.relative
            || actual.identity != expected.identity
            || actual.nlink != expected.nlink
            || actual.mode != expected.mode
            || actual.size != expected.size
            || actual.mtime != expected.mtime
            || actual.mtime_nsec != expected.mtime_nsec
            || digest(&actual.bytes) != digest(&expected.bytes)
        {
            return Err(contract("original release inventory changed"));
        }
    }
    let Some(checksum) = final_inventory
        .files
        .iter()
        .find(|entry| entry.relative == Path::new("SHA256SUMS"))
    else {
        return Err(contract("SHA256SUMS is missing from final inventory"));
    };
    if checksum.bytes != checksums {
        return Err(contract("SHA256SUMS does not match original inventory"));
    }
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn collect_directories_fd(
    root: impl AsFd,
    current: PathBuf,
    result: &mut BTreeSet<DirectoryIdentity>,
) -> Result<()> {
    let scan = openat(
        root.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
    let mut buffer = Vec::with_capacity(8192);
    let mut names = Vec::new();
    {
        let mut dir = RawDir::new(&scan, buffer.spare_capacity_mut());
        while let Some(entry) = dir.next() {
            let entry =
                entry.map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
    }
    for name in names {
        let name = std::str::from_utf8(&name).map_err(|_| contract("invalid staging entry"))?;
        let stat = statat(&scan, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let relative = if current.as_os_str().is_empty() {
                PathBuf::from(name)
            } else {
                current.join(name)
            };
            let child = openat(
                &scan,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            let opened = fstat(&child)
                .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            if opened.st_dev != stat.st_dev || opened.st_ino != stat.st_ino {
                return Err(contract("staging directory changed while scanning"));
            }
            result.insert(DirectoryIdentity {
                relative: relative.clone(),
                device: opened.st_dev,
                inode: opened.st_ino,
                mode: opened.st_mode,
                nlink: opened.st_nlink,
            });
            collect_directories_fd(&child, relative, result)?;
        }
    }
    Ok(())
}

fn checksum_manifest(files: &[InventoryEntry]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for file in files {
        let _ = &file.identity;
        // SHA256SUMS is deliberately the only excluded member: including its
        // own digest would be recursive. Every other regular final member is
        // represented once as `sha256 size path`, sorted by its relative path.
        bytes.extend_from_slice(
            format!(
                "{} {} {}\n",
                digest(&file.bytes),
                file.bytes.len(),
                file.relative.display()
            )
            .as_bytes(),
        );
    }
    bytes
}
#[allow(clippy::needless_pass_by_value)]
fn collect_files_fd(
    root: impl AsFd,
    current: PathBuf,
    result: &mut Vec<InventoryEntry>,
) -> Result<()> {
    let scan_root = openat(
        root.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
    let root = &scan_root;
    let mut buffer = Vec::with_capacity(8192);
    let mut names = Vec::new();
    {
        let mut dir = RawDir::new(root.as_fd(), buffer.spare_capacity_mut());
        while let Some(entry) = dir.next() {
            let entry = entry.map_err(|error| io_error(&current)(std::io::Error::from(error)))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
    }
    for name in names {
        let name_str =
            std::str::from_utf8(&name).map_err(|_| ReleaseError::UnsafeFile(current.clone()))?;
        let stat = statat(root, name_str, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error(&current)(std::io::Error::from(error)))?;
        let relative = if current.as_os_str().is_empty() {
            PathBuf::from(name_str)
        } else {
            current.join(name_str)
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = openat(
                    root,
                    name_str,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| io_error(&relative)(std::io::Error::from(error)))?;
                collect_files_fd(&child, relative, result)?;
            }
            FileType::RegularFile => {
                let fd = openat(
                    root,
                    name_str,
                    OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| io_error(&relative)(std::io::Error::from(error)))?;
                let before =
                    fstat(&fd).map_err(|error| io_error(&relative)(std::io::Error::from(error)))?;
                if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
                    || before.st_nlink != 1
                    || before.st_size < 0
                    || before.st_size.cast_unsigned() > MAX_MATERIAL_BYTES
                {
                    return Err(ReleaseError::UnsafeFile(relative));
                }
                let mut file = File::from(fd);
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(MAX_MATERIAL_BYTES.saturating_add(1))
                    .read_to_end(&mut bytes)
                    .map_err(io_error(&relative))?;
                let after = fstat(&file)
                    .map_err(|error| io_error(&relative)(std::io::Error::from(error)))?;
                if before.st_dev != after.st_dev
                    || before.st_ino != after.st_ino
                    || before.st_nlink != after.st_nlink
                    || before.st_mode != after.st_mode
                    || before.st_size != after.st_size
                    || before.st_mtime != after.st_mtime
                    || before.st_mtime_nsec != after.st_mtime_nsec
                    || bytes.len() as u64 != before.st_size.cast_unsigned()
                {
                    return Err(contract("staged file changed while reading"));
                }
                result.push(InventoryEntry {
                    relative,
                    bytes,
                    identity: FileIdentity {
                        device: before.st_dev,
                        inode: before.st_ino,
                    },
                    nlink: before.st_nlink,
                    mode: before.st_mode,
                    size: before.st_size.cast_unsigned(),
                    mtime: before.st_mtime,
                    mtime_nsec: before.st_mtime_nsec,
                });
            }
            _ => return Err(ReleaseError::UnsafeFile(relative)),
        }
    }
    Ok(())
}

impl Stage {
    fn write_new(&self, relative: &Path, bytes: &[u8]) -> Result<()> {
        safe_relative(relative)?;
        let (parent_fd, name) = self.open_parent(relative)?;
        let path = self.parent_path.join(&self.stage_name).join(relative);
        let mut file = openat(
            &parent_fd,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::from_raw_mode(0o600),
        )
        .map(File::from)
        .map_err(|error| io_error(&path)(std::io::Error::from(error)))?;
        file.write_all(bytes).map_err(io_error(&path))?;
        file.sync_all().map_err(io_error(&path))?;
        fsync(&parent_fd).map_err(|error| io_error(&path)(std::io::Error::from(error)))?;
        Ok(())
    }

    fn open_parent(&self, relative: &Path) -> Result<(OwnedFd, String)> {
        let components: Vec<_> = relative.components().collect();
        let (last, parents) = components
            .split_last()
            .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
        let mut directory = openat(
            &self.root_fd,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
        for component in parents {
            let Component::Normal(name) = component else {
                return Err(ReleaseError::InvalidPath(relative.to_path_buf()));
            };
            let name = name
                .to_str()
                .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
            match mkdirat(&directory, name, Mode::from_raw_mode(0o700)) {
                Ok(()) | Err(Errno::EXIST) => {}
                Err(error) => return Err(io_error(relative)(std::io::Error::from(error))),
            }
            directory = openat(
                &directory,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| io_error(relative)(std::io::Error::from(error)))?;
        }
        let Component::Normal(name) = last else {
            return Err(ReleaseError::InvalidPath(relative.to_path_buf()));
        };
        let name = name
            .to_str()
            .ok_or_else(|| ReleaseError::InvalidPath(relative.to_path_buf()))?;
        Ok((directory, name.to_owned()))
    }
}

fn sync_tree_fd(root: impl AsFd) -> Result<()> {
    let mut buffer = Vec::with_capacity(8192);
    let mut names = Vec::new();
    {
        let mut dir = RawDir::new(root.as_fd(), buffer.spare_capacity_mut());
        while let Some(entry) = dir.next() {
            let entry =
                entry.map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(name.to_vec());
            }
        }
    }
    for name in names {
        let name = std::str::from_utf8(&name).map_err(|_| contract("invalid staging entry"))?;
        let stat = statat(&root, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            let child = openat(
                &root,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            sync_tree_fd(&child)?;
        } else if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(ReleaseError::UnsafeFile(PathBuf::from(name)));
        }
    }
    fsync(&root).map_err(|error| io_error("staging fd")(std::io::Error::from(error)))
}

fn clear_dir_fd(root: impl AsFd) -> Result<()> {
    let scan_root = openat(
        root.as_fd(),
        ".",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
    let root = &scan_root;
    let mut buffer = Vec::with_capacity(8192);
    let mut names = Vec::new();
    {
        let mut dir = RawDir::new(root.as_fd(), buffer.spare_capacity_mut());
        while let Some(entry) = dir.next() {
            let entry =
                entry.map_err(|error| io_error("staging fd")(std::io::Error::from(error)))?;
            let child_name = entry.file_name().to_bytes();
            if child_name != b"." && child_name != b".." {
                names.push(child_name.to_vec());
            }
        }
    }
    for child_name in names {
        let child_name =
            std::str::from_utf8(&child_name).map_err(|_| contract("invalid staging entry"))?;
        match statat(root, child_name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) if FileType::from_raw_mode(stat.st_mode) == FileType::Directory => {
                let child = openat(
                    root,
                    child_name,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                    Mode::empty(),
                )
                .map_err(|error| io_error(child_name)(std::io::Error::from(error)))?;
                clear_dir_fd(&child)?;
                unlinkat(root, child_name, AtFlags::REMOVEDIR)
                    .map_err(|error| io_error(child_name)(std::io::Error::from(error)))?;
            }
            Ok(_) => {
                unlinkat(root, child_name, AtFlags::empty())
                    .map_err(|error| io_error(child_name)(std::io::Error::from(error)))?;
            }
            Err(_) => {}
        }
    }
    Ok(())
}

fn cleanup_created_stage(parent: &impl AsFd, name: &str, created: &rustix::fs::Stat) {
    if let Ok(current) = statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
        && current.st_dev == created.st_dev
        && current.st_ino == created.st_ino
    {
        let _ = unlinkat(parent, name, AtFlags::REMOVEDIR);
    }
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
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    /// Tests exercise the production namespace policy, so their roots must
    /// not inherit `/tmp`'s sticky world-writable component.
    struct TempDir(tempfile::TempDir);
    impl TempDir {
        fn new() -> std::io::Result<Self> {
            let base = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target")
                .join("release-materials-tests");
            fs::create_dir_all(&base)?;
            fs::set_permissions(&base, fs::Permissions::from_mode(0o700))?;
            tempfile::Builder::new()
                .prefix("case-")
                .tempdir_in(base)
                .map(Self)
        }
        fn path(&self) -> &Path {
            self.0.path()
        }
    }

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
                    source_tree: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
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
    fn fragments_compose_to_rewritable_inputs_and_refuse_existing_output() {
        let root = TempDir::new().expect("temp");
        let fixture = inputs();
        let mut fragments = Vec::new();
        for component in &fixture.components {
            let name = &component.component;
            let mut component = component.clone();
            for (path, bytes) in [
                (&component.build_recipe.path, b"recipe".as_slice()),
                (&component.artifact.path, b"artifact".as_slice()),
                (&component.sbom.path, b"sbom".as_slice()),
                (&component.third_party_notice.path, b"notice".as_slice()),
                (&component.license.path, b"license".as_slice()),
            ] {
                let full = root.path().join(path);
                fs::create_dir_all(full.parent().expect("parent")).expect("directories");
                fs::write(full, bytes).expect("material");
            }
            let fragment = ReleaseInputFragmentV1 {
                schema: "dirextalk.release-input-fragment".into(),
                schema_version: 1,
                release: fixture.release.clone(),
                component: {
                    component.source_commit = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
                    component.source_tree = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into();
                    component
                },
            };
            let path = root.path().join(format!("{name}.json"));
            fs::write(
                &path,
                strict_json::canonical_bytes(&serde_json::to_value(&fragment).expect("json"), true)
                    .expect("canonical"),
            )
            .expect("fragment");
            fragments.push(path);
        }
        let output = root.path().join("composed");
        let composed = compose(&fragments, &output).expect("compose");
        assert_eq!(composed.components.len(), 5);
        assert_eq!(
            ReleaseInputsV1::load(&output.join("release-inputs.json")).expect("reload"),
            composed
        );
        assert!(compose(&fragments, &output).is_err());
        assert!(!root.path().read_dir().expect("entries").any(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .starts_with(".release-evidence-")
        }));
    }

    #[test]
    fn composed_inputs_feed_evidence_assembly() {
        let root = TempDir::new().expect("temp");
        let (_inputs_path, manifest, roots, fixture) = assembly_fixture(root.path());
        let mut fragments = Vec::new();
        for component in fixture.components {
            let fragment = ReleaseInputFragmentV1 {
                schema: "dirextalk.release-input-fragment".into(),
                schema_version: 1,
                release: fixture.release.clone(),
                component,
            };
            let path = root
                .path()
                .join(format!("fragment-{}.json", fragment.component.component));
            fs::write(
                &path,
                strict_json::canonical_bytes(&serde_json::to_value(&fragment).expect("json"), true)
                    .expect("canonical"),
            )
            .expect("fragment");
            fragments.push(path);
        }
        let composed_dir = root.path().join("composed");
        compose(&fragments, &composed_dir).expect("compose");
        let evidence_dir = root.path().join("evidence");
        assemble(
            &composed_dir.join("release-inputs.json"),
            &manifest,
            &roots,
            &evidence_dir,
        )
        .expect("assemble");
        ReleaseMaterialsV1::validate_dir(&evidence_dir).expect("validate");
    }

    #[test]
    fn fragment_parent_replacement_after_parse_is_rejected_without_residue() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (_inputs_path, _manifest, _roots, fixture) = assembly_fixture(root.path());
        let fragment_parent = root.path().join("fragments");
        let fragments = fragment_fixture(root.path(), &fragment_parent, &fixture);
        let renamed = root.path().join("fragments-old");
        let replacement = root.path().join("fragments-new");
        let barrier = Arc::new(Barrier::new(2));
        test_seams::set_before_fragment_copy(Some(Arc::clone(&barrier)));
        let worker_parent = fragment_parent.clone();
        let worker_renamed = renamed.clone();
        let worker_replacement = replacement.clone();
        let worker = std::thread::spawn(move || {
            barrier.wait();
            fs::rename(&worker_parent, &worker_renamed).expect("rename fragments");
            copy_tree(&worker_renamed, &worker_replacement);
            fs::write(worker_replacement.join("server/recipe"), b"CHANGE")
                .expect("same-size replacement");
            barrier.wait();
        });
        let output = root.path().join("composed");
        assert!(compose(&fragments, &output).is_err());
        worker.join().expect("worker");
        test_seams::set_before_fragment_copy(None);
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
        fs::remove_dir_all(&renamed).expect("old fragments");
        fs::remove_dir_all(&replacement).expect("replacement fragments");
    }

    #[test]
    fn fragment_parent_replacement_before_publish_is_rejected_without_residue() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (_inputs_path, _manifest, _roots, fixture) = assembly_fixture(root.path());
        let fragment_parent = root.path().join("fragments");
        let fragments = fragment_fixture(root.path(), &fragment_parent, &fixture);
        let renamed = root.path().join("fragments-old");
        let replacement = root.path().join("fragments-new");
        let barrier = Arc::new(Barrier::new(2));
        test_seams::set_before_parent_reresolve(Some(Arc::clone(&barrier)));
        let worker_parent = fragment_parent.clone();
        let worker_renamed = renamed.clone();
        let worker_replacement = replacement.clone();
        let worker = std::thread::spawn(move || {
            barrier.wait();
            fs::rename(&worker_parent, &worker_renamed).expect("rename fragments");
            copy_tree(&worker_renamed, &worker_replacement);
            fs::write(worker_replacement.join("server/recipe"), b"CHANGE")
                .expect("same-size replacement");
            barrier.wait();
        });
        let output = root.path().join("composed");
        assert!(compose(&fragments, &output).is_err());
        worker.join().expect("worker");
        test_seams::set_before_parent_reresolve(None);
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
        fs::remove_dir_all(&renamed).expect("old fragments");
        fs::remove_dir_all(&replacement).expect("replacement fragments");
    }

    fn copy_tree(source: &Path, destination: &Path) {
        fs::create_dir_all(destination).expect("directory");
        for entry in fs::read_dir(source).expect("tree") {
            let entry = entry.expect("entry");
            let target = destination.join(entry.file_name());
            if entry.file_type().expect("type").is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                fs::copy(entry.path(), target).expect("file");
            }
        }
    }

    #[test]
    fn aliases_between_roles_are_rejected_before_copy() {
        let root = TempDir::new().expect("temp");
        let source = root.path().join("one");
        fs::write(&source, b"material").expect("write");
        let stage = Stage::create(root.path()).expect("stage");
        let mut seen = BTreeSet::new();
        let first = copy_material(&stage, root.path(), Path::new("one"), "out/a", &mut seen)
            .expect("first");
        assert_eq!(first.size, 8);
        assert!(copy_material(&stage, root.path(), Path::new("one"), "out/b", &mut seen).is_err());
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
    fn repository(root: &Path, name: &str) -> (PathBuf, String, String) {
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
        let commit = String::from_utf8(output.stdout)
            .expect("utf8")
            .trim()
            .to_owned();
        let output = Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "HEAD^{tree}"])
            .output()
            .expect("tree");
        (
            path,
            commit,
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
        let mut trees = BTreeMap::new();
        for component in REQUIRED_RELEASE_COMPONENTS {
            let (path, commit, tree) = repository(root, &format!("repo-{component}"));
            roots.insert((*component).into(), path);
            commits.insert(*component, commit);
            trees.insert(*component, tree);
        }
        let mut fixture = inputs();
        for component in &mut fixture.components {
            component.source_commit = commits[component.component.as_str()].clone();
            component.source_tree = trees[component.component.as_str()].clone();
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

    fn fragment_fixture(root: &Path, parent: &Path, fixture: &ReleaseInputsV1) -> Vec<PathBuf> {
        fs::create_dir_all(parent).expect("fragment parent");
        let mut fragments = Vec::new();
        for component in &fixture.components {
            for path in [
                &component.build_recipe.path,
                &component.artifact.path,
                &component.sbom.path,
                &component.third_party_notice.path,
                &component.license.path,
            ] {
                let destination = parent.join(path);
                fs::create_dir_all(destination.parent().expect("role parent")).expect("roles");
                fs::write(
                    &destination,
                    fs::read(root.join(path)).expect("fixture material"),
                )
                .expect("role");
            }
            let fragment = ReleaseInputFragmentV1 {
                schema: "dirextalk.release-input-fragment".into(),
                schema_version: 1,
                release: fixture.release.clone(),
                component: component.clone(),
            };
            let path = parent.join(format!("{}.json", component.component));
            fs::write(
                &path,
                strict_json::canonical_bytes(&serde_json::to_value(&fragment).expect("json"), true)
                    .expect("canonical"),
            )
            .expect("fragment");
            fragments.push(path);
        }
        fragments
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
            33,
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
        ReleaseMaterialsV1::validate_dir(&first).expect("validate finalized directory");
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
    fn finalized_snapshot_missing_or_tampered_is_rejected() {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let output = root.path().join("output");
        assemble(&inputs_path, &manifest_path, &roots, &output).expect("assemble");
        fs::remove_file(output.join("release-inputs.json")).expect("remove snapshot");
        assert!(ReleaseMaterialsV1::validate_dir(&output).is_err());
    }

    fn assert_recanonicalized_provenance_schema_tamper_rejected(
        field: &str,
        value: serde_json::Value,
    ) {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let output = root.path().join("output");
        assemble(&inputs_path, &manifest_path, &roots, &output).expect("assemble");
        let path = output.join("provenance/server.json");
        let mut provenance =
            strict_json::parse_value(&fs::read(&path).expect("provenance")).expect("parse");
        provenance
            .as_object_mut()
            .expect("object")
            .insert(field.to_owned(), value);
        let provenance_bytes = strict_json::canonical_bytes(&provenance, true).expect("canonical");
        fs::write(&path, &provenance_bytes).expect("provenance");
        let evidence_path = output.join("release-evidence.json");
        let mut evidence =
            ReleaseEvidenceV1::from_bytes(&fs::read(&evidence_path).expect("evidence"))
                .expect("evidence");
        let attestation = evidence
            .attestations
            .iter_mut()
            .find(|entry| entry.component == "server")
            .expect("attestation");
        attestation.size = provenance_bytes.len() as u64;
        attestation.sha256 = digest(&provenance_bytes);
        fs::write(
            &evidence_path,
            evidence.canonical_bytes().expect("canonical evidence"),
        )
        .expect("evidence");
        let fd = open(
            &output,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("fd");
        let inventory = validated_inventory_fd(fd.as_fd()).expect("inventory");
        let checksums = checksum_manifest(
            &inventory
                .files
                .iter()
                .filter(|entry| entry.relative != Path::new("SHA256SUMS"))
                .cloned()
                .collect::<Vec<_>>(),
        );
        fs::write(output.join("SHA256SUMS"), checksums).expect("sums");
        assert!(ReleaseMaterialsV1::validate_dir(&output).is_err());
    }

    #[test]
    fn recanonicalized_provenance_schema_tamper_is_rejected() {
        assert_recanonicalized_provenance_schema_tamper_rejected(
            "schema",
            serde_json::json!("other"),
        );
    }

    #[test]
    fn recanonicalized_provenance_version_tamper_is_rejected() {
        assert_recanonicalized_provenance_schema_tamper_rejected(
            "schema_version",
            serde_json::json!(2),
        );
    }

    #[test]
    fn wrong_input_source_tree_rejects_before_staging() {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, mut fixture) = assembly_fixture(root.path());
        fixture.components[0].source_tree = "b".repeat(40);
        fs::write(&inputs_path, fixture.canonical_bytes().expect("inputs")).expect("rewrite");
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn material_replacement_after_read_is_rejected_without_residue() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, fixture) = assembly_fixture(root.path());
        let target = root.path().join(&fixture.components[0].build_recipe.path);
        let barrier = Arc::new(Barrier::new(2));
        crate::digest::set_after_material_read_barrier(Some(Arc::clone(&barrier)));
        let replacement = target.clone();
        let worker = std::thread::spawn(move || {
            barrier.wait();
            fs::write(replacement, b"replacement").expect("replace");
            barrier.wait();
        });
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        worker.join().expect("worker");
        crate::digest::set_after_material_read_barrier(None);
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn material_truncation_after_read_is_rejected_without_residue() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, fixture) = assembly_fixture(root.path());
        let target = root.path().join(&fixture.components[0].build_recipe.path);
        let barrier = Arc::new(Barrier::new(2));
        crate::digest::set_after_material_read_barrier(Some(Arc::clone(&barrier)));
        let worker = std::thread::spawn(move || {
            barrier.wait();
            std::fs::OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(target)
                .expect("truncate");
            barrier.wait();
        });
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        worker.join().expect("worker");
        crate::digest::set_after_material_read_barrier(None);
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
    }

    fn staged_mutation_after_sha_is_rejected<F>(mutate: F)
    where
        F: FnOnce(PathBuf) + Send + 'static,
    {
        use std::sync::mpsc;
        use std::time::Duration;
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let parent = root.path().to_path_buf();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        test_seams::set_before_rename(Some((entered_tx, resume_rx)));
        let worker = std::thread::spawn(move || {
            if entered_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                return false;
            }
            let stage = fs::read_dir(&parent)
                .expect("parent")
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.file_name().is_some_and(|name| {
                        name.to_string_lossy().starts_with(".release-evidence-")
                    })
                })
                .expect("stage");
            mutate(stage);
            resume_tx.send(()).expect("resume assembly");
            true
        });
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        assert!(
            worker.join().expect("worker"),
            "post-SHA seam was not reached"
        );
        test_seams::set_before_rename(None);
        assert!(!output.exists());
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn staged_insertion_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            fs::write(stage.join("injected"), b"x").expect("insert");
        });
    }

    #[test]
    fn staged_removal_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            fs::remove_file(stage.join("release-evidence.json")).expect("remove");
        });
    }

    #[test]
    fn staged_same_name_replacement_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            let path = stage.join("release-evidence.json");
            fs::rename(&path, stage.join("saved-evidence")).expect("rename");
            fs::write(path, b"replacement").expect("replace");
        });
    }

    #[cfg(unix)]
    #[test]
    fn staged_hardlink_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            fs::hard_link(stage.join("release-evidence.json"), stage.join("alias")).expect("link");
        });
    }

    #[test]
    fn staged_nonzero_modify_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            fs::write(stage.join("release-evidence.json"), b"nonzero replacement").expect("modify");
        });
    }

    #[test]
    fn staged_directory_replacement_after_sha_is_rejected_without_residue() {
        staged_mutation_after_sha_is_rejected(|stage| {
            let directory = stage.join("provenance");
            for entry in fs::read_dir(&directory).expect("dir") {
                fs::remove_file(entry.expect("entry").path()).expect("file");
            }
            fs::remove_dir(&directory).expect("remove dir");
            fs::create_dir(&directory).expect("replace dir");
        });
    }

    #[test]
    fn parent_replacement_is_rejected_and_retained_fd_cleanup_is_scoped() {
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let parent = root.path().to_path_buf();
        let renamed = root.path().with_extension("renamed");
        let worker_parent = parent.clone();
        let worker_renamed = renamed.clone();
        let barrier = Arc::new(Barrier::new(2));
        test_seams::set_before_parent_reresolve(Some(Arc::clone(&barrier)));
        let worker = std::thread::spawn(move || {
            barrier.wait();
            fs::rename(&worker_parent, &worker_renamed).expect("rename parent");
            fs::create_dir(&worker_parent).expect("replacement parent");
            barrier.wait();
        });
        let output = root.path().join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        worker.join().expect("worker");
        test_seams::set_before_parent_reresolve(None);
        assert!(!output.exists());
        assert_eq!(staging_count(&renamed), 0);
        fs::remove_dir(&parent).expect("remove replacement");
        fs::rename(renamed, parent).expect("restore parent");
    }

    #[cfg(unix)]
    #[test]
    fn parent_symlink_replacement_is_rejected_and_cleanup_stays_on_original() {
        use std::os::unix::fs::symlink;
        use std::sync::{Arc, Barrier};
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let parent = root.path().to_path_buf();
        let renamed = root.path().with_extension("symlink-renamed");
        let target = root.path().with_extension("symlink-target");
        fs::create_dir(&target).expect("target");
        let worker_parent = parent.clone();
        let worker_renamed = renamed.clone();
        let worker_target = target.clone();
        let barrier = Arc::new(Barrier::new(2));
        test_seams::set_before_parent_reresolve(Some(Arc::clone(&barrier)));
        let worker = std::thread::spawn(move || {
            barrier.wait();
            fs::rename(&worker_parent, &worker_renamed).expect("rename parent");
            symlink(&worker_target, &worker_parent).expect("symlink parent");
            barrier.wait();
        });
        let output = parent.join("output");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        worker.join().expect("worker");
        test_seams::set_before_parent_reresolve(None);
        assert!(!output.exists());
        assert_eq!(staging_count(&renamed), 0);
        fs::remove_file(&parent).expect("remove symlink");
        fs::rename(renamed, parent).expect("restore parent");
        fs::remove_dir(target).expect("remove target");
    }

    #[test]
    fn competing_output_is_preserved_and_stage_removed() {
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let output = root.path().join("output");
        fs::create_dir(&output).expect("output");
        fs::write(output.join("keep"), b"keep").expect("keep");
        assert!(assemble(&inputs_path, &manifest_path, &roots, &output).is_err());
        assert_eq!(fs::read(output.join("keep")).expect("keep"), b"keep");
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn competing_output_created_before_rename_is_preserved() {
        use std::sync::mpsc;
        use std::time::Duration;
        let root = TempDir::new().expect("temp");
        let (inputs_path, manifest_path, roots, _) = assembly_fixture(root.path());
        let output = root.path().join("output");
        let worker_output = output.clone();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        test_seams::set_before_rename(Some((entered_tx, resume_rx)));
        let worker = std::thread::spawn(move || {
            if entered_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                return false;
            }
            fs::create_dir(&worker_output).expect("output");
            fs::write(worker_output.join("competitor"), b"preserve").expect("competitor");
            resume_tx.send(()).expect("resume assembly");
            true
        });
        assert!(matches!(
            assemble(&inputs_path, &manifest_path, &roots, &output),
            Err(ReleaseError::OutputNotEmpty(_))
        ));
        assert!(
            worker.join().expect("worker"),
            "post-SHA seam was not reached"
        );
        test_seams::set_before_rename(None);
        assert_eq!(
            fs::read(output.join("competitor")).expect("competitor"),
            b"preserve"
        );
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn injected_stage_initialization_failure_removes_only_created_stage() {
        let root = TempDir::new().expect("temp");
        test_seams::fail_stage_init_once();
        assert!(Stage::create(root.path()).is_err());
        assert_eq!(staging_count(root.path()), 0);
    }

    #[test]
    fn namespace_lock_rejects_second_assembler() {
        let root = TempDir::new().expect("temp");
        let first = Stage::create(root.path()).expect("first lock");
        assert!(Stage::create(root.path()).is_err());
        drop(first);
        assert!(Stage::create(root.path()).is_ok());
    }

    fn staging_count(root: &Path) -> usize {
        fs::read_dir(root)
            .expect("dir")
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".release-evidence-")
            })
            .count()
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
