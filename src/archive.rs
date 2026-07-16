use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use flate2::{Compression, write::GzEncoder};
use serde::{Deserialize, Serialize};
use tar::{Builder as TarBuilder, Header as TarHeader};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

use crate::{
    digest::{FileDigest, digest_regular_file},
    error::{ReleaseError, Result, io_error},
    manifest::{ArchiveKind, LoadedManifest, ReleaseTarget},
    receipt::BuildReceipt,
    source::SourceRevisions,
};

const MAX_BINARY_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AssembledRelease {
    pub schema_version: u32,
    pub version: String,
    pub tag: String,
    pub image: ContainerImage,
    pub sources: SourceRevisions,
    pub assets: Vec<ReleaseAsset>,
    pub npm_directory: String,
    pub npm_files: Vec<PackageFile>,
}

impl AssembledRelease {
    /// Load and minimally validate an assembled GitHub asset manifest.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is unsafe, oversized, malformed, or uses
    /// an unsupported schema version.
    pub fn load(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > 1024 * 1024
        {
            return Err(ReleaseError::UnsafeFile(path.to_path_buf()));
        }
        let release: Self = serde_json::from_slice(&fs::read(path).map_err(io_error(path))?)?;
        if release.schema_version != 1 {
            return Err(ReleaseError::Manifest(
                "assembled release schema_version must be 1".to_owned(),
            ));
        }
        Ok(release)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerImage {
    pub reference: String,
    pub platforms: Vec<String>,
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAsset {
    pub name: String,
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: String,
    pub target: Option<String>,
    pub kind: AssetKind,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssetKind {
    BinaryBundle,
    Checksums,
}

#[derive(Serialize)]
struct BundleMetadata<'a> {
    schema_version: u32,
    version: &'a str,
    target: &'a str,
    sources: &'a SourceRevisions,
    binaries: BTreeMap<&'a str, FileDigest>,
}

/// Assemble verified binary inputs into release archives and npm metadata.
///
/// # Errors
///
/// Returns an error when an input is missing or unsafe, the output directory
/// is not empty, or an archive/hash write fails.
pub fn assemble(
    loaded: &LoadedManifest,
    artifacts_dir: &Path,
    output_dir: &Path,
) -> Result<AssembledRelease> {
    let artifacts_dir = loaded.resolve(artifacts_dir);
    let output_dir = loaded.resolve(output_dir);
    let sources = SourceRevisions::resolve(loaded)?;
    sources.verify_publishable(loaded)?;
    prepare_output_directory(&output_dir)?;
    let mut assets = Vec::with_capacity(loaded.manifest.targets.len() + 1);

    for target in &loaded.manifest.targets {
        let inputs = target_inputs(loaded, &artifacts_dir, target, &sources)?;
        let archive_name = archive_name(loaded, target);
        let archive_path = output_dir.join(&archive_name);
        write_bundle_archive(loaded, target, &sources, &inputs, &archive_path)?;
        assets.push(asset_for_file(
            &archive_path,
            &archive_name,
            Some(target.id.clone()),
            AssetKind::BinaryBundle,
            match target.archive {
                ArchiveKind::Zip => "application/zip",
                ArchiveKind::TarGz => "application/gzip",
            },
        )?);
    }

    let npm_files = write_npm_package(loaded, &artifacts_dir, &output_dir.join("npm"))?;
    let checksums_name = "checksums-sha256.txt";
    let checksums_path = output_dir.join(checksums_name);
    write_checksums(&checksums_path, &assets)?;
    assets.push(asset_for_file(
        &checksums_path,
        checksums_name,
        None,
        AssetKind::Checksums,
        "text/plain",
    )?);

    let release = AssembledRelease {
        schema_version: 1,
        version: loaded.manifest.release.version.clone(),
        tag: format!(
            "{}{}",
            loaded.manifest.github.tag_prefix, loaded.manifest.release.version
        ),
        image: ContainerImage {
            reference: format!(
                "{}:{}",
                loaded.manifest.server.image, loaded.manifest.release.version
            ),
            platforms: loaded.manifest.server.platforms.clone(),
            digest: None,
        },
        sources,
        assets,
        npm_directory: "npm".to_owned(),
        npm_files,
    };
    let manifest_path = output_dir.join("github-assets.json");
    write_json(&manifest_path, &release)?;
    Ok(release)
}

fn target_inputs(
    loaded: &LoadedManifest,
    artifacts_dir: &Path,
    target: &ReleaseTarget,
    sources: &SourceRevisions,
) -> Result<Vec<(String, PathBuf, FileDigest)>> {
    let suffix = target.executable_suffix();
    let target_dir = artifacts_dir.join(&target.id);
    let mut paths = Vec::with_capacity(2);
    for binary in [
        &loaded.manifest.deployer.binary,
        &loaded.manifest.connector.binary,
    ] {
        let file_name = format!("{binary}{suffix}");
        let path = target_dir.join(&file_name);
        paths.push((file_name, path));
    }
    let receipt_inputs = paths
        .iter()
        .map(|(name, path)| (name.as_str(), path.as_path()))
        .collect::<Vec<_>>();
    BuildReceipt::load_and_verify(
        &target_dir.join("build-receipt.json"),
        &loaded.manifest.release.version,
        &target.id,
        sources,
        &receipt_inputs,
    )?;
    paths
        .into_iter()
        .map(|(name, path)| {
            let digest = digest_regular_file(&path, MAX_BINARY_BYTES)?;
            Ok((name, path, digest))
        })
        .collect()
}

fn archive_name(loaded: &LoadedManifest, target: &ReleaseTarget) -> String {
    let extension = match target.archive {
        ArchiveKind::Zip => "zip",
        ArchiveKind::TarGz => "tar.gz",
    };
    format!(
        "dirextalk-vnext-{}-{}.{}",
        loaded.manifest.release.version, target.id, extension
    )
}

fn write_bundle_archive(
    loaded: &LoadedManifest,
    target: &ReleaseTarget,
    sources: &SourceRevisions,
    inputs: &[(String, PathBuf, FileDigest)],
    output: &Path,
) -> Result<()> {
    let root = format!(
        "dirextalk-vnext-{}-{}/",
        loaded.manifest.release.version, target.id
    );
    let binaries = inputs
        .iter()
        .map(|(name, _, metadata)| {
            (
                name.as_str(),
                FileDigest {
                    sha256: metadata.sha256.clone(),
                    size: metadata.size,
                },
            )
        })
        .collect();
    let metadata = serde_json::to_vec_pretty(&BundleMetadata {
        schema_version: 1,
        version: &loaded.manifest.release.version,
        target: &target.id,
        sources,
        binaries,
    })?;
    let legal_files = legal_files(loaded)?;
    match target.archive {
        ArchiveKind::Zip => write_zip(output, &root, inputs, &metadata, &legal_files),
        ArchiveKind::TarGz => write_tar_gz(
            output,
            &root,
            inputs,
            &metadata,
            &legal_files,
            loaded.manifest.release.source_date_epoch,
        ),
    }
}

fn write_zip(
    output: &Path,
    root: &str,
    inputs: &[(String, PathBuf, FileDigest)],
    metadata: &[u8],
    legal_files: &[(String, PathBuf)],
) -> Result<()> {
    let file = File::create(output).map_err(io_error(output))?;
    let mut zip = ZipWriter::new(BufWriter::new(file));
    let executable = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o755);
    for (name, path, _) in inputs {
        zip.start_file(format!("{root}bin/{name}"), executable)?;
        let mut input = File::open(path).map_err(io_error(path))?;
        io::copy(&mut input, &mut zip).map_err(io_error(output))?;
    }
    let regular = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    zip.start_file(format!("{root}release-metadata.json"), regular)?;
    zip.write_all(metadata).map_err(io_error(output))?;
    for (name, path) in legal_files {
        zip.start_file(format!("{root}{name}"), regular)?;
        let mut input = File::open(path).map_err(io_error(path))?;
        io::copy(&mut input, &mut zip).map_err(io_error(output))?;
    }
    zip.finish()?;
    Ok(())
}

fn write_tar_gz(
    output: &Path,
    root: &str,
    inputs: &[(String, PathBuf, FileDigest)],
    metadata: &[u8],
    legal_files: &[(String, PathBuf)],
    source_date_epoch: u64,
) -> Result<()> {
    let file = File::create(output).map_err(io_error(output))?;
    let encoder = GzEncoder::new(BufWriter::new(file), Compression::best());
    let mut archive = TarBuilder::new(encoder);
    archive.mode(tar::HeaderMode::Deterministic);
    for (name, path, binary_metadata) in inputs {
        let mut header = deterministic_tar_header(binary_metadata.size, 0o755, source_date_epoch)?;
        let mut input = File::open(path).map_err(io_error(path))?;
        archive
            .append_data(&mut header, format!("{root}bin/{name}"), &mut input)
            .map_err(io_error(output))?;
    }
    let mut header = deterministic_tar_header(metadata.len() as u64, 0o644, source_date_epoch)?;
    archive
        .append_data(
            &mut header,
            format!("{root}release-metadata.json"),
            metadata,
        )
        .map_err(io_error(output))?;
    for (name, path) in legal_files {
        let size = fs::metadata(path).map_err(io_error(path))?.len();
        let mut header = deterministic_tar_header(size, 0o644, source_date_epoch)?;
        let mut input = File::open(path).map_err(io_error(path))?;
        archive
            .append_data(&mut header, format!("{root}{name}"), &mut input)
            .map_err(io_error(output))?;
    }
    let encoder = archive.into_inner().map_err(io_error(output))?;
    encoder.finish().map_err(io_error(output))?;
    Ok(())
}

fn deterministic_tar_header(size: u64, mode: u32, mtime: u64) -> Result<TarHeader> {
    let mut header = TarHeader::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(mtime);
    header.set_username("").map_err(io_error("tar-header"))?;
    header.set_groupname("").map_err(io_error("tar-header"))?;
    header.set_cksum();
    Ok(header)
}

fn write_npm_package(
    loaded: &LoadedManifest,
    artifacts_dir: &Path,
    npm_dir: &Path,
) -> Result<Vec<PackageFile>> {
    fs::create_dir(npm_dir).map_err(io_error(npm_dir))?;
    let bin_dir = npm_dir.join("bin");
    let vendor_dir = npm_dir.join("vendor");
    fs::create_dir(&bin_dir).map_err(io_error(&bin_dir))?;
    fs::create_dir(&vendor_dir).map_err(io_error(&vendor_dir))?;

    let (target_map, mut package_paths) = copy_npm_binaries(loaded, artifacts_dir, &vendor_dir)?;

    let package_json = serde_json::json!({
        "name": loaded.manifest.npm.package,
        "version": loaded.manifest.release.version,
        "description": "Dirextalk vNext typed deployer and multi-Agent connector binaries",
        "license": "MIT",
        "type": "commonjs",
        "engines": { "node": ">=18" },
        "bin": {
            "dirextalk-vnext-deployer": "bin/deployer.js",
            "dirextalk-agent-connector": "bin/connector.js"
        },
        "files": [
            "bin",
            "vendor",
            "release-metadata.json",
            "LICENSE",
            "LICENSE-connector",
            "THIRD_PARTY_NOTICES"
        ],
        "publishConfig": { "access": loaded.manifest.npm.access.as_str() }
    });
    write_json(&npm_dir.join("package.json"), &package_json)?;
    let npm_metadata = serde_json::json!({
        "schema_version": 1,
        "version": loaded.manifest.release.version,
        "targets": target_map,
        "image": format!("{}:{}", loaded.manifest.server.image, loaded.manifest.release.version)
    });
    write_json(&npm_dir.join("release-metadata.json"), &npm_metadata)?;
    copy_legal_file(
        &loaded.deployer_repository().join("LICENSE"),
        &npm_dir.join("LICENSE"),
    )?;
    copy_legal_file(
        &loaded.connector_repository().join("LICENSE"),
        &npm_dir.join("LICENSE-connector"),
    )?;
    copy_legal_file(
        &loaded.connector_repository().join("NOTICE"),
        &npm_dir.join("THIRD_PARTY_NOTICES"),
    )?;
    let mapping_json = serde_json::to_string(&target_map)?;
    write_launcher(
        &bin_dir.join("deployer.js"),
        &mapping_json,
        &loaded.manifest.deployer.binary,
    )?;
    write_launcher(
        &bin_dir.join("connector.js"),
        &mapping_json,
        &loaded.manifest.connector.binary,
    )?;
    package_paths.sort();
    package_paths
        .into_iter()
        .map(|relative| {
            let digest = digest_regular_file(&npm_dir.join(&relative), MAX_BINARY_BYTES)?;
            Ok(PackageFile {
                path: relative,
                sha256: digest.sha256,
                size: digest.size,
            })
        })
        .collect()
}

fn copy_npm_binaries(
    loaded: &LoadedManifest,
    artifacts_dir: &Path,
    vendor_dir: &Path,
) -> Result<(BTreeMap<String, String>, Vec<String>)> {
    let mut target_map = BTreeMap::new();
    let mut package_paths = vec![
        "package.json".to_owned(),
        "release-metadata.json".to_owned(),
        "LICENSE".to_owned(),
        "LICENSE-connector".to_owned(),
        "THIRD_PARTY_NOTICES".to_owned(),
        "bin/deployer.js".to_owned(),
        "bin/connector.js".to_owned(),
    ];
    for target in &loaded.manifest.targets {
        target_map.insert(target.npm_key(), target.id.clone());
        let target_vendor = vendor_dir.join(&target.id);
        fs::create_dir(&target_vendor).map_err(io_error(&target_vendor))?;
        let suffix = target.executable_suffix();
        for binary in [
            &loaded.manifest.deployer.binary,
            &loaded.manifest.connector.binary,
        ] {
            let name = format!("{binary}{suffix}");
            let source = artifacts_dir.join(&target.id).join(&name);
            let _ = digest_regular_file(&source, MAX_BINARY_BYTES)?;
            let destination = target_vendor.join(&name);
            fs::copy(&source, &destination).map_err(io_error(&destination))?;
            #[cfg(unix)]
            set_executable(&destination)?;
            package_paths.push(format!("vendor/{}/{name}", target.id));
        }
    }
    Ok((target_map, package_paths))
}

fn legal_files(loaded: &LoadedManifest) -> Result<Vec<(String, PathBuf)>> {
    let files = vec![
        (
            "LICENSE-deployer".to_owned(),
            loaded.deployer_repository().join("LICENSE"),
        ),
        (
            "LICENSE-connector".to_owned(),
            loaded.connector_repository().join("LICENSE"),
        ),
        (
            "THIRD_PARTY_NOTICES".to_owned(),
            loaded.connector_repository().join("NOTICE"),
        ),
    ];
    for (_, path) in &files {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.len() == 0
            || metadata.len() > 1024 * 1024
        {
            return Err(ReleaseError::UnsafeFile(path.clone()));
        }
    }
    Ok(files)
}

fn copy_legal_file(source: &Path, destination: &Path) -> Result<()> {
    fs::copy(source, destination).map_err(io_error(destination))?;
    Ok(())
}

fn write_launcher(path: &Path, mapping_json: &str, binary: &str) -> Result<()> {
    let script = format!(
        r"#!/usr/bin/env node
'use strict';
const {{ spawnSync }} = require('node:child_process');
const path = require('node:path');
const targets = {mapping_json};
const key = `${{process.platform}}-${{process.arch}}`;
const target = targets[key];
if (!target) {{
  console.error(`Dirextalk does not provide a binary for ${{key}}`);
  process.exit(1);
}}
const suffix = process.platform === 'win32' ? '.exe' : '';
const executable = path.join(__dirname, '..', 'vendor', target, '{binary}' + suffix);
const result = spawnSync(executable, process.argv.slice(2), {{ stdio: 'inherit', windowsHide: true }});
if (result.error) {{
  console.error(`Unable to start Dirextalk binary: ${{result.error.message}}`);
  process.exit(1);
}}
process.exit(result.status === null ? 1 : result.status);
"
    );
    fs::write(path, script.as_bytes()).map_err(io_error(path))?;
    #[cfg(unix)]
    set_executable(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(io_error(path))
}

fn write_checksums(path: &Path, assets: &[ReleaseAsset]) -> Result<()> {
    let mut contents = String::new();
    for asset in assets {
        contents.push_str(&asset.sha256);
        contents.push_str("  ");
        contents.push_str(&asset.name);
        contents.push('\n');
    }
    fs::write(path, contents.as_bytes()).map_err(io_error(path))
}

fn asset_for_file(
    path: &Path,
    name: &str,
    target: Option<String>,
    kind: AssetKind,
    media_type: &str,
) -> Result<ReleaseAsset> {
    let digest = digest_regular_file(path, u64::MAX)?;
    Ok(ReleaseAsset {
        name: name.to_owned(),
        path: name.to_owned(),
        sha256: digest.sha256,
        size: digest.size,
        media_type: media_type.to_owned(),
        target,
        kind,
    })
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut encoded = serde_json::to_vec_pretty(value)?;
    encoded.push(b'\n');
    fs::write(path, encoded).map_err(io_error(path))
}

fn prepare_output_directory(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(io_error(path))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ReleaseError::InvalidPath(path.to_path_buf()));
        }
        if fs::read_dir(path).map_err(io_error(path))?.next().is_some() {
            return Err(ReleaseError::OutputNotEmpty(path.to_path_buf()));
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(io_error(path))
}
