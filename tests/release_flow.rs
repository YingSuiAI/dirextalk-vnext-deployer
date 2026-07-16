use std::{collections::BTreeMap, fs, path::Path, process::Command};

use dirextalk_vnext_deployer::{
    ReleaseError,
    archive::assemble,
    manifest::LoadedManifest,
    plan::{BuildHost, MutationKind, PlannedCommand, ReleasePlan},
    publish::{PublicationPlan, PublicationSelection},
    receipt::BuildReceipt,
    source::SourceRevisions,
};
use serde_json::{Value, json};
use tempfile::TempDir;

#[test]
fn plan_contains_only_local_mutations_and_immutable_image_tag() {
    let fixture = Fixture::new();
    let loaded = LoadedManifest::load(&fixture.manifest).expect("valid fixture manifest");
    let plan = ReleasePlan::create(
        &loaded,
        Path::new("artifacts"),
        Path::new("dist"),
        &[],
        true,
    )
    .expect("release plan");

    assert_eq!(plan.image, "dirextalk/vent:1.2.3-alpha.1");
    assert_eq!(plan.commands.len(), 5);
    assert!(
        plan.commands
            .iter()
            .all(|command| !matches!(command.mutation, MutationKind::RemotePublish))
    );
    let image = plan
        .commands
        .iter()
        .find(|command| command.id == "build-server-image")
        .expect("server image command");
    assert!(
        image
            .arguments
            .iter()
            .any(|argument| argument == "--output")
    );
    assert!(!image.arguments.iter().any(|argument| argument == "--push"));
}

#[test]
fn assemble_generates_binary_archives_npm_wrapper_and_hash_manifest() {
    let fixture = Fixture::new();
    let loaded = LoadedManifest::load(&fixture.manifest).expect("valid fixture manifest");
    fixture.write_artifacts(&loaded);
    let assembled =
        assemble(&loaded, Path::new("artifacts"), Path::new("dist")).expect("assembled release");

    assert_eq!(assembled.assets.len(), 3);
    assert!(
        fixture
            .root
            .path()
            .join("dist/github-assets.json")
            .is_file()
    );
    assert!(
        fixture
            .root
            .path()
            .join("dist/checksums-sha256.txt")
            .is_file()
    );
    assert!(
        fixture
            .root
            .path()
            .join("dist/dirextalk-vnext-1.2.3-alpha.1-windows-x64.zip")
            .is_file()
    );
    assert!(
        fixture
            .root
            .path()
            .join("dist/dirextalk-vnext-1.2.3-alpha.1-linux-x64.tar.gz")
            .is_file()
    );

    let package: Value = serde_json::from_slice(
        &fs::read(fixture.root.path().join("dist/npm/package.json")).expect("package.json"),
    )
    .expect("valid package JSON");
    assert_eq!(package["name"], "@dirextalk/vnext-deployer");
    assert_eq!(
        package["bin"]["dirextalk-agent-connector"],
        "bin/connector.js"
    );
    assert!(
        fixture
            .root
            .path()
            .join("dist/npm/vendor/windows-x64/dirextalk-vnext-deployer.exe")
            .is_file()
    );

    let no_destination =
        PublicationPlan::create(&loaded, Path::new("dist"), PublicationSelection::default());
    assert!(matches!(
        no_destination,
        Err(ReleaseError::NoPublicationSelected)
    ));
    let preview = PublicationPlan::create(
        &loaded,
        Path::new("dist"),
        PublicationSelection {
            github: true,
            ..PublicationSelection::default()
        },
    )
    .expect("publication preview");
    assert_eq!(preview.commands.len(), 1);
    assert!(matches!(
        preview.commands[0].mutation,
        MutationKind::RemotePublish
    ));

    fs::write(
        fixture
            .root
            .path()
            .join("dist/npm/vendor/windows-x64/dirextalk-agent-connector.exe"),
        b"tampered",
    )
    .expect("tamper npm fixture");
    assert!(
        PublicationPlan::create(
            &loaded,
            Path::new("dist"),
            PublicationSelection {
                npm: true,
                ..PublicationSelection::default()
            },
        )
        .is_err()
    );
}

#[test]
fn strict_manifest_rejects_unknown_fields_and_floating_image_tags() {
    let fixture = Fixture::new();
    let mut value: Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).expect("manifest bytes"))
            .expect("manifest JSON");
    value["unexpected"] = json!(true);
    fs::write(
        &fixture.manifest,
        serde_json::to_vec_pretty(&value).expect("encoded manifest"),
    )
    .expect("replace manifest");
    assert!(LoadedManifest::load(&fixture.manifest).is_err());

    value
        .as_object_mut()
        .expect("manifest object")
        .remove("unexpected");
    value["server"]["image"] = json!("dirextalk/vent:latest");
    fs::write(
        &fixture.manifest,
        serde_json::to_vec_pretty(&value).expect("encoded manifest"),
    )
    .expect("replace manifest");
    assert!(LoadedManifest::load(&fixture.manifest).is_err());
}

#[test]
fn native_build_rejects_the_wrong_host_before_starting_a_process() {
    let command = PlannedCommand {
        id: "native-test".to_owned(),
        program: "this-program-must-not-run".to_owned(),
        arguments: Vec::new(),
        working_directory: std::env::current_dir().expect("current directory"),
        environment: BTreeMap::new(),
        required_host: Some(BuildHost {
            os: "impossible-os".to_owned(),
            architecture: "impossible-architecture".to_owned(),
        }),
        mutation: MutationKind::LocalBuild,
    };
    assert!(matches!(
        command.execute(),
        Err(ReleaseError::BuildHostMismatch { .. })
    ));
}

#[test]
fn assemble_rejects_stale_binary_receipts_and_dirty_sources() {
    let fixture = Fixture::new();
    let loaded = LoadedManifest::load(&fixture.manifest).expect("valid fixture manifest");
    fixture.write_artifacts(&loaded);
    fs::write(
        fixture
            .root
            .path()
            .join("artifacts/windows-x64/dirextalk-agent-connector.exe"),
        b"changed-after-receipt",
    )
    .expect("tamper artifact");
    assert!(assemble(&loaded, Path::new("artifacts"), Path::new("dist")).is_err());

    fixture.write_artifacts(&loaded);
    fs::write(
        fixture.root.path().join("connector/NOTICE"),
        b"dirty legal file",
    )
    .expect("dirty source");
    assert!(matches!(
        assemble(&loaded, Path::new("artifacts"), Path::new("dist")),
        Err(ReleaseError::DirtyRepository(_))
    ));
}

struct Fixture {
    root: TempDir,
    manifest: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = TempDir::new().expect("temporary directory");
        write(root.path().join("server/Cargo.toml"), b"[workspace]\n");
        write(
            root.path().join("server/docker/release/Dockerfile"),
            b"FROM scratch\n",
        );
        write(
            root.path().join("deployer/Cargo.toml"),
            b"[package]\nname='dirextalk-vnext-deployer'\nversion='0.1.0'\n",
        );
        write(root.path().join("deployer/LICENSE"), b"MIT fixture\n");
        write(
            root.path().join("connector/go.mod"),
            b"module example.invalid/connector\n",
        );
        write(root.path().join("connector/LICENSE"), b"MIT fixture\n");
        write(root.path().join("connector/NOTICE"), b"fixture notice\n");
        for repository in ["server", "deployer", "connector"] {
            init_git(&root.path().join(repository));
        }
        let manifest = root.path().join("release.json");
        let value = json!({
            "schema_version": 1,
            "release": { "version": "1.2.3-alpha.1", "source_date_epoch": 1_784_246_400_u64 },
            "server": {
                "repository": "server",
                "dockerfile": "docker/release/Dockerfile",
                "image": "dirextalk/vent",
                "platforms": ["linux/amd64", "linux/arm64"]
            },
            "deployer": {
                "repository": "deployer",
                "package": "dirextalk-vnext-deployer",
                "binary": "dirextalk-vnext-deployer"
            },
            "connector": {
                "repository": "connector",
                "module": "./cmd/dirextalk-agent-connector",
                "binary": "dirextalk-agent-connector"
            },
            "targets": [
                {
                    "id": "windows-x64",
                    "rust_target": "x86_64-pc-windows-gnu",
                    "goos": "windows",
                    "goarch": "amd64",
                    "node_platform": "win32",
                    "node_arch": "x64",
                    "archive": "zip"
                },
                {
                    "id": "linux-x64",
                    "rust_target": "x86_64-unknown-linux-gnu",
                    "goos": "linux",
                    "goarch": "amd64",
                    "node_platform": "linux",
                    "node_arch": "x64",
                    "archive": "tar_gz"
                }
            ],
            "npm": { "package": "@dirextalk/vnext-deployer", "access": "public" },
            "github": { "repository": "YingSuiAI/dirextalk-vnext-deployer", "tag_prefix": "v" }
        });
        write(
            &manifest,
            &serde_json::to_vec_pretty(&value).expect("manifest encoding"),
        );
        Self { root, manifest }
    }

    fn write_artifacts(&self, loaded: &LoadedManifest) {
        let sources = SourceRevisions::resolve(loaded).expect("fixture source revisions");
        for (target, suffix) in [("windows-x64", ".exe"), ("linux-x64", "")] {
            let deployer = self.root.path().join(format!(
                "artifacts/{target}/dirextalk-vnext-deployer{suffix}"
            ));
            let connector = self.root.path().join(format!(
                "artifacts/{target}/dirextalk-agent-connector{suffix}"
            ));
            write(&deployer, format!("rust-{target}").as_bytes());
            write(&connector, format!("go-{target}").as_bytes());
            BuildReceipt::write(
                &self
                    .root
                    .path()
                    .join(format!("artifacts/{target}/build-receipt.json")),
                "1.2.3-alpha.1",
                target,
                &sources,
                &[
                    (&format!("dirextalk-vnext-deployer{suffix}"), &deployer),
                    (&format!("dirextalk-agent-connector{suffix}"), &connector),
                ],
            )
            .expect("build receipt");
        }
    }
}

fn write(path: impl AsRef<Path>, bytes: &[u8]) {
    let path = path.as_ref();
    fs::create_dir_all(path.parent().expect("parent directory")).expect("create parent");
    fs::write(path, bytes).expect("write fixture");
}

fn init_git(repository: &Path) {
    for arguments in [
        vec!["init", "-b", "main"],
        vec!["config", "user.email", "release-test@example.invalid"],
        vec!["config", "user.name", "Dirextalk Release Test"],
        vec!["add", "."],
        vec!["commit", "-m", "fixture"],
    ] {
        let output = Command::new("git")
            .args(arguments)
            .current_dir(repository)
            .output()
            .expect("start Git fixture command");
        assert!(
            output.status.success(),
            "Git fixture command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
