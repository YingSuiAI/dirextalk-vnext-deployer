# Release manifest and artifact contract

The JSON manifest is strict (`schema_version: 1`); unknown fields are rejected.
All paths are resolved relative to the manifest file. The server Dockerfile and
Go module path must remain relative and cannot contain parent traversal.

## Non-secret configuration

| Field | Purpose |
| --- | --- |
| `release.version` | SemVer used for immutable image, npm, archive, and GitHub tags |
| `release.source_date_epoch` | Reproducible build/archive timestamp |
| `server.image` | Untagged OCI repository; defaults by policy to `dirextalk/vent` |
| `server.platforms` | Exact Buildx platforms |
| `targets` | Rust target, Go OS/arch, Node platform/arch, and archive mapping |
| `targets[].rust_toolchain` | Optional exact rustup toolchain for a specialized builder |
| `targets[].rust_native` | Require a matching native runner and omit Cargo `--target` |
| `npm.package` | Scoped npm package containing both executable wrappers |
| `github.repository` | GitHub Release destination in `owner/repository` form |
| `*.source_commit` | Optional full Git object ID; otherwise resolved from `HEAD` |

Do not add tokens, registry passwords, npm configuration, private keys, signing
material, database URLs, or cloud credentials. Publication recognizes only
credential presence and never serializes a credential value.

## Builder input layout

Each target directory must contain both executable assets:

```text
artifacts/
  windows-x64/
    dirextalk-vnext-deployer.exe
    dirextalk-agent-connector.exe
    build-receipt.json
  linux-x64/
    dirextalk-vnext-deployer
    dirextalk-agent-connector
    build-receipt.json
```

`build --execute` creates this layout for selected targets. Cross-compiling the
Rust CLI requires the target and linker to be installed on that builder; the Go
Connector is built with `CGO_ENABLED=0` and exact `GOOS`/`GOARCH` values.

The Windows GNU example selects the installed
`1.97.0-x86_64-pc-windows-gnu` toolchain. Other targets normally build on a
matching native GitHub Actions runner and omit `rust_toolchain`.
The CLI refuses a native build on a mismatched OS or architecture before it
starts a compiler.
Each receipt records the release version, target, exact deployer/Connector
commits, and both binary SHA-256 digests. Assembly will not infer provenance
from a filename or package directory.

## Assembled output

`assemble` refuses a non-empty output directory and creates:

```text
dist/
  dirextalk-vnext-<version>-<target>.zip|tar.gz
  checksums-sha256.txt
  github-assets.json
  npm/
    package.json
    release-metadata.json
    bin/deployer.js
    bin/connector.js
    vendor/<target>/<both binaries>
```

The Node wrappers select an exact `process.platform`/`process.arch` mapping and
start the corresponding binary without a shell. Unsupported platforms fail
closed.

## Credential presence checks

- Docker: non-empty `DOCKER_AUTH_CONFIG`, or a non-empty Docker `config.json`.
- npm: non-empty `NPM_TOKEN` or `NODE_AUTH_TOKEN`.
- GitHub: non-empty `GH_TOKEN` or `GITHUB_TOKEN`.

These are presence checks, not permission proofs. After an authorized execute,
verify the pushed image digest, npm version, and GitHub asset hashes. Signed npm
provenance remains a later release-hardening gate and is not claimed by this
slice.
