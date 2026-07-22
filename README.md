# Dirextalk vNext Deployer

`dirextalk-vnext-deployer` is the new typed Rust release/deployment CLI for the
Matrix-independent Dirextalk vNext stack. It starts with the release boundary:

- strict JSON release manifests;
- reproducible command plans for the `dirextalk/vent` server image;
- Rust deployer and Go multi-Agent Connector build plans;
- deterministic per-platform binary bundles;
- per-target build receipts binding binary hashes to clean source commits;
- one npm package exposing both executables;
- SHA-256 checksums and a GitHub Release asset manifest;
- fail-closed, credential-gated publication.

It is a new implementation. It does not execute or embed the legacy
`dirextalk-deployer` shell scripts.

## Safety model

`validate`, `plan`, and `build` without `--execute` cannot publish. `assemble`
only writes a new or empty local output directory. `publish` is also a dry run
unless `--execute` is present, and every remote destination requires its own
flag:

```text
--push-image
--publish-npm
--publish-github
```

Execution then requires a detected credential source. Only readiness booleans
are printed; token and Docker auth values are never read into the plan or
logged. Publication also verifies that all three source repositories still
match the assembled commits and have clean worktrees.

An executed binary build first checks the relevant source worktrees and writes
`artifacts/<target>/build-receipt.json`. Assembly refuses missing, stale, or
hash-mismatched receipts. Publication re-hashes every GitHub asset and every
file in the npm package and rejects unlisted npm files.

The image repository, npm package, GitHub repository, target matrix, version,
and source-date epoch are configurable in the release manifest. The example
uses `dirextalk/vent`; no `latest` tag is generated.

## Quick start

```powershell
cargo run --locked -- validate --manifest release.example.json
cargo run --locked -- plan --manifest release.example.json

# Build one locally supported target. Without --execute this still only prints.
cargo run --locked -- build --manifest release.example.json `
  --target windows-x64 --execute

# After CI or local builders have populated artifacts/<target>/...
cargo run --locked -- assemble --manifest release.example.json `
  --artifacts-dir artifacts --output-dir dist

# Safe publication preview; no network mutation.
cargo run --locked -- publish --manifest release.example.json `
  --release-dir dist --push-image --publish-npm --publish-github
```

Real publication is intentionally a separate, explicit operation:

```powershell
cargo run --locked -- publish --manifest release.example.json `
  --release-dir dist --push-image --publish-npm --publish-github --execute
```

See [references/release-manifest.md](references/release-manifest.md) for the
artifact layout and non-secret configuration contract.

## Offline deployment-contract foundation

The separate `deployment.example.json` validates immutable artifact identities,
logical HTTPS origins, and exact host bindings without changing the release
manifest v1 contract. Its plan is deterministic and uses a closed action set.

```text
cargo run --locked -- deployment-validate --manifest deployment.example.json
cargo run --locked -- deployment-plan --manifest deployment.example.json
cargo run --locked -- deployment-status --operation-id <uuid>
```

This is strictly offline. No production remote transport, privileged production
migrator, service mutation, provider activation, deployment, or X3/X4/X5
acceptance is implemented or claimed. See
[references/deployment-manifest.md](references/deployment-manifest.md).

## Current boundary

This foundation owns release artifact planning, assembly, guarded publication,
and Unix-only offline durable ownership/lifecycle evidence. Production host
installation, migration execution, rollback execution, service management, and
remote Connector enrollment remain later typed CLI stages. They must consume the
fenced durable state and fixed actions without an arbitrary command or
shell-script escape hatch.
