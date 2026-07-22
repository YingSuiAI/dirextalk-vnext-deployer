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

## Local Connector-host lifecycle

`deployment-connector-apply --execute` is a closed, root-only local transport
for one Connector target. It validates the existing deployment manifest and
Server-issued Connector plan, reads the protected handoff, config, and three
CA files, then persists `.dirextalk-connector-execution-state` before each
fixed Host Supervisor V2/V1 effect. It invokes only
`/usr/local/libexec/dirextalk/dtx-agent-host-supervisor` with no arguments.
It performs V2 prepare, ordinary V1 start, independent V1 Running observation,
and V2 finalize. No secret handoff, enrollment token, bearer, raw receipt, or
operator output is written to state or printed.

## Current boundary

This foundation owns release artifact planning, assembly, guarded publication,
and Unix-only offline durable ownership/lifecycle evidence. Production host
installation, migration execution, rollback execution, service management, and
remote Connector enrollment remain later typed CLI stages. They must consume the
fenced durable state and fixed actions without an arbitrary command or
shell-script escape hatch.

## Single-node AWS EC2 lifecycle

`ec2-plan` validates one immutable Ubuntu 24.04 amd64 node in `ap-east-1` and
prints fixed `aws`, `ssh`, and `scp` argv. `ec2-apply`/`ec2-resume`,
`ec2-update`, and `ec2-destroy` remain dry runs unless `--execute` is present.
The manifest requires the exact `dirextalk/vnet-server@sha256:<64>` image and
stack bundle digest, a 0600 private key, and a pinned host key. State is a
0600 integrity-sealed journal; status redacts credentials and destroy only
touches resources recorded as Dirextalk-owned. Use the same manifest shape for
`x6`, `x7`, or `x8` (see `aws-ec2.example.json`). No AWS credentials are read
from files or persisted; the standard AWS environment/profile is inherited by
the fixed `aws` process.

`ec2-status` and `ec2-update` perform one bounded, read-only Docker Hub
discovery using the fixed command `docker buildx imagetools inspect` for
`docker.io/dirextalk/vnet-server:latest`. Its JSON manifest digest must parse
as canonical `sha256:<64>`. The tag is comparison-only: apply/update state and
the digest-bound installer contract accept only
`dirextalk/vnet-server@sha256:<64>`, and update refuses a manifest whose exact
digest does not match the registry readback. Docker credentials, command
stderr, and registry tokens are neither printed nor persisted.

```text
cargo run --locked -- ec2-plan --manifest aws-ec2.example.json
cargo run --locked -- ec2-plan --manifest aws-ec2-x7.example.json
cargo run --locked -- ec2-plan --manifest aws-ec2-x8.example.json
```
