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

Verification note: focused EC2 replay, rollback, and legacy-seal tests pass.
The full suite has one external concurrent-workspace failure only:
`real_server_bundle_5bf0090_parses_and_plans` reports `SourceMismatch` for the
live `dirextalk-vnext-server/target/production-release/dirextalk-vnext.bundle`
artifact; no deployer fixture or code path is involved.

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

`deployment-connector-claim --execute` creates (or exactly replays) the
canonical durable operation required by apply:

```text
sudo cargo run --locked -- deployment-connector-claim --execute --operation-id <uuidv7> --manifest deployment.json --target <connector-host-id> [--predecessor-operation-id <terminal-uuidv7>]
```

It is root-only; its manifest must be a root-owned no-follow `0600` regular
file. It rejects Node targets, verifies the fixed root-owned Host Supervisor
tuple evidence before mutating state, and delegates target ownership,
predecessor terminality, and exact replay to the canonical local state store.
It neither stages artifacts nor contacts remote hosts, invokes services, or
handles secrets. Its output is the same sanitized durable operation projection
as `deployment-status`.

`deployment-connector-apply --execute` is a closed, root-only local transport
for one Connector target. It validates the existing deployment manifest and
Server-issued Connector plan, reads the protected handoff, config, and three
CA files, then advances the pre-existing canonical deployment operation and
Connector claim in `/var/lib/dirextalk-vnext-deployer` before each fixed Host
Supervisor V2/V1 effect. The Connector plan operation ID is correlation only;
it is never substituted for deployment ownership. It invokes only
`/usr/local/libexec/dirextalk/dtx-agent-host-supervisor` with no arguments.
It performs V2 prepare, ordinary V1 start, independent V1 Running observation,
and V2 finalize. No secret handoff, enrollment token, bearer, raw receipt, or
operator output is written to state or printed.

## Client binding issue

After a terminal-successful EC2 deployment, the root-only
`ec2-client-binding-issue --execute` action stages one exact request at the
fixed host path, invokes the release-bundled zero-argument issuer helper, pulls
the exact import artifact, and invokes the fixed cleanup helper. The action
reuses the sealed EC2 lifecycle state, operation lock, pinned SSH key and
known-hosts file, and writes one short-lived client-binding JSON artifact as a
no-follow operator-local `0600` file. Authorization and PEM contents are never
printed or retained in durable state; replay is exact and conflicts fail
closed. The staged Ubuntu-owned request is transport-only; the authenticated
bundle helper atomically moves and validates it before the root-owned issuer
container consumes its protected copy.

## Current boundary

The generic offline deployment foundation owns release artifact planning,
assembly, guarded publication, and Unix-only durable ownership evidence. Its
Connector transport remains separate from the AWS EC2 lifecycle below. Both
surfaces consume fenced durable state and fixed actions without an arbitrary
command or shell-script escape hatch.

## Single-node AWS EC2 lifecycle

`ec2-plan` validates one immutable Ubuntu 24.04 amd64 node in `ap-east-1` and
prints the closed action set and conservative monthly cost ceiling.
`ec2-apply`, `ec2-resume`, and `ec2-destroy` remain dry runs unless `--execute`
is present. `ec2-update` validates dry runs without effects and, with
`--execute`, supports only the authenticated forward `0.1.1` to `0.1.4` path.
Both the retained and candidate digest-bound stack manifests must carry the
same strict compatibility marker declaring forward-only migrations and
code-only rollback. The durable state records candidate, retained, request,
and receipt facts before every host effect; it uses the existing pinned SSH/SCP
channel, checks authenticated remote byte and inode capacity, and replays each
post-crash boundary without duplicate installer effects. It never changes EBS,
Docker volumes, TLS, secrets, or provisioned configuration. A library-only
`rollback_update` primitive is separately fenced to an unverified candidate and
requires a server-produced `rolled_back` receipt; it performs no down migration.
`ec2-rebind-operator-cidr` is a separately fenced recovery operation for an
already-owned security group: it requires the exact current `/32` in state and
an otherwise identical, digest-bound manifest with a new `/32`. With
`--execute`, it verifies caller account and exact ownership tags, accepts only
the old-only, old+new replay, or new-only post-revoke ingress shapes, authorizes
the exact new TCP/22 rule before revoking the exact old rule, then reseals only
`infrastructure.operator_ssh_cidr` without changing lifecycle phase.
The manifest requires exact runtime and migrator images from the single
authorized repository `dirextalk/vnet-server@sha256:<64>`, digest-pinned
Postgres, Caddy, and probe images, a deterministic uncompressed USTAR stack
bundle, and three external host helpers with independent SHA-256 bindings.
Apply requires `--max-monthly-usd`, generates a per-operation Ed25519 key,
pins the host key against an instance/client-token/AMI-bound EC2 console
attestation, then stages the installer, provisioner, and receipt reader over
that pinned SSH channel. Cloud-init contains only package setup, Docker
enablement, and the small console attestor and stays below EC2's 16 KiB raw
user-data limit. Remote helper paths are fixed and accepted on resume only with
the exact digest, regular-file type, root ownership, `0555` mode, and link count
before use.

The release installer consumes only fixed root-owned `0400` bundle/request
paths. Initial host provisioning consumes
`/home/ubuntu/dirextalk-vnext.provision`, materializes production config,
secrets, TLS, and services, and publishes the root-owned `0600`
`/var/lib/dirextalk-vnext/host-provision/ready.json`. Apply and every later
verify validate the canonical self-hashed release and host-ready receipts before
accepting HTTPS health. State and key material live in a locked 0700 directory
as 0600 integrity-sealed files.
Destroy re-reads ownership tags before every destructive effect, retains the
root EBS volume by default, and requires a separate exact volume-ID fence to
purge it. Use the same manifest shape for `x6`, `x7`, or `x8`.

`ec2-status` performs one bounded, read-only Docker Hub discovery using the
fixed command `docker buildx imagetools inspect` for
`docker.io/dirextalk/vnet-server:latest`. Its JSON manifest digest must parse
as canonical `sha256:<64>`. The tag is comparison-only and is never consulted
by apply or update. Update validation consumes only the explicitly supplied
immutable bundle and image digests. Cross-version mutation additionally
requires the server-produced compatibility markers described above; a missing,
mismatched, or malformed marker fails closed before any remote effect.
Docker
credentials, command stderr, and registry tokens are neither printed nor
persisted.

```text
cargo run --locked -- ec2-plan --manifest aws-ec2.example.json --max-monthly-usd 100
cargo run --locked -- ec2-plan --manifest aws-ec2-x7.example.json
cargo run --locked -- ec2-plan --manifest aws-ec2-x8.example.json
```
