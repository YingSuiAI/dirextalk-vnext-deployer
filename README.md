# Dirextalk vNext Deployer

This repository owns the typed Rust deployer for the fresh-only Dirextalk
Internal Test Alpha. The active contract is
[`references/internal-test-alpha-deployer.md`](references/internal-test-alpha-deployer.md).
It binds one disposable target to exact server, client, Connector, Sidecar,
deployer, image, APK, test-APK, binary, and configuration identities.

The target contract has exactly one `schema_version: 3` and this lifecycle:

```text
Planned -> Installed -> Started -> ReadinessVerified -> AcceptanceObserved -> Completed
```

`AcceptanceObserved` is reached only by observing the independently signed
acceptance receipt for the exact target package and current fences. A crate,
fixture, build, dry-run plan, or service process is not acceptance evidence.

## Current executable boundary

The current executable evidence is limited to repository checks and help:

```text
cargo fmt --all -- --check
cargo test --locked deployment
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked -- --help
```

The CLI also exposes an offline deployment foundation, but its manifest reader
is not schema 3 and its claim/apply/status commands are non-Alpha only. They
must not be used as an Alpha substitute. No schema-3 end-to-end entry exists
yet for install/start/readiness, signed-receipt observation, or scoped rollback;
the cross-repository Alpha run must not be described as complete until those
target capabilities and their real acceptance evidence exist.

Fresh-only means an empty target and schema 3. No schema 1/2 reader,
compatibility path, migration, or fallback is part of this release boundary.
Prompt and conversation plaintext remain outside deployer inputs.
