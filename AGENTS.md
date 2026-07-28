# Dirextalk vNext Deployer

This repository owns the typed Rust deployer for the fresh-only Dirextalk
Internal Test Alpha. It does not reuse the legacy `dirextalk-deployer` shell
orchestration. The only active deployer contract is
[`references/internal-test-alpha-deployer.md`](references/internal-test-alpha-deployer.md),
whose sole manifest contract is `references/deployment-schema3.md`.

## Boundaries

- This vNext repository remains in internal development. Feature and logic work
  adopts the active target-product contract directly.
- Internal Test Alpha accepts exactly one fresh-only `schema_version: 3` target.
  Reject any other schema before an effect. Do not add a prior-schema reader,
  compatibility path, migration, fallback, or dual deployment path.
- The required lifecycle is exactly
  `Planned -> Installed -> Started -> ReadinessVerified -> AcceptanceObserved -> Completed`.
  A build, fixture, focused test, dry-run plan, or service process is not
  acceptance evidence. Do not claim missing install/start/readiness,
  signed-receipt observation, or scoped-rollback behavior as implemented.
- The primary worktree is the default. Use an extra worktree only for
  simultaneous non-overlapping writers in this same repository. One owner
  handles locate, implementation, focused test, self-review, and commit; run
  one accumulated review at stage close. Ordinary fixes do not trigger a full
  re-review unless a high-risk public, persistence, or deployment contract
  changes.
- Do not create an extra worktree for ordinary single-owner development,
  verification, review, release, or deployment. At most one temporary
  auxiliary worktree may exist for an explicitly concurrent non-overlapping
  writer, and it must be removed as soon as that work is integrated or
  abandoned.
- Keep only two versions of generated release or acceptance material: the
  current version and one immediately previous rollback version. Build caches
  are disposable and must be cleaned after the stage. Preserve active
  deployment state, but remove older bundles, binaries, logs, and superseded
  acceptance artifacts once the newer version is verified.
- Check disk capacity before builds and releases. Generated material must not
  exceed 20 GiB in this repository without explicit user approval; stop and
  clean Cargo and Docker BuildKit outputs before crossing the limit.
- During Internal Test Alpha, ordinary single-owner work does not auto-load or
  use `$govern-agent-system` and does not delegate; the primary-worktree owner
  performs the full workflow directly. Use governance delegation only when the
  user explicitly requests it for this task or two genuinely independent,
  non-overlapping writer surfaces exist.
- A command is a dry run unless an explicit `--execute` flag is present. Keep
  existing mutation commands closed to their fixed Host Supervisor boundary;
  never accept arbitrary shell fragments, commands, paths, URLs, or
  environments from a manifest.
- Keep server, client, Connector, Sidecar, deployer, image, APK, test-APK,
  binary, and configuration identities exact and digest-bound. Never log or
  persist credentials, private keys, tokens, prompts, decrypted events, or
  conversation plaintext.
- Agent Control remains opaque to deployer logic. The Rust Agent Device Sidecar
  is the conversation data plane; do not reimplement encrypted messaging or
  add a plaintext input shortcut.
- Use Rust 2024, the pinned stable toolchain, and forbid unsafe Rust.

## Finish

Run the focused checks relevant to the active boundary:

```text
cargo fmt --all -- --check
cargo test --locked deployment
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked -- --help
git diff --check
```

The existing CLI has no standalone install, start, readiness, signed-receipt
observation, or scoped-rollback command; report those gaps instead of claiming
Internal Test Alpha completion. Do not run or describe release-only gates as
active acceptance.
