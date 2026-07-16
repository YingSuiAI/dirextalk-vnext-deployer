# Dirextalk vNext Deployer

This repository owns the typed Rust release/deployment CLI and its Codex skill.
It does not reuse the legacy `dirextalk-deployer` shell orchestration.

## Boundaries

- A command is a dry run unless an explicit `--execute` flag is present.
- Registry, npm, and GitHub mutations additionally require one explicit action
  flag per destination and a non-empty credential source. Never print credential
  values, environment values, private keys, tokens, or Docker auth documents.
- Release manifests are strict, versioned data contracts. Reject unknown fields,
  unsafe paths, mutable image tags, duplicate targets, and unpinned source facts.
- Invoke tools with `std::process::Command`; do not add platform shell scripts or
  accept arbitrary shell fragments from a manifest.
- Keep release artifacts immutable and SHA-256 indexed. A publish operation must
  refuse dirty or source-mismatched repositories.
- Use Rust 2024, the pinned stable toolchain, and forbid unsafe Rust.

## Finish

Run `cargo fmt --all -- --check`, `cargo test --locked`,
`cargo clippy --locked --all-targets -- -D warnings`, a real `validate`, and a
dry-run `plan`. Never perform a real push/publish during normal verification.

