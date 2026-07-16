---
name: dirextalk-vnext-deployer
description: Build, assemble, preview, and explicitly publish Dirextalk vNext server, deployer, and multi-Agent Connector releases with the typed Rust CLI.
---

# Dirextalk vNext release workflow

Use this skill for Dirextalk vNext release preparation or publication. Run the
Rust CLI from this repository and treat `release.example.json` as a template,
not as a hidden source of credentials.

## Required sequence

1. Read the selected manifest and run `validate`.
2. Run `plan` and inspect the resolved image, target matrix, source commits,
   local output paths, and command programs. Do not translate commands into a
   shell script.
3. Run `build --execute` only for targets supported by the selected builder, or
   let CI populate the documented `artifacts/<target>/` layout.
4. Run `assemble` into a new or empty output directory. Inspect
   `checksums-sha256.txt`, `github-assets.json`, and the generated npm package.
5. Run `publish` without `--execute` and report its credential-readiness
   booleans. Never reveal environment values or Docker configuration content.
6. Add `--execute` only when the user explicitly authorizes the named registry,
   npm, and/or GitHub mutations. Select each destination with its own flag.

## Hard rules

- Never infer permission to publish from permission to build or assemble.
- Never use a floating server image tag. The default image repository is
  `dirextalk/vent`, but it remains manifest-configurable.
- Never pass secrets on a command line or write them into a manifest, plan,
  artifact, npm wrapper, log, or GitHub asset.
- Never bypass dirty-worktree or source-revision checks for a release.
- Never reuse legacy `dirextalk-deployer` shell orchestration. New install and
  lifecycle operations belong in typed Rust commands with durable state.
- A failed or interrupted publication is not proof of release completion.
  Verify each selected registry/release using its authoritative read API.

Read [references/release-manifest.md](references/release-manifest.md) when
editing a manifest, selecting targets, or preparing CI artifact paths.

