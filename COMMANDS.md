# Command Map

Run from the repository root.

| Task | Command |
| --- | --- |
| format | `cargo fmt --all` |
| check | `cargo check --locked` |
| test | `cargo test --locked` |
| lint | `cargo clippy --locked --all-targets -- -D warnings` |
| validate example | `cargo run --locked -- validate --manifest release.example.json` |
| dry-run plan | `cargo run --locked -- plan --manifest release.example.json --artifacts-dir artifacts --output-dir dist` |
| native build plan | `cargo run --locked -- build --manifest release.example.json --target windows-x64` |
| deployment contract validation | `cargo run --locked -- deployment-validate --manifest deployment.example.json` |
| deployment dry-run plan | `cargo run --locked -- deployment-plan --manifest deployment.example.json` |
| deployment status readback | `cargo run --locked -- deployment-status --operation-id <uuid>` |

`build` only executes commands when `--execute` is supplied. `publish` also
requires `--execute` plus one or more destination flags.

Deployment commands are offline contract/state operations only. No production
transport, privileged migrator, service mutation, provider activation,
deployment, or X3/X4/X5 acceptance is implemented or claimed.
`deployment-validate` and `deployment-plan` are cross-platform;
`deployment-status` is Unix-only and fails closed as unsupported elsewhere.

On Windows without Visual C++ Build Tools, use the repository's development
wrapper, for example `powershell -File scripts\cargo.ps1 test --locked`. It
selects the installed GNU toolchain and linker; it is not deployment or release
orchestration.
