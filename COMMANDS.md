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
| Connector-host lifecycle apply | `sudo cargo run --locked -- deployment-connector-apply --execute --manifest deployment.json --target <id> --plan <plan.json> --handoff <handoff.json> --config <config.toml> --enrollment-ca <ca.pem> --control-ca <ca.pem> --issuer-ca <ca.pem>` |

`build` only executes commands when `--execute` is supplied. `publish` also
requires `--execute` plus one or more destination flags.

`deployment-connector-apply` is the sole production local Connector-host
transport. It requires root and `--execute`, persists its local lifecycle
record before every effect, and invokes only the fixed no-argument Host
Supervisor executable. It accepts no remote command, path in the protocol,
environment, URL, or shell. The handoff must be a root-owned, no-follow `0600`
regular file; output and durable state retain only digests and sanitized Host
responses. It is not an SSH/cloud transport.
`deployment-validate` and `deployment-plan` are cross-platform;
`deployment-status` is Unix-only and fails closed as unsupported elsewhere.

On Windows without Visual C++ Build Tools, use the repository's development
wrapper, for example `powershell -File scripts\cargo.ps1 test --locked`. It
selects the installed GNU toolchain and linker; it is not deployment or release
orchestration.
