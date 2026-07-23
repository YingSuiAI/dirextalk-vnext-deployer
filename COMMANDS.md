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
| deployment status readback | `sudo cargo run --locked -- deployment-status --operation-id <uuid>` |
| EC2 lifecycle plan (x6/x7/x8) | `cargo run --locked -- ec2-plan --manifest aws-ec2.example.json` |
| EC2 apply/resume (explicit mutation) | `cargo run --locked -- ec2-apply --manifest aws-ec2.example.json --max-monthly-usd 100 --execute` |
| EC2 status/verify | `cargo run --locked -- ec2-status --manifest aws-ec2.example.json` / `cargo run --locked -- ec2-verify --manifest aws-ec2.example.json` |
| EC2 update validation (mutation fail-closed) / destroy | `cargo run --locked -- ec2-update --manifest aws-ec2.example.json` / `cargo run --locked -- ec2-destroy --manifest aws-ec2.example.json --execute` |
| EC2 operator SSH /32 recovery (exact old-to-new rebind) | `cargo run --locked -- ec2-rebind-operator-cidr --manifest aws-ec2.example.json --state-dir .dirextalk-ec2-state --expected-old-cidr <old/32> --execute` |
| EC2 retained-volume purge (separate exact fence) | `cargo run --locked -- ec2-destroy --manifest aws-ec2.example.json --purge-volume --purge-volume-id vol-... --execute` |
| Connector-host lifecycle apply | `sudo cargo run --locked -- deployment-connector-apply --execute --operation-id <deployment-uuidv7> --manifest deployment.json --target <id> --plan <plan.json> --handoff <handoff.json> --config <config.toml> --enrollment-ca <ca.pem> --control-ca <ca.pem> --issuer-ca <ca.pem>` |
| Connector-host operation claim | `sudo cargo run --locked -- deployment-connector-claim --execute --operation-id <deployment-uuidv7> --manifest deployment.json --target <connector-host-id> [--predecessor-operation-id <terminal-deployment-uuidv7>]` |
| Client binding issue (terminal Server deployment only) | `sudo cargo run --locked -- deployment-client-binding-issue --execute --operation-id <deployment-uuidv7> --target <node-id> --tenant-id <tenant-uuidv7> --server-origin https://host --output <operator-file>` |

`build` only executes commands when `--execute` is supplied. `publish` also
requires `--execute` plus one or more destination flags.

`deployment-connector-claim` is the root-only, local prerequisite for
`deployment-connector-apply`. It accepts only a root-owned `0600` deployment
manifest, a Connector-host target, canonical UUIDv7 operation identifiers, and
an explicit terminal predecessor for an exact successor. It verifies the fixed
root-owned host tuple evidence before creating or exactly replaying the
canonical durable operation. It has no artifact, remote, service, or secret
handling surface and prints the same sanitized operation projection as status.

`deployment-connector-apply` is the sole production local Connector-host
transport. It requires root and `--execute`, persists its local lifecycle
record under the canonical deployment operation in the fixed root-owned
`/var/lib/dirextalk-vnext-deployer` store before every effect, and invokes only
the fixed no-argument Host Supervisor executable. It accepts no remote command,
path in the protocol,
environment, URL, or shell. The handoff must be a root-owned, no-follow `0600`
regular file. Manifest, plan, config, and CA inputs must also be root-owned
closed-mode regular files. Output and durable state retain only digests and
sanitized Host responses. It is not an SSH/cloud transport.
If the Host returns the exact V2 `expired_unclaimed` prepare result (no receipt
digests and no revision change), apply durably terminalizes the unobserved
Connector claim and its single-Connector deployment operation, then returns
`Connector bootstrap expired unclaimed; reissue required`. Reissue a fresh
Server bootstrap and create a new operation with the terminal operation as its
explicit predecessor; successor ownership is accepted only when both exact
predecessor records prove that no-effect terminal state.
`deployment-validate` and `deployment-plan` are cross-platform;
`deployment-status` is Unix-only and fails closed as unsupported elsewhere.

`ec2-status` resolves Docker Hub `latest` through the fixed
read-only `docker buildx imagetools inspect` argv. It parses only a canonical
manifest `sha256:<64>` and compare it to the installed immutable
`dirextalk/vnet-server@sha256:<64>` receipt; `latest` is never installed or
used to gate `ec2-update`.

On Windows without Visual C++ Build Tools, use the repository's development
wrapper, for example `powershell -File scripts\cargo.ps1 test --locked`. It
selects the installed GNU toolchain and linker; it is not deployment or release
orchestration.
