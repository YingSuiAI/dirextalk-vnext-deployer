# Command Map

The active command and acceptance contract is
[`references/internal-test-alpha-deployer.md`](references/internal-test-alpha-deployer.md).
Run commands from this repository root. A command is a dry run unless
`--execute` is present.

| Purpose | Command currently exposed by the CLI |
| --- | --- |
| Focused formatting check | `cargo fmt --all -- --check` |
| Focused deployment tests | `cargo test --locked deployment` |
| Focused lint check | `cargo clippy --locked --all-targets -- -D warnings` |
| Show currently exposed subcommands | `cargo run --locked -- --help` |

## Existing offline foundation (non-Alpha; not acceptance)

These commands exist today, but use the historical offline foundation manifest
and do not validate or execute the active schema 3 flow. They must not be used
as an Alpha substitute:

```text
cargo run --locked -- deployment-validate --manifest deployment.example.json
cargo run --locked -- deployment-plan --manifest deployment.example.json
sudo cargo run --locked -- deployment-connector-claim --execute \
  --operation-id <uuidv7> --manifest deployment.example.json \
  --target <connector-host-id>
sudo cargo run --locked -- deployment-connector-apply --execute \
  --operation-id <uuidv7> --manifest deployment.example.json \
  --target <connector-host-id> --plan <plan.json> --handoff <handoff.json> \
  --config <config.toml> --enrollment-ca <ca.pem> --control-ca <ca.pem> \
  --issuer-ca <ca.pem>
sudo cargo run --locked -- deployment-status --operation-id <uuidv7>
```

The foundation claim/apply path invokes only the fixed Host Supervisor
boundary. It does not accept arbitrary commands, paths, URLs, environments,
secrets, prompts, or decrypted conversation events. `deployment-status` is
Unix-only. None of these commands can produce the Alpha acceptance receipt.

There are no standalone `install`, `start`, `readiness`, signed acceptance
receipt observation, or scoped rollback commands in this CLI. Those are
explicit target capabilities in the active contract, not current executable
claims. Do not replace a missing capability with an older schema reader,
compatibility branch, migration, or fallback.

## Focused repository checks

```text
cargo fmt --all -- --check
cargo test --locked deployment
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked -- --help
git diff --check
```

These checks provide implementation evidence only. A real fresh-target run with
all six lifecycle transitions and the independently signed acceptance receipt
is required for `AcceptanceObserved` and `Completed`.
