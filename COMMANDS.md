# Command map

Run commands from this repository root. `onboard`, `update`, and `destroy` are
dry runs unless `--execute` is present. Use an absolute path for
`rootkey.csv`; never print, copy, source, or pass its contents through an
environment variable.

## New-user AWS lifecycle

```text
# Validate the CSV and show only the redacted STS identity.
target/debug/dirextalk-vnext-deployer deploy credentials identify \
  --aws-rootkey-csv /absolute/path/rootkey.csv

# Plan, then execute, a fresh EC2 deployment.
target/debug/dirextalk-vnext-deployer deploy onboard \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --max-monthly-usd 60
target/debug/dirextalk-vnext-deployer deploy onboard \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --max-monthly-usd 60 \
  --execute

# Resume after an interruption with a freshly selected CSV.
target/debug/dirextalk-vnext-deployer deploy resume \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --max-monthly-usd 60 \
  --execute

# Read local redacted state and verify the live deployment.
target/debug/dirextalk-vnext-deployer deploy status \
  --config deployment.json
target/debug/dirextalk-vnext-deployer deploy verify \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv

# Historical authenticated 0.1.1-to-0.1.4 repair only.
# General release-to-release update is not admitted in this Alpha.
target/debug/dirextalk-vnext-deployer deploy update \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --execute
```

## App binding

```text
# Issue a short-lived ticket and wait for consumed/ready.
target/debug/dirextalk-vnext-deployer deploy binding issue \
  --config deployment.json \
  --output deployment-binding.dtxb \
  --execute

# Use --no-wait when the caller will poll separately.
target/debug/dirextalk-vnext-deployer deploy binding issue \
  --config deployment.json \
  --output deployment-binding.dtxb \
  --execute \
  --no-wait
target/debug/dirextalk-vnext-deployer deploy binding status \
  --config deployment.json \
  --output deployment-binding.dtxb
```

## Credential rotation

```text
target/debug/dirextalk-vnext-deployer deploy credentials verify-rotation \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/replacement-rootkey.csv
```

The replacement must belong to the same AWS account and have a different
Access Key ID. The original key must be inactive or deleted before the local
reminder is cleared.

## Inventory, catalog, and cleanup

```text
# Read only resources tagged as owned by the named deployments.
target/debug/dirextalk-vnext-deployer deploy inventory \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --region ap-east-1 \
  --target deployment-a \
  --target deployment-b

# Live Lightsail discovery only; provisioning remains deferred.
target/debug/dirextalk-vnext-deployer deploy catalog \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --region ap-east-1

# First remove infrastructure while retaining the encrypted root volume.
target/debug/dirextalk-vnext-deployer deploy destroy \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --execute

# Purge the retained volume in a separate, explicitly fenced step.
target/debug/dirextalk-vnext-deployer deploy destroy \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --purge-volume \
  --purge-volume-id vol-REVIEWED_ID \
  --execute
```

`destroy` refuses cross-account, cross-region, tag, operation, resource
identity, or DNS-value mismatches. It deletes the A record only when the record
still points to the deployment-owned IP.

## Focused repository checks

```text
cargo fmt --all -- --check
cargo test --locked --lib
cargo clippy --locked --all-targets -- -D warnings
cargo run --locked -- --help
git diff --check
```

The separate schema-3 Internal Test Alpha commands remain documented in
[`references/internal-test-alpha-deployer.md`](references/internal-test-alpha-deployer.md).

The narrowly admitted historical runtime-receipt repair remains available only
for an already-owned 0.1.1-to-0.1.4 incident; it is not part of new-user
onboarding:

```text
target/debug/dirextalk-vnext-deployer ec2-recover-runtime-011-to-014 --manifest <manifest.json> \
  --state-dir <state-dir> --recovery-helper <fixed-helper> --execute
```
