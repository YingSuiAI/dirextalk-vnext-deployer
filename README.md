# Dirextalk vNext Deployer

This repository contains the typed Rust deployer used to take a new Dirextalk
user from an AWS access-key CSV to a running vNext server and an App binding
ticket. AWS control-plane calls use the in-process AWS Rust SDK; the deployer
does not require the AWS CLI and does not create a local AWS profile.

The current new-user path is:

```text
rootkey.csv -> STS identity -> EC2/Route53 -> immutable server bundle
            -> HTTPS verification -> short-lived App binding -> cleanup
```

See
[`references/rootkey-onboarding-alpha.md`](references/rootkey-onboarding-alpha.md)
for the supported contract, configuration fields, security rules, lifecycle,
and known limitations.

## Current scope

| Capability | Status |
| --- | --- |
| Strict single-record AWS CSV import | Implemented |
| In-process AWS SDK and STS account verification | Implemented |
| EC2, encrypted root volume, EIP, security group and Route53 lifecycle | Implemented |
| Crash-safe `onboard`, `resume`, `status`, `verify`, `destroy` | Implemented |
| General release-to-release `update` | Deferred; current command is limited to the authenticated 0.1.1→0.1.4 repair path |
| Digest-pinned server bundle and images | Implemented |
| Short-lived deployment binding issue/status flow | Implemented; Android consumption still requires a real device |
| Root-key replacement verification | Implemented |
| Live Lightsail catalog discovery | Implemented |
| Lightsail create/resume/verify/destroy lifecycle | Deferred |
| Domain purchase, nameserver changes, external DNS and multi-cloud | Out of scope |
| Built-in SSH/SFTP and system file picker | Deferred |

The deployment configuration contains no AWS credential. Every mutating
lifecycle command requires the user to select the currently valid CSV again.
The Access Key ID and Secret Access Key are held only in deployer memory and
are never written to the configuration, state, command line, logs, binding
payload, server, or App.

## Quick start

Build or install the deployer, prepare a non-secret configuration as described
in the onboarding reference, then run a dry plan:

```text
dirextalk-vnext-deployer deploy onboard \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --max-monthly-usd 60
```

Inspect the account, region, resource list, cost ceiling, and RootKey warning.
Add `--execute` only after they match the intended account:

```text
dirextalk-vnext-deployer deploy onboard \
  --config deployment.json \
  --aws-rootkey-csv /absolute/path/rootkey.csv \
  --max-monthly-usd 60 \
  --execute
```

After HTTPS verification, issue a 15-minute App binding:

```text
dirextalk-vnext-deployer deploy binding issue \
  --config deployment.json \
  --output deployment-binding.dtxb \
  --execute
```

The binding authorization is short-lived and single-use. The fallback file is
created with private permissions and is removed after consumption or expiry.

Release 0.1.12 was accepted on a fresh Hong Kong EC2 deployment using Route53:
the exact security group, immutable images, signed installation receipt,
authoritative public DNS, HTTPS health, ticket issuance, and protocol redemption
were observed. The live ticket reached `redeemed`; `consumed/ready` was not
claimed because no Android device completed the secure-storage import.

## RootKey warning

The first release intentionally optimizes for a non-technical user's shortest
path and therefore accepts an AWS root access key. A root key has full account
authority. After deployment, create a different key, verify it with
`deploy credentials verify-rotation`, then deactivate or delete the original
key in AWS. The deployer verifies rotation but never deletes credentials.

## Other deployment contracts

The repository also retains the separate fresh-only schema-3 Internal Test
Alpha contract in
[`references/internal-test-alpha-deployer.md`](references/internal-test-alpha-deployer.md).
That host/Connector acceptance lifecycle is not a substitute for the new-user
EC2 onboarding flow and must be operated independently.
