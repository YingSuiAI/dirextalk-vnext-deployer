# RootKey onboarding Alpha

## Purpose

This contract covers a new user who already owns a domain in an AWS-managed
DNS zone and wants to deploy one Dirextalk vNext server without installing the
AWS CLI, Docker, Rust, Flutter, or a local AWS profile.

The Alpha implementation supports EC2 plus Route53. Lightsail catalog
discovery is available, but the Lightsail resource lifecycle is intentionally
deferred and must not be presented as deployable.

## Credential boundary

`rootkey.csv` must be a regular, non-symlink file containing exactly one
credential record. The reader:

- opens with no-follow semantics on Unix;
- requires the file to be owned by the current user and inaccessible to group
  or other users on Unix (normally mode `0600`);
- caps the file at 16 KiB;
- accepts UTF-8 BOM;
- accepts either `AWSAccessKeyId,AWSSecretKey` or
  `Access key ID,Secret access key`;
- optionally accepts `User name` and `Session token`;
- rejects empty values, duplicate/unknown headers, malformed CSV, and multiple
  records.

Credential values are non-serializable, redacted from `Debug`, zeroized on
drop, and supplied directly to the AWS Rust SDK. The deployer never creates an
AWS profile and never passes credentials to a child process, argument list,
configuration, state, log, error, QR payload, server, or App.

The durable credential reminder stores only the AWS account ID, the last four
Access Key ID characters, and a SHA-256 digest of the Access Key ID.

## Configuration

The strict JSON configuration is non-secret. It contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | Must be `1` |
| `target` | Stable deployment name used for local state and AWS tags |
| `provider` | Currently `aws` |
| `region` | Normalized AWS region, for example `ap-east-1` |
| `domain` | Existing fully qualified hostname |
| `instance_type` | EC2 type selected for the release requirements |
| `disk_gib` | Encrypted gp3 root volume size |
| `operator_ssh_cidr` | Current public IPv4 as an exact `/32` |
| `stack_bundle_path` / `stack_bundle_sha256` | Immutable release bundle and digest |
| host helper paths and SHA-256 fields | Fixed installer, provisioner and receipt reader |
| release/image/source fields | Immutable version, source commit and image digests |
| Ubuntu AMI fields | Canonical owner and active LTS image pattern |
| `key_name` | Deployment-owned EC2 key-pair name |

Floating image tags are not accepted by the deployment state. A visible
`latest` release must first resolve to immutable runtime and migrator digests;
the fresh deployment pins those digests. General release-to-release update is
deferred. The current `deploy update` command is retained only for the
authenticated 0.1.1-to-0.1.4 repair contract and must not be presented as a
general updater.

## Lifecycle

`onboard` performs STS identification before planning or mutation. The user
must review the account, principal type, region, planned resources, cost
ceiling, and RootKey warning. With `--execute`, the durable state machine:

1. resolves a canonical Ubuntu LTS AMI and validates the requested instance;
2. creates a deployment-tagged key pair and exact security group;
3. allows SSH only from the configured `/32`, with public HTTP/HTTPS;
4. creates the EC2 instance and encrypted gp3 root volume;
5. allocates and associates an EIP;
6. creates the Route53 A record only if the exact name is unoccupied;
7. pins the SSH host key and stages authenticated fixed helpers;
8. installs the digest-pinned bundle and starts the production stack;
9. verifies the signed install/host-ready receipts, public DNS through an
   HTTPS DNS resolver, and TLS health against the owned EIP.

Every external effect is recorded before execution and reconciled on
`resume`. Each AWS object carries the target, operation, domain, managed flag,
and client-token digest tags. The state directory is private and locked per
deployment.

The current AWS control plane is fully in-process. Host transport still relies
on locally available `ssh`, `scp`, `ssh-keygen`, `ssh-keyscan`, and `curl`;
replacing those with built-in transports is deferred.

## DNS

Alpha supports an existing Route53 hosted zone in the selected AWS account.
It does not buy domains, change registration or nameservers, or integrate
external DNS providers.

Creation fails closed if an A record already exists with another value.
Destruction deletes a record only if its type, TTL, name, and single value
still exactly match the deployment-owned record.

## App binding

After `verify`, `deploy binding issue` asks the verified server for a
15-minute, single-use deployment ticket. The canonical `dtxb1:` payload binds
the server origin, ticket ID, capability, protocol version, and expiry.

The fallback binding file is mode `0600`. Authorization is not logged and is
removed after the App consumes the ticket or it expires. Reissuing a ticket
does not redeploy the server. The CLI can wait for the server to report
`consumed/ready`, or return immediately with `--no-wait` for a separate status
poll.

Release 0.1.12 acceptance reached `redeemed` against a fresh Hong Kong EC2
deployment. `consumed/ready` remains a handset acceptance step: only the
Android App can generate the device key in native code, commit it to Android
secure storage, and finish initial-device provisioning. A protocol-only
redeem must never be reported as App consumption.

## Rotation

Successful deployment remains successful while showing a non-optional
RootKey rotation reminder. `deploy credentials verify-rotation` accepts a new
CSV and verifies:

1. STS resolves to the same AWS account;
2. the Access Key ID differs from the deployment key;
3. IAM `ListAccessKeys` shows the original key inactive or absent.

Only then is the local reminder cleared. The deployer does not deactivate or
delete any AWS credential.

## Destruction

Normal destruction is two-step:

1. delete the matching DNS record, EIP association, instance, EIP, security
   group, cloud key and local SSH artifacts while retaining the encrypted
   volume;
2. explicitly purge the reviewed retained volume ID.

Both steps re-identify the AWS account and revalidate region, target,
operation, tags, and exact resource identities. A mismatch stops the
operation.

## Deferred work

- Lightsail create/resume/verify/update/destroy;
- general release-to-release EC2 update and rollback;
- built-in system file picker and native SSH/SFTP/HTTPS transport;
- npm multi-platform binary publication and `skill install`;
- App-store distribution;
- domain purchase, nameserver mutation, external DNS, Cloudflare and multi-cloud;
- automatic credential deletion.

These are not compatibility gaps in the EC2 Alpha. They are explicit future
product surfaces and must not be simulated with shell deployment paths.
