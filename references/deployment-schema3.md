# Internal Test Alpha deployment schema 3

This is the sole active deployment-manifest contract for Internal Test Alpha.
It is fresh-only: the target starts with an empty deployment state and accepts
exactly `schema_version: 3`. Any other schema value is rejected before an
effect. No prior-schema reader, compatibility path, migration, or fallback is
defined.

## Canonical input

The manifest is canonical, duplicate-key-free JSON with no unknown fields:

```text
schema                  = "dirextalk.internal-test-alpha-deployment"
schema_version          = 3
fresh_only              = true
target.id               = one disposable X3, X4, or X5 host identity
server.source_commit    = exact 40-hex Git commit
server.image            = exact OCI image@sha256:<64 lowercase hex>
client.source_commit    = exact 40-hex Git commit
client.apk              = { path, sha256:<64 lowercase hex> }
client.test_apk         = { path, sha256:<64 lowercase hex> }
connector.source_commit = exact 40-hex Git commit
connector.binary        = { path, sha256:<64 lowercase hex> }
sidecar.source_commit   = exact 40-hex Git commit
sidecar.image            = exact OCI image@sha256:<64 lowercase hex>
deployer.source_commit  = exact 40-hex Git commit
config                  = { path, sha256:<64 lowercase hex> }
```

Every `path` is safe-relative to the package root. Images are immutable digest
references, never mutable tags. The client APK and test APK are distinct files
and both hashes are mandatory. All four product repositories and this deployer
must be clean and at the exact commits named by the manifest.

The manifest contains no credential, token, private key, prompt, decrypted
conversation event, arbitrary command, arbitrary environment, or unbounded
path. The Sidecar remains the only conversation data-plane dependency.

## Lifecycle

The only lifecycle is:

```text
Planned -> Installed -> Started -> ReadinessVerified -> AcceptanceObserved -> Completed
```

Each transition persists the manifest/package digest, operation identity,
current Connector fence and operation fence, and redacted facts before the next
effect.
There are no additional schema or lifecycle states.

## Output and acceptance boundary

The durable output contains the manifest digest, component digests, exact
Connector fence and operation fence identities, current lifecycle state, and
sanitized readiness facts. At `AcceptanceObserved`, it records only the digest
and signer identity of the independently produced signed acceptance receipt
observed for this exact target and package. Receipt bytes, prompts, decrypted
events, and conversation content are not copied into deployer state.

A command plan, focused test, compiled artifact, or running service is not an
acceptance receipt and cannot advance the lifecycle to `AcceptanceObserved` or
`Completed`.

## Scoped rollback

Rollback is a target-scoped operation for the same manifest, current Connector
fence, and operation fence. It may remove only the affected Alpha package,
service state, and test data, and must persist its effect before each local
mutation. It cannot touch unrelated hosts/data, restore an older schema, migrate
state, or invent a compatibility path. Rollback is not an additional lifecycle
state and does not claim completion.
