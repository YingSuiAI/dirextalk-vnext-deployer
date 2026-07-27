# Internal Test Alpha deployer contract

This is the only active deployer specification. It is a target contract for a
fresh internal test, not a statement that the current Rust CLI already closes
the cross-repository flow.

Process rule: the primary worktree is the default; an extra worktree is only
for simultaneous non-overlapping writers in this repository. One owner handles
locate, implementation, focused test, self-review, and commit, followed by one
accumulated review at stage close. Ordinary fixes do not trigger a full
re-review unless a high-risk public, persistence, or deployment contract
changes. During Internal Test Alpha, ordinary single-owner work does not
auto-load or use `$govern-agent-system` and does not delegate; the
primary-worktree owner performs the full workflow directly. Governance
delegation is used only when the user explicitly requests it for this task or
two genuinely independent, non-overlapping writer surfaces exist.

## 1. Current business goal

Install one disposable Internal Test Alpha target from one exact package and
prove the one business boundary that follows it: the target reaches
`AcceptanceObserved` only after an independently produced, signed acceptance
receipt is observed. The deployer must never inspect, rewrite, or substitute
conversation plaintext. The target is fresh-only and uses exactly
`schema_version: 3`; any other schema is rejected before an effect.

The required lifecycle is exactly:

```text
Planned -> Installed -> Started -> ReadinessVerified -> AcceptanceObserved -> Completed
```

The lifecycle records the current Connector fence, operation fence, and exact
package digest at every transition. A scoped rollback may remove only the
affected Alpha target's installed package, service state, and test data; it
must not migrate or restore an older deployment schema or touch unrelated
hosts and data. Rollback is not an additional lifecycle state.

## 2. Inputs and outputs

The sole manifest shape is the active
[`deployment-schema3.md`](deployment-schema3.md) contract. It is canonical,
duplicate-key-free JSON with no unknown fields:
The schema requires exact server, client, Connector, Sidecar, and deployer
commits; immutable server and Sidecar images; client APK and test-APK hashes;
the Connector binary hash; and a digest-bound configuration file. Paths are
safe-relative package paths, and the package is consumed only from clean,
exact-commit workspaces. No credential, token, private key, prompt, decrypted
event, or arbitrary command/path/environment is an input.

The target output is a durable, redacted lifecycle record containing the
manifest digest, component digests, exact Connector fence, operation fence,
operation identity, current lifecycle state, and sanitized readiness facts. On
the target business boundary it additionally records the digest and signer
identity of the observed signed acceptance receipt; receipt bytes and
conversation content are
not copied into deployer state. A failed or interrupted transition is not a
completion claim.

## 3. Dependencies

The package binds four product repositories and this deployer to exact commits:

- `dirextalk-vnext-server` supplies the server binary/image and its fixed
  immutable configuration surface;
- `dirextalk-vnext-client` supplies the client APK and test APK;
- `dirextalk-agent-connector` supplies the outbound Connector binary;
- the Rust Agent Device Sidecar supplies the encrypted conversation data plane
  and its immutable image; and
- this repository supplies the typed deployer commit and lifecycle record.

The host uses the fixed Host Supervisor tuple and the existing local Connector
bootstrap contract. Installation, service start, status/readiness, receipt
observation, and scoped rollback are dependencies of the target workflow; they
are not inferred from a compiled crate or a dry-run plan. Matrix and any
plaintext Agent Control input are outside this contract.

## 4. One happy path

1. On an empty disposable target, validate the schema-3 manifest and verify
   every exact commit, image, APK/test-APK, binary, and config digest.
2. Persist `Planned` with the operation fence and Connector fence, then install
   the exact package and persist `Installed` before the first start effect.
3. Start the fixed services through the closed Host Supervisor path and persist
   `Started` before accepting any readiness result.
4. Independently verify server, client, Connector, and Sidecar readiness and
   persist `ReadinessVerified` with only redacted facts.
5. Run the single internal business scenario (fresh registration, encrypted
   conversation delivery, Connector run lease, runtime report, and client
   acknowledgement) and observe its signed acceptance receipt. Persist
   `AcceptanceObserved` only for that exact target, package digest, Connector
   fence, and operation fence.
6. Seal `Completed` with the receipt digest and final redacted state. If a
   scoped failure occurs, stop at the last durable state and use only the
   target-scoped rollback boundary.

## 5. Executable acceptance

The CLI now has an isolated schema-3 foundation:
`deployment-alpha-validate` verifies the canonical manifest and all
package-local digests, `deployment-alpha-plan` creates the exact `Planned`
record (persisting it only with `--execute`),
`deployment-alpha-advance` admits only the next lifecycle edge and requires
redacted readiness or receipt-observation projections where applicable, and
`deployment-alpha-status` reads the sealed durable record. These admission
commands do not independently perform the external effect or verify a receipt
signature. This path accepts no schema 1/2 input or compatibility fallback.

The existing offline foundation commands documented in `COMMANDS.md` remain
non-Alpha only and must not be used as an Alpha substitute. Running them cannot
establish any schema-3 state or acceptance receipt.

The exact target capabilities that still need implementation are:

- clean exact-commit workspace verification in the schema-3 package preflight;
- install/start through the fixed Host Supervisor, driving the already typed
  `Planned -> Installed -> Started` record edges around the real effects;
- independent four-component readiness collection before admitting the typed
  `ReadinessVerified` evidence;
- independent signed-receipt production/observation for the exact target,
  package, Connector fence, and operation fence before admitting
  `AcceptanceObserved`; and
- target-scoped package, service-state, and test-data rollback under those same
  fences, without restoring or migrating an older schema.

The one target scenario is fresh registration, encrypted conversation delivery,
Connector run-lease execution, runtime report, client acknowledgement, and
observation of that signed receipt. The lifecycle admission commands do not
perform or infer those external effects. A focused test, service process,
foundation command, or manually advanced record alone cannot be reported as
`AcceptanceObserved` or `Completed`.

The acceptance gate is one real fresh-target run that records the exact
manifest/package digest, all six lifecycle transitions, readiness evidence,
and the independently signed receipt. A missing target capability is reported
as missing rather than replaced with a compatibility reader, migration, or
fallback.

## 6. Deferred items

The following remain outside this active gate and cannot block Internal Test
Alpha: registry publication, formal five-component release provenance,
DSSE/SLSA evidence, signing and public distribution, exhaustive crash/restart
matrices, and X6/X7/X8 or other production migration/release gates. Their
historical contracts are retained under
[`references/deferred-production/`](deferred-production/); they are release
work only after this Alpha contract passes.
