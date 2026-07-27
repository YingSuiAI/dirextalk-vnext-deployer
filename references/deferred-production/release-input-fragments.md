Deferred until Internal Test Alpha passes

# Release input fragments

`release-inputs-compose` joins exactly five producer fragments:

```text
cargo run --locked -- release-inputs-compose \
  --fragment server.json --fragment client-android.json \
  --fragment connector.json --fragment agent-device-sidecar.json \
  --fragment deployer.json --output release-inputs
```

Each fragment is canonical, duplicate-key-free JSON with schema
`dirextalk.release-input-fragment`, version `1`, one `release`, and one
`component`. The component has source commit/tree, targets, toolchain, and
the five material roles: `build_recipe`, `artifact`, `sbom`,
`third_party_notice`, and `license`. Every role path is safe-relative to the
fragment parent.

Fragments must share one exact release and cover each required component once.
The composer rejects unknown fields, duplicate targets or paths,
symlink/hardlink aliases, read races, unsafe or empty files, an existing
output, and any failed staged inventory. The published directory contains the
copied fixed role files and canonical `release-inputs.json`; it makes no
signature or cryptographic claim.

This five-component release material is deferred and cannot block Internal
Test Alpha.
