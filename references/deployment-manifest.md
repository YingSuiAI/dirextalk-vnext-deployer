# Deployment manifest v1 (offline foundation)

`deployment.example.json` is a separate strict contract from release manifest v1.
It names immutable server and Connector artifacts by version plus SHA-256 digest,
and binds each logical target to one HTTPS origin, role, and exact host tuple.
It contains no credentials, paths, commands, environment, or mutable tags.

Host `owner_id` is the stable product IdentityId (`dtxi1` followed by exactly
52 lowercase base32 characters), not a UUID. Tenant, Host, Host credential,
Connector, and operation IDs remain canonical UUIDv7 values.

The default node process is one closed `node` service (identity, group, mailbox,
public feed/discussion, and Indexer routes); `agent_control` is separate for
Connector acceptance. Host Supervisor is Connector-host-only. Production host
evidence is fixed at `/etc/dirextalk/host-supervisor/host.json`.

The concrete X3/X4/X5 host/Connector topology is external configuration: the
manifest only records node origins and named logical bindings. This foundation
does not accept or activate any physical topology.

`deployment-validate` and `deployment-plan` are offline. `deployment-status`
only reads the fixed root-owned `/var/lib/dirextalk-vnext-deployer` directory on
Unix and
fails as unsupported on other platforms. Validation and planning remain
cross-platform. The sole execution path is the closed local Connector-host
lifecycle described in `COMMANDS.md`; there is no remote transport, production
migrator, provider activation, or remote Connector enrollment implementation.

Durable records are strict Unix-only JSON. Exact target plus host ownership is
fenced independently of operation UUID, successor handoff names the current
terminal predecessor, and superseded operations cannot mutate state. Connector
claim evidence is retained per operation. A continuous Connector upgrade names
the exact released Connector owner independently of the parent predecessor; a
first introduction or reintroduction after an immediate manifest gap has no
Connector predecessor while older history remains retained. This evidence does
not imply remote enrollment. Writes use bounded serialization,
0600 no-follow temporary files, sync, atomic replacement, and parent-directory
sync. Malformed or symlinked state fails closed. A completed operation can only
fence a service restore; migrations and historical records are never reversed or
deleted.
