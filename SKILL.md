---
name: dirextalk-vnext-deployer
description: Orchestrate typed Dirextalk RootKey onboarding, EC2 lifecycle, App binding, verification, rotation, and scoped destruction commands.
---

# Dirextalk vNext deployer

Use this project Skill to guide a user through the typed CLI. Do not
reimplement the deployment in shell and do not substitute the legacy
`dirextalk-connect` deployer.

Read
[`references/rootkey-onboarding-alpha.md`](references/rootkey-onboarding-alpha.md)
before onboarding, resuming, binding, rotating credentials, or
destroying a deployment.

## RootKey rules

- Ask the App/runtime for the absolute local path selected by the user.
- Pass only that path to `--aws-rootkey-csv`.
- Never read, print, summarize, copy, upload, source, or parse the CSV in the
  agent/model layer.
- Never place credential values in a command, environment variable,
  configuration, state, log, message, QR payload, or artifact.
- Run `deploy credentials identify` first and show only its redacted STS
  account/principal result.
- Require the user to review the account, region, resources, cost ceiling, and
  RootKey warning before adding `--execute`.
- Require a freshly selected valid CSV for every resume, verify,
  rotation check, or destruction.

## Onboarding sequence

1. Validate that the configuration is non-secret and selects EC2 plus an
   existing Route53 hostname.
2. Run `deploy onboard` without `--execute` and present the plan.
3. Run the same command with `--execute` only after explicit confirmation.
4. If interrupted, use `deploy status` and then `deploy resume`; never create a
   second deployment for the same durable operation.
5. Run `deploy verify`.
6. Run `deploy binding issue --execute`, present the canonical QR/file to the
   user, and wait for `consumed/ready`. Use `--no-wait` only when a separate
   status loop is intentional.
7. Remind the user to create a different AWS key, verify it with
   `deploy credentials verify-rotation`, and deactivate/delete the old key in
   AWS.

Do not offer `deploy update` as a general release updater. In this Alpha it is
limited to the separately authenticated historical 0.1.1-to-0.1.4 repair.

## Safety

- EC2 is the only deployable provider in this Alpha. Lightsail catalog output
  is discovery evidence, not deployment support.
- Do not buy a domain, change nameservers, overwrite an occupied record, or
  accept an external DNS provider.
- Do not accept arbitrary remote commands, scripts, paths, or environment
  variables.
- Treat `destroy` as two explicit operations: infrastructure removal, then
  volume purge with the exact reviewed volume ID.
- Stop on account, region, tag, operation, resource identity, or DNS-value
  mismatch.
- Never describe a dry run, local test, catalog query, or issued-but-unconsumed
  ticket as a completed deployment.

Release assembly/publication remains a separate workflow. It does not grant
authority to mutate AWS resources and is not App binding evidence.
