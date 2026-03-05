# Manual E2E Infrastructure Plan

## Objective

Prepare a persistent, reusable fake-organization environment for manual end-to-end validation with:

- Real external connector credentials
- Real Python triage service with a live LLM provider
- Stable local stack behavior that does not wipe the org between runs

This plan deliberately focuses on infrastructure and environment readiness, not on building a full automated E2E test suite.

## Current Status

### Done

- Review findings from the bootstrap branch are fixed.
- Connector create/update/test paths accept the canonical real-connector config shapes.
- Integration runner supports `--preserve-state` so it no longer destroys a bootstrapped org by default.

### Started In This Round

- Add a dedicated real-mode bootstrap path.
- Add a persistent Docker Compose stack for manual E2E.
- Add env-file and connector-config scaffolding so credentials can be provisioned later in one pass.
- Add preflight validation so real mode fails fast on missing or placeholder config.

## Deliverables Before Account Provisioning

### Phase 1: Local Real-Mode Bootstrap

- [x] Add a persistent compose stack for manual E2E.
- [x] Add `bootstrap-e2e-infra.sh --mode real`.
- [x] Add env-file support for local real-mode bootstrap.
- [x] Add connector-config templating with environment variable substitution.
- [x] Add preflight validation for required LLM and connector environment.

### Phase 2: Operator Scaffolding

- [x] Add example env template for the real manual-E2E stack.
- [x] Add example connector seed config for the supported real connector set.
- [x] Document the provisioning order so external accounts can be created last.

### Phase 3: Remaining Repo Work

- [x] Add an app-supported fake-org persona seeding path for non-admin users.
- [ ] Add a repeatable fake-company content seed set:
  benign mail, phishing mail, IOC fixtures, and baseline incidents.
- [x] Add a readiness/smoke script that checks API health, triage readiness, and connector health after provisioning.
- [x] Add a reset/reseed runbook for shared manual-E2E usage.

## External Provisioning Last

When repo-side preparation is complete, provision these at the same time:

1. Microsoft 365 dev/sandbox tenant
2. Jira Cloud sandbox
3. Splunk sandbox
4. CrowdStrike sandbox or trial
5. VirusTotal API account
6. LLM provider account and key
7. Fake-company domain and DNS records

## Files Added For This Plan

- `deploy/docker/docker-compose.manual-e2e.yml`
- `config/examples/e2e-real.env.example`
- `config/examples/e2e-real-connectors.json`
- `scripts/e2e_real_config.py`
- `scripts/check-e2e-real-readiness.sh`
- `scripts/seed-e2e-personas.sh`
- `scripts/reset-e2e-real.sh`

## Definition Of Ready For Provisioning

Account setup should start only when all of the following are true:

1. `./scripts/bootstrap-e2e-infra.sh --mode real` is ready to consume a filled env file.
2. The local stack persists data across restarts.
3. Real-mode bootstrap fails fast on missing inputs instead of seeding dummy values.
4. The required env vars and connector shapes are documented and versioned in the repo.

## Definition Of Done

Manual real-E2E infrastructure is done when:

1. The real-mode stack boots cleanly with one command.
2. All required real connectors can be seeded from env-backed config.
3. The triage service reports `ready=true`.
4. The fake org can be reset and restored predictably.
5. External account provisioning is the only remaining manual dependency.
