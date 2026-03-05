# E2E Fake Organization (Real Integrations)

This runbook defines how to stand up a high-fidelity E2E environment that uses:

- Real connector credentials
- Real external sandbox tenants
- Real AI triage service with live LLM keys

Use this for pre-release validation and demo-grade testing. For fast local checks,
use the standard integration bootstrap and test scripts.

## Goals

1. Validate end-to-end incident handling against real systems.
2. Ensure AI triage executes through the Python triage service.
3. Catch regressions in connector wiring, authentication, and action execution.

## Prerequisites

### Local Platform

- Docker Desktop / Docker Engine
- Rust toolchain + Python/uv (for local test runners)
- Triage Warden repository checked out

### External Sandbox Tenants

- Identity/email sandbox:
  - Microsoft 365 dev tenant
- Jira cloud project
- VirusTotal API key
- Splunk sandbox endpoint/token
- CrowdStrike sandbox client credentials

## Required Environment Variables

At minimum, provide these through a local env file and point bootstrap at it with
`--env-file`:

- `TW_LLM_PROVIDER`
- `TW_LLM_MODEL`
- `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` (or `TW_LLM_API_KEY`)
- `TW_E2E_ADMIN_PASSWORD`

Common local overrides:

- `TW_E2E_API_PORT`
- `TW_E2E_TRIAGE_PORT`
- `TW_E2E_POSTGRES_PORT`
- `TW_E2E_REDIS_PORT`
- `TW_E2E_QDRANT_HTTP_PORT`

Reference templates:

- `config/examples/e2e-real.env.example`
- `config/examples/e2e-real-connectors.json`
- `manual-e2e-infrastructure-plan.md`

## Bring Up The Core Stack

```bash
./scripts/bootstrap-e2e-infra.sh \
  --mode real \
  --recreate \
  --env-file config/local/e2e-real.env \
  --connector-config config/examples/e2e-real-connectors.json
```

Verify health:

```bash
curl -fsS http://localhost:8081/health
curl -fsS http://localhost:8092/health
curl -fsS http://localhost:8092/api/triage/status
```

The real-mode bootstrap now blocks until `/api/triage/status` reports `ready=true`.

After bootstrap, run the readiness smoke check:

```bash
./scripts/check-e2e-real-readiness.sh --env-file config/local/e2e-real.env
```

Then seed the local fake-organization personas:

```bash
./scripts/seed-e2e-personas.sh --env-file config/local/e2e-real.env
```

For a full reset and reseed of the persistent manual stack:

```bash
./scripts/reset-e2e-real.sh \
  --env-file config/local/e2e-real.env \
  --connector-config config/examples/e2e-real-connectors.json
```

## Configure Real Connectors

The recommended flow is to seed connectors from the env-backed JSON config passed to
`--connector-config`. You can still create connectors through the UI or API if needed.

Supported real connector set:

- `virustotal`
- `jira`
- `splunk`
- `crowdstrike`
- `m365`

After creation, run each connector test endpoint:

`POST /api/connectors/{id}/test`

Real-mode bootstrap rejects missing values and placeholder-like connector inputs such as
`*.example.local`, `dummy`, and `localhost`.

`googleworkspace` is not part of the real E2E connector set yet. The backend only validates credential file structure today and does not perform a live Google API check.

## Fake Company Data Model

Create a repeatable fake org profile:

- Users:
  - `admin`, `analyst_level1`, `analyst_level2`, `incident_manager`, `approver_security`
- Mailboxes:
  - `soc@`, `it-admin@`, `finance@`, `hr@`, `ceo@`, `employee-*`
- Seed content:
  - Benign and phishing email sets
  - Malware IOC alerts
  - Historical incidents for retrieval/correlation tests

Keep user/persona IDs stable across runs so scenario assertions remain deterministic.

## Real AI Triage Verification

When `TW_TRIAGE_SERVICE_URL` is set, the action path delegates to the Python service.
The action also supports action-level override via `triage_service_url` for targeted tests.

Checklist:

1. Triage service status is ready.
2. Representative alerts return only accepted verdicts:
   - `true_positive`
   - `false_positive`
   - `suspicious`
   - `inconclusive`
3. Scenario logs confirm triage service usage and no fallback-only execution.

## Scenario Execution

Run baseline integration suites first:

```bash
./scripts/run-integration-tests.sh --preserve-state
```

Then run fake-org scenarios (recommended structure):

- `tests/e2e/scenarios/phishing-obvious.yaml`
- `tests/e2e/scenarios/phishing-bec.yaml`
- `tests/e2e/scenarios/malware-hash.yaml`
- `tests/e2e/scenarios/benign-false-positive.yaml`

Each scenario should assert:

- Incident creation
- Triage verdict envelope
- Connector side effects (ticket creation, intel lookups, etc.)
- Approval/action transitions where applicable

## Operational Guardrails

- Use dedicated sandbox tenants only.
- Rotate all sandbox API credentials on a schedule.
- Fail fast when required env vars are missing.
- Archive scenario artifacts for failed runs (API logs, triage logs, connector responses).

## Recommended Promotion Path

1. PR checks: fast local integration tests.
2. Merge gate: real-infra smoke scenarios.
3. Nightly: extended real-infra scenario set.

This gives quick feedback on normal development while still validating real-world integrations.
