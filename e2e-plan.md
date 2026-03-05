# E2E Infrastructure Plan (Real Connectors + Real AI Triage)

## Objective

Build an end-to-end environment that behaves like a small real company:

- Real user identities and mailboxes
- Real connector integrations (no mocked connector responses)
- Real AI triage service using live LLM provider credentials
- Repeatable execution for manual validation and automated regression checks

The existing local bootstrap remains useful for fast integration tests, but this
plan targets a higher-fidelity "fake organization" environment.

## Scope And Non-Goals

### In Scope

- Dedicated fake-org identity/email tenant
- Connector onboarding for real external systems
- Real AI triage (`TW_TRIAGE_SERVICE_URL` + live provider keys)
- Repeatable scenario execution and assertions
- Documentation and runbooks for team reuse

### Out Of Scope

- Production hardening for customer data
- High-availability topology
- Long-term SIEM/EDR retention strategy

## Success Criteria

Environment is complete only when all conditions are true:

1. Triage Warden receives alerts from external systems with real credentials.
2. AI triage runs through the Python triage service and returns valid verdicts:
   `true_positive`, `false_positive`, `suspicious`, `inconclusive`.
3. No connector test path relies on mock credentials or fake hostnames.
4. At least 10 deterministic E2E scenarios run in CI/nightly and are reproducible locally.
5. Incident lifecycle is validated end-to-end: ingest -> triage -> actions -> ticket -> closure.

## Target Architecture

### Core Platform (Self-Hosted)

- `tw-api`
- `tw-triage-service` (Python FastAPI)
- PostgreSQL
- Redis
- Qdrant

### Fake Company Control Plane (External/Sandbox)

- Email and identity tenant:
  - Microsoft 365 dev tenant
- Ticketing:
  - Jira cloud sandbox project
- Threat intel:
  - VirusTotal API key
- SIEM:
  - Splunk cloud/free or equivalent reachable endpoint
- EDR:
  - CrowdStrike sandbox tenant (or alternate supported tenant)

## Fake Organization Blueprint

### Domain And Mail

- Domain: `tw-fakeco.example` (or dedicated subdomain)
- DNS: SPF, DKIM, DMARC configured
- Mailboxes:
  - `soc@...` (security operations)
  - `it-admin@...`
  - `finance@...`
  - `hr@...`
  - `ceo@...`
  - `employee-*` test inboxes

### Users And Roles

- `admin` (platform admin)
- `analyst_level1`, `analyst_level2`
- `incident_manager`
- `approver_security`
- `end_user_*` personas for phishing simulation

### Baseline Dataset

- 50+ baseline benign emails
- 25 phishing samples (mixed sophistication)
- 15 malware/IOC alert fixtures
- 10 historical incidents to test similarity/RAG flows

## Real Connector Matrix

| Connector | Real Target | Required Credential | Validation Signal |
|---|---|---|---|
| `virustotal` | VirusTotal API | API key | Known hash lookup |
| `jira` | Jira cloud project | URL, email, API token, project key | Ticket create/update |
| `splunk` | Splunk endpoint | URL, token, index | Query + alert retrieval |
| `crowdstrike` | CrowdStrike tenant | client ID/secret | Host/detection lookup |
| `m365` | M365 tenant | tenant ID, client ID/secret | User/email operation |

## Real AI Triage Requirements

### Service Wiring

- `TW_TRIAGE_SERVICE_URL` set in API environment
- Optional action-level override via `triage_service_url` remains supported for targeted tests

### LLM Configuration

- One of:
  - `TW_LLM_PROVIDER=openai` + `OPENAI_API_KEY` (or `TW_LLM_API_KEY`)
  - `TW_LLM_PROVIDER=anthropic` + `ANTHROPIC_API_KEY` (or `TW_LLM_API_KEY`)
- Service status check:
  - `GET /api/triage/status` returns `ready=true`

### Guardrails For "No Mock" Requirement

- Reject placeholder connector values (`*.example.local`, `*_dummy_*`) in real mode.
- Include preflight checks that fail if provider keys are missing.
- Record `analyzed_by` and assert triage source is `react-agent` in scenario verification.

## Delivery Phases

### Phase 0: Foundation (Done/Existing)

- Docker-based integration stack
- Bootstrap and integration scripts
- Triage service integration path in actions

### Phase 1: Fake Company Provisioning

- Acquire domain + DNS
- Provision identity/email sandbox
- Create personas and groups
- Create mailbox seeding scripts

Exit criteria:

- All fake users can authenticate where required.
- Email routing works for inbound and outbound test messages.

### Phase 2: Real Connector Onboarding

- Configure each connector with sandbox credentials
- Execute `/api/connectors/{id}/test` for each
- Save minimal verification artifacts (request IDs, ticket IDs)

Exit criteria:

- Every required connector is healthy and has one successful real operation.

### Phase 3: Real AI Triage Enablement

- Deploy triage service with live LLM credentials
- Validate triage status endpoint
- Run representative phishing/malware triage flows

Exit criteria:

- 100% of scenario triage calls reach the Python service successfully.

### Phase 4: Scenario Harness

- Build deterministic scenario catalog:
  - obvious phishing
  - BEC style phishing
  - benign false-positive
  - malware hash alert
  - suspicious but inconclusive case
- Define assertions on verdict, severity, required actions, approval paths

Exit criteria:

- Scenario suite runs locally and in CI with stable results.

### Phase 5: Automation And Reporting

- Nightly E2E workflow
- Failure artifact capture (API logs, triage logs, connector responses)
- Summary report with pass/fail and regression diffs

Exit criteria:

- One-click nightly run with actionable output.

## Immediate Implementation Backlog

- [ ] Add `real` mode to bootstrap (`--mode baseline|real`)
- [ ] Add connector seed config input file for non-dummy credentials
- [ ] Add fake-org user seed script (tenants/users/roles)
- [ ] Add preflight validator script for required real-mode secrets
- [ ] Add scenario manifest (`tests/e2e/scenarios/*.yaml`)
- [ ] Add scenario runner with result JSON + junit output
- [ ] Add CI job for nightly real-infra smoke scenarios
- [ ] Add runbook for credential rotation and tenant reset

## Risks And Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Expired sandbox credentials | test outage | secret age checks + rotation cadence |
| SaaS API rate limits | flaky tests | throttle, retries, smaller nightly set |
| LLM variability | nondeterministic assertions | assert envelope/ranges, not exact text |
| Connector API changes | sudden regressions | smoke checks before full suite |
| Tenant data drift | false failures | scripted reset and reseed |

## Execution Notes

- Use dedicated non-production tenants only.
- Keep baseline mock-like integration tests for fast PR checks.
- Treat real-infra E2E as gated smoke + nightly regression layer.
- Defer Google Workspace live E2E coverage until a real connector implementation exists.
