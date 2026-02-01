# Stage 10: Infrastructure Completion Plan

## Overview

Complete the infrastructure gaps identified in the review: bridge connector selection, action handlers, policy engine integration, missing bridges, metrics export, and test coverage. These tasks have limited dependencies and can be highly parallelized.

## Success Criteria
- [ ] Bridges can use real connectors (VirusTotal, Splunk, CrowdStrike, Jira, M365) based on configuration
- [ ] All 13 missing action handlers implemented
- [ ] Policy engine integrated into incident action execution
- [ ] TicketingBridge and EmailGatewayBridge expose Jira/M365 to Python
- [ ] Prometheus metrics endpoint returns real metrics
- [ ] Test cases cover suspicious/inconclusive verdicts (20+ total cases)

## Architecture Notes

**Connector Selection Pattern**: Bridges should read from environment variables (e.g., `TW_THREAT_INTEL_MODE=virustotal`) to select real vs mock connectors.

**Action Handler Pattern**: Actions implement the `ActionHandler` trait with `execute()` and `rollback()` methods in tw-actions crate.

**Policy Integration**: `PolicyEngine` from tw-policy evaluates `ActionContext` and returns `PolicyDecision` (Allowed/Denied/RequiresApproval).

---

## Stage 1: Foundation Updates (No Dependencies)
**Parallel capacity: 6 developers**
**Blocking:** Nothing
**Unlocks:** Stages 2, 3

### Task 1.1: Add Connector Type Selection to ThreatIntelBridge
**Estimated complexity:** M

**Description:**
Update `ThreatIntelBridge` in `tw-bridge/src/lib.rs` to support selecting between mock and VirusTotal connectors based on the `TW_THREAT_INTEL_MODE` environment variable.

**Context:**
- File: `tw-bridge/src/lib.rs` (ThreatIntelBridge struct around line 200)
- VirusTotalConnector exists at `crates/tw-connectors/src/threat_intel/virustotal.rs`
- Current code always creates MockThreatIntelConnector

**Acceptance Criteria:**
- [ ] `ThreatIntelBridge::new(mode)` accepts "mock" or "virustotal" mode
- [ ] When mode="virustotal", creates VirusTotalConnector with API key from `TW_VIRUSTOTAL_API_KEY` env
- [ ] When mode="mock" or unset, creates MockThreatIntelConnector (backward compatible)
- [ ] Health check reflects actual connector status
- [ ] Unit test verifies connector selection

**Interface:**
- Inputs: `mode: &str` parameter
- Outputs: Bridge with appropriate connector instance

---

### Task 1.2: Add Connector Type Selection to SIEMBridge
**Estimated complexity:** M

**Description:**
Update `SIEMBridge` in `tw-bridge/src/lib.rs` to support selecting between mock and Splunk connectors.

**Context:**
- File: `tw-bridge/src/lib.rs` (SIEMBridge struct)
- SplunkConnector exists at `crates/tw-connectors/src/siem/splunk.rs`
- Requires `TW_SPLUNK_URL`, `TW_SPLUNK_TOKEN` env vars

**Acceptance Criteria:**
- [ ] `SIEMBridge::new(mode)` accepts "mock" or "splunk" mode
- [ ] When mode="splunk", creates SplunkConnector with URL/token from env
- [ ] When mode="mock" or unset, creates MockSIEMConnector
- [ ] Error handling for missing configuration
- [ ] Unit test verifies connector selection

---

### Task 1.3: Add Connector Type Selection to EDRBridge
**Estimated complexity:** M

**Description:**
Update `EDRBridge` in `tw-bridge/src/lib.rs` to support selecting between mock and CrowdStrike connectors.

**Context:**
- File: `tw-bridge/src/lib.rs` (EDRBridge struct)
- CrowdStrikeConnector exists at `crates/tw-connectors/src/edr/crowdstrike.rs`
- Requires `TW_CROWDSTRIKE_CLIENT_ID`, `TW_CROWDSTRIKE_CLIENT_SECRET`, `TW_CROWDSTRIKE_REGION` env vars

**Acceptance Criteria:**
- [ ] `EDRBridge::new(mode)` accepts "mock" or "crowdstrike" mode
- [ ] When mode="crowdstrike", creates CrowdStrikeConnector with credentials from env
- [ ] When mode="mock" or unset, creates MockEDRConnector
- [ ] OAuth2 token refresh handled internally
- [ ] Unit test verifies connector selection

---

### Task 1.4: Create TicketingBridge PyO3 Binding
**Estimated complexity:** L

**Description:**
Create a new `TicketingBridge` in `tw-bridge/src/lib.rs` that exposes the Jira connector to Python.

**Context:**
- JiraConnector exists at `crates/tw-connectors/src/ticketing/jira.rs`
- MockTicketingConnector exists at `crates/tw-connectors/src/ticketing/mock.rs`
- Follow the pattern of existing bridges (ThreatIntelBridge, SIEMBridge, EDRBridge)

**Acceptance Criteria:**
- [ ] `TicketingBridge` struct with `#[pyclass]` attribute
- [ ] `new(mode)` method accepting "mock" or "jira"
- [ ] Methods: `create_ticket()`, `get_ticket()`, `update_ticket()`, `add_comment()`, `search_tickets()`
- [ ] All methods return Python-compatible dicts via `pythonize`
- [ ] Registered in PyO3 module
- [ ] Unit tests for mock mode

**Interface:**
- Inputs: Ticket data as Python dicts
- Outputs: Ticket objects/results as Python dicts

---

### Task 1.5: Create EmailGatewayBridge PyO3 Binding
**Estimated complexity:** L

**Description:**
Create a new `EmailGatewayBridge` in `tw-bridge/src/lib.rs` that exposes the M365 connector to Python.

**Context:**
- M365Connector exists at `crates/tw-connectors/src/email/m365.rs`
- Need MockEmailGatewayConnector if it doesn't exist
- Follow the pattern of existing bridges

**Acceptance Criteria:**
- [ ] `EmailGatewayBridge` struct with `#[pyclass]` attribute
- [ ] `new(mode)` method accepting "mock" or "m365"
- [ ] Methods: `search_emails()`, `get_email()`, `quarantine_email()`, `release_email()`, `block_sender()`, `unblock_sender()`
- [ ] OAuth2 authentication for M365 Graph API
- [ ] Registered in PyO3 module
- [ ] Unit tests for mock mode

---

### Task 1.6: Integrate PolicyEngine into AppState
**Estimated complexity:** S

**Description:**
Add `PolicyEngine` to the API server's `AppState` and initialize it on startup.

**Context:**
- File: `crates/tw-api/src/state.rs`
- PolicyEngine exists in `crates/tw-policy/src/engine.rs`
- Already a dependency in tw-api's Cargo.toml

**Acceptance Criteria:**
- [ ] `AppState` struct includes `policy_engine: Arc<PolicyEngine>` field
- [ ] `AppState::new()` initializes PolicyEngine with default rules
- [ ] Policy rules loaded from config file or defaults
- [ ] Server startup logs policy engine initialization
- [ ] Existing routes continue to work

---

## Stage 2: Core Implementation (Depends on Stage 1)
**Parallel capacity: 5 developers**
**Blocking:** Stage 1 (Task 1.6 for 2.1)
**Unlocks:** Stage 3

### Task 2.1: Implement Policy Engine Evaluation in execute_action
**Estimated complexity:** M

**Description:**
Replace the TODO at `incidents.rs:183` with actual policy engine evaluation.

**Context:**
- File: `crates/tw-api/src/routes/incidents.rs` (line 183)
- PolicyEngine.evaluate() returns PolicyDecision (Allowed/Denied/RequiresApproval)
- Need to build ActionContext from request data

**Acceptance Criteria:**
- [ ] Build `ActionContext` from request (action_type, target, severity, confidence, proposer)
- [ ] Call `policy_engine.evaluate(&context)`
- [ ] Handle `PolicyDecision::Allowed` → AutoApproved status
- [ ] Handle `PolicyDecision::Denied` → Return 403 with reason
- [ ] Handle `PolicyDecision::RequiresApproval` → Pending status with approval level
- [ ] Log policy decisions for audit
- [ ] Unit tests for each decision path

---

### Task 2.2: Implement Prometheus Metrics Export
**Estimated complexity:** M

**Description:**
Replace the placeholder `/metrics` endpoint with actual Prometheus metrics using `metrics-exporter-prometheus`.

**Context:**
- File: `crates/tw-api/src/routes/metrics.rs`
- Dependencies already in Cargo.toml: `metrics`, `metrics-exporter-prometheus`
- Current endpoint returns hardcoded placeholder data

**Acceptance Criteria:**
- [ ] Initialize PrometheusBuilder on server startup
- [ ] Register metrics: `triage_warden_incidents_total`, `triage_warden_actions_total`, etc.
- [ ] `/metrics` endpoint returns prometheus text format
- [ ] Metrics include labels (severity, status, action_type)
- [ ] Connect to MetricsCollector in tw-observability
- [ ] Integration test verifies metrics format

---

### Task 2.3: Implement Email Action Handlers (parse_email, check_email_authentication)
**Estimated complexity:** M

**Description:**
Implement the email-related action handlers in `tw-actions` crate.

**Context:**
- Directory: `crates/tw-actions/src/`
- Follow pattern of existing handlers (create_ticket.rs, isolate_host.rs)
- These are analysis actions, not response actions

**Acceptance Criteria:**
- [ ] `parse_email` handler: Extracts headers, body, attachments, URLs from raw email
- [ ] `check_email_authentication` handler: Validates SPF, DKIM, DMARC
- [ ] Both implement `ActionHandler` trait
- [ ] Registered in ActionRegistry
- [ ] Unit tests with sample email data

---

### Task 2.4: Implement Lookup Action Handlers (lookup_sender_reputation, lookup_urls, lookup_attachments)
**Estimated complexity:** M

**Description:**
Implement the lookup/enrichment action handlers that query external services.

**Context:**
- Directory: `crates/tw-actions/src/`
- These use ThreatIntel connector for lookups
- Should support both sync execution and async background

**Acceptance Criteria:**
- [ ] `lookup_sender_reputation` handler: Queries sender domain/IP reputation
- [ ] `lookup_urls` handler: Checks URLs against threat intel
- [ ] `lookup_attachments` handler: Hashes attachments and checks against threat intel
- [ ] All use ThreatIntelConnector dependency injection
- [ ] Caching for repeated lookups
- [ ] Unit tests with mock connector

---

### Task 2.5: Implement Response Action Handlers (quarantine_email, block_sender, notify_user)
**Estimated complexity:** M

**Description:**
Implement the email response action handlers that take containment actions.

**Context:**
- Directory: `crates/tw-actions/src/`
- These use EmailGateway connector (M365)
- Need rollback support (release_email, unblock_sender)

**Acceptance Criteria:**
- [ ] `quarantine_email` handler: Moves email to quarantine via EmailGateway
- [ ] `block_sender` handler: Adds sender to blocklist
- [ ] `notify_user` handler: Sends notification email to affected user
- [ ] All support rollback operations
- [ ] Registered in ActionRegistry
- [ ] Unit tests with mock connector

---

## Stage 3: Integration & Polish (Depends on Stages 1, 2)
**Parallel capacity: 4 developers**
**Blocking:** Stage 2
**Unlocks:** Complete

### Task 3.1: Implement Remaining Action Handlers
**Estimated complexity:** M

**Description:**
Implement the remaining action handlers: run_triage_agent, log_false_positive, notify_reporter, escalate.

**Context:**
- `run_triage_agent`: Triggers AI triage workflow
- `log_false_positive`: Records FP for tuning
- `notify_reporter`: Sends status update to original reporter
- `escalate`: Routes to appropriate approval level

**Acceptance Criteria:**
- [ ] All four handlers implemented
- [ ] Integration with existing notification system
- [ ] Escalation integrates with policy engine approval levels
- [ ] Unit tests for each handler

---

### Task 3.2: Add Suspicious/Inconclusive Test Cases
**Estimated complexity:** S

**Description:**
Expand test case coverage to include suspicious and inconclusive verdicts.

**Context:**
- Directory: `python/tw_ai/evaluation/test_cases/`
- Currently 10 cases (5 malicious, 5 benign)
- Need cases for edge scenarios

**Acceptance Criteria:**
- [ ] Add 5+ suspicious verdict test cases (ambiguous signals, requires investigation)
- [ ] Add 5+ inconclusive verdict test cases (insufficient data, conflicting indicators)
- [ ] Cover phishing, malware, and login categories
- [ ] Include medium severity cases
- [ ] Total test cases ≥ 20
- [ ] All tests pass with evaluation runner

---

### Task 3.3: Connect Python Tools to New Bridges
**Estimated complexity:** S

**Description:**
Update Python tools in `tw_ai/agents/tools.py` to use the new TicketingBridge and EmailGatewayBridge.

**Context:**
- File: `python/tw_ai/agents/tools.py`
- Current `create_security_ticket` uses legacy mock
- Current email actions have no backend

**Acceptance Criteria:**
- [ ] `create_security_ticket` uses TicketingBridge
- [ ] `quarantine_email` uses EmailGatewayBridge
- [ ] `block_sender` uses EmailGatewayBridge
- [ ] Graceful fallback to mock if bridge unavailable
- [ ] Update environment variable documentation

---

### Task 3.4: Python-Rust Metrics Bridge
**Estimated complexity:** M

**Description:**
Create a bridge to export Python metrics to the Rust Prometheus endpoint.

**Context:**
- Python: `python/tw_ai/metrics/collector.py`
- Rust: `crates/tw-observability/src/metrics.rs`
- Currently independent, no correlation

**Acceptance Criteria:**
- [ ] Python MetricsCollector can push to Rust via bridge or HTTP
- [ ] Rust aggregates Python + Rust metrics
- [ ] Single `/metrics` endpoint shows unified metrics
- [ ] Correlation IDs link Python operations to Rust

---

## Dependency Graph

```
Stage 1 (parallel):
  1.1 ThreatIntelBridge ─┐
  1.2 SIEMBridge ────────┤
  1.3 EDRBridge ─────────┼─→ Stage 2.2, 2.3, 2.4, 2.5
  1.4 TicketingBridge ───┤
  1.5 EmailGatewayBridge ┘
  1.6 PolicyEngine AppState ─→ Stage 2.1

Stage 2 (parallel):
  2.1 Policy Evaluation ─────┐
  2.2 Prometheus Export ─────┼─→ Stage 3.4
  2.3 Email Handlers ────────┤
  2.4 Lookup Handlers ───────┼─→ Stage 3.1
  2.5 Response Handlers ─────┘

Stage 3 (parallel):
  3.1 Remaining Handlers
  3.2 Test Cases
  3.3 Python Tool Updates
  3.4 Metrics Bridge
```

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| M365 OAuth complexity | M | Use existing oauth2 crate patterns from CrowdStrike |
| Rate limiting on real APIs | M | Implement circuit breakers, use mock for CI |
| Policy engine performance | L | Cache policy decisions, benchmark |
| Test case design subjectivity | L | Document clear criteria for each verdict |

## Verification

```bash
# Stage 1 verification
TW_THREAT_INTEL_MODE=virustotal cargo test -p tw-bridge
TW_SIEM_MODE=splunk cargo test -p tw-bridge

# Stage 2 verification
curl http://localhost:8080/metrics | grep triage_warden
cargo test -p tw-actions

# Stage 3 verification
cd python && uv run pytest tests/test_evaluation.py
```

---

## Plan Summary

**Project:** Stage 10 Infrastructure Completion
**Total stages:** 3
**Maximum parallelization:** 6 developers (Stage 1)
**Critical path:** Stage 1 → Stage 2 → Stage 3

**Stage breakdown:**
- Stage 1: 6 parallel tasks - Bridge connector selection, new bridges, policy state
- Stage 2: 5 parallel tasks - Policy integration, metrics, action handlers
- Stage 3: 4 parallel tasks - Remaining handlers, tests, tool updates, metrics bridge

**Total tasks:** 15
**Estimated complexity:** 3 Small, 9 Medium, 3 Large
