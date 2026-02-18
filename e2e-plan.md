# Triage Warden E2E Testing & Demo Environment Plan

## Goals

- Simulate a realistic SOC environment for full end-to-end testing
- Enable automated and manual validation of incident workflows
- Cover all connector types with real or simulated external services
- Support continuous CI-based and ad hoc test runs
- Serve as a reusable demo instance

---

## Workstreams

### 1. Fake Organization Setup

- [ ] Register domain for fake org (e.g. acmesecops.io)
- [ ] Configure email hosting (e.g. M365 dev account, Zoho, Google Workspace trial)
- [ ] Create user personas and inboxes (5–10 users)
- [ ] Setup DNS for email deliverability (SPF, DKIM, DMARC)

### 2. Infrastructure & Signal Generation

- [ ] Create 2–3 VMs or containers for endpoint simulation
- [ ] Install log sources (e.g. auditd, syslog, Suricata, Osquery)
- [ ] Use Atomic Red Team to simulate TTPs
- [ ] Configure SIEM (e.g. Elastic, Wazuh, or Splunk Free)
- [ ] Send phishing emails using GoPhish or test email scripts

### 3. Connector Validation Setup

- [ ] Configure and test each connector type:
  - [ ] SIEM (Elastic/Splunk)
  - [ ] EDR (Defender ATP, CrowdStrike trial, Osquery)
  - [ ] Threat Intel (VirusTotal, OTX)
  - [ ] Ticketing (Jira free)
  - [ ] Email (M365 or Gmail)
  - [ ] Identity (Azure AD, Okta dev)
  - [ ] Cloud (AWS GuardDuty via free tier)

### 4. Test Harness Development

- [ ] Build alert injection tools (e.g. Python scripts hitting webhook)
- [ ] Define test incident flows and expected outcomes
- [ ] Automate triage validation (verdict, severity, actions)
- [ ] Test guardrails and approval escalation logic
- [ ] Track incidents through full lifecycle

### 5. Deployment and CI Integration

- [ ] Define clean deployment process (Docker Compose / K8s)
- [ ] Create `make e2e` or `scripts/run_e2e_tests.sh`
- [ ] Seed environment with demo org data (playbooks, policies, users)
- [ ] Add GitHub Actions workflow for nightly or pre-release E2E tests
- [ ] Add reset script (`make reset_demo_env`)

### 6. Demo Mode and Documentation

- [ ] Add optional redaction toggle for demo-safe output
- [ ] Document how to launch and test demo org locally
- [ ] Record sample test sessions or demo videos

---

## Optional Extensions

- [ ] Vector DB for internal knowledge/RAG testing
- [ ] Replay engine for historical alert test cases
- [ ] Slack/Teams ChatOps integration for incident notifications
- [ ] AI chat assistant integration for demo interaction

---

## Notes

- Prefer open source and free-tier tooling to minimize cost
- Use separate cloud accounts or sandbox tenants to avoid polluting personal infrastructure
- Design for resettable, reproducible, and isolated test runs


