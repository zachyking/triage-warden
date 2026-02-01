# Built-in Playbooks

Ready-to-use playbooks included with Triage Warden.

## Email Security

### phishing_triage

Comprehensive phishing email analysis.

**Triggers:** `incident_type: phishing`

**Steps:**
1. Parse email headers and body
2. Check SPF/DKIM/DMARC authentication
3. Look up sender reputation
4. Analyze URLs against threat intel
5. Check attachment hashes
6. AI analysis and verdict
7. Auto-quarantine if malicious (confidence > 0.8)

**Usage:**
```bash
tw-cli playbook run phishing_triage --incident INC-2024-001
```

### spam_triage

Quick spam classification.

**Triggers:** `incident_type: spam`

**Steps:**
1. Parse email
2. Check spam indicators (bulk headers, suspicious patterns)
3. Classify as spam/not spam
4. Auto-archive low-confidence spam

### bec_detection

Business Email Compromise detection.

**Triggers:** `incident_type: bec`

**Steps:**
1. Parse email
2. Check for executive impersonation
3. Analyze reply-to mismatch
4. Check for urgency indicators
5. Verify sender against directory
6. AI analysis for social engineering patterns

## Endpoint Security

### malware_triage

Malware alert analysis.

**Triggers:** `incident_type: malware`

**Steps:**
1. Get host information from EDR
2. Look up file hash
3. Check related processes
4. Query SIEM for lateral movement
5. AI verdict
6. Auto-isolate if critical severity + high confidence

### suspicious_login

Anomalous login investigation.

**Triggers:** `incident_type: suspicious_login`

**Steps:**
1. Get login details
2. Check for impossible travel
3. Query user's recent activity
4. Check IP reputation
5. Verify device fingerprint
6. AI analysis

## Customizing Built-in Playbooks

### Override Variables

```bash
tw-cli playbook run phishing_triage \
  --incident INC-2024-001 \
  --var quarantine_threshold=0.9 \
  --var auto_block=false
```

### Fork and Modify

```bash
# Export built-in playbook
tw-cli playbook export phishing_triage > my_phishing.yaml

# Edit as needed
vim my_phishing.yaml

# Register custom version
tw-cli playbook add my_phishing.yaml
```

### Extend with Hooks

```yaml
# my_phishing.yaml
extends: phishing_triage

# Add steps after parent playbook
after_steps:
  - name: Custom Logging
    action: log_to_siem
    parameters:
      event: phishing_verdict
      data: "{{ verdict }}"

# Override variables
variables:
  quarantine_threshold: 0.85
```

## Playbook Comparison

| Playbook | AI Used | Auto-Response | Typical Duration |
|----------|---------|---------------|------------------|
| phishing_triage | Yes | Quarantine, Block | 30-60s |
| spam_triage | No | Archive | 5-10s |
| bec_detection | Yes | Escalate | 45-90s |
| malware_triage | Yes | Isolate | 60-120s |
| suspicious_login | Yes | Lock account | 30-60s |

## Monitoring Playbooks

### Execution Metrics

```promql
# Playbook execution count
sum by (playbook) (playbook_executions_total)

# Average duration
avg by (playbook) (playbook_duration_seconds)

# Success rate
sum(playbook_executions_total{status="success"}) /
sum(playbook_executions_total)
```

### Alerts

```yaml
# Alert on playbook failures
- alert: PlaybookFailureRate
  expr: |
    sum(rate(playbook_executions_total{status="failed"}[5m])) /
    sum(rate(playbook_executions_total[5m])) > 0.1
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Playbook failure rate above 10%"
```
