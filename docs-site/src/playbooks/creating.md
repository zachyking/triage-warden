# Creating Playbooks

Guide to writing custom playbooks for your security workflows.

## Getting Started

### 1. Create Playbook File

```bash
mkdir -p playbooks
touch playbooks/my_playbook.yaml
```

### 2. Define Basic Structure

```yaml
name: my_playbook
description: Description of what this playbook does
version: "1.0"

triggers:
  incident_type: phishing
  auto_run: true

steps:
  - name: First Step
    action: parse_email
    output: result
```

### 3. Register Playbook

```bash
tw-cli playbook add playbooks/my_playbook.yaml
```

## Step Types

### Action Step

Execute a registered action:

```yaml
- name: Parse Email Content
  action: parse_email
  parameters:
    raw_email: "{{ incident.raw_data.raw_email }}"
  output: parsed
  on_error: continue  # or "fail" (default)
```

### Condition Step

Branch based on conditions:

```yaml
- name: Check if High Risk
  condition: "{{ sender_rep.score < 0.3 }}"
  then:
    - action: quarantine_email
      parameters:
        message_id: "{{ incident.raw_data.message_id }}"
  else:
    - action: log_event
      parameters:
        message: "Low risk, no action needed"
```

### AI Analysis Step

Get AI verdict:

```yaml
- name: AI Analysis
  type: ai_analysis
  model: claude-sonnet-4-20250514
  context:
    - parsed
    - auth_results
    - reputation
  prompt: |
    Analyze this email for phishing indicators.
    Consider the authentication results and sender reputation.
  output: ai_verdict
```

### Notification Step

Send alerts:

```yaml
- name: Alert Team
  action: notify_channel
  parameters:
    channel: slack
    message: |
      New {{ incident.severity }} incident detected
      ID: {{ incident.id }}
      Type: {{ incident.incident_type }}
```

## Error Handling

### Per-Step Error Handling

```yaml
- name: Check Reputation
  action: lookup_sender_reputation
  parameters:
    sender: "{{ parsed.sender }}"
  output: reputation
  on_error: continue  # Don't fail playbook if this fails
  default_output:     # Use this if step fails
    score: 0.5
    risk_level: "unknown"
```

### Global Error Handler

```yaml
on_error:
  - action: notify_channel
    parameters:
      channel: slack
      message: "Playbook {{ playbook.name }} failed: {{ error.message }}"
  - action: escalate
    parameters:
      level: analyst
      reason: "Automated triage failed"
```

## Variables and Templates

### Define Variables

```yaml
variables:
  high_risk_threshold: 0.3
  quarantine_enabled: true
  notification_channel: "#security-alerts"
```

### Use Variables

```yaml
- name: Check Risk
  condition: "{{ sender_rep.score < variables.high_risk_threshold }}"
  then:
    - action: quarantine_email
      condition: "{{ variables.quarantine_enabled }}"
```

### Template Functions

```yaml
parameters:
  # String manipulation
  domain: "{{ parsed.sender | split('@') | last }}"

  # Conditionals
  priority: "{{ 'critical' if incident.severity == 'critical' else 'high' }}"

  # Lists
  all_urls: "{{ parsed.urls | join(', ') }}"
  url_count: "{{ parsed.urls | length }}"

  # Defaults
  assignee: "{{ incident.assignee | default('unassigned') }}"
```

## Testing Playbooks

### Dry Run

```bash
tw-cli playbook test my_playbook \
  --incident INC-2024-001 \
  --dry-run
```

### With Mock Data

```bash
tw-cli playbook test my_playbook \
  --data '{"raw_email": "From: test@example.com..."}'
```

### Validate Syntax

```bash
tw-cli playbook validate playbooks/my_playbook.yaml
```

## Best Practices

### 1. Use Descriptive Names

```yaml
# Good
- name: Check sender domain reputation

# Bad
- name: step1
```

### 2. Handle Failures Gracefully

```yaml
- name: External Lookup
  action: lookup_sender_reputation
  on_error: continue
  default_output:
    score: 0.5
```

### 3. Add Timeouts

```yaml
- name: Slow External API
  action: custom_lookup
  timeout: 30s
```

### 4. Log Key Decisions

```yaml
- name: Log Verdict
  action: log_event
  parameters:
    level: info
    message: "Verdict: {{ verdict.classification }} ({{ verdict.confidence }})"
```

### 5. Version Your Playbooks

```yaml
name: phishing_triage
version: "2.1.0"
changelog:
  - "2.1.0: Added attachment analysis"
  - "2.0.0: Restructured for parallel lookups"
```

## Example: Complete Playbook

```yaml
name: comprehensive_phishing_triage
description: Full phishing email analysis with all checks
version: "2.0"

triggers:
  incident_type: phishing
  auto_run: true

variables:
  quarantine_threshold: 0.3
  block_threshold: 0.2

steps:
  # Parse email
  - name: Parse Email
    action: parse_email
    parameters:
      raw_email: "{{ incident.raw_data.raw_email }}"
    output: parsed

  # Parallel enrichment
  - name: Enrich Data
    parallel:
      - action: check_email_authentication
        parameters:
          headers: "{{ parsed.headers }}"
        output: auth

      - action: lookup_sender_reputation
        parameters:
          sender: "{{ parsed.sender }}"
        output: sender_rep

      - action: lookup_urls
        parameters:
          urls: "{{ parsed.urls }}"
        output: urls
        condition: "{{ parsed.urls | length > 0 }}"

      - action: lookup_attachments
        parameters:
          attachments: "{{ parsed.attachments }}"
        output: attachments
        condition: "{{ parsed.attachments | length > 0 }}"

  # AI Analysis
  - name: AI Verdict
    type: ai_analysis
    model: claude-sonnet-4-20250514
    context: [parsed, auth, sender_rep, urls, attachments]
    output: verdict

  # Response actions
  - name: Quarantine Malicious
    action: quarantine_email
    parameters:
      message_id: "{{ incident.raw_data.message_id }}"
    condition: >
      verdict.classification == 'malicious' and
      verdict.confidence >= variables.quarantine_threshold

  - name: Block Repeat Offender
    action: block_sender
    parameters:
      sender: "{{ parsed.sender }}"
    condition: >
      sender_rep.score < variables.block_threshold

  - name: Create Ticket
    action: create_ticket
    parameters:
      title: "{{ verdict.classification | title }}: {{ parsed.subject | truncate(50) }}"
      priority: "{{ incident.severity }}"
    condition: "{{ verdict.classification != 'benign' }}"

on_error:
  - action: escalate
    parameters:
      level: analyst
      reason: "Playbook execution failed"
```
