# Playbooks

Playbooks define automated investigation and response workflows.

## Overview

A playbook is a sequence of steps that:
1. Gather and analyze incident data
2. Enrich with threat intelligence
3. Determine verdict and response
4. Execute approved actions

## Playbook Structure

```yaml
name: phishing_triage
description: Automated phishing email analysis
version: "1.0"

# When this playbook applies
triggers:
  incident_type: phishing
  auto_run: true

# Variables available to steps
variables:
  quarantine_threshold: 0.7
  block_threshold: 0.3

# Execution steps
steps:
  - name: Parse Email
    action: parse_email
    parameters:
      raw_email: "{{ incident.raw_data.raw_email }}"
    output: parsed

  - name: Check Authentication
    action: check_email_authentication
    parameters:
      headers: "{{ parsed.headers }}"
    output: auth

  - name: Check Sender
    action: lookup_sender_reputation
    parameters:
      sender: "{{ parsed.sender }}"
    output: sender_rep

  - name: Check URLs
    action: lookup_urls
    parameters:
      urls: "{{ parsed.urls }}"
    output: url_results
    condition: "{{ parsed.urls | length > 0 }}"

  - name: Quarantine if Malicious
    action: quarantine_email
    parameters:
      message_id: "{{ incident.raw_data.message_id }}"
      reason: "Automated quarantine - phishing detected"
    condition: >
      sender_rep.score < variables.quarantine_threshold or
      url_results.malicious_count > 0 or
      not auth.authentication_passed

# Final verdict generation
verdict:
  use_ai: true
  model: claude-sonnet-4-20250514
  context:
    - parsed
    - auth
    - sender_rep
    - url_results
```

## Triggers

Define when a playbook runs:

```yaml
triggers:
  # Run for specific incident types
  incident_type: phishing

  # Auto-run on incident creation
  auto_run: true

  # Or require manual trigger
  auto_run: false

  # Conditions
  conditions:
    severity: ["medium", "high", "critical"]
    source: "email_gateway"
```

## Steps

### Basic Step

```yaml
- name: Step Name
  action: action_name
  parameters:
    key: value
  output: variable_name
```

### Conditional Step

```yaml
- name: Block Known Bad
  action: block_sender
  parameters:
    sender: "{{ parsed.sender }}"
  condition: "{{ sender_rep.score < 0.2 }}"
```

### Parallel Steps

```yaml
- parallel:
    - action: lookup_urls
      parameters:
        urls: "{{ parsed.urls }}"
      output: url_results

    - action: lookup_attachments
      parameters:
        attachments: "{{ parsed.attachments }}"
      output: attachment_results
```

### Loop Steps

```yaml
- name: Check Each URL
  loop: "{{ parsed.urls }}"
  action: lookup_url
  parameters:
    url: "{{ item }}"
  output: url_results
  aggregate: list
```

## Variables

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `incident` | The incident being processed |
| `incident.id` | Incident ID |
| `incident.raw_data` | Original incident data |
| `incident.severity` | Incident severity |
| `variables` | Playbook-defined variables |

### Step Outputs

Each step's output is available to subsequent steps:

```yaml
- action: parse_email
  output: parsed

- action: lookup_urls
  parameters:
    urls: "{{ parsed.urls }}"  # Use previous output
```

## Templates

Use Jinja2-style templates:

```yaml
parameters:
  message: "Alert for {{ incident.id }}: {{ parsed.subject }}"
  priority: "{{ 'high' if incident.severity == 'critical' else 'medium' }}"
```

## Next Steps

- [Creating Playbooks](./creating.md) - Write your own playbooks
- [Built-in Playbooks](./builtin.md) - Ready-to-use playbooks
