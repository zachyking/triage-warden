# Guardrails Reference

The guardrails configuration file (`config/guardrails.yaml`) defines security boundaries for AI-automated actions. These rules apply regardless of the current autonomy level.

## Deny List

Actions and targets that are **never** allowed automatically.

### Denied Actions

```yaml
deny_list:
  actions:
    - delete_user          # Too destructive
    - wipe_host            # Too destructive
    - delete_all_emails    # Too destructive
    - modify_firewall      # High risk
```

Add any action name here to prevent the AI from ever executing it. These actions can still be performed manually by an analyst.

### Target Patterns

Regex patterns that match protected systems. Any automated action targeting a hostname or identifier that matches these patterns requires human approval.

```yaml
deny_list:
  target_patterns:
    - ".*-prod-.*"         # Production systems
    - "dc\\d+\\..*"        # Domain controllers
    - ".*-critical-.*"     # Explicitly marked critical
    - ".*\\.corp\\..*"     # Corporate infrastructure
```

### Protected IPs

Specific IP addresses that must never be targeted by automated actions.

```yaml
deny_list:
  protected_ips:
    - "10.0.0.1"           # Core router
    - "10.0.0.2"           # DNS server
    - "10.0.0.3"           # DHCP server
```

### Protected Users

User accounts that are protected from automated modifications (disable, password reset, etc.). Supports exact matches and glob patterns.

```yaml
deny_list:
  protected_users:
    - "admin"
    - "root"
    - "administrator"
    - "service-account-*"
    - "svc-*"
```

## Rate Limits

Prevent runaway automation by capping how many times each action can be executed.

```yaml
rate_limits:
  isolate_host:
    max_per_hour: 5
    max_per_day: 20
    max_concurrent: 2

  disable_user:
    max_per_hour: 10
    max_per_day: 50
    max_concurrent: 5

  block_ip:
    max_per_hour: 20
    max_per_day: 100
    max_concurrent: 10

  quarantine_email:
    max_per_hour: 50
    max_per_day: 500
    max_concurrent: 20
```

| Field | Description |
|-------|-------------|
| `max_per_hour` | Maximum executions in a rolling 60-minute window |
| `max_per_day` | Maximum executions in a rolling 24-hour window |
| `max_concurrent` | Maximum simultaneous in-flight executions |

## Approval Policies

Define when human approval is required, and at what level.

```yaml
approval_policies:
  - name: critical_asset_protection
    description: "Require senior approval for actions on critical assets"
    condition:
      target_criticality:
        - critical
        - high
    requires: senior
    can_override: false
```

### Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `target_criticality` | List of strings | Asset criticality levels that trigger this policy |
| `action_type` | List of strings | Action types that trigger this policy |
| `confidence_below` | Float (0.0-1.0) | Trigger when AI confidence is below this threshold |

### Approval Levels

| Level | Who can approve |
|-------|----------------|
| `analyst` | Any analyst |
| `senior` | Senior analyst or above |
| `manager` | SOC manager |

### Overridability

When `can_override: true`, a senior user can bypass the approval requirement. When `false`, the approval is mandatory and cannot be skipped.

## Auto-Approve Rules

Actions that can be executed automatically when specific conditions are met, even in `supervised` mode.

```yaml
auto_approve_rules:
  - name: ticket_operations
    description: "Auto-approve ticket creation and updates"
    action_types:
      - create_ticket
      - update_ticket
      - add_ticket_comment
    conditions:
      - confidence_above: 0.5

  - name: email_quarantine_high_confidence
    description: "Auto-approve email quarantine for high-confidence phishing"
    action_types:
      - quarantine_email
    conditions:
      - confidence_above: 0.95
      - verdict: true_positive
```

### Condition Fields

| Field | Type | Description |
|-------|------|-------------|
| `confidence_above` | Float (0.0-1.0) | AI confidence must exceed this value |
| `verdict` | String | AI verdict must match (e.g., `true_positive`) |

All conditions in the list must be met (AND logic).

## Data Policies

Control how sensitive data is handled in logs and LLM prompts.

```yaml
data_policies:
  pii_filter: true
  pii_patterns:
    - "\\b\\d{3}-\\d{2}-\\d{4}\\b"      # SSN
    - "\\b\\d{16}\\b"                    # Credit card

  secrets_redaction: true
  secret_patterns:
    - "(?i)api[_-]?key"
    - "(?i)password"
    - "(?i)secret"
    - "(?i)token"
    - "(?i)credential"

  audit_data_access: true
```

| Field | Description |
|-------|-------------|
| `pii_filter` | Enable PII filtering in logs and LLM prompts |
| `pii_patterns` | Regex patterns matching PII to redact |
| `secrets_redaction` | Enable secret detection and redaction |
| `secret_patterns` | Regex patterns matching secrets to redact |
| `audit_data_access` | Log all data access operations |

## Escalation Rules

Define automatic escalation triggers.

```yaml
escalation_rules:
  - name: repeated_false_positives
    description: "Escalate if same alert type has high FP rate"
    condition:
      false_positive_rate_above: 0.5
      sample_size_min: 10
    action: escalate_to_analyst

  - name: incident_correlation
    description: "Escalate if multiple related incidents detected"
    condition:
      related_incidents_above: 3
      time_window_hours: 1
    action: escalate_to_senior

  - name: critical_severity
    description: "Always escalate critical severity incidents"
    condition:
      severity: critical
    action: escalate_to_manager
```

### Escalation Actions

| Action | Description |
|--------|-------------|
| `escalate_to_analyst` | Route to any available analyst |
| `escalate_to_senior` | Route to a senior analyst |
| `escalate_to_manager` | Route to the SOC manager |
