# Notification Actions

Actions for alerting stakeholders and managing escalation.

## notify_user

Send notification to an affected user.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `user` | string | Yes | User email or ID |
| `message` | string | Yes | Notification message |
| `channel` | string | No | `email`, `slack`, `teams` (default: email) |
| `template` | string | No | Notification template name |

**Output:**

```json
{
  "notification_id": "notif-abc123",
  "recipient": "user@company.com",
  "channel": "email",
  "sent_at": "2024-01-15T10:50:00Z",
  "status": "delivered"
}
```

**Templates:**

```yaml
# templates/notifications.yaml
security_alert:
  subject: "Security Alert: Action Required"
  body: |
    A security incident affecting your account has been detected.

    Incident ID: {{ incident_id }}
    Type: {{ incident_type }}

    {{ message }}

    If you did not initiate this activity, please contact IT Security.
```

## notify_reporter

Send status update to the incident reporter.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `incident_id` | string | Yes | Incident ID |
| `status` | string | Yes | Status update message |
| `include_verdict` | bool | No | Include AI verdict (default: false) |

**Output:**

```json
{
  "notification_id": "notif-def456",
  "reporter": "reporter@company.com",
  "status": "delivered"
}
```

## escalate

Route incident to appropriate approval level.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `incident_id` | string | Yes | Incident ID |
| `escalation_level` | string | Yes | `analyst`, `senior`, `manager` |
| `reason` | string | Yes | Reason for escalation |
| `override_assignee` | string | No | Specific person to assign |
| `custom_sla_hours` | int | No | Custom SLA (overrides default) |
| `notify_channels` | array | No | Additional channels (`slack`, `pagerduty`) |

**Output:**

```json
{
  "escalation_id": "esc-abc123",
  "incident_id": "INC-2024-001",
  "escalation_level": "senior",
  "assigned_to": "senior.analyst@company.com",
  "due_date": "2024-01-15T12:50:00Z",
  "priority": "high",
  "sla_hours": 2
}
```

**Default SLAs:**

| Level | SLA |
|-------|-----|
| Analyst | 4 hours |
| Senior | 2 hours |
| Manager | 1 hour |

## create_ticket

Create ticket in external ticketing system.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `title` | string | Yes | Ticket title |
| `description` | string | Yes | Ticket description |
| `priority` | string | No | `low`, `medium`, `high`, `critical` |
| `assignee` | string | No | Initial assignee |
| `labels` | array | No | Ticket labels |

**Output:**

```json
{
  "ticket_id": "12345",
  "ticket_key": "SEC-1234",
  "url": "https://company.atlassian.net/browse/SEC-1234",
  "created_at": "2024-01-15T10:55:00Z"
}
```

## log_false_positive

Record a false positive for tuning.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `incident_id` | string | Yes | Incident ID |
| `reason` | string | Yes | Why this is a false positive |
| `feedback` | string | No | Additional feedback for AI improvement |

**Output:**

```json
{
  "fp_id": "fp-abc123",
  "incident_id": "INC-2024-001",
  "recorded_at": "2024-01-15T11:00:00Z",
  "used_for_training": true
}
```

## run_triage_agent

Trigger AI triage agent on an incident.

**Parameters:**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `incident_id` | string | Yes | Incident ID |
| `playbook` | string | No | Specific playbook to use |
| `model` | string | No | AI model override |

**Output:**

```json
{
  "triage_id": "triage-abc123",
  "incident_id": "INC-2024-001",
  "verdict": "malicious",
  "confidence": 0.92,
  "reasoning": "Multiple indicators of phishing...",
  "recommended_actions": [
    "quarantine_email",
    "block_sender",
    "notify_user"
  ],
  "completed_at": "2024-01-15T10:52:00Z"
}
```

## Usage Examples

### Escalation Playbook

```yaml
name: auto_escalate
trigger:
  - verdict: malicious
  - confidence: ">= 0.9"
  - severity: critical

steps:
  - action: escalate
    parameters:
      incident_id: "{{ incident.id }}"
      escalation_level: manager
      reason: "High-confidence critical incident requiring immediate attention"
      notify_channels:
        - slack
        - pagerduty

  - action: create_ticket
    parameters:
      title: "CRITICAL: {{ incident.subject }}"
      priority: critical
```

### CLI Examples

```bash
# Escalate to senior analyst
tw-cli action execute \
  --incident INC-2024-001 \
  --action escalate \
  --param escalation_level=senior \
  --param reason="Complex threat requiring expertise"

# Create ticket
tw-cli action execute \
  --incident INC-2024-001 \
  --action create_ticket \
  --param title="Phishing Investigation" \
  --param priority=high

# Record false positive
tw-cli action execute \
  --incident INC-2024-001 \
  --action log_false_positive \
  --param reason="Legitimate vendor communication"
```
