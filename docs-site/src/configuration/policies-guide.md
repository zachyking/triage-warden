# Policies Guide

Configure approval policies, guardrails, and safety rules for Triage Warden.

## Overview

Policies control what actions Triage Warden can take automatically and what requires human approval. The policy engine provides:

- **Approval Requirements** - Which actions need human approval
- **Guardrails** - Safety limits on automated actions
- **Kill Switch** - Emergency halt for all automation
- **Audit Logging** - Complete action history

## Policy Configuration

Policies are defined in `config/guardrails.yaml` or via the web UI at **Settings → Policies**.

### Basic Structure

```yaml
# config/guardrails.yaml
version: "1"

# Global settings
global:
  operation_mode: supervised  # assisted, supervised, autonomous
  kill_switch_enabled: false
  max_actions_per_incident: 10
  max_concurrent_actions: 5

# Action-specific policies
actions:
  isolate_host:
    requires_approval: true
    approval_level: high
    allowed_sources:
      - crowdstrike
      - defender

  disable_user:
    requires_approval: true
    approval_level: critical
    max_per_hour: 5

  lookup_hash:
    requires_approval: false
    rate_limit: 100/minute

# Approval rules
approvals:
  levels:
    low:
      auto_approve_after: 5m
      approvers: [analyst]
    medium:
      auto_approve_after: 30m
      approvers: [analyst, senior_analyst]
    high:
      auto_approve_after: never
      approvers: [senior_analyst, manager]
    critical:
      auto_approve_after: never
      approvers: [manager]
      require_count: 2
```

## Operation Modes

### Assisted Mode

Human-in-the-loop for all decisions:

- All actions require explicit approval
- AI provides recommendations only
- Best for initial deployment and high-risk environments

```yaml
global:
  operation_mode: assisted
```

### Supervised Mode (Recommended)

Balanced automation with oversight:

- Low-risk actions (lookups, enrichment) run automatically
- Medium/high-risk actions require approval
- Humans can intervene at any time

```yaml
global:
  operation_mode: supervised
```

### Autonomous Mode

Maximum automation:

- Most actions run without approval
- Only critical actions require human review
- Use only after thorough testing

```yaml
global:
  operation_mode: autonomous
```

## Approval Levels

### Configuring Approval Requirements

Each action type can have an approval requirement:

| Action Type | Default Level | Typical Setting |
|-------------|---------------|-----------------|
| lookup_* | none | none |
| send_notification | none | none |
| create_ticket | low | none or low |
| add_comment | none | none |
| set_severity | low | low |
| block_ip | high | high |
| isolate_host | critical | high or critical |
| disable_user | critical | critical |

### Approval Workflow

1. **Action Requested** - Playbook or AI requests an action
2. **Policy Check** - Engine evaluates approval requirements
3. **Queue or Execute** - Action queued for approval or runs immediately
4. **Approval Decision** - Approver accepts or denies
5. **Execution** - Approved action executes
6. **Audit Log** - All decisions recorded

### Approval Escalation

Configure escalation for unanswered approvals:

```yaml
approvals:
  escalation:
    enabled: true
    rules:
      - after: 15m
        notify: [slack-security]
      - after: 30m
        notify: [pagerduty-oncall]
        escalate_to: manager
      - after: 1h
        auto_deny: true
        reason: "Approval timeout"
```

## Guardrails

### Rate Limits

Prevent runaway automation:

```yaml
guardrails:
  rate_limits:
    # Global limits
    global:
      max_actions_per_minute: 100
      max_actions_per_hour: 1000

    # Per-action limits
    isolate_host:
      max_per_hour: 10
      max_per_day: 50

    disable_user:
      max_per_hour: 5
      max_per_day: 20
```

### Blocked Actions

Completely prevent certain actions:

```yaml
guardrails:
  blocked_actions:
    - delete_user        # Never allow
    - format_disk        # Never allow
    - disable_mfa        # Too dangerous
```

### Conditional Rules

Allow/deny based on conditions:

```yaml
guardrails:
  conditional_rules:
    - action: isolate_host
      deny_if:
        - hostname_contains: "dc"      # Don't isolate domain controllers
        - hostname_contains: "prod-db" # Don't isolate production databases
        - is_server: true

    - action: disable_user
      deny_if:
        - is_admin: true               # Don't disable admins
        - is_service_account: true     # Don't disable service accounts
      require_if:
        - department: "executive"      # Extra approval for executives
```

### Asset Protection

Protect critical assets:

```yaml
guardrails:
  protected_assets:
    hosts:
      - pattern: "dc-*"
        actions_blocked: [isolate_host, shutdown]
        reason: "Domain controllers require manual intervention"

      - pattern: "prod-*"
        require_approval: critical
        reason: "Production systems require manager approval"

    users:
      - pattern: "*@executive.company.com"
        require_approval: critical

      - pattern: "svc-*"
        actions_blocked: [disable_user, reset_password]
```

## Kill Switch

### Emergency Automation Halt

The kill switch immediately stops all automated actions:

**Via UI:**
1. Go to **Settings → Safety**
2. Click **Activate Kill Switch**
3. Enter reason
4. Confirm

**Via API:**
```bash
curl -X POST http://localhost:8080/api/kill-switch/activate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Investigating potential false positives"}'
```

**Via CLI:**
```bash
triage-warden kill-switch activate --reason "Emergency halt"
```

### Kill Switch Effects

When active:
- All pending actions are paused
- New automated actions are blocked
- Manual actions still allowed
- Alerts continue to be ingested
- Enrichment continues (read-only)

### Deactivating

Only users with `admin` or `manager` role can deactivate:

```bash
curl -X POST http://localhost:8080/api/kill-switch/deactivate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Issue resolved, resuming normal operations"}'
```

## Audit Logging

### What's Logged

Every action is logged with:
- Timestamp
- Action type
- Target (host, user, etc.)
- Requestor (playbook, user, AI)
- Approver (if required)
- Result (success, failure, denied)
- Full context

### Viewing Audit Logs

**Via UI:**
- **Settings → Audit Log**
- Filter by date, action type, user, result

**Via API:**
```bash
curl "http://localhost:8080/api/audit?action=isolate_host&from=2024-01-01" \
  -H "Authorization: Bearer $API_KEY"
```

### Audit Retention

Configure retention in `config/guardrails.yaml`:

```yaml
audit:
  retention_days: 365
  archive_to: s3://audit-logs-bucket/triage-warden/
```

## Policy Testing

### Dry Run Mode

Test policies without executing actions:

```yaml
global:
  dry_run: true  # Log what would happen, don't execute
```

### Policy Simulator

Test specific scenarios:

```bash
curl -X POST http://localhost:8080/api/policies/simulate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "isolate_host",
    "context": {
      "hostname": "dc-primary",
      "severity": "critical",
      "source": "crowdstrike"
    }
  }'
```

Response:
```json
{
  "allowed": false,
  "reason": "Host matches protected pattern 'dc-*'",
  "would_require_approval": null,
  "matching_rules": [
    "protected_assets.hosts[0]"
  ]
}
```

## Best Practices

### 1. Start Restrictive

Begin with `assisted` mode and strict approvals. Loosen over time as you build confidence.

### 2. Protect Critical Assets

Always define protected assets for:
- Domain controllers
- Production databases
- Executive accounts
- Service accounts

### 3. Use Approval Escalation

Don't let approvals sit forever. Configure timeouts and escalations.

### 4. Monitor Guardrail Hits

Alert when guardrails are triggered frequently—it may indicate:
- Misconfiguration
- Attack in progress
- Need to adjust thresholds

### 5. Test Policy Changes

Always use dry run or simulator before deploying policy changes.

### 6. Keep Audit Logs

Maintain audit logs for compliance and incident review. Archive to external storage.

## Example: Phishing Response Policy

Complete policy for phishing incident automation:

```yaml
version: "1"

global:
  operation_mode: supervised

actions:
  # Enrichment - automatic
  lookup_url:
    requires_approval: false
    rate_limit: 100/minute

  lookup_domain:
    requires_approval: false
    rate_limit: 100/minute

  lookup_user:
    requires_approval: false
    rate_limit: 50/minute

  # Notifications - automatic
  send_notification:
    requires_approval: false

  # Containment - requires approval
  block_sender:
    requires_approval: true
    approval_level: medium
    max_per_hour: 50

  quarantine_email:
    requires_approval: true
    approval_level: low
    auto_approve_confidence: 0.95

  disable_user:
    requires_approval: true
    approval_level: critical

guardrails:
  conditional_rules:
    - action: disable_user
      deny_if:
        - is_admin: true
        - is_executive: true

    - action: quarantine_email
      auto_approve_if:
        - ai_confidence: "> 0.95"
        - virustotal_malicious: "> 5"
```
