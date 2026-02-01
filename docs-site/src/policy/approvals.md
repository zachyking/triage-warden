# Approval Levels

Understanding the approval workflow in Triage Warden.

## Approval Hierarchy

```
Manager (SOC Manager)
    │
    ▼
Senior (Senior Analyst)
    │
    ▼
Analyst (Security Analyst)
    │
    ▼
Auto (No approval needed)
```

Higher levels can approve actions at their level or below.

## Level Definitions

| Level | Role | Typical Actions |
|-------|------|-----------------|
| Auto | System | Lookups, analysis, low-risk notifications |
| Analyst | Security Analyst | Email quarantine, sender blocking |
| Senior | Senior Analyst | Host isolation, broad blocks |
| Manager | SOC Manager | Critical containment, policy changes |

## Approval Workflow

### 1. Action Requested

```bash
tw-cli action execute --incident INC-001 --action isolate_host
```

### 2. Policy Evaluation

Policy engine evaluates and returns:

```json
{
  "decision": "requires_approval",
  "approval_level": "senior",
  "reason": "Host isolation requires senior analyst approval"
}
```

### 3. Action Queued

Action stored with pending status:

```json
{
  "action_id": "act-abc123",
  "incident_id": "INC-001",
  "action_type": "isolate_host",
  "status": "pending_approval",
  "approval_level": "senior",
  "requested_by": "analyst@company.com",
  "requested_at": "2024-01-15T10:30:00Z"
}
```

### 4. Approvers Notified

Notification sent to eligible approvers via configured channels.

### 5. Approval Decision

Approver reviews and decides:

**Approve:**
```bash
tw-cli action approve act-abc123 --comment "Verified threat"
```

**Reject:**
```bash
tw-cli action reject act-abc123 --reason "False positive, user traveling"
```

### 6. Execution or Rejection

- **Approved**: Action executes automatically
- **Rejected**: Action marked rejected, requester notified

## Approval UI

Access pending approvals at `/approvals` in the web dashboard.

Features:
- Filterable list of pending actions
- Incident context display
- One-click approve/reject
- Bulk approval for related actions

## SLA Tracking

Each approval level has a default SLA:

| Level | Default SLA |
|-------|-------------|
| Analyst | 4 hours |
| Senior | 2 hours |
| Manager | 1 hour |

Overdue approvals are:
1. Highlighted in dashboard
2. Re-notified to approvers
3. Optionally escalated to next level

## Delegation

Approvers can delegate when unavailable:

```bash
tw-cli approval delegate \
  --from senior.analyst@company.com \
  --to backup.analyst@company.com \
  --until 2024-01-20
```

## Approval Groups

Configure approval groups for redundancy:

```toml
[approval_groups]
senior_analysts = [
  "alice@company.com",
  "bob@company.com",
  "charlie@company.com"
]

managers = [
  "soc.manager@company.com",
  "backup.manager@company.com"
]
```

Any member of the group can approve.

## Audit Trail

All approval decisions are logged:

```json
{
  "event": "action_approved",
  "action_id": "act-abc123",
  "approver": "senior.analyst@company.com",
  "decision": "approved",
  "comment": "Verified threat indicators",
  "timestamp": "2024-01-15T10:45:00Z",
  "time_to_approve": "15m"
}
```

## Emergency Override

In emergencies, managers can bypass approval:

```bash
tw-cli action execute \
  --incident INC-001 \
  --action isolate_host \
  --emergency \
  --reason "Active ransomware, immediate containment required"
```

Emergency overrides are:
- Logged with high visibility
- Require manager credentials
- Trigger additional notifications
