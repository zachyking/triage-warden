# ADR-006: Operation Modes (Supervised/Autonomous)

## Status

Accepted

## Context

Security automation involves a trust spectrum from fully manual to fully autonomous. Organizations have different risk tolerances and regulatory requirements. We needed to support:

1. Organizations starting with automation (cautious)
2. Mature SOCs ready for autonomous response
3. Gradual transition between modes
4. Compliance with approval requirements

## Decision

We implemented three operation modes configurable at the system level:

### Modes

| Mode | Description | Default Approval |
|------|-------------|------------------|
| `supervised` | All actions require human approval | require_approval |
| `semi_autonomous` | Low-risk actions auto-approved, high-risk need approval | policy-based |
| `autonomous` | Actions auto-approved unless policy denies | auto_approve |

### Mode Selection Flow

```
Incoming Action
      │
      ▼
┌─────────────────┐
│ Check Kill Switch│
└────────┬────────┘
         │ (not active)
         ▼
┌─────────────────┐
│ Evaluate Policies│
└────────┬────────┘
         │
    ┌────┴────┐
    │ Explicit │
    │ Policy?  │
    └────┬────┘
    Yes  │  No
    │    │
    │    ▼
    │ ┌─────────────────┐
    │ │ Apply Mode      │
    │ │ Default         │
    │ └────────┬────────┘
    │          │
    └────┬─────┘
         │
         ▼
   Final Decision
```

### Policy Override

Policies can override mode defaults:

```yaml
policies:
  - name: "Block critical IPs always requires approval"
    condition: "action.type == 'block_ip' && target.is_critical"
    action: "require_approval"
    approval_level: "manager"

  - name: "Low severity lookups auto-approved"
    condition: "action.type == 'lookup' && incident.severity in ['info', 'low']"
    action: "auto_approve"
```

### Configuration

```yaml
# config.yaml
general:
  mode: "supervised"  # supervised | semi_autonomous | autonomous
```

Or via API:

```bash
curl -X PUT /api/settings/general \
  -d '{"mode": "semi_autonomous"}'
```

## Consequences

### Positive

- Flexible for different organizational needs
- Gradual automation adoption path
- Policies provide fine-grained control
- Easy to fall back to supervised mode

### Negative

- More complex decision logic
- Potential for misconfiguration
- Requires clear documentation of behavior
- Audit trails must capture mode at decision time

### Mode Comparison

| Scenario | Supervised | Semi-Auto | Autonomous |
|----------|------------|-----------|------------|
| Block malware IP | Approval needed | Auto-approved | Auto-approved |
| Disable user | Approval needed | Approval needed | Auto-approved |
| Isolate host | Approval needed | Approval needed | Approval (policy) |
| Lookup IOC | Approval needed | Auto-approved | Auto-approved |
