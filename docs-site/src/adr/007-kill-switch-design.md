# ADR-007: Kill Switch Design

## Status

Accepted

## Context

Autonomous security response systems pose risks if they malfunction:

1. False positives could disable legitimate users/systems
2. Bugs could trigger cascading actions
3. Compromised AI could be weaponized
4. External events may require immediate halt

We needed an emergency stop mechanism that is:
- Fast to activate (< 1 second)
- Globally effective
- Difficult to accidentally trigger
- Easy to recover from

## Decision

We implemented a global kill switch with the following design:

### Architecture

```
                    ┌─────────────┐
                    │ Kill Switch │
                    │   State     │
                    └──────┬──────┘
                           │
        ┌──────────────────┼──────────────────┐
        │                  │                  │
        ▼                  ▼                  ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Orchestrator  │  │ Policy Engine │  │ Action Runner │
│               │  │               │  │               │
│ check()       │  │ check()       │  │ check()       │
│ before        │  │ before        │  │ before        │
│ processing    │  │ evaluation    │  │ execution     │
└───────────────┘  └───────────────┘  └───────────────┘
```

### State

```rust
pub struct KillSwitchStatus {
    pub active: bool,
    pub reason: Option<String>,
    pub activated_by: Option<String>,
    pub activated_at: Option<DateTime<Utc>>,
}
```

### Check Points

The kill switch is checked at multiple points:

1. **Alert Processing**: Before creating incidents from alerts
2. **Policy Evaluation**: Before evaluating approval policies
3. **Action Execution**: Before executing any response action
4. **Playbook Execution**: Before running playbook stages

### Activation

```rust
// Via API
POST /api/kill-switch/activate
{
    "reason": "Investigating false positive surge",
    "activated_by": "admin@example.com"
}

// Via CLI
tw-cli kill-switch activate --reason "Emergency maintenance"

// Programmatic
kill_switch.activate("Anomaly detected", "system").await;
```

### Deactivation

```rust
// Via API
POST /api/kill-switch/deactivate
{
    "reason": "Issue resolved"
}

// Only admins can deactivate
```

### Event Notification

Activation triggers:
- `KillSwitchActivated` event to all subscribers
- Dashboard alert banner
- Notification to configured channels

## Consequences

### Positive

- Immediate halt of all automation
- Clear audit trail of activation/deactivation
- Multiple activation methods (UI, API, CLI)
- Visible status in all interfaces

### Negative

- In-memory state (lost on restart, resets to inactive)
- No automatic activation triggers yet
- Single global switch (no per-action granularity)
- Requires admin access to deactivate

### Future Enhancements

1. **Persistent State**: Store kill switch state in database
2. **Auto-Activation**: Trigger on anomaly detection
3. **Scoped Switches**: Per-action-type or per-connector switches
4. **Scheduled Deactivation**: Auto-deactivate after timeout
5. **Two-Person Rule**: Require multiple admins for deactivation

### Operational Procedures

When kill switch is activated:

1. All pending actions remain pending
2. New alerts create incidents but stop at enrichment
3. Dashboard shows prominent warning banner
4. Existing approved actions are NOT rolled back

To recover:

1. Investigate root cause
2. Fix underlying issue
3. Deactivate kill switch
4. Manually review pending actions
5. Resume normal operations
