# Policy Engine

The policy engine controls action approval workflows and enforces security boundaries.

## Overview

Every action request passes through the policy engine:

```
Action Request → Build Context → Evaluate Rules → Decision
                                                    ├─ Allowed → Execute
                                                    ├─ Denied → Reject
                                                    └─ RequiresApproval → Queue
```

## Policy Decision Types

| Decision | Behavior |
|----------|----------|
| `Allowed` | Action executes immediately |
| `Denied` | Action rejected with reason |
| `RequiresApproval` | Queued for specified approval level |

## Action Context

The policy engine evaluates these attributes:

```rust
pub struct ActionContext {
    /// The action being requested
    pub action_type: String,

    /// Target of the action (host, email, user, etc.)
    pub target: String,

    /// Incident severity (if associated)
    pub severity: Option<Severity>,

    /// AI confidence score (if from triage)
    pub confidence: Option<f64>,

    /// Who/what is requesting the action
    pub proposer: Proposer,

    /// Additional context
    pub metadata: HashMap<String, Value>,
}

pub enum Proposer {
    User { id: String, role: Role },
    Agent { name: String },
    Playbook { name: String },
    System,
}
```

## Default Policies

Without custom rules, these defaults apply:

| Action Category | Default Decision |
|-----------------|------------------|
| Lookup actions | Allowed |
| Analysis actions | Allowed |
| Notification actions | Allowed |
| Response actions | RequiresApproval (analyst) |
| Host containment | RequiresApproval (senior) |

## Next Steps

- [Rules](./rules.md) - Configure custom policy rules
- [Approval Levels](./approvals.md) - Understanding approval workflow
