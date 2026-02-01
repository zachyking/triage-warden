# Actions

Actions are the executable operations that Triage Warden can perform in response to incidents.

## Overview

Actions fall into several categories:

| Category | Purpose | Examples |
|----------|---------|----------|
| Analysis | Extract and parse data | `parse_email`, `check_email_authentication` |
| Lookup | Enrich with external data | `lookup_sender_reputation`, `lookup_urls` |
| Response | Take containment actions | `quarantine_email`, `isolate_host` |
| Notification | Alert stakeholders | `notify_user`, `escalate` |
| Ticketing | Create/update tickets | `create_ticket`, `add_ticket_comment` |

## Action Trait

All actions implement the `Action` trait:

```rust
#[async_trait]
pub trait Action: Send + Sync {
    /// Action name (used in playbooks and API)
    fn name(&self) -> &str;

    /// Human-readable description
    fn description(&self) -> &str;

    /// Required and optional parameters
    fn required_parameters(&self) -> Vec<ParameterDef>;

    /// Whether this action supports rollback
    fn supports_rollback(&self) -> bool;

    /// Execute the action
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError>;

    /// Rollback the action (if supported)
    async fn rollback(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        Err(ActionError::RollbackNotSupported)
    }
}
```

## Action Context

Actions receive an `ActionContext` with:

```rust
pub struct ActionContext {
    /// Unique execution ID
    pub execution_id: Uuid,

    /// Parameters passed to the action
    pub parameters: HashMap<String, serde_json::Value>,

    /// Related incident (if any)
    pub incident_id: Option<Uuid>,

    /// User or agent requesting the action
    pub proposer: String,

    /// Connectors available for use
    pub connectors: ConnectorRegistry,
}
```

## Action Result

Actions return an `ActionResult`:

```rust
pub struct ActionResult {
    /// Whether the action succeeded
    pub success: bool,

    /// Action name
    pub action_name: String,

    /// Human-readable summary
    pub message: String,

    /// Execution duration
    pub duration: Duration,

    /// Output data (action-specific)
    pub output: HashMap<String, serde_json::Value>,

    /// Whether rollback is available
    pub rollback_available: bool,
}
```

## Policy Integration

All actions pass through the policy engine before execution:

```
Action Request → Policy Evaluation → Decision
                                       ├─ Allowed → Execute
                                       ├─ Denied → Return Error
                                       └─ RequiresApproval → Queue
```

See [Policy Engine](../policy/README.md) for approval configuration.

## Executing Actions

### Via API

```bash
curl -X POST http://localhost:8080/api/incidents/{id}/actions \
  -H "Content-Type: application/json" \
  -d '{
    "action": "quarantine_email",
    "parameters": {
      "message_id": "AAMkAGI2...",
      "reason": "Phishing detected"
    }
  }'
```

### Via CLI

```bash
tw-cli action execute \
  --incident INC-2024-001 \
  --action quarantine_email \
  --param message_id=AAMkAGI2... \
  --param reason="Phishing detected"
```

### Via Playbook

```yaml
steps:
  - action: quarantine_email
    parameters:
      message_id: "{{ incident.raw_data.message_id }}"
      reason: "Automated response to phishing"
```

## Available Actions

- [Email Actions](./email.md) - Email parsing and response
- [Host Actions](./host.md) - Endpoint containment
- [Lookup Actions](./lookup.md) - Threat intelligence enrichment
- [Notification Actions](./notification.md) - Alerts and escalation
