# Policy Rules

Define rules to control when actions require approval.

## Rule Structure

```toml
[[policy.rules]]
name = "rule_name"
description = "Human-readable description"

# Matching criteria
action = "action_name"           # Specific action
action_patterns = ["pattern_*"]  # Glob patterns

# Conditions (all must match)
severity = ["high", "critical"]  # Incident severity
confidence_min = 0.8             # Minimum AI confidence
proposer_type = "agent"          # Who's requesting
proposer_role = "analyst"        # Role (if user)

# Decision
decision = "allowed"             # or "denied" or "requires_approval"
approval_level = "senior"        # If requires_approval
reason = "Explanation"           # If denied
```

## Rule Examples

### Auto-Approve Lookups

```toml
[[policy.rules]]
name = "auto_approve_lookups"
description = "Lookup actions are always allowed"
action_patterns = ["lookup_*"]
decision = "allowed"
```

### Require Approval for Response Actions

```toml
[[policy.rules]]
name = "response_needs_analyst"
description = "Response actions require analyst approval"
action_patterns = ["quarantine_*", "block_*"]
decision = "requires_approval"
approval_level = "analyst"
```

### High-Severity Host Isolation

```toml
[[policy.rules]]
name = "critical_isolation_needs_manager"
description = "Critical severity host isolation requires manager"
action = "isolate_host"
severity = ["critical"]
decision = "requires_approval"
approval_level = "manager"
```

### Block Dangerous Actions in Production

```toml
[[policy.rules]]
name = "no_delete_production"
description = "Deletion actions not allowed in production"
action_patterns = ["delete_*"]
environment = "production"
decision = "denied"
reason = "Deletion actions are not permitted in production"
```

### Trust High-Confidence AI Decisions

```toml
[[policy.rules]]
name = "trust_high_confidence_ai"
description = "Auto-approve when AI is highly confident"
proposer_type = "agent"
confidence_min = 0.95
severity = ["low", "medium"]
action_patterns = ["quarantine_email", "block_sender"]
decision = "allowed"
```

### Analyst Self-Service

```toml
[[policy.rules]]
name = "analyst_can_notify"
description = "Analysts can send notifications without approval"
action_patterns = ["notify_*"]
proposer_role = "analyst"
decision = "allowed"
```

## Rule Evaluation Order

Rules are evaluated in order. First matching rule wins.

```toml
# More specific rules first
[[policy.rules]]
name = "critical_isolation"
action = "isolate_host"
severity = ["critical"]
approval_level = "manager"

# General fallback
[[policy.rules]]
name = "default_isolation"
action = "isolate_host"
approval_level = "senior"
```

## Condition Operators

### Severity Matching

```toml
severity = ["high", "critical"]  # Match any in list
```

### Confidence Ranges

```toml
confidence_min = 0.8   # Minimum confidence
confidence_max = 0.95  # Maximum confidence
```

### Pattern Matching

```toml
action_patterns = ["lookup_*"]        # Prefix match
action_patterns = ["*_email"]         # Suffix match
action_patterns = ["*block*"]         # Contains
```

### Proposer Conditions

```toml
proposer_type = "user"      # user, agent, playbook, system
proposer_role = "analyst"   # Only for user proposers
```

## Managing Rules

### Via Configuration File

```bash
# config/policy.toml
tw-api --config config/policy.toml
```

### Via API

```bash
# List rules
curl http://localhost:8080/api/policies

# Create rule
curl -X POST http://localhost:8080/api/policies \
  -H "Content-Type: application/json" \
  -d '{
    "name": "new_rule",
    "action": "isolate_host",
    "approval_level": "senior"
  }'
```

### Via CLI

```bash
# List rules
tw-cli policy list

# Add rule
tw-cli policy add \
  --name "block_needs_approval" \
  --action "block_sender" \
  --approval-level analyst
```

## Testing Rules

Simulate policy evaluation without executing:

```bash
tw-cli policy test \
  --action isolate_host \
  --severity critical \
  --proposer-type agent \
  --confidence 0.92

# Output:
# Decision: RequiresApproval
# Level: manager
# Matched Rule: critical_isolation_needs_manager
```
