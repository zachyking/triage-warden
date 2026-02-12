# Agentic AI Response

Control how much autonomy the AI has when responding to incidents, from fully manual to fully autonomous, with time-based rules and per-action overrides.

## Overview

The Agentic AI Response system (Stage 5.4) provides configurable autonomy levels that determine which actions the AI can execute automatically and which require human approval. It includes:

- **Four autonomy levels** with increasing automation
- **Per-action and per-severity overrides**
- **Time-based rules** for different autonomy during business hours vs. off-hours
- **Execution guardrails** to prevent dangerous actions
- **Full audit trail** of every autonomy decision

## Autonomy Levels

| Level | Actions auto-executed | Human role |
|-------|----------------------|------------|
| `assisted` | None | AI suggests, human executes everything |
| `supervised` | Low-risk only | AI auto-executes safe actions, human approves the rest |
| `autonomous` | All except protected | AI handles most actions, human reviews protected targets |
| `full_autonomous` | Everything | Emergency mode -- AI executes all actions (requires special auth) |

### Risk Level Mapping

Each action has an inherent risk level that determines whether it can be auto-executed:

| Risk level | Auto-execute in Supervised? | Auto-execute in Autonomous? |
|-----------|-----|------|
| `none` | Yes | Yes |
| `low` | Yes | Yes |
| `medium` | No | Yes |
| `high` | No | Yes |
| `critical` | No | No (requires `full_autonomous`) |

## Configuration

### Get Current Config

```bash
curl http://localhost:8080/api/v1/autonomy/config
```

### Update Config

```bash
curl -X PUT http://localhost:8080/api/v1/autonomy/config \
  -H "Content-Type: application/json" \
  -d '{
    "default_level": "supervised",
    "per_action_overrides": {
      "isolate_host": "assisted",
      "create_ticket": "autonomous"
    },
    "per_severity_overrides": {
      "critical": "assisted",
      "low": "autonomous"
    },
    "time_based_rules": [
      {
        "name": "Business hours - supervised",
        "start_hour": 9,
        "end_hour": 17,
        "days_of_week": [1, 2, 3, 4, 5],
        "level": "supervised"
      },
      {
        "name": "Off-hours - autonomous",
        "start_hour": 17,
        "end_hour": 9,
        "days_of_week": [0, 1, 2, 3, 4, 5, 6],
        "level": "autonomous"
      }
    ],
    "emergency_contacts": ["soc-manager@company.com"]
  }'
```

### Resolution Priority

When resolving the autonomy level for a given action, overrides are checked in this order:

1. **Per-action overrides** (highest priority)
2. **Per-severity overrides**
3. **Time-based rules**
4. **Default level** (fallback)

### Resolve for a Specific Action

Check what the system would decide for a specific action + severity combination:

```bash
curl -X POST http://localhost:8080/api/v1/autonomy/resolve \
  -H "Content-Type: application/json" \
  -d '{"action": "isolate_host", "severity": "critical"}'
```

Response:

```json
{
  "level": "assisted",
  "auto_execute": false,
  "reason": "Per-action override for 'isolate_host'"
}
```

## Time-Based Rules

Time-based rules let you run with less autonomy during business hours (when analysts are available) and more autonomy during nights and weekends.

| Field | Description |
|-------|-------------|
| `name` | Human-readable rule name |
| `start_hour` | Start hour, 0-23 inclusive |
| `end_hour` | End hour, 0-24 exclusive |
| `days_of_week` | Array of days (0=Sunday through 6=Saturday) |
| `level` | Autonomy level when rule applies |

Hours wrap around midnight: `start_hour: 22, end_hour: 6` means 10 PM to 6 AM.

## Execution Guardrails

The guardrails system (configured in `config/guardrails.yaml`) provides hard limits regardless of autonomy level:

- **Forbidden actions** -- actions that can never be automated (e.g., `delete_user`, `wipe_host`)
- **Protected assets** -- targets that always require human approval (production systems, domain controllers)
- **Rate limits** -- maximum actions per hour/day to prevent runaway automation
- **Blast radius limits** -- caps on how many targets a single action can affect

See [Guardrails Reference](../configuration/guardrails-reference.md) for full configuration details.

## Audit Log

Every autonomy decision is logged for compliance and debugging:

```bash
curl "http://localhost:8080/api/v1/autonomy/audit?limit=20"

# Filter by incident
curl "http://localhost:8080/api/v1/autonomy/audit?incident_id={id}"
```

Each audit entry records:

- Action and severity evaluated
- Resolved autonomy level
- Whether auto-execution was allowed
- Reason for the decision
- Whether the action was actually executed
- Execution outcome
