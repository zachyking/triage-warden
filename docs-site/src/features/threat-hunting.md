# Automated Threat Hunting

Proactively search for threats across your environment using hypothesis-driven hunts with built-in query templates mapped to MITRE ATT&CK.

## Overview

The threat hunting module (Stage 5.1) provides:

- **Hunt management** -- create, schedule, and track hunts with hypotheses
- **Built-in query library** -- 20+ pre-built queries across 8 MITRE ATT&CK categories
- **Multi-platform queries** -- Splunk SPL and Elasticsearch KQL templates
- **Finding promotion** -- promote hunt findings directly to incidents

## Hunt Lifecycle

A hunt progresses through these statuses:

| Status | Description |
|--------|-------------|
| `draft` | Hunt is being designed, not yet executable |
| `active` | Hunt is enabled and will run on schedule or trigger |
| `paused` | Temporarily suspended |
| `completed` | Finished executing (one-time hunts) |
| `failed` | Execution encountered errors |
| `archived` | No longer active, kept for reference |

## Creating a Hunt

### Via API

```bash
curl -X POST http://localhost:8080/api/v1/hunts \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Detect Kerberoasting",
    "hypothesis": "Attackers may request TGS tickets for service accounts to crack offline",
    "hunt_type": "scheduled",
    "queries": [
      {
        "query_type": "splunk",
        "query": "index=wineventlog EventCode=4769 TicketEncryptionType=0x17 | stats count by ServiceName",
        "description": "Detect RC4-encrypted TGS requests",
        "timeout_secs": 300,
        "expected_baseline": 5
      }
    ],
    "schedule": {
      "cron_expression": "0 */4 * * *",
      "timezone": "UTC",
      "max_runtime_secs": 600
    },
    "mitre_techniques": ["T1558.003"],
    "data_sources": ["windows_event_logs"],
    "tags": ["credential-access", "priority-high"],
    "enabled": true
  }'
```

## Hunt Types

| Type | Description |
|------|-------------|
| `scheduled` | Runs on a cron schedule |
| `continuous` | Runs as a streaming query |
| `on_demand` | Runs only when manually triggered |
| `triggered` | Runs when a condition is met (e.g., new threat intel) |

## Built-in Query Library

Access 20+ pre-built queries via the API:

```bash
curl http://localhost:8080/api/v1/hunts/queries/library
```

Queries span 8 MITRE ATT&CK categories:

- Initial Access
- Execution
- Persistence
- Credential Access
- Lateral Movement
- Collection
- Command and Control
- Exfiltration

Each built-in query includes Splunk SPL and Elasticsearch KQL templates, expected baselines for anomaly detection, and configurable parameters.

## Executing a Hunt

Trigger a hunt manually:

```bash
curl -X POST http://localhost:8080/api/v1/hunts/{hunt_id}/execute
```

The response includes findings with severity levels, evidence data, and the query that produced each finding.

## Viewing Results

```bash
# Get all results for a hunt
curl http://localhost:8080/api/v1/hunts/{hunt_id}/results
```

Each result includes:

- Total and critical finding counts
- Duration and execution status
- Individual findings with severity, evidence, and matched query

## Promoting Findings to Incidents

When a hunt finding warrants investigation, promote it to a full incident:

```bash
curl -X POST http://localhost:8080/api/v1/hunts/{hunt_id}/findings/{finding_id}/promote
```

This creates a new incident with the finding's evidence, severity, and hunt metadata attached.

## Query Languages

| Language | Identifier | Example |
|----------|-----------|---------|
| Splunk SPL | `splunk` | `index=wineventlog EventCode=4625` |
| Elasticsearch | `elasticsearch` | `event.code: 4625` |
| SQL | `sql` | `SELECT * FROM events WHERE event_code = 4625` |
| Kusto (KQL) | `kusto` | `SecurityEvent \| where EventID == 4625` |
| Custom | `custom` | Any custom query syntax |

## Python Hypothesis Generator

The Python `tw_ai` package includes an AI-powered hypothesis generator that suggests new hunts based on current threat intelligence and recent incident patterns.
