# Natural Language Queries

Query your security data using plain English instead of writing Splunk SPL, Elasticsearch KQL, or SQL by hand.

## Overview

The NL Query Interface (Stage 4.1) lets analysts type questions like "show me critical incidents from the last 24 hours" and have Triage Warden translate them into structured queries against your SIEM, log store, or incident database.

The pipeline has four stages:

1. **Intent classification** -- determines what the analyst is trying to do
2. **Entity extraction** -- pulls out IPs, domains, hashes, date ranges, etc.
3. **Query translation** -- converts the parsed intent + entities into the target query language
4. **Backend execution** -- runs the query against Splunk, Elasticsearch, or SQL

## Supported Intents

| Intent | Example query |
|--------|---------------|
| `search_incidents` | "show me open critical incidents" |
| `search_logs` | "find authentication failures in the last hour" |
| `lookup_ioc` | "check reputation for 192.168.1.100" |
| `explain_incident` | "what happened in INC-2024-0042?" |
| `compare_incidents` | "compare INC-001 and INC-002" |
| `timeline_query` | "show me events from last week" |
| `asset_lookup` | "who owns server web-prod-01?" |
| `statistics` | "how many phishing incidents this month?" |

Intent classification uses keyword matching and regex patterns -- no LLM call is needed for routing.

## Entity Extraction

The entity extractor recognizes security-specific tokens:

- **IP addresses** -- IPv4 (`192.168.1.100`)
- **Domains** -- `evil-domain.com`
- **Hashes** -- MD5 (32 hex chars), SHA-1 (40), SHA-256 (64)
- **Incident IDs** -- `INC-2024-0042`, `#42`
- **Date ranges** -- "last 24 hours", "past 7 days", `2024-01-01 to 2024-01-31`
- **Usernames, hostnames, CVE IDs**

## Query Translation

Once intent and entities are extracted, `NLQueryTranslator` builds a structured query object:

```python
from tw_ai.nl_query import NLQueryTranslator

translator = NLQueryTranslator()
result = translator.translate(
    "show me failed logins from 10.0.0.50 in the last hour"
)
# result.intent.intent = QueryIntent.SEARCH_LOGS
# result.structured_query returns the backend-specific query
```

### Backend Adapters

The translator outputs queries for three backends:

| Backend | Output format | Use case |
|---------|---------------|----------|
| Splunk | SPL queries | `index=auth action=failure src_ip=10.0.0.50 earliest=-1h` |
| Elasticsearch | KQL / Query DSL | `event.action:failure AND source.ip:10.0.0.50` |
| SQL | SQL WHERE clauses | Incident database queries |

## Conversation Context

Multi-turn conversations are supported via `ConversationContext`. When an analyst asks "now show me the same for last week", the system retains the entities from the previous turn.

```python
from tw_ai.nl_query import ConversationContext

ctx = ConversationContext()
ctx.update("show me incidents from 10.0.0.50", entities=[...])
ctx.update("now filter to critical only", entities=[...])
# Second turn inherits the IP entity from the first
```

## Security and Audit

All NL queries are sanitized before execution to prevent injection attacks. The `QuerySanitizer` strips dangerous characters and SQL keywords from user input.

Every query is logged to the `QueryAuditLog` with:

- Original natural language query
- Classified intent and confidence
- Translated structured query
- Execution timestamp and user ID

## API Endpoint

When FastAPI is available, the NL query service exposes a REST endpoint:

```bash
curl -X POST http://localhost:8080/api/v1/nl/query \
  -H "Content-Type: application/json" \
  -d '{"query": "show me critical incidents from the last 24 hours"}'
```

## Configuration

No special configuration is required. The NL query engine uses the same SIEM and database connections already configured in `config/default.yaml`.

To add custom keywords for intent classification:

```python
from tw_ai.nl_query import IntentClassifier, QueryIntent

classifier = IntentClassifier(
    custom_keywords={
        QueryIntent.SEARCH_LOGS: ["splunk", "kibana"],
    }
)
```
