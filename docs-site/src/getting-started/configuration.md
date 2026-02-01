# Configuration

Triage Warden is configured through environment variables and configuration files.

## Environment Variables

### Core Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_DATABASE_URL` | Database connection string | `sqlite://./triage_warden.db` |
| `TW_HOST` | API server host | `0.0.0.0` |
| `TW_PORT` | API server port | `8080` |
| `TW_LOG_LEVEL` | Logging level (trace, debug, info, warn, error) | `info` |
| `TW_ADMIN_PASSWORD` | Initial admin password | (generated) |

### Connector Selection

| Variable | Description | Values |
|----------|-------------|--------|
| `TW_THREAT_INTEL_MODE` | Threat intelligence backend | `mock`, `virustotal` |
| `TW_SIEM_MODE` | SIEM backend | `mock`, `splunk` |
| `TW_EDR_MODE` | EDR backend | `mock`, `crowdstrike` |
| `TW_EMAIL_GATEWAY_MODE` | Email gateway backend | `mock`, `m365` |
| `TW_TICKETING_MODE` | Ticketing backend | `mock`, `jira` |

### VirusTotal

```bash
TW_THREAT_INTEL_MODE=virustotal
TW_VIRUSTOTAL_API_KEY=your-api-key-here
```

### Splunk

```bash
TW_SIEM_MODE=splunk
TW_SPLUNK_URL=https://splunk.company.com:8089
TW_SPLUNK_TOKEN=your-token-here
```

### CrowdStrike

```bash
TW_EDR_MODE=crowdstrike
TW_CROWDSTRIKE_CLIENT_ID=your-client-id
TW_CROWDSTRIKE_CLIENT_SECRET=your-client-secret
TW_CROWDSTRIKE_REGION=us-1  # us-1, us-2, eu-1
```

### Microsoft 365

```bash
TW_EMAIL_GATEWAY_MODE=m365
TW_M365_TENANT_ID=your-tenant-id
TW_M365_CLIENT_ID=your-client-id
TW_M365_CLIENT_SECRET=your-client-secret
```

### Jira

```bash
TW_TICKETING_MODE=jira
TW_JIRA_URL=https://company.atlassian.net
TW_JIRA_EMAIL=automation@company.com
TW_JIRA_API_TOKEN=your-api-token
TW_JIRA_PROJECT_KEY=SEC
```

### AI Provider

```bash
TW_AI_PROVIDER=anthropic  # anthropic, openai
TW_ANTHROPIC_API_KEY=your-api-key
# or
TW_OPENAI_API_KEY=your-api-key
```

## Configuration File

For complex configurations, use a TOML file:

```toml
# config.toml

[server]
host = "0.0.0.0"
port = 8080
log_level = "info"

[database]
url = "postgres://user:pass@localhost/triage_warden"
max_connections = 10

[connectors.threat_intel]
mode = "virustotal"
api_key = "${TW_VIRUSTOTAL_API_KEY}"
rate_limit = 4  # requests per minute

[connectors.siem]
mode = "splunk"
url = "https://splunk.company.com:8089"
token = "${TW_SPLUNK_TOKEN}"

[connectors.edr]
mode = "crowdstrike"
client_id = "${TW_CROWDSTRIKE_CLIENT_ID}"
client_secret = "${TW_CROWDSTRIKE_CLIENT_SECRET}"
region = "us-1"

[ai]
provider = "anthropic"
model = "claude-sonnet-4-20250514"
max_tokens = 4096

[policy]
default_action_approval = "auto"  # auto, analyst, senior, manager
high_severity_approval = "senior"
critical_action_approval = "manager"
```

Load with:

```bash
tw-api --config config.toml
```

## Policy Rules

Policy rules control action approval requirements. See [Policy Engine](../policy/README.md) for details.

```toml
# Example policy rule
[[policy.rules]]
name = "isolate_host_requires_manager"
action = "isolate_host"
severity = ["high", "critical"]
approval_level = "manager"
```

## Logging

Configure structured logging:

```bash
# JSON output for production
TW_LOG_FORMAT=json

# Pretty output for development
TW_LOG_FORMAT=pretty

# Filter specific modules
RUST_LOG=tw_api=debug,tw_core=info
```

## Next Steps

- [Connectors](../connectors/README.md) - Detailed connector configuration
- [Policy Engine](../policy/README.md) - Configure approval workflows
- [API Authentication](../api/authentication.md) - Set up API access
