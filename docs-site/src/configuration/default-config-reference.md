# Default Configuration Reference

The default configuration file (`config/default.yaml`) contains all settings for a Triage Warden deployment. Copy this file and customize it for your environment.

Sensitive values should use environment variable interpolation: `${ENV_VAR_NAME}`.

## Operation Mode

```yaml
operation_mode: supervised
```

| Mode | Description |
|------|-------------|
| `assisted` | AI observes and suggests only, no automated actions |
| `supervised` | Low-risk actions automated, high-risk requires approval |
| `autonomous` | Full automation for configured incident types |

## Concurrency

```yaml
max_concurrent_incidents: 50
```

Maximum number of incidents being processed at the same time. Increase for high-volume environments; decrease to limit resource usage.

## Connectors

External service integrations. Each connector follows the same structure:

```yaml
connectors:
  <connector_name>:
    connector_type: <type>
    enabled: true
    base_url: <url>
    api_key: ${API_KEY_ENV_VAR}
    api_secret: ""
    timeout_secs: 30
    settings:
      <connector-specific settings>
```

### Common Fields

| Field | Type | Description |
|-------|------|-------------|
| `connector_type` | String | Connector implementation to use |
| `enabled` | Boolean | Whether this connector is active |
| `base_url` | String | Base URL for the service API |
| `api_key` | String | API key or username (use `${ENV_VAR}`) |
| `api_secret` | String | API secret or password (use `${ENV_VAR}`) |
| `timeout_secs` | Integer | HTTP request timeout in seconds |
| `settings` | Map | Connector-specific settings |

### Jira

```yaml
connectors:
  jira:
    connector_type: jira
    enabled: true
    base_url: https://your-company.atlassian.net
    api_key: ${JIRA_API_KEY}
    timeout_secs: 30
    settings:
      project_key: SEC
      default_issue_type: Incident
```

### VirusTotal

```yaml
connectors:
  virustotal:
    connector_type: virustotal
    enabled: true
    base_url: https://www.virustotal.com
    api_key: ${VIRUSTOTAL_API_KEY}
    timeout_secs: 30
    settings:
      cache_ttl_secs: 3600
```

### Splunk (SIEM)

```yaml
connectors:
  splunk:
    connector_type: splunk
    enabled: true
    base_url: https://splunk.company.com:8089
    api_key: ${SPLUNK_TOKEN}
    settings:
      index: main
      earliest_time: -24h
```

### CrowdStrike (EDR)

```yaml
connectors:
  crowdstrike:
    connector_type: crowdstrike
    enabled: true
    base_url: https://api.crowdstrike.com
    api_key: ${CS_CLIENT_ID}
    api_secret: ${CS_CLIENT_SECRET}
```

## LLM Configuration

```yaml
llm:
  provider: anthropic
  model: claude-3-5-sonnet-20241022
  api_key: ${ANTHROPIC_API_KEY}
  base_url: ""
  max_tokens: 4096
  temperature: 0.1
```

| Field | Description |
|-------|-------------|
| `provider` | LLM provider: `anthropic`, `openai`, or `local` |
| `model` | Model identifier |
| `api_key` | API key (use `${ENV_VAR}`) |
| `base_url` | Custom endpoint URL for local/self-hosted models |
| `max_tokens` | Maximum tokens in LLM responses |
| `temperature` | Sampling temperature (lower = more deterministic) |

## Policy Configuration

```yaml
policy:
  guardrails_path: config/guardrails.yaml
  default_approval_level: analyst
  auto_approve_low_risk: true
  confidence_threshold: 0.9
```

| Field | Description |
|-------|-------------|
| `guardrails_path` | Path to the guardrails configuration file |
| `default_approval_level` | Default approval level for unknown actions (`analyst`, `senior`, `manager`) |
| `auto_approve_low_risk` | Whether low-risk actions can be auto-approved |
| `confidence_threshold` | Minimum AI confidence for auto-approval (0.0-1.0) |

## Logging Configuration

```yaml
logging:
  level: info
  json_format: false
  # file_path: /var/log/triage-warden/triage-warden.log
```

| Field | Description |
|-------|-------------|
| `level` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `json_format` | Use structured JSON format (recommended for production) |
| `file_path` | Optional log file path; omit to log to stdout |

## Database Configuration

```yaml
database:
  url: sqlite://triage-warden.db?mode=rwc
  max_connections: 10
  run_migrations: true
```

| Field | Description |
|-------|-------------|
| `url` | Database connection string |
| `max_connections` | Connection pool size |
| `run_migrations` | Whether to run migrations on startup |

### Database URLs

| Database | URL format |
|----------|-----------|
| SQLite (dev) | `sqlite://triage-warden.db?mode=rwc` |
| PostgreSQL (prod) | `postgres://user:pass@host:5432/triage_warden` |

## API Server Configuration

```yaml
api:
  port: 8080
  host: "0.0.0.0"
  enable_swagger: true
  timeout_secs: 30
```

| Field | Description |
|-------|-------------|
| `port` | TCP port to listen on |
| `host` | Bind address (`0.0.0.0` for all interfaces, `127.0.0.1` for localhost only) |
| `enable_swagger` | Serve Swagger UI at `/swagger-ui` |
| `timeout_secs` | HTTP request timeout in seconds |
