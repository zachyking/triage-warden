# Configuration Reference

This document provides a comprehensive reference for all Triage Warden configuration options.

## Configuration Methods

Triage Warden can be configured through:

1. **Environment variables** (recommended for production)
2. **Configuration file** (`config/default.yaml`)
3. **Command-line arguments** (for specific settings)

Environment variables take precedence over configuration file values.

## Environment Variables

### Security Settings (Required)

| Variable | Description | Example |
|----------|-------------|---------|
| `TW_ENCRYPTION_KEY` | 32-byte base64 key for encrypting credentials stored in database | `openssl rand -base64 32` |
| `TW_JWT_SECRET` | Secret for signing JWT tokens (min 32 chars) | `openssl rand -hex 32` |
| `TW_SESSION_SECRET` | Secret for signing session cookies (min 32 chars) | `openssl rand -hex 32` |

**Warning**: These secrets must be consistent across all instances in a cluster. Changing them will invalidate existing sessions and encrypted data.

### Database Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/db` |
| `DATABASE_MAX_CONNECTIONS` | Maximum connection pool size | `25` |
| `DATABASE_MIN_CONNECTIONS` | Minimum connection pool size | `5` |
| `DATABASE_CONNECT_TIMEOUT` | Connection timeout in seconds | `30` |
| `DATABASE_IDLE_TIMEOUT` | Idle connection timeout in seconds | `600` |
| `DATABASE_MAX_LIFETIME` | Maximum connection lifetime in seconds | `1800` |

**Connection String Format**:
```
postgres://username:password@hostname:port/database?sslmode=require
```

SSL modes: `disable`, `allow`, `prefer`, `require`, `verify-ca`, `verify-full`

### Redis Configuration

Redis is required for HA deployments (message queue, cache, leader election).

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection URL | `redis://localhost:6379` |
| `TW_MESSAGE_QUEUE_ENABLED` | Enable Redis-based message queue | `false` |
| `TW_CACHE_ENABLED` | Enable Redis-based cache | `false` |
| `TW_LEADER_ELECTION_ENABLED` | Enable Redis-based leader election | `false` |
| `TW_CACHE_TTL_SECONDS` | Default cache TTL | `3600` |
| `TW_CACHE_MAX_SIZE` | Maximum cache entries | `10000` |

**Connection URL Formats**:
```
redis://localhost:6379
redis://:password@localhost:6379
redis://localhost:6379/0
rediss://localhost:6379  # TLS
```

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_BIND_ADDRESS` | Address and port to bind | `0.0.0.0:8080` |
| `TW_BASE_URL` | Public URL for the application | `http://localhost:8080` |
| `TW_ENV` | Environment: `development`, `production` | `development` |
| `TW_TRUSTED_PROXIES` | CIDR ranges for trusted reverse proxies | `` |
| `TW_REQUEST_BODY_LIMIT` | Max request body size in bytes | `10485760` (10MB) |
| `TW_REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

### Instance Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_INSTANCE_ID` | Unique identifier for this instance | Auto-generated |
| `TW_INSTANCE_TYPE` | Instance type: `api`, `orchestrator`, `combined` | `combined` |

### Authentication & Sessions

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_COOKIE_SECURE` | Require HTTPS for cookies | `true` in production |
| `TW_COOKIE_SAME_SITE` | SameSite policy: `strict`, `lax`, `none` | `strict` |
| `TW_SESSION_EXPIRY_SECONDS` | Session duration | `86400` (24 hours) |
| `TW_CSRF_ENABLED` | Enable CSRF protection | `true` |
| `TW_ADMIN_PASSWORD` | Initial admin password (first run only) | Auto-generated |

### CORS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_CORS_ALLOWED_ORIGINS` | Allowed origins (comma-separated) | Same origin only |
| `TW_CORS_ALLOW_CREDENTIALS` | Allow credentials in CORS requests | `true` |
| `TW_CORS_MAX_AGE` | Preflight cache duration in seconds | `3600` |

### LLM Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_LLM_PROVIDER` | LLM provider: `anthropic`, `openai`, `azure`, `local` | `anthropic` |
| `TW_LLM_MODEL` | Model identifier | `claude-3-sonnet-20240229` |
| `TW_LLM_TEMPERATURE` | Generation temperature (0.0-2.0) | `0.2` |
| `TW_LLM_MAX_TOKENS` | Maximum response tokens | `4096` |
| `TW_LLM_TIMEOUT_SECONDS` | API call timeout | `60` |
| `TW_LLM_RETRY_ATTEMPTS` | Number of retry attempts | `3` |
| `TW_LLM_RETRY_DELAY_MS` | Delay between retries | `1000` |

**Provider-specific API Keys**:

| Variable | Provider |
|----------|----------|
| `ANTHROPIC_API_KEY` | Anthropic Claude |
| `OPENAI_API_KEY` | OpenAI GPT |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL |

### Orchestrator Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_OPERATION_MODE` | Mode: `supervised`, `assisted`, `autonomous` | `supervised` |
| `TW_AUTO_APPROVE_LOW_RISK` | Auto-approve low-risk actions | `false` |
| `TW_MAX_CONCURRENT_INCIDENTS` | Max concurrent incident processing | `100` |
| `TW_ENRICHMENT_TIMEOUT_SECONDS` | Enrichment step timeout | `60` |
| `TW_ANALYSIS_TIMEOUT_SECONDS` | AI analysis timeout | `120` |
| `TW_ACTION_TIMEOUT_SECONDS` | Action execution timeout | `300` |

### Logging Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level filter | `info` |
| `TW_LOG_FORMAT` | Format: `json`, `pretty` | `json` in production |
| `TW_LOG_INCLUDE_LOCATION` | Include file/line in logs | `false` |

**Log Level Examples**:
```bash
# Basic level
RUST_LOG=info

# Per-module levels
RUST_LOG=info,triage_warden=debug,tw_api=trace

# All debug
RUST_LOG=debug
```

### Metrics Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_METRICS_ENABLED` | Enable Prometheus metrics | `true` |
| `TW_METRICS_PATH` | Metrics endpoint path | `/metrics` |
| `TW_METRICS_INCLUDE_LABELS` | Include additional labels | `true` |

### Rate Limiting

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `TW_RATE_LIMIT_REQUESTS` | Requests per window | `200` |
| `TW_RATE_LIMIT_WINDOW` | Window duration (e.g., `1m`, `1h`) | `1m` |
| `TW_RATE_LIMIT_BURST` | Burst allowance | `50` |

### Feature Flags

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_FEATURE_PLAYBOOKS` | Enable playbook automation | `true` |
| `TW_FEATURE_AUTO_ENRICH` | Enable automatic enrichment | `true` |
| `TW_FEATURE_API_KEYS` | Enable API key authentication | `true` |
| `TW_FEATURE_MULTI_TENANT` | Enable multi-tenancy | `false` |
| `TW_ENABLE_SWAGGER` | Enable Swagger UI | `true` in dev |

### Webhook Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_WEBHOOK_SECRET` | Default webhook signature secret | `` |
| `TW_WEBHOOK_TIMEOUT_SECONDS` | Webhook delivery timeout | `30` |
| `TW_WEBHOOK_RETRY_ATTEMPTS` | Delivery retry attempts | `3` |

**Source-specific webhook secrets**:

| Variable | Source |
|----------|--------|
| `TW_WEBHOOK_SPLUNK_SECRET` | Splunk HEC |
| `TW_WEBHOOK_CROWDSTRIKE_SECRET` | CrowdStrike |
| `TW_WEBHOOK_SENTINEL_SECRET` | Microsoft Sentinel |
| `TW_WEBHOOK_GITHUB_SECRET` | GitHub (for DevSecOps) |

## Configuration File

Configuration can also be provided via YAML file.

### File Locations

Triage Warden searches for configuration in order:
1. Path specified by `--config` flag
2. `$HOME/.config/triage-warden/config.yaml`
3. `/etc/triage-warden/config.yaml`
4. `./config/default.yaml`

### Example Configuration File

```yaml
# config/default.yaml

# Server configuration
server:
  bind_address: "0.0.0.0:8080"
  base_url: "https://triage.example.com"
  trusted_proxies:
    - "10.0.0.0/8"
    - "172.16.0.0/12"

# Database configuration
database:
  url: "postgres://triage:password@localhost:5432/triage_warden"
  max_connections: 25
  min_connections: 5
  connect_timeout: 30

# Redis configuration (for HA)
redis:
  url: "redis://localhost:6379"
  message_queue:
    enabled: true
  cache:
    enabled: true
    ttl_seconds: 3600
  leader_election:
    enabled: true

# LLM configuration
llm:
  provider: anthropic
  model: claude-3-sonnet-20240229
  temperature: 0.2
  max_tokens: 4096
  # API key should be set via environment variable

# Orchestrator settings
orchestrator:
  operation_mode: supervised
  auto_approve_low_risk: false
  max_concurrent_incidents: 100
  timeouts:
    enrichment: 60
    analysis: 120
    action: 300

# Logging
logging:
  level: info
  format: json

# Metrics
metrics:
  enabled: true
  path: /metrics

# Rate limiting
rate_limit:
  enabled: true
  requests_per_minute: 200
  burst: 50

# Feature flags
features:
  playbooks: true
  auto_enrich: true
  api_keys: true
  multi_tenant: false

# Connectors
connectors:
  crowdstrike:
    enabled: true
    type: edr
    base_url: "https://api.crowdstrike.com"
    # Credentials via environment or secrets

  splunk:
    enabled: true
    type: siem
    base_url: "https://splunk.example.com:8089"
```

## Precedence

Configuration is loaded in this order (later overrides earlier):

1. Default values (built into application)
2. Configuration file (`config/default.yaml`)
3. Environment-specific file (`config/{TW_ENV}.yaml`)
4. Environment variables

## Generating Secrets

### Encryption Key (32 bytes, base64)

```bash
# macOS/Linux
openssl rand -base64 32

# Alternative using /dev/urandom
head -c 32 /dev/urandom | base64
```

### JWT/Session Secrets

```bash
# Hex-encoded secret
openssl rand -hex 32

# Or use a password generator
pwgen -s 64 1
```

## Database URL Format

### PostgreSQL

```
postgres://username:password@hostname:port/database?sslmode=require
```

Options:
- `sslmode=disable` - No SSL (development only)
- `sslmode=require` - Require SSL, don't verify certificate
- `sslmode=verify-ca` - Require SSL, verify CA
- `sslmode=verify-full` - Require SSL, verify CA and hostname

### Connection Pooling (PgBouncer)

```
postgres://username:password@pgbouncer:6432/database?sslmode=require
```

## Operation Modes

Triage Warden supports three operation modes:

### Supervised Mode (Default)

All actions require human approval:

```bash
TW_OPERATION_MODE=supervised
TW_AUTO_APPROVE_LOW_RISK=false
```

### Assisted Mode

Low-risk actions are auto-approved, high-risk require approval:

```bash
TW_OPERATION_MODE=assisted
TW_AUTO_APPROVE_LOW_RISK=true
```

### Autonomous Mode

All actions within guardrails are auto-executed:

```bash
TW_OPERATION_MODE=autonomous
```

**Warning**: Autonomous mode should only be enabled after thorough testing and with appropriate guardrails configured.

## Health Check Endpoints

| Endpoint | Purpose | Response |
|----------|---------|----------|
| `/health` | Basic health status | `{"status": "healthy", ...}` |
| `/health/detailed` | Full component status | Includes all components |
| `/live` | Liveness probe (Kubernetes) | `200 OK` |
| `/ready` | Readiness probe (Kubernetes) | `200 OK` or `503` |

### Health Status Values

| Status | Description |
|--------|-------------|
| `healthy` | All components operational |
| `degraded` | Some non-critical components failing |
| `unhealthy` | Critical components failing |
| `halted` | Kill switch activated |

## Security Best Practices

1. **Never commit secrets** to version control
2. **Use different secrets** for each environment
3. **Rotate secrets** periodically
4. **Enable TLS** in production (`TW_COOKIE_SECURE=true`)
5. **Restrict trusted proxies** to known IP ranges
6. **Enable rate limiting** in production
7. **Use read-only database users** where possible

## Environment-Specific Recommendations

### Development

```bash
TW_ENV=development
TW_LOG_FORMAT=pretty
RUST_LOG=debug,triage_warden=trace
TW_COOKIE_SECURE=false
TW_ENABLE_SWAGGER=true
```

### Staging

```bash
TW_ENV=production
TW_LOG_FORMAT=json
RUST_LOG=info,triage_warden=debug
TW_COOKIE_SECURE=true
TW_ENABLE_SWAGGER=true
```

### Production

```bash
TW_ENV=production
TW_LOG_FORMAT=json
RUST_LOG=info
TW_COOKIE_SECURE=true
TW_ENABLE_SWAGGER=false
TW_METRICS_ENABLED=true
TW_RATE_LIMIT_ENABLED=true
```

### High-Availability

```bash
DATABASE_URL=postgres://tw_user:pass@pgbouncer:6432/triage_warden?sslmode=require
DATABASE_MAX_CONNECTIONS=50
TW_TRUSTED_PROXIES=10.0.0.0/8
TW_METRICS_ENABLED=true
TW_TRACING_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
```

## Next Steps

- Configure [monitoring](../operations/monitoring.md)
- Set up [horizontal scaling](../operations/scaling.md)
- Deploy to [Kubernetes](./kubernetes.md)
