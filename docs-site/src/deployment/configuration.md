# Configuration Reference

Complete reference for all Triage Warden configuration options.

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/db` |
| `TW_ENCRYPTION_KEY` | Credential encryption key (32 bytes, base64) | `K7gNU3sdo+OL0wNhqoVWhr...` |
| `TW_JWT_SECRET` | JWT signing secret (min 32 chars) | `your-256-bit-secret-here` |
| `TW_SESSION_SECRET` | Session encryption secret | `another-secret-value` |

### Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_BIND_ADDRESS` | Address and port to bind | `0.0.0.0:8080` |
| `TW_BASE_URL` | Public URL (for OAuth callbacks, emails) | `http://localhost:8080` |
| `TW_TRUSTED_PROXIES` | Comma-separated trusted proxy IPs | None |
| `TW_MAX_REQUEST_SIZE` | Maximum request body size | `10MB` |
| `TW_REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

### Database Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Full connection string | Required |
| `DATABASE_MAX_CONNECTIONS` | Max pool connections | `10` |
| `DATABASE_MIN_CONNECTIONS` | Min pool connections | `1` |
| `DATABASE_CONNECT_TIMEOUT` | Connection timeout (seconds) | `30` |
| `DATABASE_IDLE_TIMEOUT` | Idle connection timeout (seconds) | `600` |

### Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_JWT_SECRET` | JWT signing secret | Required |
| `TW_JWT_EXPIRY` | JWT token expiry | `24h` |
| `TW_SESSION_SECRET` | Session encryption key | Required |
| `TW_SESSION_EXPIRY` | Session duration | `7d` |
| `TW_CSRF_ENABLED` | Enable CSRF protection | `true` |

### LLM Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenAI API key | None |
| `ANTHROPIC_API_KEY` | Anthropic API key | None |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key | None |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL | None |
| `TW_LLM_PROVIDER` | Default LLM provider | `openai` |
| `TW_LLM_MODEL` | Default model name | `gpt-4-turbo` |
| `TW_LLM_TEMPERATURE` | Model temperature (0.0-2.0) | `0.2` |
| `TW_LLM_MAX_TOKENS` | Max response tokens | `4096` |

### Logging & Observability

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level filter | `info` |
| `TW_LOG_FORMAT` | Log format (`json` or `pretty`) | `json` |
| `TW_METRICS_ENABLED` | Enable Prometheus metrics | `true` |
| `TW_METRICS_PATH` | Metrics endpoint path | `/metrics` |
| `TW_TRACING_ENABLED` | Enable distributed tracing | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry endpoint | None |

### Security

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_ENCRYPTION_KEY` | Credential encryption key | Required |
| `TW_RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `TW_RATE_LIMIT_REQUESTS` | Requests per window | `100` |
| `TW_RATE_LIMIT_WINDOW` | Rate limit window | `1m` |
| `TW_ALLOWED_ORIGINS` | CORS allowed origins | `*` |

### Webhook Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_WEBHOOK_SECRET` | Default webhook signature secret | None |
| `TW_WEBHOOK_SPLUNK_SECRET` | Splunk webhook secret | None |
| `TW_WEBHOOK_CROWDSTRIKE_SECRET` | CrowdStrike webhook secret | None |
| `TW_WEBHOOK_DEFENDER_SECRET` | Defender webhook secret | None |

## Configuration File

Triage Warden can also be configured via `config/default.yaml`:

```yaml
# Server configuration
server:
  bind_address: "0.0.0.0:8080"
  base_url: "https://triage.example.com"
  request_timeout: 30
  max_request_size: "10MB"

# Database configuration
database:
  max_connections: 10
  min_connections: 1
  connect_timeout: 30
  idle_timeout: 600

# Authentication
auth:
  jwt_expiry: "24h"
  session_expiry: "7d"
  csrf_enabled: true

# LLM configuration
llm:
  provider: "anthropic"
  model: "claude-3-sonnet-20240229"
  temperature: 0.2
  max_tokens: 4096

# Logging
logging:
  level: "info"
  format: "json"

# Security
security:
  rate_limit:
    enabled: true
    requests: 100
    window: "1m"
  cors:
    allowed_origins:
      - "https://triage.example.com"

# Guardrails (from guardrails.yaml)
guardrails:
  max_actions_per_incident: 10
  require_approval_for:
    - "isolate_host"
    - "disable_user"
  blocked_actions: []
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

## Log Levels

The `RUST_LOG` variable supports granular log control:

```bash
# Global info level
RUST_LOG=info

# Debug for application, info for dependencies
RUST_LOG=info,triage_warden=debug

# Debug specific modules
RUST_LOG=info,triage_warden::api=debug,triage_warden::policy=trace

# Quiet mode (warnings and errors only)
RUST_LOG=warn
```

## Example Configurations

### Development

```bash
DATABASE_URL=sqlite:./dev.db
TW_ENCRYPTION_KEY=$(openssl rand -base64 32)
TW_JWT_SECRET=dev-jwt-secret-not-for-production
TW_SESSION_SECRET=dev-session-secret
RUST_LOG=debug,sqlx=info
TW_LOG_FORMAT=pretty
```

### Production

```bash
DATABASE_URL=postgres://tw_user:secure_pass@db.example.com:5432/triage_warden?sslmode=verify-full
TW_ENCRYPTION_KEY=K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols=
TW_JWT_SECRET=production-jwt-secret-256-bits-minimum
TW_SESSION_SECRET=production-session-secret
TW_BASE_URL=https://triage.example.com
RUST_LOG=info
TW_LOG_FORMAT=json
TW_RATE_LIMIT_ENABLED=true
ANTHROPIC_API_KEY=sk-ant-api...
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
