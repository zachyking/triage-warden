# Environment Variables Reference

Complete reference of all environment variables for Triage Warden.

## Required Variables

These must be set for Triage Warden to start.

### Database

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@localhost:5432/triage_warden` |

**Connection String Format:**
```
postgres://username:password@hostname:port/database?sslmode=require
```

**SSL Modes:**
- `disable` - No SSL (development only)
- `require` - SSL required, no certificate verification
- `verify-ca` - Verify server certificate against CA
- `verify-full` - Verify server certificate and hostname

### Security

| Variable | Description | Example |
|----------|-------------|---------|
| `TW_ENCRYPTION_KEY` | Credential encryption key (32 bytes, base64) | `K7gNU3sdo+OL0wNhqoVW...` |
| `TW_JWT_SECRET` | JWT signing secret (min 32 characters) | `your-very-long-jwt-secret-here` |
| `TW_SESSION_SECRET` | Session encryption secret | `your-session-secret-here` |

**Generating Keys:**
```bash
# Encryption key (32 bytes, base64)
openssl rand -base64 32

# JWT/Session secret (hex)
openssl rand -hex 32
```

## Server Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_BIND_ADDRESS` | Server bind address | `0.0.0.0:8080` |
| `TW_BASE_URL` | Public URL for the application | `http://localhost:8080` |
| `TW_TRUSTED_PROXIES` | Comma-separated trusted proxy IPs | None |
| `TW_MAX_REQUEST_SIZE` | Maximum request body size | `10MB` |
| `TW_REQUEST_TIMEOUT` | Request timeout in seconds | `30` |

**Example:**
```bash
TW_BIND_ADDRESS=0.0.0.0:8080
TW_BASE_URL=https://triage.company.com
TW_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

## Database Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Connection string | Required |
| `DATABASE_MAX_CONNECTIONS` | Maximum pool connections | `10` |
| `DATABASE_MIN_CONNECTIONS` | Minimum pool connections | `1` |
| `DATABASE_CONNECT_TIMEOUT` | Connection timeout (seconds) | `30` |
| `DATABASE_IDLE_TIMEOUT` | Idle connection timeout (seconds) | `600` |
| `DATABASE_MAX_LIFETIME` | Max connection lifetime (seconds) | `1800` |

**High-Traffic Configuration:**
```bash
DATABASE_MAX_CONNECTIONS=50
DATABASE_MIN_CONNECTIONS=5
DATABASE_IDLE_TIMEOUT=300
```

## Authentication

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_JWT_SECRET` | JWT signing secret | Required |
| `TW_JWT_EXPIRY` | JWT token expiry | `24h` |
| `TW_SESSION_SECRET` | Session encryption key | Required |
| `TW_SESSION_EXPIRY` | Session duration | `7d` |
| `TW_CSRF_ENABLED` | Enable CSRF protection | `true` |
| `TW_COOKIE_SECURE` | Require HTTPS for cookies | `false` |
| `TW_COOKIE_SAME_SITE` | SameSite cookie policy | `lax` |

**Production Settings:**
```bash
TW_COOKIE_SECURE=true
TW_COOKIE_SAME_SITE=strict
TW_SESSION_EXPIRY=1d
```

## LLM Configuration

### Provider Selection

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_LLM_PROVIDER` | LLM provider | `openai` |
| `TW_LLM_MODEL` | Model name | `gpt-4-turbo` |
| `TW_LLM_ENABLED` | Enable LLM features | `true` |

**Valid Providers:** `openai`, `anthropic`, `azure`, `local`

### API Keys

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL |

### Model Parameters

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_LLM_TEMPERATURE` | Response randomness (0.0-2.0) | `0.2` |
| `TW_LLM_MAX_TOKENS` | Maximum response tokens | `4096` |
| `TW_LLM_TIMEOUT` | Request timeout (seconds) | `60` |

**Example Configuration:**
```bash
# Using Anthropic
TW_LLM_PROVIDER=anthropic
TW_LLM_MODEL=claude-3-sonnet-20240229
ANTHROPIC_API_KEY=sk-ant-api03-...
TW_LLM_TEMPERATURE=0.1
TW_LLM_MAX_TOKENS=8192

# Using Azure OpenAI
TW_LLM_PROVIDER=azure
AZURE_OPENAI_API_KEY=your-azure-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
TW_LLM_MODEL=gpt-4-deployment-name
```

## Logging & Observability

| Variable | Description | Default |
|----------|-------------|---------|
| `RUST_LOG` | Log level filter | `info` |
| `TW_LOG_FORMAT` | Log format (`json` or `pretty`) | `json` |
| `TW_LOG_FILE` | Log file path (optional) | None |

### Log Levels

```bash
# Basic levels
RUST_LOG=info          # Info and above
RUST_LOG=debug         # Debug and above
RUST_LOG=warn          # Warnings and errors only

# Granular control
RUST_LOG=info,triage_warden=debug                    # Debug for app, info for deps
RUST_LOG=warn,triage_warden::api=debug               # Debug specific module
RUST_LOG=info,sqlx=warn,hyper=warn                   # Quiet noisy dependencies
```

### Metrics & Tracing

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_METRICS_ENABLED` | Enable Prometheus metrics | `true` |
| `TW_METRICS_PATH` | Metrics endpoint path | `/metrics` |
| `TW_TRACING_ENABLED` | Enable distributed tracing | `false` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry endpoint | None |
| `OTEL_SERVICE_NAME` | Service name for traces | `triage-warden` |

**Tracing Setup:**
```bash
TW_TRACING_ENABLED=true
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_SERVICE_NAME=triage-warden-prod
```

## Rate Limiting

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_RATE_LIMIT_ENABLED` | Enable rate limiting | `true` |
| `TW_RATE_LIMIT_REQUESTS` | Requests per window | `100` |
| `TW_RATE_LIMIT_WINDOW` | Rate limit window | `1m` |
| `TW_RATE_LIMIT_BURST` | Burst allowance | `20` |

## Webhooks

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_WEBHOOK_SECRET` | Default webhook signature secret | None |
| `TW_WEBHOOK_SPLUNK_SECRET` | Splunk-specific secret | None |
| `TW_WEBHOOK_CROWDSTRIKE_SECRET` | CrowdStrike-specific secret | None |
| `TW_WEBHOOK_DEFENDER_SECRET` | Defender-specific secret | None |
| `TW_WEBHOOK_SENTINEL_SECRET` | Sentinel-specific secret | None |

## CORS Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_CORS_ENABLED` | Enable CORS | `true` |
| `TW_CORS_ORIGINS` | Allowed origins (comma-separated) | `*` |
| `TW_CORS_METHODS` | Allowed methods | `GET,POST,PUT,DELETE,OPTIONS` |
| `TW_CORS_HEADERS` | Allowed headers | `*` |
| `TW_CORS_MAX_AGE` | Preflight cache duration (seconds) | `86400` |

**Production CORS:**
```bash
TW_CORS_ORIGINS=https://triage.company.com,https://admin.company.com
```

## Feature Flags

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_FEATURE_PLAYBOOKS` | Enable playbook execution | `true` |
| `TW_FEATURE_AUTO_ENRICH` | Enable automatic enrichment | `true` |
| `TW_FEATURE_API_KEYS` | Enable API key management | `true` |

## Development Variables

Not recommended for production:

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_DEV_MODE` | Enable development mode | `false` |
| `TW_SEED_DATA` | Seed database with test data | `false` |
| `TW_DISABLE_AUTH` | Disable authentication | `false` |

## Example Configurations

### Development

```bash
DATABASE_URL=sqlite:./dev.db
TW_ENCRYPTION_KEY=$(openssl rand -base64 32)
TW_JWT_SECRET=dev-jwt-secret-not-for-production
TW_SESSION_SECRET=dev-session-secret
RUST_LOG=debug
TW_LOG_FORMAT=pretty
TW_DEV_MODE=true
```

### Production

```bash
# Database
DATABASE_URL=postgres://tw:secret@db.company.com:5432/triage_warden?sslmode=verify-full
DATABASE_MAX_CONNECTIONS=25

# Security
TW_ENCRYPTION_KEY=your-production-encryption-key
TW_JWT_SECRET=your-production-jwt-secret-minimum-32-chars
TW_SESSION_SECRET=your-production-session-secret
TW_COOKIE_SECURE=true
TW_COOKIE_SAME_SITE=strict

# Server
TW_BASE_URL=https://triage.company.com
TW_TRUSTED_PROXIES=10.0.0.0/8

# LLM
TW_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-api03-...
TW_LLM_MODEL=claude-3-sonnet-20240229

# Logging
RUST_LOG=info
TW_LOG_FORMAT=json
TW_METRICS_ENABLED=true

# Rate limiting
TW_RATE_LIMIT_ENABLED=true
TW_RATE_LIMIT_REQUESTS=200
TW_RATE_LIMIT_WINDOW=1m
```

### Kubernetes

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: triage-warden-secrets
type: Opaque
stringData:
  DATABASE_URL: "postgres://user:pass@postgres:5432/triage_warden"
  TW_ENCRYPTION_KEY: "base64-encoded-32-byte-key"
  TW_JWT_SECRET: "jwt-signing-secret"
  TW_SESSION_SECRET: "session-secret"
  ANTHROPIC_API_KEY: "sk-ant-..."
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: triage-warden-config
data:
  TW_BASE_URL: "https://triage.company.com"
  TW_LLM_PROVIDER: "anthropic"
  TW_LLM_MODEL: "claude-3-sonnet-20240229"
  RUST_LOG: "info"
  TW_METRICS_ENABLED: "true"
```
