# Production Checklist

Complete this checklist before deploying Triage Warden to production.

## Security Requirements

### Authentication & Secrets

- [ ] **Encryption key configured**: Set `TW_ENCRYPTION_KEY` with a 32-byte base64-encoded key
  ```bash
  # Generate a secure key
  openssl rand -base64 32
  ```

- [ ] **JWT secret configured**: Set `TW_JWT_SECRET` with a strong random value
  ```bash
  openssl rand -hex 32
  ```

- [ ] **Session secret configured**: Set `TW_SESSION_SECRET` for session encryption

- [ ] **Default admin password changed**: Change the default admin credentials immediately after first login

- [ ] **API keys use scoped permissions**: Don't create API keys with `*` scope in production

### Network Security

- [ ] **TLS enabled**: All traffic should use HTTPS
- [ ] **TLS certificates valid**: Use certificates from a trusted CA (not self-signed)
- [ ] **Internal traffic encrypted**: Database connections use TLS
- [ ] **Firewall rules configured**: Only expose necessary ports (443 for HTTPS)
- [ ] **Rate limiting enabled**: Protect against brute force attacks

### Database Security

- [ ] **PostgreSQL in production**: Don't use SQLite for production workloads
- [ ] **Database user has minimal permissions**: Use a dedicated user, not superuser
- [ ] **Database connections encrypted**: Enable `sslmode=require` or `verify-full`
- [ ] **Regular backups configured**: Automated daily backups with tested restore procedure

## Configuration Requirements

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/triage_warden?sslmode=require` |
| `TW_ENCRYPTION_KEY` | Credential encryption key (32 bytes, base64) | `K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72...` |
| `TW_JWT_SECRET` | JWT signing secret | `your-256-bit-secret` |
| `TW_SESSION_SECRET` | Session encryption secret | `another-secret-value` |
| `RUST_LOG` | Log level | `info` or `triage_warden=debug` |

### Optional but Recommended

| Variable | Description | Default |
|----------|-------------|---------|
| `TW_BIND_ADDRESS` | Server bind address | `0.0.0.0:8080` |
| `TW_BASE_URL` | Public URL for callbacks | `https://triage.example.com` |
| `TW_TRUSTED_PROXIES` | Comma-separated proxy IPs | None |
| `TW_MAX_REQUEST_SIZE` | Maximum request body size | `10MB` |

### LLM Configuration (if using AI features)

- [ ] **LLM API key configured**: Set via UI or environment variable
- [ ] **Rate limits configured**: Prevent runaway API costs
- [ ] **Model selected appropriately**: Balance cost vs. capability

## Infrastructure Requirements

### Minimum Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4 cores |
| RAM | 2 GB | 4 GB |
| Storage | 20 GB | 50 GB SSD |

### Database Requirements

| Metric | Minimum | Recommended |
|--------|---------|-------------|
| PostgreSQL Version | 14 | 15+ |
| Connections | 20 | 50+ |
| Storage | 10 GB | 50 GB+ |

### Network Requirements

- Outbound HTTPS (443) to:
  - LLM provider (api.openai.com, api.anthropic.com)
  - Configured connectors (VirusTotal, Jira, etc.)
- Inbound HTTPS (443) from:
  - Users accessing the dashboard
  - Webhook sources (SIEM, EDR systems)

## Monitoring & Observability

### Health Checks

- [ ] **Health endpoint accessible**: `GET /health` returns component status
- [ ] **Readiness probe configured**: `GET /ready` for load balancer
- [ ] **Liveness probe configured**: `GET /live` for container orchestration

### Metrics & Logging

- [ ] **Prometheus metrics exposed**: `GET /metrics` endpoint enabled
- [ ] **Log aggregation configured**: Logs shipped to central system
- [ ] **Alerting rules configured**: Alerts for critical failures

### Recommended Alerts

| Alert | Condition | Severity |
|-------|-----------|----------|
| Service Down | `/health` returns unhealthy for 5m | Critical |
| Database Connection Failed | Database component unhealthy | Critical |
| Kill Switch Active | Kill switch activated | Warning |
| High Error Rate | >5% HTTP 5xx responses | Warning |
| Connector Unhealthy | Any connector in error state | Warning |
| LLM API Errors | LLM requests failing | Warning |

## Operational Readiness

### Documentation

- [ ] **Runbooks available**: Team has access to operational runbooks
- [ ] **Contact list current**: On-call rotation and escalation paths defined
- [ ] **Recovery procedures tested**: Backup restore verified within last 30 days

### Access Control

- [ ] **Admin accounts audited**: Remove unnecessary admin users
- [ ] **API keys audited**: Revoke unused or over-privileged keys
- [ ] **Audit logging enabled**: User actions are logged

### Backup & Recovery

- [ ] **Database backups automated**: Daily backups with 30-day retention
- [ ] **Backup encryption enabled**: Backups encrypted at rest
- [ ] **Recovery time objective defined**: Team knows target RTO
- [ ] **Recovery procedure documented**: Step-by-step restore guide exists

## Pre-Launch Testing

### Functional Tests

- [ ] User login works with configured auth
- [ ] Incidents can be created via webhook
- [ ] Playbooks execute correctly
- [ ] Connectors authenticate successfully
- [ ] Notifications are delivered

### Load Testing

- [ ] Tested with expected concurrent users
- [ ] Tested with expected webhook volume
- [ ] Response times acceptable under load

### Failover Testing

- [ ] Application recovers from database restart
- [ ] Application handles LLM API failures gracefully
- [ ] Kill switch stops all automation when activated

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Security Review | | | |
| Operations Review | | | |
| Development Lead | | | |

---

## Quick Validation Commands

```bash
# Check health endpoint
curl -s https://triage.example.com/health | jq

# Verify TLS certificate
openssl s_client -connect triage.example.com:443 -servername triage.example.com

# Test database connectivity (from application)
curl -s https://triage.example.com/health/detailed | jq '.components.database'

# Verify all connectors healthy
curl -s https://triage.example.com/health/detailed | jq '.components.connectors'
```
