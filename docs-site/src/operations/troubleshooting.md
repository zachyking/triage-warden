# Troubleshooting Guide

Common issues and their solutions.

## Quick Diagnostics

```bash
# Check overall health
curl -s http://localhost:8080/health/detailed | jq

# Check logs for errors (last 100 lines)
docker compose logs --tail=100 triage-warden | grep -i error

# Check resource usage
docker stats --no-stream
```

## Common Issues

### Service Won't Start

#### Symptoms
- Container exits immediately
- "Connection refused" errors
- Health check fails

#### Diagnosis
```bash
# Check container logs
docker compose logs triage-warden

# Check exit code
docker compose ps -a
```

#### Common Causes & Solutions

**Missing environment variables:**
```
Error: Required environment variable TW_ENCRYPTION_KEY not set
```
Solution: Ensure all required env vars are set in `.env`

**Database connection failed:**
```
Error: Failed to connect to database: Connection refused
```
Solution:
1. Verify PostgreSQL is running: `docker compose ps postgres`
2. Check DATABASE_URL is correct
3. Verify network connectivity

**Invalid encryption key:**
```
Error: Invalid encryption key: must be 32 bytes base64-encoded
```
Solution: Generate new key: `openssl rand -base64 32`

---

### Database Connection Issues

#### Symptoms
- `/ready` returns 503
- "Database unavailable" in health check
- Queries timing out

#### Diagnosis
```bash
# Check database health
docker compose exec postgres pg_isready -U triage_warden

# Check connection count
docker compose exec postgres psql -U triage_warden -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'triage_warden';"

# Check for locks
docker compose exec postgres psql -U triage_warden -c \
  "SELECT * FROM pg_locks WHERE NOT granted;"
```

#### Solutions

**Connection pool exhausted:**
```bash
# Increase max connections in docker-compose.yml
DATABASE_MAX_CONNECTIONS=50

# Or kill idle connections
docker compose exec postgres psql -U triage_warden -c \
  "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
   WHERE datname = 'triage_warden' AND state = 'idle' AND pid <> pg_backend_pid();"
```

**PostgreSQL not ready:**
```bash
# Wait for PostgreSQL to be ready
until docker compose exec postgres pg_isready -U triage_warden; do
  echo "Waiting for PostgreSQL..."
  sleep 2
done
```

---

### Authentication Issues

#### Symptoms
- "Invalid credentials" on login
- "Session expired" errors
- API returns 401

#### Diagnosis
```bash
# Check if user exists
docker compose exec postgres psql -U triage_warden -c \
  "SELECT username, enabled, last_login_at FROM users;"

# Check session configuration
curl -s http://localhost:8080/health/detailed | jq '.components'
```

#### Solutions

**Reset admin password:**
```bash
# Generate new password hash (requires bcrypt)
NEW_HASH=$(htpasswd -bnBC 10 "" "newpassword" | tr -d ':\n')

# Update in database
docker compose exec postgres psql -U triage_warden -c \
  "UPDATE users SET password_hash = '$NEW_HASH' WHERE username = 'admin';"
```

**Clear sessions:**
```bash
docker compose exec postgres psql -U triage_warden -c \
  "DELETE FROM sessions;"
```

**User account disabled:**
```bash
docker compose exec postgres psql -U triage_warden -c \
  "UPDATE users SET enabled = true WHERE username = 'admin';"
```

---

### LLM/AI Features Not Working

#### Symptoms
- "LLM analysis failed" errors
- No AI verdicts on incidents
- Empty analysis in incident details

#### Diagnosis
```bash
# Check LLM configuration
curl -s http://localhost:8080/health/detailed | jq '.components.llm'

# Check for API key
docker compose exec triage-warden env | grep -E "(OPENAI|ANTHROPIC)_API_KEY"

# Check LLM settings in database
docker compose exec postgres psql -U triage_warden -c \
  "SELECT provider, model, enabled FROM settings WHERE key = 'llm';"
```

#### Solutions

**API key not configured:**
```bash
# Set via environment variable
echo "ANTHROPIC_API_KEY=sk-ant-..." >> .env
docker compose up -d
```

**LLM disabled:**
Configure via UI: Settings → AI/LLM → Enable toggle

**Rate limited:**
Check provider dashboard for rate limit status. Consider:
- Upgrading API tier
- Reducing temperature/max_tokens
- Adding request delays

---

### Connector Failures

#### Symptoms
- "Connector error" status in settings
- Failed enrichments
- Missing threat intel data

#### Diagnosis
```bash
# Check connector status
curl -s http://localhost:8080/health/detailed | jq '.components.connectors'

# Test specific connector
curl -X POST http://localhost:8080/api/connectors/{id}/test
```

#### Solutions by Connector

**VirusTotal:**
- Verify API key is valid
- Check rate limits (4 req/min for free tier)
- Ensure outbound HTTPS to virustotal.com allowed

**Jira:**
- Verify base URL (include `/rest/api/3`)
- Use API token, not password
- Check project key exists

**CrowdStrike:**
- Verify OAuth client credentials
- Check API scopes granted
- Verify region (us-1, us-2, eu-1)

**Splunk:**
- Verify HEC token is valid
- Check SSL certificate if using HTTPS
- Verify index exists

---

### High Memory Usage

#### Symptoms
- Container OOM killed
- Slow response times
- "Out of memory" errors

#### Diagnosis
```bash
# Check container memory
docker stats --no-stream triage-warden

# Check for memory leaks (trending)
docker stats triage-warden  # Watch over time
```

#### Solutions

**Increase memory limits:**
```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      memory: 4G
```

**Reduce connection pool:**
```bash
DATABASE_MAX_CONNECTIONS=5
```

**Enable garbage collection logging:**
```bash
RUST_LOG=info,triage_warden=debug
```

---

### Slow Performance

#### Symptoms
- High latency on API calls
- Dashboard loads slowly
- Timeouts on queries

#### Diagnosis
```bash
# Check response times
curl -w "@curl-format.txt" -s http://localhost:8080/health -o /dev/null

# Check database query times
docker compose exec postgres psql -U triage_warden -c \
  "SELECT query, mean_exec_time, calls FROM pg_stat_statements ORDER BY mean_exec_time DESC LIMIT 10;"

# Check for table bloat
docker compose exec postgres psql -U triage_warden -c \
  "SELECT relname, n_dead_tup, n_live_tup FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 10;"
```

#### Solutions

**Add database indexes:**
```sql
-- Common helpful indexes
CREATE INDEX idx_incidents_created_at ON incidents(created_at DESC);
CREATE INDEX idx_incidents_severity ON incidents(severity);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp DESC);
```

**Vacuum database:**
```bash
docker compose exec postgres psql -U triage_warden -c "VACUUM ANALYZE;"
```

**Enable query caching:**
Already enabled by default in connection pool.

---

### Kill Switch Issues

#### Symptoms
- Automation stopped unexpectedly
- "Kill switch active" warnings
- Actions blocked

#### Diagnosis
```bash
# Check kill switch status
curl -s http://localhost:8080/api/kill-switch | jq

# Check who activated it
curl -s http://localhost:8080/health/detailed | jq '.components.kill_switch'
```

#### Solutions

**Deactivate kill switch:**
```bash
curl -X POST http://localhost:8080/api/kill-switch/deactivate \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Confirmed safe to resume"}'
```

Or via UI: Settings → Safety → Re-enable Automation

---

### Webhook Not Receiving Events

#### Symptoms
- No incidents created from SIEM
- Webhook endpoint returns errors
- Events missing

#### Diagnosis
```bash
# Test webhook endpoint
curl -X POST http://localhost:8080/api/webhooks/generic \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Alert", "severity": "medium"}'

# Check webhook logs
docker compose logs triage-warden | grep -i webhook
```

#### Solutions

**Signature validation failing:**
- Verify webhook secret matches source configuration
- Check signature header name (X-Signature, X-Hub-Signature-256, etc.)

**Payload format incorrect:**
- Check source webhook format documentation
- Use generic webhook with custom mapping

**Firewall blocking:**
- Ensure source IP can reach webhook endpoint
- Check for WAF rules blocking requests

## Diagnostic Commands

### Get System Info

```bash
# Application version
curl -s http://localhost:8080/health | jq '.version'

# Database version
docker compose exec postgres psql -U triage_warden -c "SELECT version();"

# Container info
docker compose version
docker version
```

### Export Debug Bundle

```bash
#!/bin/bash
# Create debug bundle
BUNDLE_DIR="debug-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BUNDLE_DIR"

# Health check
curl -s http://localhost:8080/health/detailed > "$BUNDLE_DIR/health.json"

# Recent logs
docker compose logs --tail=1000 triage-warden > "$BUNDLE_DIR/app.log"
docker compose logs --tail=500 postgres > "$BUNDLE_DIR/db.log"

# Configuration (redacted)
docker compose config | grep -v -E "(PASSWORD|SECRET|KEY)" > "$BUNDLE_DIR/config.yml"

# Create archive
tar -czf "$BUNDLE_DIR.tar.gz" "$BUNDLE_DIR"
rm -rf "$BUNDLE_DIR"

echo "Debug bundle: $BUNDLE_DIR.tar.gz"
```

## Getting Help

If you can't resolve the issue:

1. Check [GitHub Issues](https://github.com/your-org/triage-warden/issues) for known issues
2. Create a new issue with:
   - Triage Warden version
   - Deployment method (Docker/K8s)
   - Error messages
   - Debug bundle (with secrets redacted)
3. Contact support: support@example.com
