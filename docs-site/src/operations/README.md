# Operations Guide

Operational procedures and runbooks for Triage Warden.

## Runbooks

- **[Backup & Restore](./backup-restore.md)** - Database backup and recovery procedures
- **[Monitoring](./monitoring.md)** - Prometheus metrics, alerting, and dashboards
- **[Troubleshooting](./troubleshooting.md)** - Common issues and solutions
- **[Maintenance](./maintenance.md)** - Routine maintenance tasks
- **[Incident Response](./incident-response.md)** - Emergency procedures
- **[Upgrade Guide](./upgrade.md)** - Version upgrade procedures

## Quick Reference

### Health Check Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `GET /live` | Liveness probe | `200 OK` |
| `GET /ready` | Readiness probe | `200 OK` if ready, `503` if not |
| `GET /health` | Basic health | JSON with status |
| `GET /health/detailed` | Full component health | JSON with all components |

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `http_requests_total` | Total HTTP requests | N/A |
| `http_request_duration_seconds` | Request latency | p99 > 1s |
| `http_requests_in_flight` | Concurrent requests | > 100 |
| `db_pool_connections_active` | Active DB connections | > 80% of max |
| `incidents_total` | Total incidents processed | N/A |
| `actions_executed_total` | Total actions executed | N/A |

### Emergency Contacts

| Role | Contact | Escalation |
|------|---------|------------|
| On-call Engineer | PagerDuty | Auto-escalates after 15m |
| Security Lead | security@example.com | Critical security issues |
| Database Admin | dba@example.com | Database emergencies |

## Common Commands

### Docker

```bash
# View logs
docker compose logs -f triage-warden

# Restart service
docker compose restart triage-warden

# Check health
curl http://localhost:8080/health | jq

# Database backup
docker compose exec postgres pg_dump -U triage_warden > backup.sql
```

### Kubernetes

```bash
# View logs
kubectl logs -f deployment/triage-warden -n triage-warden

# Restart pods
kubectl rollout restart deployment/triage-warden -n triage-warden

# Check health
kubectl exec -it deployment/triage-warden -n triage-warden -- curl -s localhost:8080/health | jq

# Scale up/down
kubectl scale deployment triage-warden -n triage-warden --replicas=5
```

### Database

```bash
# Connect to PostgreSQL
psql $DATABASE_URL

# Check active connections
SELECT count(*) FROM pg_stat_activity WHERE datname = 'triage_warden';

# Check table sizes
SELECT relname, pg_size_pretty(pg_total_relation_size(relid))
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;
```

## Service Dependencies

```
┌──────────────────┐
│  Triage Warden   │
└────────┬─────────┘
         │
    ┌────┴────┬─────────┬─────────┐
    │         │         │         │
    ▼         ▼         ▼         ▼
┌───────┐ ┌───────┐ ┌───────┐ ┌───────┐
│Postgres│ │  LLM  │ │Connec-│ │Notifi-│
│   DB   │ │  API  │ │ tors  │ │cations│
└───────┘ └───────┘ └───────┘ └───────┘
```

### Dependency Health Impact

| Dependency | If Unavailable |
|------------|----------------|
| PostgreSQL | Service fails readiness, no data access |
| LLM API | AI analysis disabled, manual triage only |
| Connectors | Specific integrations fail, core works |
| Notifications | Alerts not delivered, incidents still process |

## Scheduled Tasks

| Task | Schedule | Description |
|------|----------|-------------|
| Database backup | Daily 2:00 AM | Full PostgreSQL backup |
| Connector health check | Every 5 minutes | Verify connector connectivity |
| Incident cleanup | Weekly Sunday 3:00 AM | Archive old incidents |
| Log rotation | Daily | Rotate and compress logs |
| Certificate renewal | 30 days before expiry | Renew TLS certificates |
