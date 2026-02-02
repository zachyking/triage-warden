# Monitoring Guide

Set up monitoring and alerting for Triage Warden.

## Prometheus Metrics

Triage Warden exposes metrics at `GET /metrics` in Prometheus format.

### Available Metrics

#### HTTP Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | Request latency |
| `http_requests_in_flight` | Gauge | Current concurrent requests |
| `http_response_size_bytes` | Histogram | Response body sizes |

Labels: `method`, `path`, `status`

#### Database Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `db_pool_connections_total` | Gauge | Total pool connections |
| `db_pool_connections_active` | Gauge | Active connections |
| `db_pool_connections_idle` | Gauge | Idle connections |
| `db_query_duration_seconds` | Histogram | Query execution time |

#### Application Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `incidents_total` | Counter | Total incidents created |
| `incidents_by_severity` | Gauge | Incidents by severity |
| `actions_executed_total` | Counter | Total actions executed |
| `actions_by_type` | Counter | Actions by type |
| `playbook_executions_total` | Counter | Playbook executions |
| `llm_requests_total` | Counter | LLM API requests |
| `llm_request_duration_seconds` | Histogram | LLM request latency |
| `llm_tokens_used_total` | Counter | Total LLM tokens used |

#### Component Health

| Metric | Type | Description |
|--------|------|-------------|
| `component_healthy` | Gauge | Component health (1=healthy, 0=unhealthy) |
| `kill_switch_active` | Gauge | Kill switch status (1=active, 0=inactive) |

Labels: `component` (database, llm, connector_name)

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'triage-warden'
    scrape_interval: 15s
    static_configs:
      - targets: ['triage-warden:8080']
    metrics_path: /metrics
```

### Kubernetes ServiceMonitor

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: triage-warden
  namespace: triage-warden
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
```

## Alerting Rules

### Critical Alerts

```yaml
# alerts.yml
groups:
  - name: triage-warden-critical
    rules:
      - alert: TriageWardenDown
        expr: up{job="triage-warden"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Triage Warden is down"
          description: "Triage Warden has been unreachable for more than 2 minutes."
          runbook_url: "https://docs.example.com/runbooks/service-down"

      - alert: TriageWardenDatabaseDown
        expr: component_healthy{component="database"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection lost"
          description: "Triage Warden cannot connect to the database."

      - alert: TriageWardenHighErrorRate
        expr: |
          sum(rate(http_requests_total{job="triage-warden",status=~"5.."}[5m])) /
          sum(rate(http_requests_total{job="triage-warden"}[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "More than 5% of requests are failing."
```

### Warning Alerts

```yaml
  - name: triage-warden-warning
    rules:
      - alert: TriageWardenKillSwitchActive
        expr: kill_switch_active == 1
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Kill switch is active"
          description: "All automation has been halted."

      - alert: TriageWardenConnectorUnhealthy
        expr: component_healthy{component=~"connector_.*"} == 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Connector {{ $labels.component }} is unhealthy"
          description: "Connector has been unhealthy for more than 10 minutes."

      - alert: TriageWardenHighLatency
        expr: |
          histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High API latency"
          description: "P99 latency is above 1 second."

      - alert: TriageWardenLLMErrors
        expr: |
          rate(llm_requests_total{status="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "LLM API errors increasing"
          description: "LLM requests are failing frequently."

      - alert: TriageWardenDatabasePoolExhausted
        expr: |
          db_pool_connections_active / db_pool_connections_total > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool nearly exhausted"
          description: "More than 90% of database connections are in use."
```

## Grafana Dashboards

### Overview Dashboard

Import the dashboard from `deploy/grafana/triage-warden-overview.json` or use this JSON:

```json
{
  "title": "Triage Warden Overview",
  "panels": [
    {
      "title": "Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "sum(rate(http_requests_total{job=\"triage-warden\"}[5m]))",
          "legendFormat": "Requests/sec"
        }
      ]
    },
    {
      "title": "Error Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "sum(rate(http_requests_total{job=\"triage-warden\",status=~\"5..\"}[5m]))",
          "legendFormat": "5xx/sec"
        }
      ]
    },
    {
      "title": "Latency (P99)",
      "type": "graph",
      "targets": [
        {
          "expr": "histogram_quantile(0.99, rate(http_request_duration_seconds_bucket{job=\"triage-warden\"}[5m]))",
          "legendFormat": "P99 Latency"
        }
      ]
    },
    {
      "title": "Incidents by Severity",
      "type": "piechart",
      "targets": [
        {
          "expr": "incidents_by_severity",
          "legendFormat": "{{ severity }}"
        }
      ]
    }
  ]
}
```

### Key Panels to Include

1. **Service Health**
   - Uptime percentage
   - Component health status
   - Kill switch status

2. **Traffic**
   - Request rate over time
   - Requests by endpoint
   - Response codes distribution

3. **Performance**
   - P50, P95, P99 latency
   - Database query times
   - LLM response times

4. **Business Metrics**
   - Incidents created per hour
   - Actions executed per hour
   - Playbook execution success rate

## Log Aggregation

### Structured Logging

Triage Warden outputs JSON logs by default:

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "target": "triage_warden::api",
  "message": "Request completed",
  "method": "GET",
  "path": "/api/incidents",
  "status": 200,
  "duration_ms": 45,
  "request_id": "abc123"
}
```

### Log Queries

**Find errors:**
```
level:ERROR
```

**Slow requests:**
```
duration_ms:>1000
```

**Specific user actions:**
```
user.id:"user-uuid" AND target:*auth*
```

### Loki Configuration

```yaml
# promtail.yml
scrape_configs:
  - job_name: triage-warden
    docker_sd_configs:
      - host: unix:///var/run/docker.sock
    relabel_configs:
      - source_labels: ['__meta_docker_container_name']
        regex: '/triage-warden'
        action: keep
    pipeline_stages:
      - json:
          expressions:
            level: level
            target: target
      - labels:
          level:
          target:
```

## Health Check Monitoring

### Synthetic Monitoring

```yaml
# blackbox-exporter probe
modules:
  http_triage_warden:
    prober: http
    timeout: 5s
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: [200]
      method: GET
      fail_if_body_not_matches_regexp:
        - '"status":"healthy"'
```

### Uptime Monitoring

Configure external uptime monitoring (Pingdom, UptimeRobot, etc.) to check:

- `https://triage.example.com/live` - Basic availability
- `https://triage.example.com/ready` - Full readiness

## SLO/SLI Definitions

### Availability SLO

**Target: 99.9% availability**

```promql
# SLI: Successful requests / Total requests
sum(rate(http_requests_total{job="triage-warden",status!~"5.."}[30d])) /
sum(rate(http_requests_total{job="triage-warden"}[30d]))
```

### Latency SLO

**Target: 99% of requests < 500ms**

```promql
# SLI: Requests under threshold / Total requests
sum(rate(http_request_duration_seconds_bucket{job="triage-warden",le="0.5"}[30d])) /
sum(rate(http_request_duration_seconds_count{job="triage-warden"}[30d]))
```

### Error Budget

```promql
# Remaining error budget
1 - (
  (1 - (sum(rate(http_requests_total{status!~"5.."}[30d])) / sum(rate(http_requests_total[30d])))) /
  (1 - 0.999)
)
```
