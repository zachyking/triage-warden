# Monitoring Guide

This guide covers monitoring, metrics, and alerting for Triage Warden deployments.

## Overview

Triage Warden exposes metrics in Prometheus format and supports integration with common observability stacks.

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring Stack                          │
│                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │  Prometheus  │───▶│   Grafana    │    │ Alertmanager │  │
│  │  (scraping)  │    │ (dashboards) │    │  (alerts)    │  │
│  └──────┬───────┘    └──────────────┘    └──────────────┘  │
│         │                                                    │
└─────────┼────────────────────────────────────────────────────┘
          │
          │ /metrics
          │
┌─────────▼────────────────────────────────────────────────────┐
│                    Triage Warden                              │
│  ┌───────────┐  ┌───────────┐  ┌─────────────┐              │
│  │ API-1     │  │ API-2     │  │Orchestrator │              │
│  │ :8080     │  │ :8080     │  │    :8080    │              │
│  └───────────┘  └───────────┘  └─────────────┘              │
└──────────────────────────────────────────────────────────────┘
```

## Metrics Endpoints

| Endpoint | Format | Description |
|----------|--------|-------------|
| `/metrics` | Prometheus | Prometheus-compatible metrics |
| `/api/metrics` | JSON | Dashboard-friendly JSON format |
| `/health` | JSON | Basic health status |
| `/health/detailed` | JSON | Comprehensive health including components |

## Available Metrics

### HTTP Metrics

```prometheus
# Request counter by method, path, status
http_requests_total{method="GET", path="/api/incidents", status="200"} 1234

# Request duration histogram
http_request_duration_seconds_bucket{method="GET", path="/api/incidents", le="0.1"} 900
http_request_duration_seconds_bucket{method="GET", path="/api/incidents", le="0.5"} 1100
http_request_duration_seconds_bucket{method="GET", path="/api/incidents", le="1.0"} 1200

# Active connections
http_connections_active 42
```

### Incident Metrics

```prometheus
# Total incidents by severity and status
triage_warden_incidents_total{severity="critical", status="new"} 5
triage_warden_incidents_total{severity="high", status="resolved"} 128

# Incidents currently being processed
triage_warden_incidents_in_progress 12

# Triage duration histogram
triage_warden_triage_duration_seconds_bucket{le="60"} 500
triage_warden_triage_duration_seconds_bucket{le="300"} 800
```

### Action Metrics

```prometheus
# Actions by type and status
triage_warden_actions_total{action_type="isolate_host", status="success"} 45
triage_warden_actions_total{action_type="isolate_host", status="failed"} 2

# Pending approvals
triage_warden_actions_pending_approval 8

# Action execution duration
triage_warden_action_duration_seconds_bucket{action_type="isolate_host", le="30"} 40
```

### System Metrics

```prometheus
# Kill switch status
kill_switch_active 0

# Component health (1=healthy, 0=unhealthy)
component_healthy{component="database"} 1
component_healthy{component="redis"} 1
component_healthy{component="connector_crowdstrike"} 1

# Database connection pool
db_pool_connections_total 25
db_pool_connections_idle 20
db_pool_connections_waiting 0

# Cache statistics
cache_hits_total 10000
cache_misses_total 500
cache_size 2500
```

### LLM Metrics

```prometheus
# LLM API calls by provider and model
llm_requests_total{provider="anthropic", model="claude-3-sonnet"} 500

# LLM latency
llm_request_duration_seconds_bucket{provider="anthropic", le="5"} 400
llm_request_duration_seconds_bucket{provider="anthropic", le="30"} 490

# Token usage
llm_tokens_used_total{provider="anthropic", type="input"} 150000
llm_tokens_used_total{provider="anthropic", type="output"} 75000
```

### Message Queue Metrics

```prometheus
# Queue depth by topic
mq_messages_pending{topic="triage.alerts"} 15
mq_messages_pending{topic="triage.enrichment"} 3

# Message processing rate
mq_messages_processed_total{topic="triage.alerts"} 5000
mq_messages_acknowledged_total{topic="triage.alerts"} 4995
```

## Prometheus Configuration

### Basic Scrape Config

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'triage-warden'
    static_configs:
      - targets:
          - 'triage-warden-api:8080'
          - 'triage-warden-orchestrator:8080'
    metrics_path: /metrics
    scrape_interval: 15s
    scrape_timeout: 10s
```

### Kubernetes ServiceMonitor

For Prometheus Operator deployments:

```yaml
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: triage-warden
  labels:
    release: prometheus
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
  namespaceSelector:
    matchNames:
      - triage-warden
  endpoints:
    - port: http
      path: /metrics
      interval: 15s
      scrapeTimeout: 10s
```

### Pod Annotations (Alternative)

If using annotation-based discovery:

```yaml
metadata:
  annotations:
    prometheus.io/scrape: "true"
    prometheus.io/port: "8080"
    prometheus.io/path: "/metrics"
```

## Alerting Rules

### PrometheusRule Resource

```yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: triage-warden-alerts
  labels:
    release: prometheus
spec:
  groups:
    - name: triage-warden.availability
      rules:
        # Service Down
        - alert: TriageWardenDown
          expr: up{job="triage-warden"} == 0
          for: 2m
          labels:
            severity: critical
          annotations:
            summary: "Triage Warden instance is down"
            description: "{{ $labels.instance }} has been unreachable for more than 2 minutes."

        # High Error Rate
        - alert: TriageWardenHighErrorRate
          expr: |
            sum(rate(http_requests_total{job="triage-warden",status=~"5.."}[5m])) /
            sum(rate(http_requests_total{job="triage-warden"}[5m])) > 0.05
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "High error rate detected"
            description: "More than 5% of requests are returning 5xx errors."

        # Database Unhealthy
        - alert: TriageWardenDatabaseUnhealthy
          expr: component_healthy{job="triage-warden",component="database"} == 0
          for: 1m
          labels:
            severity: critical
          annotations:
            summary: "Database connection lost"
            description: "Triage Warden cannot connect to the database."

    - name: triage-warden.performance
      rules:
        # High Latency
        - alert: TriageWardenHighLatency
          expr: |
            histogram_quantile(0.99,
              rate(http_request_duration_seconds_bucket{job="triage-warden"}[5m])
            ) > 1
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "High API latency"
            description: "P99 latency is above 1 second for the last 10 minutes."

        # Slow Triage Time
        - alert: TriageWardenSlowTriage
          expr: |
            histogram_quantile(0.90,
              rate(triage_warden_triage_duration_seconds_bucket[1h])
            ) > 300
          for: 30m
          labels:
            severity: warning
          annotations:
            summary: "Incident triage taking too long"
            description: "P90 triage duration is above 5 minutes."

    - name: triage-warden.operations
      rules:
        # Kill Switch Active
        - alert: TriageWardenKillSwitchActive
          expr: kill_switch_active == 1
          for: 0m
          labels:
            severity: warning
          annotations:
            summary: "Kill switch is active"
            description: "All automation has been halted by the kill switch."

        # High Pending Approvals
        - alert: TriageWardenHighPendingApprovals
          expr: triage_warden_actions_pending_approval > 50
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "High number of pending approvals"
            description: "{{ $value }} actions are waiting for approval."

        # Connector Unhealthy
        - alert: TriageWardenConnectorUnhealthy
          expr: component_healthy{component=~"connector_.*"} == 0
          for: 10m
          labels:
            severity: warning
          annotations:
            summary: "Connector {{ $labels.component }} is unhealthy"
            description: "Connector has been unhealthy for more than 10 minutes."

        # Queue Backlog
        - alert: TriageWardenQueueBacklog
          expr: mq_messages_pending{topic="triage.alerts"} > 100
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "Alert queue backlog growing"
            description: "{{ $value }} unprocessed alerts in queue."

    - name: triage-warden.resources
      rules:
        # High CPU
        - alert: TriageWardenHighCPU
          expr: |
            sum(rate(container_cpu_usage_seconds_total{
              container="triage-warden"
            }[5m])) by (pod) > 0.8
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "High CPU usage"
            description: "Pod {{ $labels.pod }} CPU usage above 80%."

        # High Memory
        - alert: TriageWardenHighMemory
          expr: |
            container_memory_usage_bytes{container="triage-warden"} /
            container_spec_memory_limit_bytes{container="triage-warden"} > 0.9
          for: 15m
          labels:
            severity: warning
          annotations:
            summary: "High memory usage"
            description: "Pod {{ $labels.pod }} memory usage above 90%."

        # Database Connection Exhaustion
        - alert: TriageWardenDBConnectionsLow
          expr: db_pool_connections_idle < 2
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "Database connection pool nearly exhausted"
            description: "Only {{ $value }} idle connections remaining."
```

## Key Metrics to Monitor

### SLI/SLO Recommendations

| Indicator | Target | Alert Threshold |
|-----------|--------|-----------------|
| Availability | 99.9% | < 99.5% |
| API Latency P99 | < 500ms | > 1s |
| Error Rate | < 0.1% | > 1% |
| Triage Time P90 | < 5min | > 10min |

### Dashboard Panels

**Overview**:
- Instance count and status
- Requests per second
- Error rate percentage
- Active incidents

**Performance**:
- Request latency histogram
- Database query duration
- LLM response time
- Cache hit ratio

**Operations**:
- Incidents by severity/status
- Actions executed vs pending
- Queue depths
- Connector health matrix

**Resources**:
- CPU utilization by instance
- Memory utilization by instance
- Database connections
- Redis memory usage

## Grafana Dashboards

### Importing Dashboards

Triage Warden provides pre-built Grafana dashboards:

```bash
# Download dashboard JSON
curl -o triage-warden-dashboard.json \
  https://raw.githubusercontent.com/triage-warden/triage-warden/main/deploy/grafana/dashboards/overview.json

# Import via Grafana API
curl -X POST -H "Content-Type: application/json" \
  -d @triage-warden-dashboard.json \
  http://admin:admin@localhost:3000/api/dashboards/db
```

### Dashboard Provisioning

For automatic dashboard provisioning in Kubernetes:

```yaml
# ConfigMap for dashboard provisioning
apiVersion: v1
kind: ConfigMap
metadata:
  name: grafana-dashboards
  labels:
    grafana_dashboard: "1"
data:
  triage-warden.json: |
    {
      "dashboard": {
        "title": "Triage Warden",
        "panels": [...]
      }
    }
```

### Example Panel Queries

**Requests per Second**:
```promql
sum(rate(http_requests_total{job="triage-warden"}[5m]))
```

**Error Rate**:
```promql
sum(rate(http_requests_total{job="triage-warden",status=~"5.."}[5m])) /
sum(rate(http_requests_total{job="triage-warden"}[5m])) * 100
```

**P99 Latency**:
```promql
histogram_quantile(0.99,
  sum(rate(http_request_duration_seconds_bucket{job="triage-warden"}[5m])) by (le)
)
```

**Incidents by Status**:
```promql
triage_warden_incidents_total{job="triage-warden"}
```

**Cache Hit Ratio**:
```promql
sum(rate(cache_hits_total[5m])) /
(sum(rate(cache_hits_total[5m])) + sum(rate(cache_misses_total[5m]))) * 100
```

## Logging

### Log Format

Triage Warden outputs structured JSON logs:

```json
{
  "timestamp": "2024-01-15T10:30:00.000Z",
  "level": "info",
  "target": "tw_api::routes::incidents",
  "message": "Incident created",
  "incident_id": "123e4567-e89b-12d3-a456-426614174000",
  "severity": "high",
  "source": "crowdstrike",
  "trace_id": "abc123",
  "span_id": "def456"
}
```

### Log Aggregation

**Loki Configuration**:

```yaml
# promtail config
scrape_configs:
  - job_name: triage-warden
    kubernetes_sd_configs:
      - role: pod
    relabel_configs:
      - source_labels: [__meta_kubernetes_pod_label_app_kubernetes_io_name]
        regex: triage-warden
        action: keep
    pipeline_stages:
      - json:
          expressions:
            level: level
            incident_id: incident_id
            trace_id: trace_id
      - labels:
          level:
          incident_id:
```

**Elasticsearch/Fluentd**:

```yaml
# Fluentd config
<match kubernetes.var.log.containers.triage-warden**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name triage-warden
  <buffer>
    @type file
    path /var/log/fluentd-buffers/triage-warden
  </buffer>
</match>
```

## Distributed Tracing

### OpenTelemetry Configuration

```bash
# Environment variables
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_SERVICE_NAME=triage-warden
OTEL_TRACES_EXPORTER=otlp
```

### Trace Propagation

Triage Warden propagates trace context through:
- HTTP headers (W3C Trace Context)
- Message queue metadata
- Internal async tasks

## Health Check Integration

### Kubernetes Probes

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 3
```

### Health Status Interpretation

| Status | HTTP Code | Meaning |
|--------|-----------|---------|
| healthy | 200 | All systems operational |
| degraded | 200 | Non-critical issues |
| unhealthy | 503 | Critical component failure |
| halted | 200 | Kill switch active |

## Troubleshooting with Metrics

### High Latency Investigation

```promql
# Identify slow endpoints
topk(5,
  histogram_quantile(0.99,
    sum(rate(http_request_duration_seconds_bucket[5m])) by (path, le)
  )
)

# Check database query time
histogram_quantile(0.99,
  rate(db_query_duration_seconds_bucket[5m])
)
```

### Memory Issues

```promql
# Memory growth rate
deriv(process_resident_memory_bytes{job="triage-warden"}[1h])

# Compare to limits
container_memory_usage_bytes / container_spec_memory_limit_bytes
```

### Queue Bottlenecks

```promql
# Processing rate vs arrival rate
rate(mq_messages_processed_total[5m]) - rate(mq_messages_received_total[5m])

# Time in queue
histogram_quantile(0.95, rate(mq_message_wait_seconds_bucket[5m]))
```

## Next Steps

- Configure [horizontal scaling](./scaling.md) based on metrics
- Review [configuration options](../deployment/configuration.md)
- Set up [Kubernetes deployment](../deployment/kubernetes.md)
