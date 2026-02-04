# Horizontal Scaling Guide

This guide covers scaling Triage Warden horizontally to handle increased load and ensure high availability.

## Architecture Overview

Triage Warden consists of two main components that scale differently:

```
                    ┌─────────────────────┐
                    │   Load Balancer     │
                    │  (Traefik/nginx)    │
                    └──────────┬──────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│   API Server  │      │   API Server  │      │   API Server  │
│   (stateless) │      │   (stateless) │      │   (stateless) │
└───────┬───────┘      └───────┬───────┘      └───────┬───────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│ Orchestrator  │      │ Orchestrator  │      │ Orchestrator  │
│   (worker)    │      │   (worker)    │      │   (leader)    │
└───────┬───────┘      └───────┬───────┘      └───────┬───────┘
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               │
        ┌──────────────────────┼──────────────────────┐
        │                      │                      │
        ▼                      ▼                      ▼
┌───────────────┐      ┌───────────────┐      ┌───────────────┐
│    Redis      │      │  PostgreSQL   │      │  PostgreSQL   │
│  (MQ + Cache) │      │   (primary)   │      │   (replica)   │
└───────────────┘      └───────────────┘      └───────────────┘
```

## Scaling Components

### API Servers

API servers are **stateless** and can be scaled horizontally without coordination.

**When to Scale**:
- CPU utilization > 70% sustained
- Request latency P99 > 500ms
- Concurrent connections approaching limits

**Scaling Method**:

```yaml
# Kubernetes HPA
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: triage-warden-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: triage-warden-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

**Helm Configuration**:

```yaml
api:
  replicas: 3
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

### Orchestrators

Orchestrators process incidents asynchronously. They use **leader election** for singleton tasks (scheduled jobs, metrics aggregation) while allowing parallel incident processing across all instances.

**When to Scale**:
- Incident queue depth increasing
- Mean time to triage increasing
- Worker CPU utilization > 70%

**Scaling Considerations**:

1. **Leader Tasks**: Only one orchestrator runs scheduled jobs
2. **Worker Tasks**: All orchestrators process incidents from the queue
3. **State Sharing**: Uses Redis for message queue and coordination

**Configuration**:

```yaml
orchestrator:
  replicas: 3
  leaderElection:
    enabled: true
    leaseDuration: 15s
    renewDeadline: 10s
    retryPeriod: 2s
```

## When to Scale

### Metrics to Monitor

| Metric | Warning Threshold | Critical Threshold | Action |
|--------|-------------------|-------------------|--------|
| `http_request_duration_seconds` P99 | > 500ms | > 1s | Scale API |
| `cpu_usage_percent` | > 70% | > 85% | Scale component |
| `memory_usage_percent` | > 80% | > 90% | Scale or optimize |
| `incident_queue_depth` | > 100 | > 500 | Scale orchestrators |
| `db_connection_pool_waiting` | > 0 | > 5 | Increase pool size |
| `redis_connected_clients` | > 80% max | > 95% max | Scale Redis |

### Capacity Planning

**API Server Capacity** (per instance):
- ~500 requests/second (simple endpoints)
- ~100 requests/second (complex queries)
- ~50 concurrent WebSocket connections

**Orchestrator Capacity** (per instance):
- ~10 concurrent incident processing
- ~5 concurrent LLM analysis calls
- ~20 concurrent enrichment requests

### Scaling Decision Matrix

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| High API latency | API overloaded | Scale API servers |
| Growing queue depth | Orchestrators overloaded | Scale orchestrators |
| Database timeouts | Connection exhaustion | Increase pool, add replicas |
| Cache misses high | Cache too small | Increase Redis memory |
| LLM rate limits | Too many concurrent calls | Add rate limiting, queue |

## Database Scaling

### Connection Pooling

Each instance maintains a connection pool. Total connections:

```
Total = API_instances * pool_size + Orchestrator_instances * pool_size
```

**Example**: 3 API + 2 Orchestrator with pool_size=15:
```
Total = (3 * 15) + (2 * 15) = 75 connections
```

**Configuration**:

```yaml
database:
  max_connections: 15  # Per instance
  min_connections: 2
  connect_timeout: 30
```

### Read Replicas

For read-heavy workloads, configure read replicas:

```yaml
database:
  primary_url: "postgres://user:pass@primary:5432/db"
  replica_url: "postgres://user:pass@replica:5432/db"
  read_replica_enabled: true
```

### Connection Pooler (PgBouncer)

For large deployments, use PgBouncer:

```yaml
# Kubernetes ConfigMap for PgBouncer
apiVersion: v1
kind: ConfigMap
metadata:
  name: pgbouncer-config
data:
  pgbouncer.ini: |
    [databases]
    triage_warden = host=postgres port=5432 dbname=triage_warden

    [pgbouncer]
    listen_port = 6432
    listen_addr = 0.0.0.0
    auth_type = md5
    pool_mode = transaction
    max_client_conn = 1000
    default_pool_size = 50
```

## Redis Scaling

### Standalone vs Cluster

**Standalone** (default): Suitable for most deployments
- Up to ~100k ops/second
- Single point of failure (use replica for HA)

**Cluster**: For high-throughput requirements
- Horizontal scaling across nodes
- Automatic sharding

### Redis Configuration

```yaml
redis:
  architecture: replication  # standalone, replication, cluster
  master:
    resources:
      limits:
        memory: 2Gi
  replica:
    replicaCount: 2
```

### Cache Sizing

Calculate cache memory needs:

```
Memory = average_entry_size * expected_entries * 1.5 (overhead)
```

**Example**: 1KB average, 100k entries:
```
Memory = 1KB * 100,000 * 1.5 = 150MB
```

## Load Balancer Configuration

### Health Checks

Configure proper health checks for load balancing:

```yaml
# Traefik
- "traefik.http.services.api.loadbalancer.healthcheck.path=/ready"
- "traefik.http.services.api.loadbalancer.healthcheck.interval=5s"
- "traefik.http.services.api.loadbalancer.healthcheck.timeout=3s"
```

### Session Affinity

For WebSocket connections, enable sticky sessions:

```yaml
# Traefik
- "traefik.http.services.api.loadbalancer.sticky.cookie.name=tw_server"
- "traefik.http.services.api.loadbalancer.sticky.cookie.httpOnly=true"
```

### Rate Limiting

Configure rate limiting at the load balancer level:

```yaml
# Traefik rate limiting middleware
http:
  middlewares:
    rate-limit:
      rateLimit:
        average: 100
        burst: 50
        period: 1s
```

## Kubernetes Autoscaling

### Horizontal Pod Autoscaler (HPA)

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: triage-warden-api
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: triage-warden-api
  minReplicas: 2
  maxReplicas: 10
  metrics:
    # CPU-based scaling
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    # Memory-based scaling
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    # Custom metric scaling (requires Prometheus adapter)
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "100"
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300  # 5 min cooldown
      policies:
        - type: Percent
          value: 10
          periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 0
      policies:
        - type: Percent
          value: 100
          periodSeconds: 15
```

### Vertical Pod Autoscaler (VPA)

For automatic resource adjustment:

```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: triage-warden-api
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: triage-warden-api
  updatePolicy:
    updateMode: "Auto"  # or "Off" for recommendations only
  resourcePolicy:
    containerPolicies:
      - containerName: triage-warden
        minAllowed:
          cpu: 250m
          memory: 256Mi
        maxAllowed:
          cpu: 4
          memory: 4Gi
```

### Pod Disruption Budget

Ensure availability during scaling:

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: triage-warden-api
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
      app.kubernetes.io/component: api
```

## Scaling Best Practices

### 1. Scale Gradually

- Increase by 25-50% at a time
- Monitor for 10-15 minutes before next scale
- Watch for downstream bottlenecks

### 2. Test Scale Limits

```bash
# Load testing with k6
k6 run --vus 100 --duration 5m load-test.js
```

### 3. Set Resource Limits

```yaml
resources:
  requests:
    cpu: 500m
    memory: 512Mi
  limits:
    cpu: 2000m
    memory: 2Gi
```

### 4. Use Pod Anti-Affinity

Spread pods across nodes:

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: triage-warden
          topologyKey: kubernetes.io/hostname
```

### 5. Configure Topology Spread

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: triage-warden
```

## Troubleshooting Scaling Issues

### Pods Not Scaling Up

```bash
# Check HPA status
kubectl describe hpa triage-warden-api

# Check metrics availability
kubectl get --raw "/apis/metrics.k8s.io/v1beta1/pods" | jq

# Check events
kubectl get events --sort-by='.lastTimestamp' | grep -i scale
```

### Pods Stuck Pending

```bash
# Check node resources
kubectl describe nodes | grep -A 5 "Allocated resources"

# Check pod events
kubectl describe pod <pod-name> | grep -A 10 Events
```

### Scaling Oscillation

If pods scale up and down frequently:

1. Increase stabilization window
2. Adjust metric thresholds
3. Add cooldown periods

```yaml
behavior:
  scaleDown:
    stabilizationWindowSeconds: 600  # 10 min
```

## Next Steps

- Set up [monitoring](./monitoring.md) for scaling metrics
- Review [configuration options](../deployment/configuration.md)
- Configure [Kubernetes deployment](../deployment/kubernetes.md)
