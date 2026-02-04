# Triage Warden Helm Chart

A Helm chart for deploying Triage Warden security automation platform to Kubernetes.

## Overview

Triage Warden is a security automation platform that helps security teams triage and respond to incidents more efficiently. This Helm chart deploys the following components:

- **API Server**: Handles HTTP requests, webhooks, and serves the web UI
- **Orchestrator**: Manages background tasks, scheduling, and automation workflows

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (if using persistent storage)
- **External PostgreSQL** database (required)
- **External Redis** instance (optional, required for distributed deployments)

### Required External Services

This chart does **not** bundle PostgreSQL or Redis. You must provision these services separately:

**PostgreSQL 14+**
- Recommended: Use a managed service (AWS RDS, Google Cloud SQL, Azure Database for PostgreSQL)
- Or deploy using the [Bitnami PostgreSQL chart](https://artifacthub.io/packages/helm/bitnami/postgresql)

**Redis 7+ (Optional)**
- Required for: distributed caching, message queues, leader election
- Recommended: Use a managed service (AWS ElastiCache, Google Memorystore)
- Or deploy using the [Bitnami Redis chart](https://artifacthub.io/packages/helm/bitnami/redis)

## Installation

### Quick Start (Development)

```bash
# Add your values file
cat > my-values.yaml << EOF
postgresql:
  host: "postgres.default.svc.cluster.local"
  port: 5432
  database: "triage_warden"
  username: "triage"
  password: "your-password"

secrets:
  encryptionKey: "$(openssl rand -base64 32)"
  jwtSecret: "$(openssl rand -hex 32)"
  sessionSecret: "$(openssl rand -hex 32)"

config:
  enableSwagger: true
  secureCookies: false
EOF

# Install the chart
helm install triage-warden ./helm/triage-warden -f my-values.yaml
```

### Production Installation

```bash
# Create namespace
kubectl create namespace triage-warden

# Create secrets (recommended: use external secrets manager)
kubectl create secret generic triage-warden-secrets \
  --namespace triage-warden \
  --from-literal=TW_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=TW_JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=TW_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl create secret generic postgresql-credentials \
  --namespace triage-warden \
  --from-literal=postgresql-password="your-db-password"

# Create values file
cat > production-values.yaml << EOF
image:
  repository: ghcr.io/triage-warden/triage-warden
  tag: "0.1.0"

api:
  replicas: 3
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

postgresql:
  host: "your-postgres-host.rds.amazonaws.com"
  port: 5432
  database: "triage_warden"
  username: "triage"
  existingSecret: "postgresql-credentials"
  sslMode: "require"

secrets:
  create: false
  existingSecret: "triage-warden-secrets"

config:
  baseUrl: "https://triage.company.com"
  logLevel: "info"
  logFormat: "json"
  secureCookies: true

ingress:
  enabled: true
  className: nginx
  hosts:
    - host: triage.company.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: triage-warden-tls
      hosts:
        - triage.company.com

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

serviceMonitor:
  enabled: true
  labels:
    release: prometheus
EOF

# Install
helm install triage-warden ./helm/triage-warden \
  --namespace triage-warden \
  -f production-values.yaml
```

## Configuration

### Parameters

#### Global Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imagePullSecrets` | Global image pull secrets | `[]` |
| `global.nameOverride` | Override chart name | `""` |
| `global.fullnameOverride` | Override full name | `""` |

#### Image Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `image.repository` | Image repository | `ghcr.io/triage-warden/triage-warden` |
| `image.tag` | Image tag | `""` (defaults to Chart.appVersion) |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |

#### API Server Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.enabled` | Enable API server | `true` |
| `api.replicas` | Number of replicas | `2` |
| `api.resources.requests.cpu` | CPU request | `100m` |
| `api.resources.requests.memory` | Memory request | `256Mi` |
| `api.resources.limits.cpu` | CPU limit | `500m` |
| `api.resources.limits.memory` | Memory limit | `512Mi` |
| `api.podAntiAffinityPreset` | Pod anti-affinity preset | `soft` |

#### Orchestrator Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `orchestrator.enabled` | Enable Orchestrator | `true` |
| `orchestrator.replicas` | Number of replicas | `1` |
| `orchestrator.resources.requests.cpu` | CPU request | `100m` |
| `orchestrator.resources.requests.memory` | Memory request | `256Mi` |

#### PostgreSQL Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.host` | PostgreSQL host (required) | `""` |
| `postgresql.port` | PostgreSQL port | `5432` |
| `postgresql.database` | Database name | `triage_warden` |
| `postgresql.username` | Database username | `triage` |
| `postgresql.existingSecret` | Existing secret with password | `""` |
| `postgresql.password` | Database password (not recommended) | `""` |
| `postgresql.sslMode` | SSL mode | `require` |

#### Redis Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `redis.enabled` | Enable Redis integration | `false` |
| `redis.host` | Redis host | `""` |
| `redis.port` | Redis port | `6379` |
| `redis.existingSecret` | Existing secret with password | `""` |
| `redis.tls` | Enable TLS | `false` |

#### Ingress Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `nginx` |
| `ingress.hosts` | Ingress hosts | `[]` |
| `ingress.tls` | TLS configuration | `[]` |

#### Autoscaling Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `autoscaling.targetCPUUtilizationPercentage` | Target CPU % | `80` |

#### Monitoring Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |
| `serviceMonitor.interval` | Scrape interval | `15s` |
| `prometheusRules.enabled` | Enable PrometheusRule | `false` |

See `values.yaml` for the complete list of configurable parameters.

## Deployment Scenarios

### Single-Instance Development

```yaml
api:
  replicas: 1

orchestrator:
  replicas: 1

autoscaling:
  enabled: false

podDisruptionBudget:
  enabled: false

config:
  enableSwagger: true
  secureCookies: false
```

### Multi-Instance Production

```yaml
api:
  replicas: 3
  podAntiAffinityPreset: soft

orchestrator:
  replicas: 1

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10

podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

### High Availability Setup

```yaml
api:
  replicas: 5
  podAntiAffinityPreset: hard
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels:
          app.kubernetes.io/component: api

redis:
  enabled: true
  host: "redis-master.redis.svc.cluster.local"

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20

podDisruptionBudget:
  enabled: true
  minAvailable: 2

networkPolicy:
  enabled: true
```

## External Secrets Integration

### Using External Secrets Operator

```yaml
secrets:
  create: false
  existingSecret: "triage-warden-external"

# Then create an ExternalSecret:
# apiVersion: external-secrets.io/v1beta1
# kind: ExternalSecret
# metadata:
#   name: triage-warden-external
# spec:
#   refreshInterval: 1h
#   secretStoreRef:
#     name: vault-backend
#     kind: ClusterSecretStore
#   target:
#     name: triage-warden-external
#   data:
#     - secretKey: TW_ENCRYPTION_KEY
#       remoteRef:
#         key: secret/triage-warden
#         property: encryption-key
```

### Using AWS Secrets Manager with IRSA

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/triage-warden-role
```

## Monitoring

### Prometheus Integration

Enable the ServiceMonitor for automatic Prometheus scraping:

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus  # Match your Prometheus Operator selector

prometheusRules:
  enabled: true
  labels:
    release: prometheus
```

### Available Alerts

- `TriageWardenDown` - Instance unreachable for 2+ minutes
- `TriageWardenHighErrorRate` - 5xx errors exceed 5%
- `TriageWardenKillSwitchActive` - Kill switch activated
- `TriageWardenDatabaseUnhealthy` - Database connection issues
- `TriageWardenHighLatency` - P99 latency above 1 second
- `TriageWardenConnectorUnhealthy` - Connector health issues

## Upgrading

```bash
helm upgrade triage-warden ./helm/triage-warden \
  --namespace triage-warden \
  -f production-values.yaml
```

## Uninstalling

```bash
helm uninstall triage-warden --namespace triage-warden
kubectl delete namespace triage-warden
```

## Troubleshooting

### Check Pod Status

```bash
kubectl get pods -n triage-warden
kubectl describe pod -n triage-warden <pod-name>
kubectl logs -n triage-warden <pod-name>
```

### Check Health Endpoints

```bash
kubectl port-forward -n triage-warden svc/triage-warden 8080:80

# Health check
curl http://localhost:8080/health

# Detailed health
curl http://localhost:8080/health/detailed

# Readiness
curl http://localhost:8080/ready

# Liveness
curl http://localhost:8080/live
```

### Common Issues

**Pod stuck in Pending state**
- Check node resources: `kubectl describe nodes`
- Check PVC status if using persistent volumes

**Database connection errors**
- Verify PostgreSQL host is reachable from the cluster
- Check secret has correct password
- Verify SSL mode matches database configuration

**Ingress not working**
- Verify ingress controller is installed
- Check ingress class name matches your controller
- Verify TLS secret exists if using HTTPS

## Contributing

Please read our [Contributing Guide](../../CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This chart is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.
