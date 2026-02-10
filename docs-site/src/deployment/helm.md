# Helm Chart Deployment

Deploy Triage Warden to Kubernetes using the bundled Helm chart. This is the recommended approach for Kubernetes deployments, providing templated manifests with environment-specific value overrides.

The chart lives at `deploy/helm/` in the repository.

## Prerequisites

- Kubernetes 1.25+
- Helm 3.8+
- External PostgreSQL database (required)
- External Redis (optional, required for HA deployments)
- Ingress controller (nginx recommended)
- cert-manager (for automatic TLS)
- Prometheus Operator (for monitoring)

## Quick Start

### Development

```bash
# Create a values file
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

# Install
helm install triage-warden ./deploy/helm -f my-values.yaml
```

### Production

```bash
# Create namespace
kubectl create namespace triage-warden

# Create secrets externally (recommended)
kubectl create secret generic triage-warden-secrets \
  --namespace triage-warden \
  --from-literal=TW_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=TW_JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=TW_SESSION_SECRET="$(openssl rand -hex 32)"

kubectl create secret generic postgresql-credentials \
  --namespace triage-warden \
  --from-literal=postgresql-password="your-db-password"

# Install with production values
helm install triage-warden ./deploy/helm \
  --namespace triage-warden \
  -f deploy/helm/values-prod.yaml
```

## Value Files

The chart ships with pre-built value files for common scenarios:

| File | Purpose |
|------|---------|
| `values.yaml` | Defaults (base for all environments) |
| `values-dev.yaml` | Single-instance development (debug logging, no TLS) |
| `values-prod.yaml` | Multi-instance production (3 API replicas, TLS, monitoring) |
| `values-ha.yaml` | Maximum availability (5+ replicas, zone spreading, strict anti-affinity) |

Override with `-f`:

```bash
helm install triage-warden ./deploy/helm \
  --namespace triage-warden \
  -f deploy/helm/values-prod.yaml \
  -f my-secrets.yaml
```

## Key Parameters

### Application

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.replicas` | API server replicas | `2` |
| `api.resources.requests.cpu` | CPU request | `100m` |
| `api.resources.requests.memory` | Memory request | `256Mi` |
| `orchestrator.replicas` | Orchestrator replicas | `1` |
| `config.logLevel` | Log level | `info` |
| `config.enableSwagger` | Enable Swagger UI | `false` |

### Database

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.host` | PostgreSQL host (required) | `""` |
| `postgresql.port` | PostgreSQL port | `5432` |
| `postgresql.database` | Database name | `triage_warden` |
| `postgresql.existingSecret` | Existing secret with password | `""` |
| `postgresql.sslMode` | SSL mode | `require` |

### Networking

| Parameter | Description | Default |
|-----------|-------------|---------|
| `ingress.enabled` | Enable ingress | `false` |
| `ingress.className` | Ingress class name | `nginx` |
| `networkPolicy.enabled` | Enable network policies | `false` |

### Scaling & HA

| Parameter | Description | Default |
|-----------|-------------|---------|
| `autoscaling.enabled` | Enable HPA | `false` |
| `autoscaling.minReplicas` | Minimum replicas | `2` |
| `autoscaling.maxReplicas` | Maximum replicas | `10` |
| `podDisruptionBudget.enabled` | Enable PDB | `false` |

### Monitoring

| Parameter | Description | Default |
|-----------|-------------|---------|
| `serviceMonitor.enabled` | Enable ServiceMonitor | `false` |
| `prometheusRules.enabled` | Enable alerting rules | `false` |

See `deploy/helm/values.yaml` for the complete list.

## Components

The chart deploys two main components:

- **API Server** (`deployment-api.yaml`) - Handles HTTP requests, webhooks, and the web UI
- **Orchestrator** (`deployment-orchestrator.yaml`) - Manages background tasks, scheduling, and automation

Supporting resources: ServiceAccount, ConfigMap, Secret, Service, Ingress, HPA, PDB, NetworkPolicy, ServiceMonitor, PrometheusRule.

## External Secrets

For production, use an external secrets manager instead of storing secrets in values files:

```yaml
secrets:
  create: false
  existingSecret: "triage-warden-secrets"
```

Compatible with:
- [External Secrets Operator](https://external-secrets.io/)
- AWS Secrets Manager with IRSA
- HashiCorp Vault

## Upgrading

```bash
helm upgrade triage-warden ./deploy/helm \
  --namespace triage-warden \
  -f deploy/helm/values-prod.yaml

# Monitor rollout
kubectl rollout status deployment/triage-warden-api -n triage-warden
```

## Rollback

```bash
helm history triage-warden -n triage-warden
helm rollback triage-warden 1 -n triage-warden
```

## Uninstalling

```bash
helm uninstall triage-warden -n triage-warden
kubectl delete namespace triage-warden
```

## Alerts

When `prometheusRules.enabled: true`, the chart installs these alerts:

- `TriageWardenDown` - Instance unreachable for 2+ minutes
- `TriageWardenHighErrorRate` - 5xx errors exceed 5%
- `TriageWardenKillSwitchActive` - Kill switch activated
- `TriageWardenDatabaseUnhealthy` - Database connection issues
- `TriageWardenHighLatency` - P99 latency above 1 second
- `TriageWardenConnectorUnhealthy` - Connector health issues

The HA values file (`values-ha.yaml`) adds zone-balance and replica-mismatch alerts.

## Next Steps

- [Production Checklist](./production-checklist.md) - Security and configuration review
- [Monitoring](../operations/monitoring.md) - Set up dashboards and alerting
- [Scaling](../operations/scaling.md) - Horizontal scaling guidance
- [Raw Manifests](./kubernetes.md) - Alternative: deploy without Helm
