# Kubernetes Deployment Guide

This guide covers deploying Triage Warden to Kubernetes using Helm or raw manifests.

## Prerequisites

Before deploying, ensure you have:

- **Kubernetes cluster** version 1.25 or later
- **kubectl** configured with cluster access
- **Helm 3.x** (if using Helm deployment)
- **Container registry access** to pull Triage Warden images
- **PostgreSQL database** (managed or self-hosted)
- **Redis** (optional, required for HA deployments)

### Optional Prerequisites

- **Ingress controller** (nginx-ingress or Traefik recommended)
- **cert-manager** for automatic TLS certificate management
- **Prometheus Operator** for metrics and alerting

## Quick Start with Helm

### 1. Add the Helm Repository

```bash
# Add the Triage Warden Helm repository
helm repo add triage-warden https://charts.triage-warden.io
helm repo update
```

### 2. Create Namespace

```bash
kubectl create namespace triage-warden
```

### 3. Create Secrets

Generate required secrets before deployment:

```bash
# Generate encryption keys
export TW_ENCRYPTION_KEY=$(openssl rand -base64 32)
export TW_JWT_SECRET=$(openssl rand -hex 32)
export TW_SESSION_SECRET=$(openssl rand -hex 32)

# Create Kubernetes secret
kubectl create secret generic triage-warden-secrets \
  --namespace triage-warden \
  --from-literal=TW_ENCRYPTION_KEY="$TW_ENCRYPTION_KEY" \
  --from-literal=TW_JWT_SECRET="$TW_JWT_SECRET" \
  --from-literal=TW_SESSION_SECRET="$TW_SESSION_SECRET" \
  --from-literal=DATABASE_URL="postgres://user:password@postgres:5432/triage_warden"
```

### 4. Install Triage Warden

```bash
# Basic installation
helm install triage-warden triage-warden/triage-warden \
  --namespace triage-warden \
  --set global.domain=triage.example.com

# Installation with custom values
helm install triage-warden triage-warden/triage-warden \
  --namespace triage-warden \
  --values values-production.yaml
```

### 5. Verify Deployment

```bash
# Check pod status
kubectl get pods -n triage-warden

# Check service status
kubectl get svc -n triage-warden

# View logs
kubectl logs -n triage-warden -l app.kubernetes.io/name=triage-warden -f
```

## Helm Configuration

### Minimal Production Values

Create a `values-production.yaml` file:

```yaml
# values-production.yaml
global:
  domain: triage.example.com

api:
  replicas: 2
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

orchestrator:
  replicas: 2
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

postgresql:
  # Use external database
  enabled: false
  external:
    host: postgres.example.com
    port: 5432
    database: triage_warden
    existingSecret: triage-warden-secrets
    existingSecretPasswordKey: DATABASE_PASSWORD

redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: true
    existingSecret: triage-warden-secrets
    existingSecretPasswordKey: REDIS_PASSWORD

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: triage-warden-tls
      hosts:
        - triage.example.com

monitoring:
  enabled: true
  serviceMonitor:
    enabled: true
```

### Common Configuration Options

| Parameter | Description | Default |
|-----------|-------------|---------|
| `api.replicas` | Number of API server replicas | `2` |
| `orchestrator.replicas` | Number of orchestrator replicas | `2` |
| `image.repository` | Container image repository | `ghcr.io/triage-warden/triage-warden` |
| `image.tag` | Container image tag | `latest` |
| `ingress.enabled` | Enable ingress | `true` |
| `postgresql.enabled` | Deploy PostgreSQL | `true` |
| `redis.enabled` | Deploy Redis | `true` |
| `monitoring.enabled` | Enable monitoring | `true` |

## Manual Deployment (Without Helm)

If you prefer to use raw Kubernetes manifests:

### 1. Apply Namespace

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
```

### 2. Create Secrets

```bash
# Edit secret.yaml with your values first
kubectl apply -f deploy/kubernetes/secret.yaml
```

### 3. Apply ConfigMap

```bash
kubectl apply -f deploy/kubernetes/configmap.yaml
```

### 4. Deploy Application

```bash
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
```

### 5. Configure Ingress (Optional)

```bash
kubectl apply -f deploy/kubernetes/ingress.yaml
```

### 6. Enable Monitoring (Optional)

```bash
kubectl apply -f deploy/kubernetes/servicemonitor.yaml
kubectl apply -f deploy/kubernetes/hpa.yaml
```

## High Availability Configuration

For production HA deployments:

### API Server HA

The API servers are stateless and can be scaled horizontally:

```yaml
api:
  replicas: 3
  podAntiAffinity:
    enabled: true
    topologyKey: kubernetes.io/hostname
  topologySpreadConstraints:
    enabled: true
    maxSkew: 1
```

### Orchestrator HA

Orchestrators use leader election to coordinate singleton tasks:

```yaml
orchestrator:
  replicas: 2
  leaderElection:
    enabled: true
    leaseDuration: 15s
    renewDeadline: 10s
    retryPeriod: 2s
```

### Pod Disruption Budget

Ensure availability during updates:

```yaml
podDisruptionBudget:
  enabled: true
  minAvailable: 1
```

## Upgrading

### Helm Upgrade

```bash
# Check current version
helm list -n triage-warden

# Upgrade to new version
helm upgrade triage-warden triage-warden/triage-warden \
  --namespace triage-warden \
  --values values-production.yaml \
  --set image.tag=v1.1.0

# Monitor the rollout
kubectl rollout status deployment/triage-warden-api -n triage-warden
```

### Rollback

```bash
# View release history
helm history triage-warden -n triage-warden

# Rollback to previous version
helm rollback triage-warden 1 -n triage-warden
```

## Database Migrations

Triage Warden automatically runs database migrations on startup. For manual control:

```bash
# Run migrations manually
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  triage-warden migrate

# Check migration status
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  triage-warden migrate --status
```

## TLS Configuration

### Using cert-manager

```yaml
ingress:
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: triage-warden-tls
      hosts:
        - triage.example.com
```

### Manual TLS Secret

```bash
kubectl create secret tls triage-warden-tls \
  --namespace triage-warden \
  --cert=tls.crt \
  --key=tls.key
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n triage-warden -l app.kubernetes.io/name=triage-warden

# Check logs
kubectl logs -n triage-warden -l app.kubernetes.io/name=triage-warden --previous
```

### Database Connection Issues

```bash
# Test database connectivity from a pod
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  curl -v telnet://postgres:5432

# Check database URL
kubectl get secret triage-warden-secrets -n triage-warden -o jsonpath='{.data.DATABASE_URL}' | base64 -d
```

### Health Check Failures

```bash
# Check liveness endpoint
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  curl -s http://localhost:8080/live

# Check readiness endpoint
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  curl -s http://localhost:8080/ready

# Check detailed health
kubectl exec -it deployment/triage-warden-api -n triage-warden -- \
  curl -s http://localhost:8080/health/detailed | jq
```

### Leader Election Issues

```bash
# Check which instance is the leader
kubectl exec -it deployment/triage-warden-orchestrator-0 -n triage-warden -- \
  curl -s http://localhost:8080/health/detailed | jq '.components.leader_elector'

# Check leader lease in Redis
kubectl exec -it deployment/triage-warden-redis-0 -n triage-warden -- \
  redis-cli KEYS "tw:leader:*"
```

### Performance Issues

```bash
# Check resource usage
kubectl top pods -n triage-warden

# Check HPA status
kubectl get hpa -n triage-warden

# View Prometheus metrics
kubectl port-forward svc/prometheus -n monitoring 9090:9090
```

## Uninstalling

### Helm Uninstall

```bash
# Uninstall Triage Warden
helm uninstall triage-warden -n triage-warden

# Delete namespace (optional, removes all resources)
kubectl delete namespace triage-warden

# Delete PVCs if needed
kubectl delete pvc -n triage-warden --all
```

## Next Steps

- Configure [monitoring and alerting](../operations/monitoring.md)
- Set up [horizontal scaling](../operations/scaling.md)
- Review [configuration options](./configuration.md)
