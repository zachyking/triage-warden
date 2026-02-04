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

### Architecture

```
                        ┌─────────────────┐
                        │    Ingress      │
                        │  (TLS + routing)│
                        └────────┬────────┘
                                 │
                ┌────────────────┼────────────────┐
                │                │                │
          ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
          │    Pod    │    │    Pod    │    │    Pod    │
          │  replica  │    │  replica  │    │  replica  │
          └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
                │                │                │
                └────────────────┼────────────────┘
                                 │
                        ┌────────▼────────┐
                        │    Service      │
                        │  (ClusterIP)    │
                        └────────┬────────┘
                                 │
                        ┌────────▼────────┐
                        │   PostgreSQL    │
                        │  (StatefulSet)  │
                        └─────────────────┘
```

### Manifests

#### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: triage-warden
  labels:
    app.kubernetes.io/name: triage-warden
```

#### Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: triage-warden-secrets
  namespace: triage-warden
type: Opaque
stringData:
  # Generate these values securely!
  # encryption-key: $(openssl rand -base64 32)
  # jwt-secret: $(openssl rand -hex 32)
  # session-secret: $(openssl rand -hex 32)
  encryption-key: "REPLACE_WITH_BASE64_32_BYTE_KEY"
  jwt-secret: "REPLACE_WITH_JWT_SECRET"
  session-secret: "REPLACE_WITH_SESSION_SECRET"
  database-url: "postgres://triage_warden:password@postgres-postgresql:5432/triage_warden"
```

#### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: triage-warden-config
  namespace: triage-warden
data:
  RUST_LOG: "info"
  TW_BIND_ADDRESS: "0.0.0.0:8080"
  TW_BASE_URL: "https://triage.example.com"
```

#### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: triage-warden
  namespace: triage-warden
  labels:
    app.kubernetes.io/name: triage-warden
    app.kubernetes.io/component: server
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
  template:
    metadata:
      labels:
        app.kubernetes.io/name: triage-warden
    spec:
      serviceAccountName: triage-warden
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: triage-warden
          image: ghcr.io/your-org/triage-warden:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 8080
              protocol: TCP
          env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: triage-warden-secrets
                  key: database-url
            - name: TW_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: triage-warden-secrets
                  key: encryption-key
            - name: TW_JWT_SECRET
              valueFrom:
                secretKeyRef:
                  name: triage-warden-secrets
                  key: jwt-secret
            - name: TW_SESSION_SECRET
              valueFrom:
                secretKeyRef:
                  name: triage-warden-secrets
                  key: session-secret
          envFrom:
            - configMapRef:
                name: triage-warden-config
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 1000m
              memory: 1Gi
          livenessProbe:
            httpGet:
              path: /live
              port: http
            initialDelaySeconds: 30
            periodSeconds: 10
            timeoutSeconds: 5
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /ready
              port: http
            initialDelaySeconds: 5
            periodSeconds: 5
            timeoutSeconds: 3
            failureThreshold: 3
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
```

#### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: triage-warden
  namespace: triage-warden
  labels:
    app.kubernetes.io/name: triage-warden
spec:
  type: ClusterIP
  ports:
    - port: 80
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: triage-warden
```

#### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: triage-warden
  namespace: triage-warden
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-body-size: "10m"
spec:
  tls:
    - hosts:
        - triage.example.com
      secretName: triage-warden-tls
  rules:
    - host: triage.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: triage-warden
                port:
                  number: 80
```

#### ServiceAccount

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: triage-warden
  namespace: triage-warden
```

#### HorizontalPodAutoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: triage-warden
  namespace: triage-warden
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: triage-warden
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

#### PodDisruptionBudget

```yaml
# pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: triage-warden
  namespace: triage-warden
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
```

### Apply Manifests

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/secret.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/deployment.yaml
kubectl apply -f deploy/kubernetes/service.yaml
kubectl apply -f deploy/kubernetes/ingress.yaml
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

## Database Setup

### Using Helm (PostgreSQL)

```bash
# Add Bitnami repo
helm repo add bitnami https://charts.bitnami.com/bitnami

# Install PostgreSQL
helm install postgres bitnami/postgresql \
  --namespace triage-warden \
  --set auth.username=triage_warden \
  --set auth.password=your-secure-password \
  --set auth.database=triage_warden \
  --set primary.persistence.size=20Gi
```

### Using External Database

Update the secret with your external database URL:

```bash
kubectl create secret generic triage-warden-secrets \
  --namespace triage-warden \
  --from-literal=database-url="postgres://user:pass@your-rds-instance.region.rds.amazonaws.com:5432/triage_warden?sslmode=require" \
  # ... other secrets
```

## Monitoring

### ServiceMonitor (Prometheus)

```yaml
# servicemonitor.yaml
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
      interval: 30s
```

### PrometheusRule (Alerts)

```yaml
# prometheusrule.yaml
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: triage-warden
  namespace: triage-warden
spec:
  groups:
    - name: triage-warden
      rules:
        - alert: TriageWardenDown
          expr: up{job="triage-warden"} == 0
          for: 5m
          labels:
            severity: critical
          annotations:
            summary: "Triage Warden is down"
            description: "Triage Warden has been down for more than 5 minutes."

        - alert: TriageWardenHighErrorRate
          expr: rate(http_requests_total{job="triage-warden",status=~"5.."}[5m]) > 0.05
          for: 5m
          labels:
            severity: warning
          annotations:
            summary: "High error rate in Triage Warden"
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

## Security Hardening

### Network Policy

```yaml
# networkpolicy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: triage-warden
  namespace: triage-warden
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: triage-warden
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - protocol: TCP
          port: 8080
  egress:
    - to:
        - podSelector:
            matchLabels:
              app.kubernetes.io/name: postgresql
      ports:
        - protocol: TCP
          port: 5432
    - to:
        - namespaceSelector: {}
          podSelector:
            matchLabels:
              k8s-app: kube-dns
      ports:
        - protocol: UDP
          port: 53
    - to:  # External APIs (LLM, connectors)
        - ipBlock:
            cidr: 0.0.0.0/0
            except:
              - 10.0.0.0/8
              - 172.16.0.0/12
              - 192.168.0.0/16
      ports:
        - protocol: TCP
          port: 443
```

## Troubleshooting

### Pod Not Starting

```bash
# Check pod events
kubectl describe pod -n triage-warden -l app.kubernetes.io/name=triage-warden

# Check logs
kubectl logs -n triage-warden -l app.kubernetes.io/name=triage-warden --previous

# Common issues:
# - ImagePullBackOff: Check image name and registry credentials
# - CrashLoopBackOff: Check logs for startup errors
# - Pending: Check resource requests and node capacity
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

### Ingress Not Working

```bash
# Check ingress
kubectl describe ingress triage-warden -n triage-warden

# Check TLS secret
kubectl get secret triage-warden-tls -n triage-warden

# Check ingress controller logs
kubectl logs -l app.kubernetes.io/name=ingress-nginx -n ingress-nginx
```

## Operations

### View Logs

```bash
# All pods
kubectl logs -l app.kubernetes.io/name=triage-warden -n triage-warden -f

# Specific pod
kubectl logs -f deployment/triage-warden -n triage-warden

# Previous container (after crash)
kubectl logs deployment/triage-warden -n triage-warden --previous
```

### Scale Deployment

```bash
# Manual scale
kubectl scale deployment triage-warden -n triage-warden --replicas=5

# Check HPA status
kubectl get hpa -n triage-warden
```

### Rolling Update

```bash
# Update image
kubectl set image deployment/triage-warden \
  triage-warden=ghcr.io/your-org/triage-warden:v1.2.0 \
  -n triage-warden

# Watch rollout
kubectl rollout status deployment/triage-warden -n triage-warden

# Rollback if needed
kubectl rollout undo deployment/triage-warden -n triage-warden
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
