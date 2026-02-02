# Kubernetes Deployment

Deploy Triage Warden on Kubernetes for scalable, production-grade deployments.

## Prerequisites

- Kubernetes 1.25+
- kubectl configured with cluster access
- Helm 3.x (optional, for database)
- Storage class for persistent volumes
- Ingress controller (nginx, traefik, or similar)

## Quick Start

```bash
# Create namespace
kubectl create namespace triage-warden

# Create secrets
kubectl create secret generic triage-warden-secrets \
  --namespace triage-warden \
  --from-literal=encryption-key=$(openssl rand -base64 32) \
  --from-literal=jwt-secret=$(openssl rand -hex 32) \
  --from-literal=session-secret=$(openssl rand -hex 32) \
  --from-literal=database-url="postgres://user:pass@postgres:5432/triage_warden"

# Apply manifests
kubectl apply -f deploy/kubernetes/ -n triage-warden

# Check status
kubectl get pods -n triage-warden
kubectl logs -f deployment/triage-warden -n triage-warden
```

## Architecture

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

## Manifests

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: triage-warden
  labels:
    app.kubernetes.io/name: triage-warden
```

### Secret

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

### ConfigMap

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

### Deployment

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

### Service

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

### Ingress

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

### ServiceAccount

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: triage-warden
  namespace: triage-warden
```

### HorizontalPodAutoscaler

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

### PodDisruptionBudget

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

### Database Migration

```bash
# Run migrations via job
kubectl create job --from=cronjob/triage-warden-migrate migrate-$(date +%s) -n triage-warden
```

## Troubleshooting

### Pod Not Starting

```bash
# Check events
kubectl describe pod -l app.kubernetes.io/name=triage-warden -n triage-warden

# Common issues:
# - ImagePullBackOff: Check image name and registry credentials
# - CrashLoopBackOff: Check logs for startup errors
# - Pending: Check resource requests and node capacity
```

### Database Connection Issues

```bash
# Test from pod
kubectl exec -it deployment/triage-warden -n triage-warden -- \
  curl -s http://localhost:8080/health | jq '.components.database'

# Check secret
kubectl get secret triage-warden-secrets -n triage-warden -o jsonpath='{.data.database-url}' | base64 -d
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

## Next Steps

- [Configure connectors](../configuration/connectors-setup.md)
- [Set up monitoring](../operations/monitoring.md)
- [Review operational runbooks](../operations/README.md)
