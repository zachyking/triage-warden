# Triage Warden Deployment

Deployment configurations for Triage Warden.

## Directory Structure

```
deploy/
├── docker/                    # Docker deployment files
│   ├── Dockerfile             # Multi-stage build
│   ├── docker-compose.yml     # Development compose
│   ├── docker-compose.prod.yml # Production compose
│   └── .env.example           # Environment template
│
└── kubernetes/                # Kubernetes manifests
    ├── namespace.yaml         # Namespace definition
    ├── configmap.yaml         # Non-sensitive config
    ├── secret.yaml            # Secrets template
    ├── deployment.yaml        # Deployment + ServiceAccount + PDB
    ├── service.yaml           # ClusterIP service
    ├── ingress.yaml           # Ingress + NetworkPolicy
    ├── servicemonitor.yaml    # Prometheus monitoring
    └── hpa.yaml               # Horizontal Pod Autoscaler
```

## Quick Start

### Docker Compose (Development)

```bash
cd deploy/docker

# Generate secrets
export TW_ENCRYPTION_KEY=$(openssl rand -base64 32)

# Start services
docker-compose up -d

# View logs
docker-compose logs -f app
```

### Docker Compose (Production)

```bash
cd deploy/docker

# Copy and configure environment
cp .env.example .env
# Edit .env with your production values

# Start with production config
docker-compose -f docker-compose.prod.yml up -d
```

### Kubernetes

```bash
cd deploy/kubernetes

# Create namespace
kubectl apply -f namespace.yaml

# Create secrets (edit first or use kubectl create secret)
kubectl apply -f secret.yaml

# Apply all other manifests
kubectl apply -f configmap.yaml
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
kubectl apply -f ingress.yaml

# Optional: monitoring and autoscaling
kubectl apply -f servicemonitor.yaml
kubectl apply -f hpa.yaml
```

## Prerequisites

### Docker
- Docker 20.10+
- Docker Compose v2
- PostgreSQL 14+ (or use included container)

### Kubernetes
- Kubernetes 1.25+
- kubectl configured
- Ingress controller (nginx recommended)
- cert-manager (for TLS)
- Prometheus Operator (for monitoring)

## Configuration

See the main documentation for detailed configuration:
- [Environment Variables](../docs-site/src/configuration/environment-variables.md)
- [Production Checklist](../docs-site/src/deployment/production-checklist.md)
- [Docker Deployment](../docs-site/src/deployment/docker.md)
- [Kubernetes Deployment](../docs-site/src/deployment/kubernetes.md)

## Security Notes

1. **Never commit secrets** - Use environment variables, secret managers, or Kubernetes secrets
2. **Generate unique keys** - Each environment needs unique encryption/JWT/session keys
3. **Use TLS** - Always use HTTPS in production
4. **Network policies** - Restrict pod-to-pod communication
5. **Non-root user** - Container runs as non-root by default

## Building the Image

```bash
# From repository root
docker build -t triage-warden:latest -f deploy/docker/Dockerfile .

# For a specific tag
docker build -t ghcr.io/your-org/triage-warden:v1.0.0 -f deploy/docker/Dockerfile .
```

## Monitoring

Triage Warden exposes Prometheus metrics at `/metrics`. The Kubernetes deployment includes:
- ServiceMonitor for automatic scraping
- PrometheusRule with pre-configured alerts
- Pod annotations for Prometheus auto-discovery

## Support

See the [Troubleshooting Guide](../docs-site/src/operations/troubleshooting.md) for common issues.
