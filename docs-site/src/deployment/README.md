# Production Deployment

This section covers deploying Triage Warden in production environments.

## Deployment Options

Triage Warden can be deployed in several ways:

- **[Docker](./docker.md)** - Recommended for most deployments. Quick setup with Docker Compose.
- **[Kubernetes](./kubernetes.md)** - For orchestrated, scalable deployments.
- **[Binary](./binary.md)** - Direct binary installation on Linux servers.

## Before You Deploy

Before deploying to production, review:

1. **[Production Checklist](./production-checklist.md)** - Security and configuration requirements
2. **[Configuration Reference](./configuration.md)** - All environment variables and settings
3. **[Database Setup](./database.md)** - PostgreSQL configuration for production
4. **[Security Hardening](./security.md)** - TLS, secrets, network policies
5. **[Scaling](./scaling.md)** - Horizontal scaling considerations

## Quick Start

For a quick production deployment with Docker:

```bash
# Clone the repository
git clone https://github.com/your-org/triage-warden.git
cd triage-warden/deploy/docker

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Generate encryption key
echo "TW_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env

# Start services
docker compose -f docker-compose.prod.yml up -d
```

## Architecture Overview

A typical production deployment includes:

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │   (TLS term.)   │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
        ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐
        │  Triage   │  │  Triage   │  │  Triage   │
        │  Warden   │  │  Warden   │  │  Warden   │
        │ Instance 1│  │ Instance 2│  │ Instance 3│
        └─────┬─────┘  └─────┬─────┘  └─────┬─────┘
              │              │              │
              └──────────────┼──────────────┘
                             │
                    ┌────────▼────────┐
                    │   PostgreSQL    │
                    │   (Primary)     │
                    └─────────────────┘
```

## Support

For deployment assistance:
- Check the [Troubleshooting Guide](../operations/troubleshooting.md)
- Review [GitHub Issues](https://github.com/your-org/triage-warden/issues)
- Contact support at support@example.com
