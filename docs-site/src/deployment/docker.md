# Docker Deployment

Deploy Triage Warden using Docker and Docker Compose.

## Prerequisites

- Docker Engine 20.10+
- Docker Compose v2.0+
- 4 GB RAM minimum (2 GB for basic, 4 GB+ for HA)
- 20 GB disk space

## Overview

Triage Warden provides three Docker Compose configurations:

| File | Purpose | Use Case |
|------|---------|----------|
| `docker-compose.yml` | Basic setup | Quick start, single instance |
| `docker-compose.dev.yml` | Development | Local development with hot reload |
| `docker-compose.ha.yml` | High Availability | HA testing, multi-instance |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-org/triage-warden.git
cd triage-warden/deploy/docker

# Copy and configure environment
cp .env.example .env

# Generate required secrets
echo "TW_ENCRYPTION_KEY=$(openssl rand -base64 32)" >> .env
echo "TW_JWT_SECRET=$(openssl rand -hex 32)" >> .env
echo "TW_SESSION_SECRET=$(openssl rand -hex 32)" >> .env
echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" >> .env

# Start services
docker compose up -d

# Check status
docker compose ps
docker compose logs -f triage-warden
```

Access the dashboard at `http://localhost:8080`

Default credentials: `admin` / `admin` (change immediately!)

## Configuration

### Environment Variables

Edit `.env` file with your configuration:

```bash
# Database
POSTGRES_USER=triage_warden
POSTGRES_PASSWORD=your-secure-password
POSTGRES_DB=triage_warden
DATABASE_URL=postgres://triage_warden:your-secure-password@postgres:5432/triage_warden

# Application
TW_BIND_ADDRESS=0.0.0.0:8080
TW_BASE_URL=https://triage.example.com
TW_ENCRYPTION_KEY=your-32-byte-base64-key
TW_JWT_SECRET=your-jwt-secret
TW_SESSION_SECRET=your-session-secret

# Logging
RUST_LOG=info

# LLM (optional)
OPENAI_API_KEY=sk-...
# or
ANTHROPIC_API_KEY=sk-ant-...
```

### Production Configuration

For production, use `docker-compose.prod.yml`:

```bash
docker compose -f docker-compose.prod.yml up -d
```

Key differences from development:
- Uses external PostgreSQL volume for data persistence
- Enables health checks
- Sets resource limits
- Configures restart policies

## Docker Compose Files

### Development (`docker-compose.yml`)

```yaml
version: '3.8'

services:
  triage-warden:
    image: ghcr.io/your-org/triage-warden:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - TW_ENCRYPTION_KEY=${TW_ENCRYPTION_KEY}
      - TW_JWT_SECRET=${TW_JWT_SECRET}
      - TW_SESSION_SECRET=${TW_SESSION_SECRET}
      - RUST_LOG=${RUST_LOG:-info}
    depends_on:
      postgres:
        condition: service_healthy

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
```

### Production (`docker-compose.prod.yml`)

```yaml
version: '3.8'

services:
  triage-warden:
    image: ghcr.io/your-org/triage-warden:latest
    ports:
      - "8080:8080"
    environment:
      - DATABASE_URL=${DATABASE_URL}
      - TW_ENCRYPTION_KEY=${TW_ENCRYPTION_KEY}
      - TW_JWT_SECRET=${TW_JWT_SECRET}
      - TW_SESSION_SECRET=${TW_SESSION_SECRET}
      - TW_BASE_URL=${TW_BASE_URL}
      - RUST_LOG=${RUST_LOG:-info}
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/live"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=${POSTGRES_DB}
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d:ro
    restart: unless-stopped
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 1G
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  postgres_data:
    external: true
    name: triage_warden_postgres
```

## High Availability Testing

The HA configuration runs multiple instances for testing distributed features locally before deploying to Kubernetes.

### Architecture

```
                    ┌─────────────┐
                    │   Traefik   │
                    │   (LB)      │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
    ┌──────▼─────┐  ┌──────▼─────┐  ┌──────▼──────┐
    │   API-1    │  │   API-2    │  │   API-N     │
    │  (serve)   │  │  (serve)   │  │  (serve)    │
    └──────┬─────┘  └──────┬─────┘  └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
    ┌──────────────────────┼──────────────────────┐
    │                      │                      │
    ▼                      ▼                      ▼
┌───────┐           ┌──────────┐           ┌───────────┐
│ Redis │◄─────────►│ PostgreSQL│◄─────────►│Orchestrator│
│(MQ/Cache)│        │   (DB)   │           │ (1 leader) │
└───────┘           └──────────┘           └───────────┘
```

### Starting HA Stack

```bash
# Navigate to deploy directory
cd deploy/docker

# Configure environment
cp .env.example .env
# Edit .env with required values

# Start all services
docker-compose -f docker-compose.ha.yml up -d

# Start with monitoring stack
docker-compose -f docker-compose.ha.yml --profile monitoring up -d
```

### Accessing Services

| Service | URL | Description |
|---------|-----|-------------|
| API (Load Balanced) | http://localhost:8080 | Main application endpoint |
| Traefik Dashboard | http://localhost:8081 | Load balancer metrics |
| Prometheus | http://localhost:9090 | Metrics (with monitoring profile) |
| Grafana | http://localhost:3000 | Dashboards (admin/admin) |
| PostgreSQL | localhost:5432 | Database (for debugging) |
| Redis | localhost:6379 | Cache/MQ (for debugging) |

### Verifying HA Behavior

```bash
# Check all instances are healthy
curl -s http://localhost:8080/health | jq

# Check load balancing (run multiple times)
for i in {1..10}; do
  curl -s http://localhost:8080/health | jq -r '.instance_id // "unknown"'
done

# Check leader election
curl -s http://localhost:8080/health/detailed | jq '.components.leader_elector'

# Simulate failure - stop one API instance
docker stop tw-api-1

# Verify traffic still flows
curl -s http://localhost:8080/health

# Restart the instance
docker start tw-api-1
```

### Testing Orchestrator Failover

```bash
# Check which orchestrator is leader
docker exec tw-orchestrator-1 curl -s http://localhost:8080/health/detailed | jq '.components.leader_elector'
docker exec tw-orchestrator-2 curl -s http://localhost:8080/health/detailed | jq '.components.leader_elector'

# Stop the leader
docker stop tw-orchestrator-1

# Verify failover (second orchestrator becomes leader)
sleep 5
docker exec tw-orchestrator-2 curl -s http://localhost:8080/health/detailed | jq '.components.leader_elector'

# Restart original
docker start tw-orchestrator-1
```

## Building the Image

To build the Docker image locally:

```bash
# From repository root
docker build -t triage-warden:local -f deploy/docker/Dockerfile .

# Build with no cache
docker-compose -f docker-compose.ha.yml build --no-cache

# Build specific service
docker-compose -f docker-compose.ha.yml build api-1

# Use local image
# In docker-compose.yml, change:
# image: ghcr.io/your-org/triage-warden:latest
# to:
# image: triage-warden:local
```

## Persistent Storage

### Volume Management

```bash
# List volumes
docker volume ls | grep triage-warden

# Backup PostgreSQL
docker exec tw-postgres pg_dump -U triage triage_warden > backup.sql

# Restore PostgreSQL
cat backup.sql | docker exec -i tw-postgres psql -U triage triage_warden

# Backup Redis
docker exec tw-redis redis-cli BGSAVE
docker cp tw-redis:/data/dump.rdb ./redis-backup.rdb
```

### Cleaning Up

```bash
# Stop services
docker-compose -f docker-compose.ha.yml down

# Stop and remove volumes (WARNING: deletes all data)
docker-compose -f docker-compose.ha.yml down -v

# Remove only unused volumes
docker volume prune
```

## Common Operations

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f triage-warden

# Last 100 lines
docker compose logs --tail=100 triage-warden

# With timestamps
docker-compose -f docker-compose.ha.yml logs -f --timestamps
```

### Restart Services

```bash
# Restart all
docker compose restart

# Restart specific service
docker compose restart triage-warden
```

### Update to New Version

```bash
# Pull new images
docker compose pull

# Recreate containers
docker compose up -d

# Verify update
docker compose ps
curl http://localhost:8080/health | jq '.version'
```

### Database Operations

```bash
# Create backup
docker compose exec postgres pg_dump -U triage_warden triage_warden > backup.sql

# Restore backup
docker compose exec -T postgres psql -U triage_warden triage_warden < backup.sql

# Access database shell
docker compose exec postgres psql -U triage_warden triage_warden
```

### Debug Mode

Enable debug logging:

```bash
# In .env file
RUST_LOG=debug,triage_warden=trace,tw_api=trace,tw_core=trace
TW_LOG_FORMAT=pretty  # Human-readable format
```

### Inspecting Containers

```bash
# Shell access
docker exec -it tw-api-1 /bin/sh

# Check process status
docker exec tw-api-1 ps aux

# Check network connectivity
docker exec tw-api-1 curl -v http://postgres:5432
docker exec tw-api-1 curl -v http://redis:6379
```

## Resource Limits

The HA configuration includes resource limits suitable for local testing:

| Service | CPU Limit | Memory Limit |
|---------|-----------|--------------|
| API | 1 core | 512MB |
| Orchestrator | 1.5 cores | 1GB |
| PostgreSQL | 1 core | 1GB |
| Redis | 0.5 core | 512MB |
| Traefik | 0.5 core | 256MB |

Adjust in `docker-compose.ha.yml` under `deploy.resources`.

## TLS Configuration

For production, use a reverse proxy (nginx, Traefik, Caddy) for TLS termination:

### With Traefik

```yaml
# Add to docker-compose.prod.yml
services:
  traefik:
    image: traefik:v2.10
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.tlschallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - letsencrypt:/letsencrypt

  triage-warden:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.triage.rule=Host(`triage.example.com`)"
      - "traefik.http.routers.triage.entrypoints=websecure"
      - "traefik.http.routers.triage.tls.certresolver=letsencrypt"

volumes:
  letsencrypt:
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs for errors
docker compose logs triage-warden

# Common issues:
# - DATABASE_URL not set or incorrect
# - TW_ENCRYPTION_KEY missing
# - PostgreSQL not ready (check depends_on health)
```

### Database Connection Failed

```bash
# Verify PostgreSQL is running
docker compose ps postgres

# Check PostgreSQL logs
docker compose logs postgres

# Test connection
docker compose exec postgres pg_isready -U triage_warden

# Verify connection from app container
docker exec tw-api-1 curl -v telnet://postgres:5432
```

### Port Conflicts

```bash
# Find process using port 8080
lsof -i :8080

# Use different ports
# In docker-compose.ha.yml or via environment:
# - "8090:80" instead of "8080:80"
```

### Container Exits Immediately

```bash
# Check exit code and logs
docker-compose -f docker-compose.ha.yml logs api-1

# Common causes:
# - Missing environment variables
# - Database not ready
# - Invalid configuration
```

### Redis Connection Issues

```bash
# Test Redis connectivity
docker exec tw-api-1 curl -v telnet://redis:6379

# Check Redis logs
docker-compose -f docker-compose.ha.yml logs redis

# Connect to Redis CLI
docker exec -it tw-redis redis-cli ping
```

### Out of Memory

```bash
# Check container memory usage
docker stats

# Increase limits in docker-compose.prod.yml
deploy:
  resources:
    limits:
      memory: 4G  # Increase from 2G
```

## Next Steps

- [Configure connectors](../configuration/connectors-setup.md)
- [Set up notifications](../configuration/notifications-setup.md)
- [Create playbooks](../configuration/playbooks-guide.md)
- [Set up monitoring](../operations/monitoring.md)
- [Deploy to Kubernetes](./kubernetes.md) for production HA
