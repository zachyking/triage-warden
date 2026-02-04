# Docker Compose Deployment Guide

This guide covers deploying Triage Warden using Docker Compose for development, testing, and small-scale production environments.

## Overview

Triage Warden provides three Docker Compose configurations:

| File | Purpose | Use Case |
|------|---------|----------|
| `docker-compose.yml` | Basic setup | Quick start, single instance |
| `docker-compose.dev.yml` | Development | Local development with hot reload |
| `docker-compose.ha.yml` | High Availability | HA testing, multi-instance |

## Prerequisites

- **Docker** 20.10 or later
- **Docker Compose** v2.0 or later
- 4GB+ RAM available for Docker
- Ports 8080, 5432, 6379 available (configurable)

## Quick Start (Development)

### 1. Navigate to Deploy Directory

```bash
cd deploy/docker
```

### 2. Start Services

```bash
# Basic setup (will prompt for required secrets)
docker-compose -f docker-compose.dev.yml up -d

# View logs
docker-compose -f docker-compose.dev.yml logs -f app
```

### 3. Access the Application

- **Web UI**: http://localhost:8080
- **API Docs**: http://localhost:8080/swagger-ui
- **Health Check**: http://localhost:8080/health

### 4. Default Credentials

On first startup, an admin user is created. Check the logs for the generated password:

```bash
docker-compose -f docker-compose.dev.yml logs app | grep "Password:"
```

## Production Setup

### 1. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Generate secrets
export TW_ENCRYPTION_KEY=$(openssl rand -base64 32)
export TW_JWT_SECRET=$(openssl rand -hex 32)
export TW_SESSION_SECRET=$(openssl rand -hex 32)
export POSTGRES_PASSWORD=$(openssl rand -hex 16)

# Edit .env with your values
nano .env
```

### 2. Required Environment Variables

```bash
# .env file
# Security - REQUIRED
TW_ENCRYPTION_KEY=<32-byte base64 key>
TW_JWT_SECRET=<64-character hex string>
TW_SESSION_SECRET=<64-character hex string>

# Database
POSTGRES_PASSWORD=<strong password>
DATABASE_URL=postgres://triage:${POSTGRES_PASSWORD}@postgres:5432/triage_warden

# Server
TW_BASE_URL=https://triage.example.com
TW_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.0/12
```

### 3. Start Production Services

```bash
docker-compose -f docker-compose.yml up -d
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

## Logs and Debugging

### Viewing Logs

```bash
# All services
docker-compose -f docker-compose.ha.yml logs -f

# Specific service
docker-compose -f docker-compose.ha.yml logs -f api-1

# With timestamps
docker-compose -f docker-compose.ha.yml logs -f --timestamps

# Last 100 lines
docker-compose -f docker-compose.ha.yml logs --tail=100
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

## Building Custom Images

### Local Build

```bash
# Build from source
docker-compose -f docker-compose.ha.yml build

# Build with no cache
docker-compose -f docker-compose.ha.yml build --no-cache

# Build specific service
docker-compose -f docker-compose.ha.yml build api-1
```

### Custom Dockerfile

The multi-stage Dockerfile (`deploy/docker/Dockerfile`) produces a minimal production image:

```bash
# Build directly
docker build -t triage-warden:custom -f deploy/docker/Dockerfile .

# Build with specific target
docker build -t triage-warden:debug --target builder -f deploy/docker/Dockerfile .
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

## Common Issues

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

### Database Connection Refused

```bash
# Ensure postgres is healthy
docker-compose -f docker-compose.ha.yml ps postgres

# Check postgres logs
docker-compose -f docker-compose.ha.yml logs postgres

# Verify connection from app container
docker exec tw-api-1 curl -v telnet://postgres:5432
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

## Next Steps

- Set up [monitoring](../operations/monitoring.md) for production
- Review [configuration options](./configuration.md)
- Deploy to [Kubernetes](./kubernetes.md) for production HA
