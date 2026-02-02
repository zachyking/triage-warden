# Backup & Restore

Procedures for backing up and restoring Triage Warden data.

## Overview

Triage Warden stores all persistent data in PostgreSQL. Regular backups are essential for disaster recovery.

**What to backup:**
- PostgreSQL database (all data)
- Configuration files (optional, if customized)
- TLS certificates (if not using cert-manager)

**What NOT to backup:**
- Application containers (stateless, rebuilt from image)
- Logs (should be in log aggregation system)
- Metrics (stored in Prometheus)

## Backup Procedures

### Manual Backup

#### Docker

```bash
# Create backup directory
mkdir -p /backups/triage-warden

# Create timestamped backup
BACKUP_FILE="/backups/triage-warden/backup-$(date +%Y%m%d-%H%M%S).sql"

docker compose exec -T postgres pg_dump \
  -U triage_warden \
  --format=custom \
  --compress=9 \
  triage_warden > "$BACKUP_FILE"

# Verify backup
pg_restore --list "$BACKUP_FILE" | head -20

echo "Backup created: $BACKUP_FILE ($(du -h $BACKUP_FILE | cut -f1))"
```

#### Kubernetes

```bash
# Get PostgreSQL pod
PG_POD=$(kubectl get pods -n triage-warden -l app.kubernetes.io/name=postgresql -o jsonpath='{.items[0].metadata.name}')

# Create backup
BACKUP_FILE="backup-$(date +%Y%m%d-%H%M%S).sql"

kubectl exec -n triage-warden $PG_POD -- \
  pg_dump -U triage_warden --format=custom --compress=9 triage_warden \
  > "$BACKUP_FILE"

# Upload to S3 (optional)
aws s3 cp "$BACKUP_FILE" s3://your-backup-bucket/triage-warden/
```

### Automated Backup

#### Docker (Cron)

```bash
# /etc/cron.d/triage-warden-backup
0 2 * * * root /opt/triage-warden/scripts/backup.sh >> /var/log/triage-warden-backup.log 2>&1
```

```bash
#!/bin/bash
# /opt/triage-warden/scripts/backup.sh

set -e

BACKUP_DIR="/backups/triage-warden"
RETENTION_DAYS=30
BACKUP_FILE="$BACKUP_DIR/backup-$(date +%Y%m%d-%H%M%S).sql"

# Create backup
cd /opt/triage-warden
docker compose exec -T postgres pg_dump \
  -U triage_warden \
  --format=custom \
  --compress=9 \
  triage_warden > "$BACKUP_FILE"

# Verify backup
if ! pg_restore --list "$BACKUP_FILE" > /dev/null 2>&1; then
  echo "ERROR: Backup verification failed"
  rm -f "$BACKUP_FILE"
  exit 1
fi

# Cleanup old backups
find "$BACKUP_DIR" -name "backup-*.sql" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE"
```

#### Kubernetes (CronJob)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: triage-warden-backup
  namespace: triage-warden
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  concurrencyPolicy: Forbid
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 3
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: backup
              image: postgres:15-alpine
              env:
                - name: PGPASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: postgres-postgresql
                      key: postgres-password
              command:
                - /bin/sh
                - -c
                - |
                  set -e
                  BACKUP_FILE="/backups/backup-$(date +%Y%m%d-%H%M%S).sql"
                  pg_dump -h postgres-postgresql -U triage_warden \
                    --format=custom --compress=9 triage_warden > "$BACKUP_FILE"
                  echo "Backup completed: $BACKUP_FILE"
              volumeMounts:
                - name: backup-storage
                  mountPath: /backups
          volumes:
            - name: backup-storage
              persistentVolumeClaim:
                claimName: backup-pvc
```

## Restore Procedures

### Prerequisites

1. Stop the Triage Warden application (to prevent data conflicts)
2. Have the backup file accessible
3. Database credentials available

### Full Restore

#### Docker

```bash
# Stop application
docker compose stop triage-warden

# Restore from backup
docker compose exec -T postgres pg_restore \
  -U triage_warden \
  --clean \
  --if-exists \
  --no-owner \
  -d triage_warden < /path/to/backup.sql

# Start application
docker compose start triage-warden

# Verify
curl http://localhost:8080/health | jq
```

#### Kubernetes

```bash
# Scale down application
kubectl scale deployment triage-warden -n triage-warden --replicas=0

# Get PostgreSQL pod
PG_POD=$(kubectl get pods -n triage-warden -l app.kubernetes.io/name=postgresql -o jsonpath='{.items[0].metadata.name}')

# Copy backup to pod
kubectl cp backup.sql triage-warden/$PG_POD:/tmp/backup.sql

# Restore
kubectl exec -n triage-warden $PG_POD -- \
  pg_restore -U triage_warden --clean --if-exists --no-owner \
  -d triage_warden /tmp/backup.sql

# Scale up application
kubectl scale deployment triage-warden -n triage-warden --replicas=3

# Verify
kubectl exec -it deployment/triage-warden -n triage-warden -- curl -s localhost:8080/health
```

### Point-in-Time Recovery

For point-in-time recovery, enable PostgreSQL WAL archiving:

```yaml
# PostgreSQL configuration
archive_mode: on
archive_command: 'aws s3 cp %p s3://your-bucket/wal/%f'
```

Recovery procedure:
```bash
# 1. Stop PostgreSQL
# 2. Clear data directory
# 3. Restore base backup
# 4. Create recovery.signal
# 5. Set recovery_target_time in postgresql.conf
# 6. Start PostgreSQL
```

## Verification

After any restore, verify:

```bash
# 1. Health check passes
curl http://localhost:8080/health | jq '.status'
# Expected: "healthy"

# 2. Recent incidents exist
curl http://localhost:8080/api/incidents | jq '. | length'

# 3. User can login
# Test via UI or API

# 4. Connectors configured
curl http://localhost:8080/health/detailed | jq '.components.connectors'
```

## Backup Storage

### Local Storage

- Pros: Simple, fast
- Cons: Single point of failure
- Recommendation: Development only

### Cloud Storage (S3/GCS/Azure Blob)

```bash
# Upload to S3
aws s3 cp backup.sql s3://bucket/triage-warden/backup-$(date +%Y%m%d).sql

# Download from S3
aws s3 cp s3://bucket/triage-warden/backup-20240115.sql ./restore.sql
```

### Encryption

Encrypt backups before storing:

```bash
# Encrypt backup
gpg --symmetric --cipher-algo AES256 backup.sql

# Decrypt for restore
gpg --decrypt backup.sql.gpg > backup.sql
```

## Disaster Recovery Plan

### RTO/RPO Targets

| Metric | Target |
|--------|--------|
| Recovery Time Objective (RTO) | 4 hours |
| Recovery Point Objective (RPO) | 24 hours |

### Recovery Steps

1. **Assess the situation**
   - Determine extent of data loss
   - Identify latest valid backup

2. **Provision new infrastructure**
   - Deploy new database instance
   - Deploy new application instances

3. **Restore data**
   - Restore database from backup
   - Verify data integrity

4. **Reconfigure**
   - Update DNS/load balancer
   - Reconfigure connectors if needed
   - Reset API keys if compromised

5. **Verify and communicate**
   - Run health checks
   - Test critical workflows
   - Notify stakeholders

### Testing Schedule

| Test | Frequency | Last Tested |
|------|-----------|-------------|
| Backup verification | Weekly | |
| Restore to test environment | Monthly | |
| Full DR simulation | Quarterly | |
