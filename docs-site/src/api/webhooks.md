# Webhooks API

Receive events from external security tools.

## Endpoint

```
POST /api/webhooks/:source
```

Where `:source` identifies the sending system (e.g., `email-gateway`, `edr`, `siem`).

## Authentication

Webhooks are authenticated via HMAC signatures:

```
X-Webhook-Signature: sha256=abc123...
X-Webhook-Timestamp: 1705320000
```

## Registering Webhook Sources

### Via CLI

```bash
tw-cli webhook add email-gateway \
  --secret "your-secret-key" \
  --auto-triage true \
  --playbook phishing_triage
```

### Via API

```bash
curl -X POST "http://localhost:8080/api/webhooks" \
  -H "Authorization: Bearer tw_xxx" \
  -d '{
    "source": "email-gateway",
    "secret": "your-secret-key",
    "auto_triage": true,
    "playbook": "phishing_triage"
  }'
```

## Payload Formats

### Generic Format

```json
{
  "event_type": "security_alert",
  "timestamp": "2024-01-15T10:00:00Z",
  "source": "email-gateway",
  "data": {
    "alert_id": "alert-123",
    "severity": "high",
    "details": {...}
  }
}
```

### Microsoft Defender for Office 365

```json
{
  "eventType": "PhishingEmail",
  "id": "AAMkAGI2...",
  "creationTime": "2024-01-15T10:00:00Z",
  "severity": "high",
  "category": "Phish",
  "entityType": "Email",
  "data": {
    "sender": "phisher@malicious.com",
    "subject": "Urgent Action Required",
    "recipients": ["user@company.com"]
  }
}
```

### CrowdStrike Falcon

```json
{
  "metadata": {
    "eventType": "DetectionSummaryEvent",
    "eventCreationTime": 1705320000000
  },
  "event": {
    "DetectId": "ldt:abc123",
    "Severity": 4,
    "HostnameField": "WORKSTATION-01",
    "DetectName": "Malicious File Detected"
  }
}
```

### Splunk Alert

```json
{
  "result": {
    "host": "server-01",
    "source": "WinEventLog:Security",
    "sourcetype": "WinEventLog",
    "_raw": "...",
    "EventCode": "4625"
  },
  "search_name": "Failed Login Alert",
  "trigger_time": 1705320000
}
```

## Response

### Success

```json
{
  "status": "accepted",
  "incident_id": "550e8400-e29b-41d4-a716-446655440000",
  "incident_number": "INC-2024-0001"
}
```

### Queued for Processing

```json
{
  "status": "queued",
  "queue_id": "queue-abc123",
  "message": "Event queued for processing"
}
```

## Configuring Auto-Triage

When `auto_triage` is enabled, incidents created from webhooks are automatically triaged:

```yaml
# webhook_config.yaml
sources:
  email-gateway:
    secret: "${EMAIL_GATEWAY_SECRET}"
    auto_triage: true
    playbook: phishing_triage
    severity_mapping:
      critical: critical
      high: high
      medium: medium
      low: low

  edr:
    secret: "${EDR_SECRET}"
    auto_triage: true
    playbook: malware_triage
```

## Testing Webhooks

### Send Test Event

```bash
# Generate signature
TIMESTAMP=$(date +%s)
BODY='{"event_type":"test","data":{}}'
SIGNATURE=$(echo -n "${TIMESTAMP}.${BODY}" | openssl dgst -sha256 -hmac "your-secret")

# Send request
curl -X POST "http://localhost:8080/api/webhooks/email-gateway" \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=${SIGNATURE}" \
  -H "X-Webhook-Timestamp: ${TIMESTAMP}" \
  -d "${BODY}"
```

### Verify Configuration

```bash
tw-cli webhook test email-gateway
```

## Error Handling

### Invalid Signature

```json
{
  "error": {
    "code": "invalid_signature",
    "message": "Webhook signature verification failed"
  }
}
```

### Unknown Source

```json
{
  "error": {
    "code": "unknown_source",
    "message": "Webhook source 'unknown' is not registered"
  }
}
```

### Replay Attack

```json
{
  "error": {
    "code": "timestamp_expired",
    "message": "Webhook timestamp is too old (>5 minutes)"
  }
}
```

## Monitoring Webhooks

### Metrics

```promql
# Webhook receive rate
rate(webhook_received_total[5m])

# Error rate by source
rate(webhook_errors_total[5m])
```

### Logs

```bash
tw-cli logs --filter webhook --tail 100
```
