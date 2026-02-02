# Notifications Setup Guide

Configure notification channels for alerts and incident updates.

## Overview

Triage Warden supports multiple notification channels:
- **Slack** - Team messaging
- **Microsoft Teams** - Enterprise collaboration
- **PagerDuty** - On-call alerting
- **Email** - SMTP notifications
- **Webhooks** - Custom integrations

## Adding a Notification Channel

1. Navigate to **Settings → Notifications**
2. Click **Add Channel**
3. Select channel type
4. Configure settings
5. Test and save

---

## Slack

### Prerequisites
- Slack workspace admin access
- Slack app with webhook permissions

### Setup Steps

1. **Create Slack App:**
   - Go to [api.slack.com/apps](https://api.slack.com/apps)
   - Click **Create New App** → **From scratch**
   - Name it "Triage Warden" and select your workspace

2. **Enable Incoming Webhooks:**
   - In app settings, click **Incoming Webhooks**
   - Toggle **Activate Incoming Webhooks** to On
   - Click **Add New Webhook to Workspace**
   - Select the channel for alerts

3. **Copy Webhook URL:**
   - Copy the webhook URL (starts with `https://hooks.slack.com/...`)

4. **Configure in Triage Warden:**

| Field | Value |
|-------|-------|
| Name | `Slack - Security` |
| Type | `slack` |
| Webhook URL | Your webhook URL |
| Channel | `#security-alerts` |

### Message Format

Triage Warden sends formatted Slack messages with:
- Severity color coding (red=critical, orange=high, yellow=medium, gray=low)
- Incident summary and details
- Quick action buttons (View, Acknowledge)
- Enrichment highlights

### Example Notification

```json
{
  "attachments": [{
    "color": "#ff0000",
    "title": "Critical: Malware Detected on WORKSTATION-001",
    "text": "CrowdStrike detected Emotet malware on endpoint",
    "fields": [
      {"title": "Source", "value": "CrowdStrike", "short": true},
      {"title": "Severity", "value": "Critical", "short": true}
    ],
    "actions": [
      {"type": "button", "text": "View Incident", "url": "https://..."}
    ]
  }]
}
```

---

## Microsoft Teams

### Prerequisites
- Microsoft 365 account
- Teams channel where you can add connectors

### Setup Steps

1. **Add Incoming Webhook Connector:**
   - In Teams, go to the channel for alerts
   - Click **...** → **Connectors**
   - Find **Incoming Webhook** and click **Configure**
   - Name it "Triage Warden" and upload an icon (optional)
   - Click **Create**

2. **Copy Webhook URL:**
   - Copy the generated webhook URL

3. **Configure in Triage Warden:**

| Field | Value |
|-------|-------|
| Name | `Teams - Security` |
| Type | `teams` |
| Webhook URL | Your webhook URL |

### Adaptive Cards

Triage Warden sends Teams notifications as Adaptive Cards with:
- Severity indicators
- Incident details in structured format
- Action buttons for quick response

---

## PagerDuty

### Prerequisites
- PagerDuty account
- Service with Events API v2 integration

### Setup Steps

1. **Create PagerDuty Service:**
   - In PagerDuty, go to **Services** → **New Service**
   - Name it "Triage Warden Alerts"
   - Add an escalation policy

2. **Add Events API Integration:**
   - On the service page, go to **Integrations**
   - Click **Add Integration**
   - Select **Events API v2**
   - Copy the **Integration Key**

3. **Configure in Triage Warden:**

| Field | Value |
|-------|-------|
| Name | `PagerDuty - Security` |
| Type | `pagerduty` |
| Integration Key | Your integration key |
| Severity Mapping | See below |

### Severity Mapping

Map Triage Warden severities to PagerDuty:

| TW Severity | PagerDuty Severity |
|-------------|-------------------|
| Critical | `critical` |
| High | `error` |
| Medium | `warning` |
| Low | `info` |

### Auto-Resolution

Configure auto-resolution to close PagerDuty incidents when Triage Warden incidents are resolved:

```yaml
notifications:
  pagerduty:
    auto_resolve: true
    resolve_on_status:
      - resolved
      - closed
      - false_positive
```

---

## Email (SMTP)

### Prerequisites
- SMTP server credentials
- Recipient email addresses

### Configuration

| Field | Value |
|-------|-------|
| Name | `Email - SOC Team` |
| Type | `email` |
| SMTP Host | `smtp.company.com` |
| SMTP Port | `587` |
| Username | `triage-warden@company.com` |
| Password | SMTP password |
| From Address | `triage-warden@company.com` |
| To Addresses | `soc-team@company.com` |
| Use TLS | `true` |

### Email Templates

Customize email templates by creating files in `config/templates/`:

```
config/templates/
├── email_incident_created.html
├── email_incident_updated.html
└── email_incident_resolved.html
```

Template variables:
- `{{ incident.title }}` - Incident title
- `{{ incident.severity }}` - Severity level
- `{{ incident.source }}` - Alert source
- `{{ incident.description }}` - Full description
- `{{ incident.url }}` - Link to incident

---

## Custom Webhooks

Send notifications to any HTTP endpoint.

### Configuration

| Field | Value |
|-------|-------|
| Name | `Custom - SIEM` |
| Type | `webhook` |
| URL | `https://siem.company.com/api/alerts` |
| Method | `POST` |
| Headers | `{"Authorization": "Bearer ..."}` |
| Secret | Webhook signing secret (optional) |

### Payload Format

Default JSON payload:

```json
{
  "event_type": "incident_created",
  "timestamp": "2024-01-15T10:30:00Z",
  "incident": {
    "id": "uuid",
    "title": "Alert Title",
    "severity": "high",
    "source": "crowdstrike",
    "description": "...",
    "created_at": "2024-01-15T10:29:00Z"
  }
}
```

### Webhook Signatures

If a secret is configured, Triage Warden signs webhooks with HMAC-SHA256:

```
X-TW-Signature: sha256=<signature>
X-TW-Timestamp: <unix_timestamp>
```

Verify signatures:
```python
import hmac
import hashlib

def verify_signature(payload, signature, secret, timestamp):
    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{payload}".encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## Notification Rules

Configure when and how notifications are sent.

### Severity Filtering

Send only high/critical alerts to PagerDuty:

```yaml
notifications:
  rules:
    - channel: pagerduty-security
      conditions:
        severity:
          - critical
          - high
```

### Time-Based Rules

Different channels for business hours vs. after hours:

```yaml
notifications:
  rules:
    - channel: slack-security
      conditions:
        hours: "09:00-17:00"
        days: ["mon", "tue", "wed", "thu", "fri"]
    - channel: pagerduty-oncall
      conditions:
        hours: "17:00-09:00"
        days: ["sat", "sun"]
```

### Source-Based Rules

Route by alert source:

```yaml
notifications:
  rules:
    - channel: slack-phishing
      conditions:
        source: email_gateway
    - channel: slack-edr
      conditions:
        source:
          - crowdstrike
          - defender
```

---

## Testing Notifications

### Test via UI

1. Go to **Settings → Notifications**
2. Click **Test** next to any channel
3. Check that test message arrives

### Test via API

```bash
curl -X POST http://localhost:8080/api/notifications/test \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "channel_id": "uuid-of-channel",
    "message": "Test notification from Triage Warden"
  }'
```

### Test via CLI

```bash
triage-warden notifications test --channel slack-security
```

---

## Troubleshooting

### Notifications Not Arriving

1. **Check channel health:**
   ```bash
   curl http://localhost:8080/health/detailed | jq '.components.notifications'
   ```

2. **Verify webhook URL:**
   - Test URL with curl
   - Check for firewalls or network restrictions

3. **Check logs:**
   ```bash
   grep "notification" /var/log/triage-warden/app.log
   ```

### Rate Limiting

If notifications are delayed:

- Slack: 1 message per second per channel
- PagerDuty: 120 events per minute
- Teams: 4 messages per second

Configure rate limits:
```yaml
notifications:
  rate_limits:
    slack: 1/s
    pagerduty: 2/s
    teams: 4/s
```

### Duplicate Notifications

If receiving duplicates:

1. Check for multiple channels targeting same destination
2. Enable deduplication:
   ```yaml
   notifications:
     deduplicate: true
     dedupe_window: 5m
   ```
