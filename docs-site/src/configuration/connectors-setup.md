# Connector Setup Guide

Step-by-step instructions for configuring each connector type.

## Overview

Connectors enable Triage Warden to:
- **Ingest alerts** from SIEMs and security tools
- **Enrich incidents** with threat intelligence
- **Execute actions** like creating tickets or isolating hosts
- **Send notifications** to communication platforms

## Adding a Connector

1. Navigate to **Settings → Connectors**
2. Click **Add Connector**
3. Select connector type
4. Fill in the required fields
5. Click **Test Connection** to verify
6. Click **Save**

---

## Threat Intelligence Connectors

### VirusTotal

Enriches file hashes, URLs, IPs, and domains with reputation data.

**Prerequisites:**
- VirusTotal account (free or premium)
- API key from [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `VirusTotal` |
| Type | `virustotal` |
| API Key | Your API key |
| Rate Limit | `4` (free) or `500` (premium) |

**Rate Limits:**
- Free tier: 4 requests/minute
- Premium: 500+ requests/minute

**Verify It Works:**
1. Create a test incident with a known-bad hash
2. Check incident enrichments for VirusTotal data

### AlienVault OTX

Open threat intelligence from AlienVault.

**Prerequisites:**
- OTX account at [otx.alienvault.com](https://otx.alienvault.com)
- API key from Settings → API Keys

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `AlienVault OTX` |
| Type | `alienvault` |
| API Key | Your OTX API key |

---

## SIEM Connectors

### Splunk

Ingest alerts from Splunk and run queries.

**Prerequisites:**
- Splunk Enterprise or Cloud
- HTTP Event Collector (HEC) token
- User with search capabilities

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Splunk Production` |
| Type | `splunk` |
| Host | `https://splunk.company.com:8089` |
| Username | Service account username |
| Password | Service account password |
| App | `search` (or your app context) |

**Setting Up Webhooks:**

1. In Splunk, create an alert action that sends to webhook
2. Configure webhook URL: `https://triage.company.com/api/webhooks/splunk`
3. Set webhook secret in Triage Warden connector config

### Elastic Security

Connect to Elastic Security for SIEM alerts.

**Prerequisites:**
- Elasticsearch 7.x or 8.x
- User with read access to security indices

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Elastic SIEM` |
| Type | `elastic` |
| URL | `https://elasticsearch.company.com:9200` |
| Username | Service account username |
| Password | Service account password |
| Index Pattern | `security-*` or `.alerts-security.*` |

### Microsoft Sentinel

Azure Sentinel integration for cloud SIEM.

**Prerequisites:**
- Azure subscription with Sentinel workspace
- App registration with Log Analytics Reader role

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Azure Sentinel` |
| Type | `sentinel` |
| Workspace ID | Log Analytics Workspace ID |
| Tenant ID | Azure AD Tenant ID |
| Client ID | App Registration Client ID |
| Client Secret | App Registration Secret |

**Azure Setup:**
1. Create App Registration in Azure AD
2. Grant `Log Analytics Reader` role on Sentinel workspace
3. Create client secret
4. Copy IDs and secret to Triage Warden

---

## EDR Connectors

### CrowdStrike Falcon

Endpoint detection and host isolation.

**Prerequisites:**
- CrowdStrike Falcon subscription
- API client with appropriate scopes

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `CrowdStrike Falcon` |
| Type | `crowdstrike` |
| Region | `us-1`, `us-2`, `eu-1`, or `us-gov-1` |
| Client ID | OAuth Client ID |
| Client Secret | OAuth Client Secret |

**Required API Scopes:**
- `Detections: Read`
- `Hosts: Read, Write` (for isolation)
- `Incidents: Read`

**CrowdStrike Setup:**
1. Go to Support → API Clients and Keys
2. Create new API client
3. Select required scopes
4. Copy Client ID and Secret

### Microsoft Defender for Endpoint

MDE integration for alerts and host actions.

**Prerequisites:**
- Microsoft 365 E5 or Defender for Endpoint license
- App registration with Defender API permissions

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Defender for Endpoint` |
| Type | `defender` |
| Tenant ID | Azure AD Tenant ID |
| Client ID | App Registration Client ID |
| Client Secret | App Registration Secret |

**Required API Permissions:**
- `Alert.Read.All`
- `Machine.Read.All`
- `Machine.Isolate` (for isolation actions)

### SentinelOne

SentinelOne EDR integration.

**Prerequisites:**
- SentinelOne console access
- API token with appropriate permissions

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `SentinelOne` |
| Type | `sentinelone` |
| Console URL | `https://usea1-pax8.sentinelone.net` |
| API Token | Your API token |

---

## Ticketing Connectors

### Jira

Create and manage security tickets.

**Prerequisites:**
- Jira Cloud or Server instance
- API token (Cloud) or password (Server)

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Jira Security` |
| Type | `jira` |
| URL | `https://yourcompany.atlassian.net` |
| Email | Your Jira email |
| API Token | API token from Atlassian account |
| Default Project | `SEC` (your security project key) |

**Jira Cloud Setup:**
1. Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
2. Create API token
3. Use your email as username

**Jira Server Setup:**
- Use password instead of API token
- Ensure user has project access

### ServiceNow

ServiceNow ITSM integration.

**Prerequisites:**
- ServiceNow instance
- User with incident table access

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `ServiceNow` |
| Type | `servicenow` |
| Instance URL | `https://yourcompany.service-now.com` |
| Username | Service account username |
| Password | Service account password |

---

## Identity Connectors

### Microsoft 365 / Azure AD

User management and sign-in data.

**Prerequisites:**
- Azure AD with appropriate licenses
- App registration with Graph API permissions

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Microsoft 365` |
| Type | `m365` |
| Tenant ID | Azure AD Tenant ID |
| Client ID | App Registration Client ID |
| Client Secret | App Registration Secret |

**Required API Permissions:**
- `User.Read.All`
- `AuditLog.Read.All`
- `User.RevokeSessions.All` (for user disable)

### Google Workspace

Google Workspace user management.

**Prerequisites:**
- Google Workspace admin access
- Service account with domain-wide delegation

**Configuration:**

| Field | Value |
|-------|-------|
| Name | `Google Workspace` |
| Type | `google` |
| Service Account JSON | Paste JSON key file contents |
| Domain | `company.com` |

**Google Setup:**
1. Create service account in Google Cloud Console
2. Enable domain-wide delegation
3. Add required OAuth scopes in Google Admin
4. Download JSON key file

---

## Testing Connectors

After configuration, always test:

1. Click **Test Connection** in connector settings
2. Check the response for success/errors
3. For ingestion connectors, verify sample data appears

### Common Issues

| Error | Solution |
|-------|----------|
| Connection refused | Check URL and network access |
| 401 Unauthorized | Verify credentials/API key |
| 403 Forbidden | Check permissions/scopes |
| SSL certificate error | Verify certificate or disable verification |
| Rate limited | Reduce request rate or upgrade tier |

## Connector Health

Monitor connector health at **Settings → Connectors** or via API:

```bash
curl http://localhost:8080/health/detailed | jq '.components.connectors'
```

Healthy connectors show status `connected`. Troubleshoot any showing `error` or `disconnected`.
