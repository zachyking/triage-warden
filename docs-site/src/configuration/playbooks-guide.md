# Playbooks Guide

Create effective automated response playbooks.

## What is a Playbook?

A playbook is an automated workflow that executes when specific conditions are met. Playbooks contain:

- **Trigger** - Conditions that start the playbook
- **Stages** - Ordered groups of steps
- **Steps** - Individual actions to execute

## Creating a Playbook

### Via Web UI

1. Navigate to **Playbooks**
2. Click **Create Playbook**
3. Enter name and description
4. Configure trigger conditions
5. Add stages and steps
6. Enable and save

### Via API

```bash
curl -X POST http://localhost:8080/api/playbooks \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phishing Response",
    "description": "Automated response for phishing alerts",
    "trigger": {
      "type": "incident_created",
      "conditions": {
        "source": "email_gateway",
        "severity": ["high", "critical"]
      }
    },
    "stages": [...]
  }'
```

## Trigger Types

### incident_created

Fires when a new incident is created.

```json
{
  "type": "incident_created",
  "conditions": {
    "severity": ["high", "critical"],
    "source": "crowdstrike",
    "title_contains": "malware"
  }
}
```

### incident_updated

Fires when an incident is updated.

```json
{
  "type": "incident_updated",
  "conditions": {
    "field": "severity",
    "new_value": "critical"
  }
}
```

### scheduled

Fires on a schedule (cron format).

```json
{
  "type": "scheduled",
  "schedule": "0 */6 * * *"
}
```

### manual

Only triggered manually by user action.

```json
{
  "type": "manual"
}
```

## Stages

Stages group steps that should execute together. Configure:

- **Name** - Descriptive name
- **Description** - What this stage does
- **Parallel** - Execute steps in parallel (default: false)

### Sequential Execution

```json
{
  "stages": [
    {
      "name": "Enrichment",
      "steps": [/* step 1, step 2, step 3 */]
    },
    {
      "name": "Response",
      "steps": [/* step 4, step 5 */]
    }
  ]
}
```
Steps in Enrichment complete before Response starts.

### Parallel Execution

```json
{
  "stages": [
    {
      "name": "Gather Intel",
      "parallel": true,
      "steps": [
        {"action": "lookup_hash_virustotal"},
        {"action": "lookup_ip_reputation"},
        {"action": "lookup_domain_reputation"}
      ]
    }
  ]
}
```
All lookups run simultaneously.

## Step Types

### Enrichment Actions

#### lookup_hash

Look up file hash reputation.

```json
{
  "action": "lookup_hash",
  "parameters": {
    "hash": "{{ incident.iocs.file_hash }}",
    "providers": ["virustotal", "alienvault"]
  }
}
```

#### lookup_ip

Look up IP address reputation.

```json
{
  "action": "lookup_ip",
  "parameters": {
    "ip": "{{ incident.source_ip }}"
  }
}
```

#### lookup_domain

Look up domain reputation.

```json
{
  "action": "lookup_domain",
  "parameters": {
    "domain": "{{ incident.domain }}"
  }
}
```

#### lookup_user

Get user details from identity provider.

```json
{
  "action": "lookup_user",
  "parameters": {
    "email": "{{ incident.user_email }}",
    "provider": "m365"
  }
}
```

### Containment Actions

#### isolate_host

Isolate endpoint from network.

```json
{
  "action": "isolate_host",
  "parameters": {
    "hostname": "{{ incident.hostname }}",
    "provider": "crowdstrike"
  },
  "requires_approval": true
}
```

#### disable_user

Disable user account.

```json
{
  "action": "disable_user",
  "parameters": {
    "email": "{{ incident.user_email }}",
    "provider": "m365"
  },
  "requires_approval": true
}
```

#### block_ip

Block IP address at firewall.

```json
{
  "action": "block_ip",
  "parameters": {
    "ip": "{{ incident.source_ip }}",
    "duration": "24h"
  },
  "requires_approval": true
}
```

### Notification Actions

#### send_notification

Send alert to notification channel.

```json
{
  "action": "send_notification",
  "parameters": {
    "channel": "slack-security",
    "message": "Critical incident: {{ incident.title }}"
  }
}
```

#### create_ticket

Create ticket in ticketing system.

```json
{
  "action": "create_ticket",
  "parameters": {
    "provider": "jira",
    "project": "SEC",
    "type": "Incident",
    "title": "{{ incident.title }}",
    "description": "{{ incident.description }}"
  }
}
```

### Analysis Actions

#### analyze_with_llm

Run AI analysis on incident.

```json
{
  "action": "analyze_with_llm",
  "parameters": {
    "prompt": "Analyze this security incident and provide recommendations",
    "include_enrichments": true
  }
}
```

### Utility Actions

#### wait

Pause execution for specified duration.

```json
{
  "action": "wait",
  "parameters": {
    "duration": "5m"
  }
}
```

#### set_severity

Update incident severity.

```json
{
  "action": "set_severity",
  "parameters": {
    "severity": "critical"
  }
}
```

#### add_comment

Add comment to incident.

```json
{
  "action": "add_comment",
  "parameters": {
    "comment": "Automated enrichment complete. Found {{ enrichments.virustotal.positives }} detections."
  }
}
```

## Variables and Templates

Use Jinja2-style templates to reference incident data:

### Available Variables

| Variable | Description |
|----------|-------------|
| `{{ incident.id }}` | Incident UUID |
| `{{ incident.title }}` | Incident title |
| `{{ incident.severity }}` | Severity level |
| `{{ incident.source }}` | Alert source |
| `{{ incident.description }}` | Full description |
| `{{ incident.hostname }}` | Affected hostname |
| `{{ incident.username }}` | Affected username |
| `{{ incident.source_ip }}` | Source IP address |
| `{{ incident.iocs.* }}` | Extracted IOCs |
| `{{ enrichments.* }}` | Enrichment results |
| `{{ previous_step.output }}` | Previous step output |

### Conditional Logic

```json
{
  "action": "isolate_host",
  "conditions": "{{ incident.severity == 'critical' and enrichments.virustotal.positives > 5 }}"
}
```

## Approval Requirements

Mark steps as requiring approval for dangerous actions:

```json
{
  "action": "disable_user",
  "requires_approval": true
}
```

When `requires_approval: true`:
1. Step pauses at approval queue
2. Analyst reviews and approves/denies
3. Execution continues or stops

## Example Playbooks

### Phishing Triage

```json
{
  "name": "Phishing Triage",
  "description": "Automated triage for reported phishing emails",
  "trigger": {
    "type": "incident_created",
    "conditions": {
      "source": "email_gateway",
      "title_contains": "phishing"
    }
  },
  "stages": [
    {
      "name": "Extract and Enrich",
      "parallel": true,
      "steps": [
        {
          "action": "lookup_domain",
          "parameters": {"domain": "{{ incident.sender_domain }}"}
        },
        {
          "action": "lookup_url",
          "parameters": {"url": "{{ incident.iocs.url }}"}
        },
        {
          "action": "lookup_user",
          "parameters": {"email": "{{ incident.recipient }}"}
        }
      ]
    },
    {
      "name": "Analyze",
      "steps": [
        {
          "action": "analyze_with_llm",
          "parameters": {
            "prompt": "Analyze this phishing attempt and determine if it's targeted spear-phishing"
          }
        }
      ]
    },
    {
      "name": "Respond",
      "steps": [
        {
          "action": "send_notification",
          "parameters": {
            "channel": "slack-phishing",
            "message": "Phishing alert: {{ incident.title }}\nSender: {{ incident.sender }}\nVerdict: {{ analysis.verdict }}"
          }
        },
        {
          "action": "create_ticket",
          "conditions": "{{ analysis.verdict == 'malicious' }}",
          "parameters": {
            "provider": "jira",
            "project": "SEC",
            "title": "Phishing: {{ incident.title }}"
          }
        }
      ]
    }
  ]
}
```

### Malware Containment

```json
{
  "name": "Malware Containment",
  "description": "Isolate hosts with confirmed malware",
  "trigger": {
    "type": "incident_created",
    "conditions": {
      "source": "crowdstrike",
      "severity": "critical",
      "title_contains": "malware"
    }
  },
  "stages": [
    {
      "name": "Verify",
      "steps": [
        {
          "action": "lookup_hash",
          "parameters": {"hash": "{{ incident.iocs.file_hash }}"}
        }
      ]
    },
    {
      "name": "Contain",
      "steps": [
        {
          "action": "isolate_host",
          "conditions": "{{ enrichments.virustotal.positives >= 5 }}",
          "requires_approval": true,
          "parameters": {
            "hostname": "{{ incident.hostname }}",
            "reason": "Confirmed malware with {{ enrichments.virustotal.positives }} detections"
          }
        }
      ]
    },
    {
      "name": "Notify",
      "steps": [
        {
          "action": "send_notification",
          "parameters": {
            "channel": "pagerduty-security",
            "message": "Host {{ incident.hostname }} isolated due to malware"
          }
        }
      ]
    }
  ]
}
```

## Best Practices

1. **Start small** - Begin with enrichment-only playbooks before adding containment
2. **Require approval** - Always require approval for containment actions initially
3. **Test in staging** - Test playbooks with mock incidents first
4. **Monitor execution** - Watch playbook executions for errors
5. **Document thoroughly** - Include clear descriptions for each stage/step
6. **Use conditions** - Don't execute actions blindly; use conditions to validate
7. **Handle failures** - Consider what happens if a step fails

## Troubleshooting

### Playbook Not Triggering

- Verify trigger conditions match incoming incidents
- Check playbook is enabled
- Review trigger condition syntax

### Step Failing

- Check connector is healthy
- Verify required parameters are provided
- Check variable templates resolve correctly
- Review step logs in incident timeline

### Approval Stuck

- Check Approvals queue for pending items
- Verify approvers have notification channel configured
- Consider timeout settings for approvals
