# AI Triage

Automated incident analysis using Claude AI agents.

## Overview

The triage agent analyzes security incidents to:
1. **Classify** - Determine if the incident is malicious, suspicious, or benign
2. **Assess confidence** - Quantify certainty in the classification
3. **Explain** - Provide reasoning for the verdict
4. **Recommend** - Suggest response actions

## How It Works

```
Incident → Playbook Selection → Tool Execution → AI Analysis → Verdict
```

1. **Incident received** - New incident created via webhook or API
2. **Playbook selected** - Based on incident type (phishing, malware, etc.)
3. **Tools executed** - Parse data, lookup reputation, check authentication
4. **AI analysis** - Claude analyzes gathered data
5. **Verdict returned** - Classification with confidence and recommendations

## Example Verdict

```json
{
  "incident_id": "INC-2024-001",
  "classification": "malicious",
  "confidence": 0.92,
  "category": "phishing",
  "reasoning": "Multiple indicators suggest this is a credential phishing attempt:\n1. Sender domain registered 2 days ago\n2. SPF and DKIM authentication failed\n3. URL leads to a fake Microsoft login page\n4. Subject uses urgency tactics",
  "recommended_actions": [
    {
      "action": "quarantine_email",
      "priority": 1,
      "reason": "Prevent user access to phishing content"
    },
    {
      "action": "block_sender",
      "priority": 2,
      "reason": "Sender has no legitimate history"
    },
    {
      "action": "notify_user",
      "priority": 3,
      "reason": "Educate user about phishing attempt"
    }
  ],
  "iocs": [
    {"type": "domain", "value": "phishing-site.com"},
    {"type": "ip", "value": "192.168.1.100"}
  ],
  "mitre_attack": ["T1566.001", "T1078"]
}
```

## Triggering Triage

### Automatic (Webhook)

Configure webhooks to auto-triage new incidents:

```yaml
webhooks:
  email_gateway:
    auto_triage: true
    playbook: phishing_triage
```

### Manual (CLI)

```bash
tw-cli triage run --incident INC-2024-001
```

### Manual (API)

```bash
curl -X POST http://localhost:8080/api/incidents/INC-2024-001/triage
```

## Next Steps

- [Triage Agent](./agent.md) - Agent architecture and configuration
- [Verdict Types](./verdicts.md) - Understanding classifications
- [Confidence Scoring](./confidence.md) - How confidence is calculated
