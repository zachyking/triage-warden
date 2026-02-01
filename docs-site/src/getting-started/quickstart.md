# Quick Start

Get Triage Warden running and process your first incident in 5 minutes.

## 1. Start the Server

```bash
# Start with default settings (SQLite, mock connectors)
cargo run --bin tw-api

# Or use the release binary
./target/release/tw-api
```

The web dashboard is now available at `http://localhost:8080`.

## 2. Create an Incident

### Via Web Dashboard

1. Open `http://localhost:8080` in your browser
2. Click **"New Incident"**
3. Fill in the incident details:
   - **Type**: Phishing
   - **Source**: Email Gateway
   - **Severity**: Medium
4. Click **Create**

### Via CLI

```bash
tw-cli incident create \
  --type phishing \
  --source "email-gateway" \
  --severity medium \
  --data '{
    "subject": "Urgent: Verify Your Account",
    "sender": "security@fake-bank.com",
    "recipient": "employee@company.com"
  }'
```

### Via API

```bash
curl -X POST http://localhost:8080/api/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "incident_type": "phishing",
    "source": "email-gateway",
    "severity": "medium",
    "raw_data": {
      "subject": "Urgent: Verify Your Account",
      "sender": "security@fake-bank.com"
    }
  }'
```

## 3. Run AI Triage

```bash
# Trigger triage for the incident
tw-cli triage run --incident INC-2024-0001
```

The AI agent will:
1. Parse email headers and content
2. Check sender reputation
3. Analyze URLs and attachments
4. Generate a verdict with confidence score

## 4. View the Verdict

```bash
# Get incident with triage results
tw-cli incident get INC-2024-0001

# Example output:
# Incident: INC-2024-0001
# Type: phishing
# Status: triaged
# Verdict: malicious
# Confidence: 0.92
# Recommended Actions:
#   - quarantine_email
#   - block_sender
#   - notify_user
```

## 5. Execute Actions

Actions may require approval based on your policy configuration:

```bash
# Request to quarantine the email
tw-cli action execute --incident INC-2024-0001 --action quarantine_email

# If auto-approved:
# Action executed: quarantine_email (status: completed)

# If requires approval:
# Action pending approval from: Senior Analyst
```

Approve pending actions via the dashboard at `/approvals`.

## Next Steps

- [Configuration](./configuration.md) - Set up real connectors
- [Playbooks](../playbooks/README.md) - Create automated workflows
- [Policy Engine](../policy/README.md) - Configure approval rules
