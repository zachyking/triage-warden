# Configuration Guide

Complete guides for configuring Triage Warden.

## Initial Setup

After installation, configure Triage Warden in this order:

1. **[Environment Variables](./environment-variables.md)** - Set required environment variables
2. **[Connectors](./connectors-setup.md)** - Connect to your security tools
3. **[Notifications](./notifications-setup.md)** - Set up alert channels
4. **[Playbooks](./playbooks-guide.md)** - Create automation workflows
5. **[Policies](./policies-guide.md)** - Define approval and safety rules

## Quick Configuration

### First Run

After starting Triage Warden, log in with the default credentials:

- **Username:** `admin`
- **Password:** `admin`

**Important:** Change the default password immediately!

### Essential Settings

Navigate to **Settings** and configure:

1. **General**
   - Organization name
   - Timezone
   - Operation mode (Assisted → Supervised → Autonomous)

2. **AI/LLM**
   - Select provider (Anthropic, OpenAI, or Local)
   - Enter API key
   - Choose model

3. **Connectors** (at minimum)
   - Threat intelligence (VirusTotal recommended)
   - Your primary SIEM or alert source

4. **Notifications**
   - At least one channel for critical alerts

## Configuration Methods

### Web UI (Recommended)

Most settings can be configured through the web dashboard at **Settings**.

Pros:
- User-friendly interface
- Validation feedback
- Immediate effect

### Environment Variables

For deployment configuration and secrets:

```bash
# Required
DATABASE_URL=postgres://...
TW_ENCRYPTION_KEY=...

# Optional overrides
TW_LLM_PROVIDER=anthropic
TW_LLM_MODEL=claude-3-sonnet
```

See [Environment Variables Reference](./environment-variables.md) for full list.

### Configuration Files

For complex configurations:

```yaml
# config/default.yaml
server:
  bind_address: "0.0.0.0:8080"

guardrails:
  max_actions_per_incident: 10
  blocked_actions: []
```

## Configuration Hierarchy

Configuration is loaded in this order (later overrides earlier):

```
1. Built-in defaults
         ↓
2. config/default.yaml
         ↓
3. config/{environment}.yaml
         ↓
4. Environment variables
         ↓
5. Database settings (via UI)
```

## Validation

Triage Warden validates configuration at startup:

```bash
# Validate without starting
triage-warden serve --validate-only

# Check specific configuration
triage-warden config check
```

### Common Validation Errors

| Error | Solution |
|-------|----------|
| `Missing TW_ENCRYPTION_KEY` | Set encryption key environment variable |
| `Invalid DATABASE_URL` | Check connection string format |
| `LLM API key required` | Set API key or disable LLM features |
| `Guardrails file not found` | Create `config/guardrails.yaml` |

## Backup Configuration

Before making changes, backup current settings:

```bash
# Export settings via API
curl -H "Authorization: Bearer $API_KEY" \
  http://localhost:8080/api/settings/export > settings-backup.json

# Restore settings
curl -X POST -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d @settings-backup.json \
  http://localhost:8080/api/settings/import
```

## Next Steps

- [Set up connectors](./connectors-setup.md)
- [Configure notifications](./notifications-setup.md)
- [Create playbooks](./playbooks-guide.md)
