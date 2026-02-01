# CLI Reference

Command-line interface for Triage Warden.

## Installation

The CLI is built with the main project:

```bash
cargo build --release
./target/release/tw-cli --help
```

## Global Options

```
tw-cli [OPTIONS] <COMMAND>

Options:
  -c, --config <FILE>     Configuration file path
  -v, --verbose           Enable verbose output
  -q, --quiet             Suppress non-error output
  --json                  Output as JSON
  -h, --help              Print help
  -V, --version           Print version
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `TW_API_URL` | API server URL (default: http://localhost:8080) |
| `TW_API_KEY` | API key for authentication |
| `TW_CONFIG` | Path to config file |

## Commands Overview

| Command | Description |
|---------|-------------|
| `incident` | Manage incidents |
| `action` | Execute and manage actions |
| `triage` | Run AI triage |
| `playbook` | Manage playbooks |
| `policy` | Manage policy rules |
| `connector` | Manage connectors |
| `user` | User management |
| `api-key` | API key management |
| `webhook` | Webhook management |
| `config` | Configuration management |
| `db` | Database operations |
| `serve` | Start API server |

## Quick Examples

```bash
# List open incidents
tw-cli incident list --status open

# Create incident
tw-cli incident create --type phishing --severity high

# Run triage
tw-cli triage run --incident INC-2024-001

# Execute action
tw-cli action execute --incident INC-2024-001 --action quarantine_email

# Approve pending action
tw-cli action approve act-abc123

# Start server
tw-cli serve --port 8080
```

## Next Steps

- [Commands](./commands.md) - Detailed command reference
