# Triage Warden

**AI-powered security incident triage and response platform**

Triage Warden automates the analysis and response to security incidents using AI agents, configurable playbooks, and integrations with your existing security stack.

## Features

- **AI-Powered Triage**: Automated analysis of phishing emails, malware alerts, and suspicious login attempts
- **Configurable Playbooks**: Define custom investigation and response workflows
- **Policy Engine**: Role-based approval workflows for sensitive actions
- **Connector Framework**: Integrate with VirusTotal, Splunk, CrowdStrike, Jira, Microsoft 365, and more
- **Web Dashboard**: Real-time incident management with approval workflows
- **REST API**: Programmatic access for automation and integration
- **Audit Trail**: Complete logging of all actions and decisions

## Quick Example

```bash
# Analyze a phishing email
tw-cli incident create --type phishing --source "email-gateway" --data '{"subject": "Urgent: Update Account"}'

# Run AI triage
tw-cli triage run --incident INC-2024-001

# View the verdict
tw-cli incident get INC-2024-001 --format json
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Web Dashboard                             │
│                    (HTMX + Askama Templates)                     │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         REST API                                 │
│                     (Axum + Tower)                               │
└─────────────────────────────────────────────────────────────────┘
                                │
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
┌───────────────┐    ┌───────────────────┐    ┌───────────────┐
│ Policy Engine │    │   AI Triage Agent │    │    Actions    │
│    (Rust)     │    │     (Python)      │    │    (Rust)     │
└───────────────┘    └───────────────────┘    └───────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Connector Layer                            │
│        (VirusTotal, Splunk, CrowdStrike, Jira, M365)            │
└─────────────────────────────────────────────────────────────────┘
```

## Getting Started

1. [Installation](./getting-started/installation.md) - Install Triage Warden
2. [Quick Start](./getting-started/quickstart.md) - Create your first incident
3. [Configuration](./getting-started/configuration.md) - Configure connectors and policies

## License

Triage Warden is licensed under the MIT License.
