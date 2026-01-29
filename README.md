# Triage Warden

AI-Augmented SOC Triage System for automated incident analysis and response.

## Overview

Triage Warden uses LLM-powered agents to analyze security alerts, enrich indicators, and propose remediation actions—all governed by configurable policy guardrails.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Triage Warden                          │
├─────────────┬─────────────┬─────────────┬──────────────────┤
│  Connectors │   Policy    │  AI Agents  │    Workflows     │
│  (Rust)     │   Engine    │  (Python)   │                  │
├─────────────┼─────────────┼─────────────┼──────────────────┤
│ • SIEM      │ • Guardrails│ • ReAct     │ • Phishing       │
│ • EDR       │ • Approvals │ • Tools     │ • Malware        │
│ • ThreatIntel│ • Kill Switch│ • Prompts  │ • Suspicious Login│
│ • Ticketing │ • Modes     │ • LLM Layer │                  │
└─────────────┴─────────────┴─────────────┴──────────────────┘
```

## Quick Start

```bash
# Build Rust components
cargo build --release

# Install Python package
cd python && pip install -e .

# Run phishing triage
python -c "
from tw_ai.workflows.phishing import PhishingTriageWorkflow
workflow = PhishingTriageWorkflow()
result = await workflow.triage(alert_data)
"
```

## Project Structure

```
├── crates/
│   ├── tw-core/        # Core data models, event bus
│   ├── tw-connectors/  # SIEM, EDR, ThreatIntel, Ticketing
│   ├── tw-policy/      # Guardrails, approvals, kill switch
│   ├── tw-actions/     # Response action implementations
│   └── tw-cli/         # Command-line interface
├── tw-bridge/          # PyO3 Rust-Python bridge
├── python/
│   └── tw_ai/
│       ├── agents/     # ReAct agent, tools, prompts
│       ├── analysis/   # Email, phishing, security analysis
│       ├── workflows/  # Triage orchestration
│       ├── llm/        # OpenAI, Anthropic, Local providers
│       └── metrics/    # Collection and reporting
└── config/
    ├── guardrails.yaml # Policy configuration
    └── playbooks/      # Triage playbooks
```

## Key Features

- **ReAct Agent**: Reasoning + Acting loop for intelligent triage
- **Multi-Provider LLM**: OpenAI, Anthropic, local models
- **Policy Guardrails**: Deny lists, rate limits, approval workflows
- **Kill Switch**: Emergency halt for all automation
- **Operation Modes**: Assisted → Supervised → Autonomous
- **Playbooks**: YAML-configured triage workflows

## Configuration

Edit `config/guardrails.yaml` to configure:
- Protected assets and users
- Rate limits per action type
- Approval requirements
- Auto-approve rules

## Testing

```bash
# Rust tests
cargo test --workspace

# Python tests
cd python && pytest tests/ -v
```

## License

MIT
