# Architecture Overview

Triage Warden is built as a modular, layered system combining Rust for performance-critical components and Python for AI capabilities.

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                           Clients                                    │
│              (Web Browser, CLI, API Consumers)                       │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         API Layer (tw-api)                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  REST API   │  │ Web Handlers│  │  Webhooks   │  │   Metrics   │ │
│  │   (Axum)    │  │(HTMX+Askama)│  │             │  │ (Prometheus)│ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌───────────────┐        ┌───────────────────┐       ┌───────────────┐
│ Policy Engine │        │   Action Registry │       │  Event Bus    │
│   (tw-policy) │        │    (tw-actions)   │       │  (tw-core)    │
└───────────────┘        └───────────────────┘       └───────────────┘
        │                          │                          │
        └──────────────────────────┼──────────────────────────┘
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Core Domain (tw-core)                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │  Incidents  │  │  Playbooks  │  │   Users     │  │   Audit     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Database Layer (SQLx)                             │
│              (SQLite for dev, PostgreSQL for prod)                   │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                      Python Bridge (tw-bridge)                       │
│                          (PyO3 Bindings)                             │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       AI Layer (tw_ai)                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │Triage Agent │  │    Tools    │  │  Playbook   │  │  Evaluation │ │
│  │  (Claude)   │  │             │  │   Engine    │  │  Framework  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    Connector Layer (tw-connectors)                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐ │
│  │ VirusTotal  │  │   Splunk    │  │ CrowdStrike │  │    Jira     │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Crate Structure

| Crate | Purpose |
|-------|---------|
| `tw-api` | HTTP server, REST API, web handlers, webhooks |
| `tw-core` | Domain models, database repositories, event bus |
| `tw-actions` | Action handlers (quarantine, isolate, notify, etc.) |
| `tw-policy` | Policy engine, approval rules, decision evaluation |
| `tw-connectors` | External service integrations (VirusTotal, Splunk, etc.) |
| `tw-bridge` | PyO3 bindings exposing Rust to Python |
| `tw-cli` | Command-line interface |
| `tw-observability` | Metrics, tracing, logging infrastructure |

## Key Design Decisions

### Rust + Python Hybrid

- **Rust**: Core platform, API server, policy engine, actions
- **Python**: AI agents, LLM integrations, playbook execution
- **Bridge**: PyO3 enables Python to call Rust connectors and actions

### Trait-Based Connectors

All connectors implement traits for testability:

```rust
#[async_trait]
pub trait ThreatIntelConnector: Send + Sync {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatReport>;
    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatReport>;
    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatReport>;
}
```

### Event-Driven Architecture

The event bus enables loose coupling:

```rust
event_bus.publish(Event::IncidentCreated { id, incident_type });
event_bus.publish(Event::ActionExecuted { action_id, result });
```

### Policy-First Actions

All actions pass through the policy engine:

```
Request → Policy Evaluation → (Allowed | Denied | RequiresApproval) → Execute
```

## Next Steps

- [Components](./components.md) - Detailed component descriptions
- [Data Flow](./data-flow.md) - How data moves through the system
- [Security Model](./security.md) - Authentication and authorization
