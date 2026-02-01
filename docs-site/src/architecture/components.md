# Components

Detailed description of each major component in Triage Warden.

## tw-api

The HTTP server and web interface.

### REST API Routes

| Route | Description |
|-------|-------------|
| `GET /api/incidents` | List incidents with filtering |
| `POST /api/incidents` | Create new incident |
| `GET /api/incidents/:id` | Get incident details |
| `POST /api/incidents/:id/actions` | Execute action on incident |
| `GET /api/playbooks` | List playbooks |
| `POST /api/webhooks/:source` | Receive webhook events |

### Web Handlers

Server-rendered pages using HTMX and Askama templates:

- Dashboard with KPIs
- Incident list and detail views
- Approval workflow interface
- Playbook management
- Settings configuration

### Authentication

- Session-based auth for web dashboard
- API key auth for programmatic access
- Role-based access control (admin, analyst, viewer)

## tw-core

Core domain logic and data access.

### Domain Models

```rust
pub struct Incident {
    pub id: Uuid,
    pub incident_type: IncidentType,
    pub severity: Severity,
    pub status: IncidentStatus,
    pub source: String,
    pub raw_data: serde_json::Value,
    pub verdict: Option<Verdict>,
    pub confidence: Option<f64>,
    pub created_at: DateTime<Utc>,
}

pub struct Action {
    pub id: Uuid,
    pub incident_id: Uuid,
    pub action_type: ActionType,
    pub status: ActionStatus,
    pub approval_level: Option<ApprovalLevel>,
    pub executed_by: Option<String>,
}
```

### Repositories

Database access layer with SQLite and PostgreSQL support:

- `IncidentRepository`
- `ActionRepository`
- `PlaybookRepository`
- `UserRepository`
- `AuditRepository`

### Event Bus

Async event distribution:

```rust
pub enum Event {
    IncidentCreated { id: Uuid },
    IncidentUpdated { id: Uuid },
    ActionRequested { id: Uuid },
    ActionApproved { id: Uuid, approver: String },
    ActionExecuted { id: Uuid, success: bool },
}
```

## tw-actions

Action handlers for incident response.

### Email Actions

| Action | Description |
|--------|-------------|
| `parse_email` | Extract headers, body, attachments |
| `check_email_authentication` | Validate SPF/DKIM/DMARC |
| `quarantine_email` | Move to quarantine |
| `block_sender` | Add to blocklist |

### Lookup Actions

| Action | Description |
|--------|-------------|
| `lookup_sender_reputation` | Check sender against threat intel |
| `lookup_urls` | Analyze URLs in content |
| `lookup_attachments` | Hash and check attachments |

### Host Actions

| Action | Description |
|--------|-------------|
| `isolate_host` | Network isolation via EDR |
| `scan_host` | Trigger endpoint scan |

### Notification Actions

| Action | Description |
|--------|-------------|
| `notify_user` | Send user notification |
| `notify_reporter` | Update incident reporter |
| `escalate` | Route to approval level |
| `create_ticket` | Create Jira ticket |

## tw-policy

Policy engine for action approval.

### Rule Evaluation

```rust
pub struct PolicyRule {
    pub name: String,
    pub action_type: ActionType,
    pub conditions: Vec<Condition>,
    pub approval_level: ApprovalLevel,
}

pub enum PolicyDecision {
    Allowed,
    Denied { reason: String },
    RequiresApproval { level: ApprovalLevel },
}
```

### Approval Levels

1. **Auto** - No approval required
2. **Analyst** - Any analyst can approve
3. **Senior** - Senior analyst required
4. **Manager** - SOC manager required

## tw-connectors

External service integrations.

### Connector Trait

```rust
#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;
    fn connector_type(&self) -> &str;
    async fn health_check(&self) -> ConnectorResult<ConnectorHealth>;
    async fn test_connection(&self) -> ConnectorResult<bool>;
}
```

### Available Connectors

| Type | Implementations |
|------|-----------------|
| Threat Intel | VirusTotal, Mock |
| SIEM | Splunk, Mock |
| EDR | CrowdStrike, Mock |
| Email Gateway | Microsoft 365, Mock |
| Ticketing | Jira, Mock |

## tw-bridge

PyO3 bindings for Python integration.

### Exposed Classes

```python
from tw_bridge import ThreatIntelBridge, SIEMBridge, EDRBridge

# Use connectors from Python
threat_intel = ThreatIntelBridge("virustotal")
result = threat_intel.lookup_hash("abc123...")
```

## tw_ai (Python)

AI triage and playbook execution.

### Triage Agent

Claude-powered agent for incident analysis:

```python
agent = TriageAgent(model="claude-sonnet-4-20250514")
verdict = await agent.analyze(incident)
# Returns: Verdict(classification="malicious", confidence=0.92, ...)
```

### Playbook Engine

YAML-based playbook execution:

```yaml
name: phishing_triage
steps:
  - action: parse_email
  - action: check_email_authentication
  - action: lookup_sender_reputation
  - condition: sender_reputation < 0.3
    action: quarantine_email
```
