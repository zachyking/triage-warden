# Data Flow

How data moves through Triage Warden from incident creation to resolution.

## Incident Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Created   │────▶│   Triaging  │────▶│   Triaged   │────▶│  Resolved   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
       │                   │                   │                   │
       ▼                   ▼                   ▼                   ▼
   Webhook/API        AI Agent          Actions Executed      Closed
   receives data      analyzes          (with approval)
```

## Detailed Flow

### 1. Incident Creation

```
External Source (Email Gateway, SIEM, EDR)
                    │
                    ▼
            Webhook Endpoint
            /api/webhooks/:source
                    │
                    ▼
         ┌──────────────────┐
         │  Parse & Validate │
         │  Incoming Data    │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Create Incident   │
         │ Record in DB      │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Publish Event:    │
         │ IncidentCreated   │
         └──────────────────┘
```

### 2. AI Triage

```
         ┌──────────────────┐
         │ Event: Incident   │
         │ Created           │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Load Playbook     │
         │ (based on type)   │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Execute Playbook  │
         │ Steps             │
         └──────────────────┘
                    │
        ┌───────────┴───────────┐
        ▼                       ▼
┌───────────────┐       ┌───────────────┐
│ Enrichment    │       │ AI Analysis   │
│ Actions       │       │ (Claude)      │
│ - parse_email │       │               │
│ - lookup_*    │       │ Generates:    │
└───────────────┘       │ - Verdict     │
        │               │ - Confidence  │
        │               │ - Reasoning   │
        │               │ - Actions     │
        └───────┬───────└───────────────┘
                │
                ▼
         ┌──────────────────┐
         │ Update Incident   │
         │ with Verdict      │
         └──────────────────┘
```

### 3. Action Execution

```
         ┌──────────────────┐
         │ Action Request    │
         │ (from agent or    │
         │  human)           │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Build Action      │
         │ Context           │
         └──────────────────┘
                    │
                    ▼
         ┌──────────────────┐
         │ Policy Engine     │
         │ Evaluation        │
         └──────────────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   ┌────────┐  ┌────────┐  ┌────────┐
   │Allowed │  │Denied  │  │Requires│
   │        │  │        │  │Approval│
   └────────┘  └────────┘  └────────┘
        │           │           │
        ▼           ▼           ▼
   Execute      Return       Queue for
   Action       Error        Approval
        │                       │
        │                       ▼
        │              ┌──────────────┐
        │              │ Notify       │
        │              │ Approvers    │
        │              └──────────────┘
        │                       │
        │                       ▼
        │              ┌──────────────┐
        │              │ Wait for     │
        │              │ Approval     │
        │              └──────────────┘
        │                       │
        │        ┌──────────────┴──────────────┐
        │        ▼                             ▼
        │   ┌────────┐                    ┌────────┐
        │   │Approved│                    │Rejected│
        │   └────────┘                    └────────┘
        │        │                             │
        │        ▼                             ▼
        │   Execute Action               Update Status
        │        │
        └────────┴─────────┐
                           ▼
                  ┌──────────────┐
                  │ Connector    │
                  │ Execution    │
                  │ (External    │
                  │  Service)    │
                  └──────────────┘
                           │
                           ▼
                  ┌──────────────┐
                  │ Update       │
                  │ Action       │
                  │ Status       │
                  └──────────────┘
                           │
                           ▼
                  ┌──────────────┐
                  │ Audit Log    │
                  │ Entry        │
                  └──────────────┘
```

## Data Stores

### Primary Database

| Table | Purpose |
|-------|---------|
| `incidents` | Incident records |
| `actions` | Action requests and results |
| `playbooks` | Playbook definitions |
| `users` | User accounts |
| `sessions` | Active sessions |
| `api_keys` | API credentials |
| `audit_logs` | Action audit trail |
| `connectors` | Connector configurations |
| `policies` | Policy rules |
| `notifications` | Notification history |
| `settings` | System settings |

### Event Bus (In-Memory)

Transient event distribution for real-time updates:

- Incident lifecycle events
- Action status changes
- Approval notifications
- System health events

## External Data Flow

### Inbound (Webhooks)

```
Email Gateway ──────┐
SIEM Alerts ────────┼──▶ Webhook Handler ──▶ Incident Creation
EDR Events ─────────┘
```

### Outbound (Connectors)

```
                           ┌──▶ VirusTotal (threat intel)
Action Execution ──────────┼──▶ Splunk (SIEM queries)
                           ├──▶ CrowdStrike (host actions)
                           ├──▶ M365 (email actions)
                           └──▶ Jira (ticketing)
```

## Metrics Flow

```
Rust Components ──┬──▶ Prometheus Registry ──▶ /metrics endpoint
Python Components ─┘
```

Exposed metrics:
- `triage_warden_incidents_total{type, severity}`
- `triage_warden_actions_total{action, status}`
- `triage_warden_triage_duration_seconds{type}`
- `triage_warden_connector_requests_total{connector, status}`
