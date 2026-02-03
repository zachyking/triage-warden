# Database Schema

Triage Warden supports both SQLite (development/small deployments) and PostgreSQL (production). This document describes the database schema used by both backends.

## Overview

The database consists of 11 tables organized into three logical groups:

- **Core Incident Management**: incidents, audit_logs, actions, approvals
- **Configuration**: playbooks, connectors, policies, notification_channels, settings
- **Authentication**: users, sessions, api_keys

## Entity Relationship Diagram

```
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│    users     │       │   api_keys   │       │   sessions   │
├──────────────┤       ├──────────────┤       ├──────────────┤
│ id (PK)      │◄──────│ user_id (FK) │       │ id (PK)      │
│ email        │       │ id (PK)      │       │ data         │
│ username     │       │ key_hash     │       │ expiry_date  │
│ password_hash│       │ scopes       │       └──────────────┘
│ role         │       └──────────────┘
└──────────────┘

┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  incidents   │       │  audit_logs  │       │   actions    │
├──────────────┤       ├──────────────┤       ├──────────────┤
│ id (PK)      │◄──────│ incident_id  │       │ id (PK)      │
│ source       │       │ id (PK)      │       │ incident_id  │──┐
│ severity     │       │ action       │       │ action_type  │  │
│ status       │◄──────│ actor        │       │ target       │  │
│ alert_data   │       │ details      │       │ approval_status│ │
│ enrichments  │       │ created_at   │       └──────────────┘  │
│ analysis     │       └──────────────┘                         │
│ proposed_actions│                                             │
│ ticket_id    │       ┌──────────────┐                         │
│ tags         │       │  approvals   │◄────────────────────────┘
│ metadata     │       ├──────────────┤
└──────────────┘       │ id (PK)      │
                       │ action_id    │
                       │ incident_id  │
                       │ status       │
                       └──────────────┘
```

## Core Tables

### incidents

Stores security incidents created from incoming alerts.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| source | JSON/TEXT | NOT NULL | Alert source metadata |
| severity | ENUM/TEXT | NOT NULL | info, low, medium, high, critical |
| status | ENUM/TEXT | NOT NULL | See [Status Values](#incident-status-values) |
| alert_data | JSON/TEXT | NOT NULL | Original alert payload |
| enrichments | JSON/TEXT | DEFAULT '[]' | Array of enrichment results |
| analysis | JSON/TEXT | NULLABLE | AI triage analysis |
| proposed_actions | JSON/TEXT | DEFAULT '[]' | Array of proposed actions |
| ticket_id | TEXT | NULLABLE | External ticket reference |
| tags | JSON/TEXT | DEFAULT '[]' | User-defined tags |
| metadata | JSON/TEXT | DEFAULT '{}' | Additional metadata |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: status, severity, created_at, updated_at

#### Incident Status Values

- `new` - Newly created from alert
- `enriching` - Gathering threat intelligence
- `analyzing` - AI analysis in progress
- `pending_review` - Awaiting analyst review
- `pending_approval` - Actions awaiting approval
- `executing` - Actions being executed
- `resolved` - Incident resolved
- `false_positive` - Marked as false positive
- `escalated` - Escalated to higher tier
- `closed` - Administratively closed

### audit_logs

Immutable audit trail for all incident actions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| incident_id | UUID/TEXT | FK → incidents | Parent incident |
| action | TEXT | NOT NULL | Action type (status_changed, action_approved, etc.) |
| actor | TEXT | NOT NULL | Username or "system" |
| details | JSON/TEXT | NULLABLE | Action-specific details |
| created_at | TIMESTAMP/TEXT | NOT NULL | Action timestamp |

**Indexes**: incident_id, created_at

### actions

Stores proposed and executed response actions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| incident_id | UUID/TEXT | FK → incidents | Parent incident |
| action_type | TEXT | NOT NULL | isolate_host, disable_user, block_ip, etc. |
| target | JSON/TEXT | NOT NULL | Action target details |
| parameters | JSON/TEXT | DEFAULT '{}' | Action parameters |
| reason | TEXT | NOT NULL | Justification for action |
| priority | INTEGER | DEFAULT 50 | Execution priority (1-100) |
| approval_status | ENUM/TEXT | NOT NULL | See [Approval Status Values](#approval-status-values) |
| approved_by | TEXT | NULLABLE | Approving user |
| approval_timestamp | TIMESTAMP/TEXT | NULLABLE | Approval time |
| result | JSON/TEXT | NULLABLE | Execution result |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| executed_at | TIMESTAMP/TEXT | NULLABLE | Execution timestamp |

**Indexes**: incident_id, approval_status, created_at

#### Approval Status Values

- `pending` - Awaiting approval decision
- `auto_approved` - Automatically approved by policy
- `approved` - Manually approved
- `denied` - Manually denied
- `executed` - Successfully executed
- `failed` - Execution failed

### approvals

Tracks multi-level approval workflows.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| action_id | UUID/TEXT | FK → actions | Related action |
| incident_id | UUID/TEXT | FK → incidents | Parent incident |
| approval_level | TEXT | NOT NULL | analyst, senior, manager, executive |
| status | ENUM/TEXT | NOT NULL | pending, approved, denied, expired |
| requested_by | TEXT | NOT NULL | Requesting user/system |
| requested_at | TIMESTAMP/TEXT | NOT NULL | Request timestamp |
| decided_by | TEXT | NULLABLE | Deciding user |
| decided_at | TIMESTAMP/TEXT | NULLABLE | Decision timestamp |
| decision_reason | TEXT | NULLABLE | Optional reason |
| expires_at | TIMESTAMP/TEXT | NULLABLE | Approval expiration |

**Indexes**: action_id, status, expires_at

## Configuration Tables

### playbooks

Automation workflow definitions.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| name | TEXT | NOT NULL | Playbook name |
| description | TEXT | NULLABLE | Description |
| trigger_type | TEXT | NOT NULL | alert_type, severity, source, manual |
| trigger_condition | TEXT | NULLABLE | Trigger condition expression |
| stages | JSON/TEXT | DEFAULT '[]' | Array of workflow stages |
| enabled | BOOLEAN/INTEGER | DEFAULT TRUE | Active status |
| execution_count | INTEGER | DEFAULT 0 | Times executed |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: name, trigger_type, enabled, created_at

### connectors

External integration configurations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| name | TEXT | NOT NULL | Display name |
| connector_type | TEXT | NOT NULL | virus_total, jira, splunk, etc. |
| config | JSON/TEXT | DEFAULT '{}' | Connection configuration (encrypted credentials) |
| status | TEXT | DEFAULT 'unknown' | connected, disconnected, error, unknown |
| enabled | BOOLEAN/INTEGER | DEFAULT TRUE | Active status |
| last_health_check | TIMESTAMP/TEXT | NULLABLE | Last health check time |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: name, connector_type, status, enabled

### policies

Approval and automation policy rules.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| name | TEXT | NOT NULL | Policy name |
| description | TEXT | NULLABLE | Description |
| condition | TEXT | NOT NULL | Condition expression |
| action | TEXT | NOT NULL | auto_approve, require_approval, deny |
| approval_level | TEXT | NULLABLE | Required approval level |
| priority | INTEGER | DEFAULT 0 | Evaluation priority |
| enabled | BOOLEAN/INTEGER | DEFAULT TRUE | Active status |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: name, action, priority, enabled

### notification_channels

Alert notification configurations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| name | TEXT | NOT NULL | Channel name |
| channel_type | TEXT | NOT NULL | slack, teams, email, pagerduty, webhook |
| config | JSON/TEXT | DEFAULT '{}' | Channel configuration |
| events | JSON/TEXT | DEFAULT '[]' | Subscribed event types |
| enabled | BOOLEAN/INTEGER | DEFAULT TRUE | Active status |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: name, channel_type, enabled

### settings

Key-value configuration store.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| key | TEXT | PRIMARY KEY | Setting key (general, rate_limits, llm) |
| value | JSON/TEXT | NOT NULL | Setting value as JSON |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

## Authentication Tables

### users

User accounts for dashboard and API access.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| email | TEXT | UNIQUE, NOT NULL | Email address |
| username | TEXT | UNIQUE, NOT NULL | Login username |
| password_hash | TEXT | NOT NULL | Argon2 password hash |
| role | ENUM/TEXT | NOT NULL | admin, analyst, viewer |
| display_name | TEXT | NULLABLE | Display name |
| enabled | BOOLEAN/INTEGER | DEFAULT TRUE | Account active status |
| last_login_at | TIMESTAMP/TEXT | NULLABLE | Last login timestamp |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |
| updated_at | TIMESTAMP/TEXT | NOT NULL | Last update timestamp |

**Indexes**: email, username, role, enabled

### sessions

User session storage (tower-sessions compatible).

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | TEXT | PRIMARY KEY | Session ID |
| data | BLOB | NOT NULL | Encrypted session data |
| expiry_date | INTEGER | NOT NULL | Unix timestamp expiration |

**Indexes**: expiry_date

### api_keys

API key authentication.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID/TEXT | PRIMARY KEY | Unique identifier |
| user_id | UUID/TEXT | FK → users | Owner user |
| name | TEXT | NOT NULL | Key display name |
| key_hash | TEXT | NOT NULL | SHA-256 hash of key |
| key_prefix | TEXT | NOT NULL | First 8 chars for identification |
| scopes | JSON/TEXT | DEFAULT '[]' | Allowed API scopes |
| expires_at | TIMESTAMP/TEXT | NULLABLE | Key expiration |
| last_used_at | TIMESTAMP/TEXT | NULLABLE | Last usage timestamp |
| created_at | TIMESTAMP/TEXT | NOT NULL | Creation timestamp |

**Indexes**: user_id, key_prefix, expires_at

## Database-Specific Notes

### SQLite

- UUIDs stored as TEXT
- Timestamps stored as ISO 8601 TEXT
- Boolean stored as INTEGER (0/1)
- JSON stored as TEXT
- Uses `CHECK` constraints for enums

### PostgreSQL

- Native UUID type
- Native TIMESTAMPTZ type
- Native BOOLEAN type
- Native JSONB type with indexing
- Uses custom ENUM types for status fields

## Migrations

Migrations are managed by SQLx and located in:

- SQLite: `crates/tw-core/src/db/migrations/sqlite/`
- PostgreSQL: `crates/tw-core/src/db/migrations/postgres/`

Run migrations automatically on startup or manually:

```bash
# SQLite
tw-cli db migrate --database-url "sqlite:data/triage.db"

# PostgreSQL
tw-cli db migrate --database-url "postgres://user:pass@host/db"
```
