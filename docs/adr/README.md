# Architectural Decision Records

This directory contains Architectural Decision Records (ADRs) for Triage Warden.

## What is an ADR?

An ADR is a document that captures an important architectural decision made along with its context and consequences.

## ADR Index

| Number | Title | Status | Date |
|--------|-------|--------|------|
| [001](001-event-bus-architecture.md) | Event Bus Architecture | Accepted | 2024-01 |
| [002](002-dual-database-support.md) | Dual Database Support (SQLite + PostgreSQL) | Accepted | 2024-01 |
| [003](003-credential-encryption.md) | Credential Encryption at Rest | Accepted | 2024-01 |
| [004](004-session-management.md) | Session Management Strategy | Accepted | 2024-01 |
| [005](005-api-key-format.md) | API Key Format and Security | Accepted | 2024-01 |
| [006](006-operation-modes.md) | Operation Modes (Supervised/Autonomous) | Accepted | 2024-01 |
| [007](007-kill-switch-design.md) | Kill Switch Design | Accepted | 2024-01 |

## ADR Template

New ADRs should follow this template:

```markdown
# ADR-XXX: Title

## Status

Proposed | Accepted | Deprecated | Superseded

## Context

What is the issue that we're seeing that is motivating this decision or change?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or more difficult to do because of this change?
```
