# Collaboration

Coordinate incident response across your team with assignments, comments, real-time events, activity feeds, and shift handoffs.

## Overview

The collaboration module (Stage 4.3) adds team workflow features to incident management:

- **Incident assignment** -- manual and auto-assignment with rules
- **Comments** -- threaded discussion on incidents with mentions
- **Real-time events** -- live updates pushed to connected clients
- **Activity feed** -- chronological audit trail of all actions
- **Shift handoff** -- structured handoff reports between shifts

## Incident Assignment

### Manual Assignment

Assign an incident to an analyst via the API:

```bash
curl -X PUT http://localhost:8080/api/incidents/{id}/assignment \
  -H "Content-Type: application/json" \
  -d '{
    "assignee_id": "analyst-uuid",
    "reason": "Specialist in lateral movement investigations"
  }'
```

### Auto-Assignment Rules

Create rules that automatically assign incidents based on conditions:

```json
{
  "name": "Critical to Senior Analysts",
  "enabled": true,
  "conditions": [
    { "field": "severity", "operator": "equals", "value": "critical" }
  ],
  "assignee": { "type": "team", "team_id": "senior-analysts" },
  "priority": 1
}
```

Rules are evaluated in priority order (lower number = higher priority). The first matching rule wins.

### Assignee Targets

| Type | Description |
|------|-------------|
| `user` | Assign to a specific analyst by ID |
| `team` | Round-robin across team members |
| `on_call` | Assign to whoever is on-call |

## Comments

Add discussion, analysis notes, and action records to incidents.

### Creating a Comment

```bash
curl -X POST http://localhost:8080/api/comments \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "incident-uuid",
    "content": "Found lateral movement evidence via PsExec. @senior-analyst please review.",
    "comment_type": "analysis",
    "mentions": ["senior-analyst-uuid"]
  }'
```

### Comment Types

| Type | Use case |
|------|----------|
| `note` | General notes and observations |
| `analysis` | Technical findings and analysis |
| `action_taken` | Record of actions performed |
| `question` | Questions for other team members |
| `resolution` | Final resolution summary |

### Filtering Comments

```bash
# All comments for an incident
curl "http://localhost:8080/api/comments?incident_id={id}"

# Only analysis comments
curl "http://localhost:8080/api/comments?incident_id={id}&comment_type=analysis"

# Comments by a specific analyst
curl "http://localhost:8080/api/comments?author_id={analyst_id}"
```

Comments support pagination with `page` and `per_page` query parameters.

## Real-time Events

The real-time event system pushes updates to connected clients when incidents are modified, comments are added, or assignments change. Events include:

- Incident status changes
- New comments and mentions
- Assignment updates
- Action execution results
- Field-level change tracking

Subscribers can filter events by incident ID, event type, or severity.

## Activity Feed

Every action on an incident is recorded in the activity feed, providing a complete audit trail:

- Who did what and when
- What fields changed (with before/after values)
- Comment and assignment history
- Action execution records

Filter the activity feed by incident, user, or activity type.

## Shift Handoff

Generate structured handoff reports at shift transitions:

```bash
curl -X POST http://localhost:8080/api/handoff \
  -H "Content-Type: application/json" \
  -d '{
    "outgoing_shift": "Day Shift",
    "incoming_shift": "Night Shift",
    "notes": "Ongoing phishing campaign targeting finance department"
  }'
```

Handoff reports include:

- Summary of open incidents per severity
- Actions pending approval
- Recent escalations
- Custom notes from the outgoing team
