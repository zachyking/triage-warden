# Web Dashboard

Browser-based interface for incident management.

## Overview

The dashboard provides:
- Real-time incident monitoring
- Approval workflow management
- Playbook configuration
- System settings

Access at: `http://localhost:8080`

## Features

### Home Dashboard

The main dashboard displays:
- **KPIs**: Open incidents, pending approvals, triage rate
- **Recent Incidents**: Latest incidents with status
- **Trend Charts**: Incident volume over time
- **Quick Actions**: Create incident, run playbook

### Incident Management

- List view with filtering and sorting
- Detail view with full incident context
- Action execution interface
- Triage results and reasoning

### Approval Workflow

- Queue of pending approvals
- One-click approve/reject
- Bulk approval for related actions
- SLA countdown timers

### Playbook Management

- Create and edit playbooks
- Visual step editor
- Test with sample data
- Execution history

### Settings

- Connector configuration
- Policy rule management
- User administration
- System preferences

## Navigation

| Path | Description |
|------|-------------|
| `/` | Dashboard home |
| `/incidents` | Incident list |
| `/incidents/:id` | Incident detail |
| `/approvals` | Pending approvals |
| `/playbooks` | Playbook management |
| `/settings` | System settings |
| `/login` | Login page |

## Next Steps

- [Incidents](./incidents.md) - Managing incidents
- [Approvals](./approvals.md) - Approval workflow
- [Playbooks](./playbooks.md) - Playbook configuration
- [Settings](./settings.md) - System settings
