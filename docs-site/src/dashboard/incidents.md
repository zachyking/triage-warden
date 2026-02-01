# Incidents

Managing incidents in the web dashboard.

## Incident List

Access at `/incidents`

### Filtering

- **Status**: Open, Triaged, Resolved
- **Severity**: Low, Medium, High, Critical
- **Type**: Phishing, Malware, Suspicious Login
- **Date Range**: Custom time period

### Sorting

Click column headers to sort:
- Created (newest/oldest)
- Severity (highest/lowest)
- Status

### Bulk Actions

Select multiple incidents for:
- Bulk resolve
- Bulk escalate
- Export to CSV

## Incident Detail

Click an incident to view details.

### Overview Tab

- Incident metadata
- AI verdict and confidence
- Recommended actions
- Timeline of events

### Raw Data Tab

- Original incident data (JSON)
- Parsed email content (for phishing)
- Detection details (for malware)

### Actions Tab

- Available actions
- Executed actions with results
- Pending approvals

### Enrichment Tab

- Threat intelligence results
- SIEM correlation data
- Related incidents

## Creating Incidents

Click "New Incident" button.

### Required Fields

- **Type**: Select incident type
- **Source**: Origin of the incident
- **Severity**: Initial severity assessment

### Optional Fields

- **Description**: Free-form description
- **Raw Data**: JSON payload
- **Assignee**: Initial assignment

## Executing Actions

From the incident detail page:

1. Click "Actions" tab
2. Select action from dropdown
3. Fill in parameters
4. Click "Execute"

If approval is required:
- Action appears in pending state
- Notification sent to approvers
- Status updates when approved/rejected

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `j` / `k` | Navigate list |
| `Enter` | Open incident |
| `Esc` | Close modal |
| `a` | Open actions menu |
| `e` | Escalate |
| `r` | Resolve |

## Real-time Updates

The dashboard uses HTMX for live updates:
- New incidents appear automatically
- Status changes reflect immediately
- Approval decisions update in real-time
