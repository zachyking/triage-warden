# Approvals

Managing action approvals in the web dashboard.

## Approval Queue

Access at `/approvals`

The queue shows all actions pending your approval based on your role level.

### Queue Columns

- **Action**: Type of action requested
- **Incident**: Related incident
- **Requested By**: Who/what requested it
- **Requested At**: When requested
- **SLA**: Time remaining to respond

### Filtering

- **Approval Level**: Analyst, Senior, Manager
- **Action Type**: Specific actions
- **Incident Type**: Phishing, malware, etc.

## Approval Detail

Click an approval to see full context.

### Context Section

- Full incident details
- AI reasoning (if from triage)
- Related actions already taken

### Decision Section

- **Approve**: Execute the action
- **Reject**: Decline with reason
- **Delegate**: Assign to another approver

## Approving Actions

### Single Approval

1. Click on pending action
2. Review incident context
3. Click "Approve" or "Reject"
4. Add optional comment
5. Confirm decision

### Bulk Approval

For related actions:

1. Select multiple actions (checkbox)
2. Click "Bulk Approve" or "Bulk Reject"
3. Add comment applying to all
4. Confirm

## Rejection

When rejecting:

1. Click "Reject"
2. **Required**: Enter rejection reason
3. Optionally suggest alternative
4. Confirm

The requester is notified of rejection and reason.

## SLA Indicators

| Color | Meaning |
|-------|---------|
| Green | Plenty of time |
| Yellow | < 50% time remaining |
| Orange | < 25% time remaining |
| Red | SLA exceeded |

## Notifications

You receive notifications for:
- New actions requiring your approval
- SLA warnings (50%, 75% elapsed)
- Escalations to your level

Configure notification preferences in Settings.

## Delegation

If unavailable:

1. Go to Settings > Delegation
2. Select delegate user
3. Set date range
4. Delegate receives your approvals

## Audit Trail

All approvals are logged:
- Who approved/rejected
- When decision was made
- Time to approve
- Comments provided

View at Settings > Audit Logs.
