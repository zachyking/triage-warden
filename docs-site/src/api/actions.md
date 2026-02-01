# Actions API

Manage action execution and approvals.

## List Actions

```
GET /api/actions
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | pending, pending_approval, completed, failed |
| `action_type` | string | Filter by action type |
| `incident_id` | uuid | Filter by incident |
| `approval_level` | string | analyst, senior, manager |

### Example

```bash
curl "http://localhost:8080/api/actions?status=pending_approval" \
  -H "Authorization: Bearer tw_xxx"
```

### Response

```json
{
  "data": [
    {
      "id": "act-abc123",
      "incident_id": "550e8400-e29b-41d4-a716-446655440000",
      "action_type": "isolate_host",
      "status": "pending_approval",
      "approval_level": "senior",
      "parameters": {
        "host_id": "aid:xyz789",
        "reason": "Malware detected"
      },
      "requested_by": "triage_agent",
      "requested_at": "2024-01-15T10:45:00Z"
    }
  ]
}
```

## Get Action

```
GET /api/actions/:id
```

### Response

```json
{
  "data": {
    "id": "act-abc123",
    "incident_id": "550e8400-e29b-41d4-a716-446655440000",
    "action_type": "isolate_host",
    "status": "pending_approval",
    "approval_level": "senior",
    "parameters": {
      "host_id": "aid:xyz789",
      "reason": "Malware detected"
    },
    "requested_by": "triage_agent",
    "requested_at": "2024-01-15T10:45:00Z",
    "incident": {
      "incident_number": "INC-2024-0001",
      "incident_type": "malware",
      "severity": "high"
    }
  }
}
```

## Approve Action

```
POST /api/actions/:id/approve
```

### Request Body

```json
{
  "comment": "Verified threat, approved for isolation"
}
```

### Response

```json
{
  "data": {
    "id": "act-abc123",
    "status": "completed",
    "approved_by": "senior.analyst@company.com",
    "approved_at": "2024-01-15T11:00:00Z",
    "result": {
      "success": true,
      "message": "Host isolated successfully"
    }
  }
}
```

### Errors

**403 Forbidden** - Insufficient approval level:

```json
{
  "error": {
    "code": "insufficient_approval_level",
    "message": "This action requires senior analyst approval",
    "required_level": "senior",
    "your_level": "analyst"
  }
}
```

## Reject Action

```
POST /api/actions/:id/reject
```

### Request Body

```json
{
  "reason": "False positive - user confirmed legitimate activity"
}
```

### Response

```json
{
  "data": {
    "id": "act-abc123",
    "status": "rejected",
    "rejected_by": "senior.analyst@company.com",
    "rejected_at": "2024-01-15T11:00:00Z",
    "rejection_reason": "False positive - user confirmed legitimate activity"
  }
}
```

## Execute Action Directly

```
POST /api/actions/execute
```

Execute an action without associating with an incident.

### Request Body

```json
{
  "action": "block_sender",
  "parameters": {
    "sender": "spammer@malicious.com"
  }
}
```

### Response

```json
{
  "data": {
    "action_id": "act-ghi789",
    "status": "completed",
    "result": {
      "success": true,
      "message": "Sender blocked"
    }
  }
}
```

## Get Action Types

```
GET /api/actions/types
```

List all available action types.

### Response

```json
{
  "data": [
    {
      "name": "quarantine_email",
      "description": "Move email to quarantine",
      "category": "email",
      "supports_rollback": true,
      "parameters": [
        {
          "name": "message_id",
          "type": "string",
          "required": true
        },
        {
          "name": "reason",
          "type": "string",
          "required": false
        }
      ]
    },
    {
      "name": "isolate_host",
      "description": "Network-isolate a host",
      "category": "endpoint",
      "supports_rollback": true,
      "default_approval_level": "senior",
      "parameters": [...]
    }
  ]
}
```

## Rollback Action

```
POST /api/actions/:id/rollback
```

Rollback a previously executed action.

### Request Body

```json
{
  "reason": "False positive confirmed"
}
```

### Response

```json
{
  "data": {
    "rollback_action_id": "act-jkl012",
    "original_action_id": "act-abc123",
    "status": "completed",
    "result": {
      "success": true,
      "message": "Host unisolated successfully"
    }
  }
}
```

### Errors

**400 Bad Request** - Action doesn't support rollback:

```json
{
  "error": {
    "code": "rollback_not_supported",
    "message": "Action type 'notify_user' does not support rollback"
  }
}
```
