# Incidents API

Create, read, update, and manage security incidents.

## List Incidents

```
GET /api/incidents
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status (open, triaged, resolved) |
| `severity` | string | Filter by severity (low, medium, high, critical) |
| `type` | string | Filter by incident type |
| `created_after` | datetime | Created after timestamp |
| `created_before` | datetime | Created before timestamp |
| `page` | integer | Page number |
| `per_page` | integer | Items per page |
| `sort` | string | Sort field (prefix `-` for desc) |

### Example

```bash
curl "http://localhost:8080/api/incidents?status=open&severity=high&per_page=10" \
  -H "Authorization: Bearer tw_xxx"
```

### Response

```json
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "incident_number": "INC-2024-0001",
      "incident_type": "phishing",
      "severity": "high",
      "status": "open",
      "source": "email_gateway",
      "created_at": "2024-01-15T10:30:00Z",
      "updated_at": "2024-01-15T10:30:00Z"
    }
  ],
  "meta": {
    "page": 1,
    "per_page": 10,
    "total": 42
  }
}
```

## Get Incident

```
GET /api/incidents/:id
```

### Example

```bash
curl "http://localhost:8080/api/incidents/550e8400-e29b-41d4-a716-446655440000" \
  -H "Authorization: Bearer tw_xxx"
```

### Response

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "incident_number": "INC-2024-0001",
    "incident_type": "phishing",
    "severity": "high",
    "status": "triaged",
    "source": "email_gateway",
    "raw_data": {
      "message_id": "AAMkAGI2...",
      "sender": "phisher@malicious.com",
      "subject": "Urgent: Update Account"
    },
    "verdict": {
      "classification": "malicious",
      "confidence": 0.92,
      "category": "phishing",
      "reasoning": "Multiple phishing indicators..."
    },
    "recommended_actions": [
      "quarantine_email",
      "block_sender"
    ],
    "created_at": "2024-01-15T10:30:00Z",
    "updated_at": "2024-01-15T10:35:00Z",
    "triaged_at": "2024-01-15T10:35:00Z"
  }
}
```

## Create Incident

```
POST /api/incidents
```

### Request Body

```json
{
  "incident_type": "phishing",
  "source": "email_gateway",
  "severity": "medium",
  "raw_data": {
    "message_id": "AAMkAGI2...",
    "sender": "unknown@domain.com",
    "recipient": "employee@company.com",
    "subject": "Important Document",
    "received_at": "2024-01-15T10:00:00Z"
  }
}
```

### Example

```bash
curl -X POST "http://localhost:8080/api/incidents" \
  -H "Authorization: Bearer tw_xxx" \
  -H "Content-Type: application/json" \
  -d '{
    "incident_type": "phishing",
    "source": "email_gateway",
    "severity": "medium",
    "raw_data": {...}
  }'
```

### Response

```json
{
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440001",
    "incident_number": "INC-2024-0002",
    "status": "open",
    "created_at": "2024-01-15T11:00:00Z"
  }
}
```

## Update Incident

```
PUT /api/incidents/:id
```

### Request Body

```json
{
  "severity": "high",
  "status": "resolved",
  "resolution": "False positive - legitimate vendor email"
}
```

## Delete Incident

```
DELETE /api/incidents/:id
```

**Note:** Requires admin role.

## Run Triage

```
POST /api/incidents/:id/triage
```

Trigger AI triage on an incident.

### Request Body (Optional)

```json
{
  "playbook": "custom_phishing",
  "force": true
}
```

### Response

```json
{
  "data": {
    "triage_id": "triage-abc123",
    "status": "completed",
    "verdict": {
      "classification": "malicious",
      "confidence": 0.92
    },
    "duration_ms": 45000
  }
}
```

## Execute Action

```
POST /api/incidents/:id/actions
```

Execute an action on an incident.

### Request Body

```json
{
  "action": "quarantine_email",
  "parameters": {
    "message_id": "AAMkAGI2...",
    "reason": "Phishing detected"
  }
}
```

### Response (Immediate Execution)

```json
{
  "data": {
    "action_id": "act-abc123",
    "status": "completed",
    "result": {
      "success": true,
      "message": "Email quarantined successfully"
    }
  }
}
```

### Response (Pending Approval)

```json
{
  "data": {
    "action_id": "act-abc123",
    "status": "pending_approval",
    "approval_level": "senior",
    "message": "Action requires senior analyst approval"
  }
}
```

## Get Incident Actions

```
GET /api/incidents/:id/actions
```

List all actions for an incident.

### Response

```json
{
  "data": [
    {
      "id": "act-abc123",
      "action_type": "quarantine_email",
      "status": "completed",
      "executed_at": "2024-01-15T10:40:00Z",
      "executed_by": "system"
    },
    {
      "id": "act-def456",
      "action_type": "block_sender",
      "status": "pending_approval",
      "approval_level": "analyst",
      "requested_at": "2024-01-15T10:41:00Z"
    }
  ]
}
```
