# Playbooks API

Manage and execute playbooks.

## List Playbooks

```
GET /api/playbooks
```

### Response

```json
{
  "data": [
    {
      "id": "pb-abc123",
      "name": "phishing_triage",
      "description": "Automated phishing email analysis",
      "version": "2.0",
      "enabled": true,
      "triggers": {
        "incident_type": "phishing",
        "auto_run": true
      },
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-10T00:00:00Z"
    }
  ]
}
```

## Get Playbook

```
GET /api/playbooks/:id
```

### Response

```json
{
  "data": {
    "id": "pb-abc123",
    "name": "phishing_triage",
    "description": "Automated phishing email analysis",
    "version": "2.0",
    "enabled": true,
    "triggers": {
      "incident_type": "phishing",
      "auto_run": true
    },
    "variables": {
      "quarantine_threshold": 0.7
    },
    "steps": [
      {
        "name": "Parse Email",
        "action": "parse_email",
        "parameters": {
          "raw_email": "{{ incident.raw_data.raw_email }}"
        },
        "output": "parsed"
      }
    ],
    "created_at": "2024-01-01T00:00:00Z",
    "updated_at": "2024-01-10T00:00:00Z"
  }
}
```

## Create Playbook

```
POST /api/playbooks
```

### Request Body

```json
{
  "name": "custom_playbook",
  "description": "My custom investigation playbook",
  "triggers": {
    "incident_type": "phishing",
    "auto_run": false
  },
  "steps": [
    {
      "name": "Parse Email",
      "action": "parse_email",
      "output": "parsed"
    }
  ]
}
```

### Response

```json
{
  "data": {
    "id": "pb-def456",
    "name": "custom_playbook",
    "version": "1.0",
    "created_at": "2024-01-15T12:00:00Z"
  }
}
```

## Update Playbook

```
PUT /api/playbooks/:id
```

### Request Body

```json
{
  "description": "Updated description",
  "enabled": false
}
```

## Delete Playbook

```
DELETE /api/playbooks/:id
```

**Note:** Built-in playbooks cannot be deleted.

## Run Playbook

```
POST /api/playbooks/:id/run
```

Execute a playbook on an incident.

### Request Body

```json
{
  "incident_id": "550e8400-e29b-41d4-a716-446655440000",
  "variables": {
    "quarantine_threshold": 0.9
  }
}
```

### Response

```json
{
  "data": {
    "execution_id": "exec-abc123",
    "playbook_id": "pb-abc123",
    "incident_id": "550e8400-e29b-41d4-a716-446655440000",
    "status": "completed",
    "started_at": "2024-01-15T12:00:00Z",
    "completed_at": "2024-01-15T12:00:45Z",
    "steps_completed": 5,
    "steps_total": 5,
    "verdict": {
      "classification": "malicious",
      "confidence": 0.92
    }
  }
}
```

## Get Playbook Executions

```
GET /api/playbooks/:id/executions
```

### Response

```json
{
  "data": [
    {
      "execution_id": "exec-abc123",
      "incident_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "completed",
      "duration_ms": 45000,
      "started_at": "2024-01-15T12:00:00Z"
    }
  ]
}
```

## Validate Playbook

```
POST /api/playbooks/validate
```

Validate playbook YAML without creating it.

### Request Body

```json
{
  "content": "name: test\nsteps:\n  - action: parse_email"
}
```

### Response (Valid)

```json
{
  "data": {
    "valid": true,
    "warnings": []
  }
}
```

### Response (Invalid)

```json
{
  "data": {
    "valid": false,
    "errors": [
      {
        "line": 3,
        "message": "Unknown action: invalid_action"
      }
    ]
  }
}
```

## Export Playbook

```
GET /api/playbooks/:id/export
```

Download playbook as YAML file.

### Response

```yaml
name: phishing_triage
description: Automated phishing email analysis
version: "2.0"
...
```
