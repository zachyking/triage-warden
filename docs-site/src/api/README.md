# REST API

Programmatic access to Triage Warden functionality.

## Base URL

```
http://localhost:8080/api
```

## Authentication

See [Authentication](./authentication.md) for details.

### API Key

```bash
curl -H "Authorization: Bearer tw_abc123_secretkey" \
  http://localhost:8080/api/incidents
```

### Session Cookie

For browser-based access, use session authentication via `/login`.

## Response Format

All responses are JSON:

```json
{
  "data": { ... },
  "meta": {
    "page": 1,
    "per_page": 20,
    "total": 150
  }
}
```

### Error Responses

```json
{
  "error": {
    "code": "not_found",
    "message": "Incident not found",
    "details": { ... }
  }
}
```

## HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 422 | Validation Error |
| 429 | Rate Limited |
| 500 | Server Error |

## Endpoints Overview

### Incidents

| Method | Path | Description |
|--------|------|-------------|
| GET | `/incidents` | List incidents |
| POST | `/incidents` | Create incident |
| GET | `/incidents/:id` | Get incident |
| PUT | `/incidents/:id` | Update incident |
| DELETE | `/incidents/:id` | Delete incident |
| POST | `/incidents/:id/triage` | Run triage |
| POST | `/incidents/:id/actions` | Execute action |

### Actions

| Method | Path | Description |
|--------|------|-------------|
| GET | `/actions` | List actions |
| GET | `/actions/:id` | Get action |
| POST | `/actions/:id/approve` | Approve action |
| POST | `/actions/:id/reject` | Reject action |

### Playbooks

| Method | Path | Description |
|--------|------|-------------|
| GET | `/playbooks` | List playbooks |
| POST | `/playbooks` | Create playbook |
| GET | `/playbooks/:id` | Get playbook |
| PUT | `/playbooks/:id` | Update playbook |
| DELETE | `/playbooks/:id` | Delete playbook |
| POST | `/playbooks/:id/run` | Run playbook |

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| POST | `/webhooks/:source` | Receive webhook |

### System

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/metrics` | Prometheus metrics |
| GET | `/connectors/health` | Connector status |

## Pagination

List endpoints support pagination:

```bash
curl "http://localhost:8080/api/incidents?page=2&per_page=50"
```

Parameters:
- `page` - Page number (default: 1)
- `per_page` - Items per page (default: 20, max: 100)

## Filtering

Filter list results:

```bash
curl "http://localhost:8080/api/incidents?status=open&severity=high"
```

Common filters:
- `status` - Filter by status
- `severity` - Filter by severity
- `type` - Filter by incident type
- `created_after` - Created after date
- `created_before` - Created before date

## Sorting

```bash
curl "http://localhost:8080/api/incidents?sort=-created_at"
```

- Prefix with `-` for descending order
- Default: `-created_at` (newest first)

## Rate Limiting

API requests are rate limited:

| Endpoint | Limit |
|----------|-------|
| Read operations | 100/min |
| Write operations | 20/min |
| Triage requests | 10/min |

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705320000
```

## Next Steps

- [Authentication](./authentication.md) - API authentication
- [Incidents](./incidents.md) - Incident endpoints
- [Actions](./actions.md) - Action endpoints
- [Playbooks](./playbooks.md) - Playbook endpoints
- [Webhooks](./webhooks.md) - Webhook integration
