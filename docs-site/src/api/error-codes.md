# API Error Codes

All API errors return a consistent JSON structure with an error code, message, and optional details.

## Error Response Format

```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": { ... },
  "request_id": "optional-request-id"
}
```

## Error Codes Reference

### Authentication Errors (4xx)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `UNAUTHORIZED` | 401 | Missing or invalid authentication | Provide valid API key or session cookie |
| `INVALID_CREDENTIALS` | 401 | Invalid username or password | Check login credentials |
| `SESSION_EXPIRED` | 401 | Session has expired | Re-authenticate to get new session |
| `INVALID_SIGNATURE` | 401 | Webhook signature validation failed | Verify webhook secret configuration |
| `FORBIDDEN` | 403 | Authenticated but not authorized | Check user role and permissions |
| `CSRF_VALIDATION_FAILED` | 403 | CSRF token missing or invalid | Include valid CSRF token in request |
| `ACCOUNT_DISABLED` | 403 | User account is disabled | Contact administrator |

### Client Errors (4xx)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `NOT_FOUND` | 404 | Resource not found | Verify resource ID exists |
| `BAD_REQUEST` | 400 | Malformed request | Check request syntax and parameters |
| `CONFLICT` | 409 | Resource conflict (e.g., already exists) | Action already completed or duplicate resource |
| `UNPROCESSABLE_ENTITY` | 422 | Semantic error in request | Check request logic and data validity |
| `VALIDATION_ERROR` | 422 | Field validation failed | See `details` for field-specific errors |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests | Wait and retry with exponential backoff |

### Server Errors (5xx)

| Code | HTTP Status | Description | Resolution |
|------|-------------|-------------|------------|
| `INTERNAL_ERROR` | 500 | Unexpected server error | Check server logs, contact support |
| `DATABASE_ERROR` | 500 | Database operation failed | Check database connectivity |
| `SERVICE_UNAVAILABLE` | 503 | Service temporarily unavailable | Retry later |

## Detailed Error Examples

### Validation Error

When field validation fails, the response includes detailed field-level errors:

```json
{
  "code": "VALIDATION_ERROR",
  "message": "Validation failed",
  "details": {
    "name": {
      "code": "required",
      "message": "Name is required"
    },
    "email": {
      "code": "invalid_format",
      "message": "Invalid email format"
    }
  }
}
```

### Not Found Error

```json
{
  "code": "NOT_FOUND",
  "message": "Not found: Incident 550e8400-e29b-41d4-a716-446655440000 not found"
}
```

### Conflict Error

Returned when attempting an action that conflicts with current state:

```json
{
  "code": "CONFLICT",
  "message": "Conflict: Action is not pending approval (current status: Approved)"
}
```

### Rate Limit Error

```json
{
  "code": "RATE_LIMIT_EXCEEDED",
  "message": "Rate limit exceeded"
}
```

Include a `Retry-After` header when available.

### Unauthorized Error

```json
{
  "code": "UNAUTHORIZED",
  "message": "Unauthorized: No authentication provided"
}
```

## Error Handling Best Practices

### Client Implementation

```python
import requests

def handle_api_error(response):
    error = response.json()
    code = error.get('code')

    if code == 'RATE_LIMIT_EXCEEDED':
        # Implement exponential backoff
        retry_after = int(response.headers.get('Retry-After', 60))
        time.sleep(retry_after)
        return retry_request()

    elif code == 'SESSION_EXPIRED':
        # Re-authenticate
        refresh_session()
        return retry_request()

    elif code == 'VALIDATION_ERROR':
        # Handle field-specific errors
        for field, details in error.get('details', {}).items():
            print(f"Field '{field}': {details['message']}")

    elif code in ['INTERNAL_ERROR', 'DATABASE_ERROR']:
        # Log and alert on server errors
        log_error(error)
        raise ServerError(error['message'])
```

### Retry Strategy

For transient errors (5xx, RATE_LIMIT_EXCEEDED), implement exponential backoff:

```python
import time
import random

def retry_with_backoff(func, max_retries=3):
    for attempt in range(max_retries):
        try:
            return func()
        except (RateLimitError, ServiceUnavailableError) as e:
            if attempt == max_retries - 1:
                raise
            delay = (2 ** attempt) + random.uniform(0, 1)
            time.sleep(delay)
```

## HTTP Status Code Summary

| Status | Meaning | Retryable |
|--------|---------|-----------|
| 400 | Bad Request | No |
| 401 | Unauthorized | After re-auth |
| 403 | Forbidden | No |
| 404 | Not Found | No |
| 409 | Conflict | No |
| 422 | Unprocessable Entity | After fixing request |
| 429 | Rate Limited | Yes, with backoff |
| 500 | Internal Error | Yes, with caution |
| 503 | Service Unavailable | Yes, with backoff |
