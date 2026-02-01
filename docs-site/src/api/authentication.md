# API Authentication

Authenticate with the Triage Warden API.

## API Keys

### Creating an API Key

```bash
# Via CLI
tw-cli api-key create --name "automation-script" --scopes read,write

# Output:
# API Key created successfully
# Key: tw_abc123_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# WARNING: Store this key securely. It cannot be retrieved again.
```

### Using API Keys

Include in the `Authorization` header:

```bash
curl -H "Authorization: Bearer tw_abc123_secretkey" \
  http://localhost:8080/api/incidents
```

### API Key Scopes

| Scope | Permissions |
|-------|-------------|
| `read` | Read incidents, actions, playbooks |
| `write` | Create/update incidents, execute actions |
| `admin` | User management, system configuration |

### Managing API Keys

```bash
# List keys
tw-cli api-key list

# Revoke key
tw-cli api-key revoke tw_abc123

# Rotate key
tw-cli api-key rotate tw_abc123
```

## Session Authentication

For web dashboard access:

### Login

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=analyst&password=secret&csrf_token=xxx" \
  -c cookies.txt
```

### Using Session

```bash
curl -b cookies.txt http://localhost:8080/api/incidents
```

### Logout

```bash
curl -X POST http://localhost:8080/logout -b cookies.txt
```

## CSRF Protection

State-changing requests require CSRF tokens:

1. Get token from login page or API
2. Include in request header or body

```bash
# Header
curl -X POST http://localhost:8080/api/incidents \
  -H "X-CSRF-Token: abc123" \
  -b cookies.txt \
  -d '{"type": "phishing"}'

# Form body
curl -X POST http://localhost:8080/api/incidents \
  -d "csrf_token=abc123&type=phishing" \
  -b cookies.txt
```

## Webhook Authentication

Webhooks use HMAC signatures:

### Configuring Webhook Secret

```bash
tw-cli webhook add email-gateway \
  --url http://localhost:8080/api/webhooks/email-gateway \
  --secret "your-secret-key"
```

### Verifying Signatures

Triage Warden validates the `X-Webhook-Signature` header:

```
X-Webhook-Signature: sha256=abc123...
```

Signature is computed as:
```
HMAC-SHA256(secret, timestamp + "." + body)
```

### Signature Verification Example

```python
import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str, timestamp: str) -> bool:
    expected = hmac.new(
        secret.encode(),
        f"{timestamp}.{payload.decode()}".encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

## Service Accounts

For automated systems:

```bash
# Create service account
tw-cli user create \
  --username automation-bot \
  --role analyst \
  --service-account

# Generate API key for service account
tw-cli api-key create \
  --user automation-bot \
  --name "ci-cd-integration" \
  --scopes read,write
```

## Security Best Practices

1. **Rotate keys regularly** - Set up automated rotation
2. **Use minimal scopes** - Only grant necessary permissions
3. **Secure storage** - Use secret managers, not code
4. **Monitor usage** - Review audit logs for suspicious activity
5. **IP allowlisting** - Restrict API access by IP (optional)

```bash
# Enable IP allowlist
tw-cli config set api.allowed_ips "10.0.0.0/8,192.168.1.0/24"
```

## Error Responses

### 401 Unauthorized

Missing or invalid credentials:

```json
{
  "error": {
    "code": "unauthorized",
    "message": "Invalid or missing authentication"
  }
}
```

### 403 Forbidden

Valid credentials but insufficient permissions:

```json
{
  "error": {
    "code": "forbidden",
    "message": "Insufficient permissions for this operation"
  }
}
```
