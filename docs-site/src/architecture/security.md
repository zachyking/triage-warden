# Security Model

Triage Warden implements defense-in-depth with multiple security layers.

## Authentication

### Web Dashboard

Session-based authentication with secure cookies:

- **Session tokens**: Random 256-bit tokens
- **Cookie settings**: HttpOnly, Secure, SameSite=Lax
- **Session duration**: 8 hours (configurable)
- **CSRF protection**: Per-request tokens on all state-changing forms

### API Access

API key authentication for programmatic access:

```bash
curl -H "Authorization: Bearer tw_abc123_secretkey" \
  https://api.example.com/api/incidents
```

API key features:
- Prefix stored in plain text for lookup (`tw_abc123`)
- Secret portion hashed with Argon2
- Scopes limit allowed operations
- Expiration dates supported

## Authorization

### Role-Based Access Control (RBAC)

| Role | Capabilities |
|------|--------------|
| **Viewer** | Read incidents, view dashboards |
| **Analyst** | Viewer + execute low-risk actions, approve analyst-level |
| **Senior Analyst** | Analyst + execute medium-risk actions, approve senior-level |
| **Admin** | Full access, user management, system configuration |

### Policy-Based Action Control

The policy engine evaluates every action request:

```rust
// Policy evaluation flow
ActionRequest
    → Build ActionContext (action_type, target, severity, proposer)
    → Evaluate policy rules
    → Return PolicyDecision
        - Allowed: Execute immediately
        - Denied: Return error with reason
        - RequiresApproval: Queue for specified approval level
```

### Example Policy Rules

```toml
# Low-risk actions auto-approve
[[policy.rules]]
name = "auto_approve_lookups"
action_patterns = ["lookup_*"]
decision = "allowed"

# High-severity host isolation requires manager
[[policy.rules]]
name = "isolate_requires_manager"
action = "isolate_host"
severity = ["high", "critical"]
approval_level = "manager"

# Block dangerous actions on production
[[policy.rules]]
name = "no_delete_in_prod"
action_patterns = ["delete_*"]
environment = "production"
decision = "denied"
reason = "Deletion not allowed in production"
```

## Data Protection

### At Rest

- **Database encryption**: SQLite with SQLCipher (optional), PostgreSQL with TDE
- **Credential storage**: All API keys/tokens hashed with Argon2id
- **Secrets management**: Environment variables or external secret stores

### In Transit

- **TLS 1.3**: Required for all external connections
- **Certificate validation**: Strict validation for connectors
- **Internal traffic**: TLS optional for localhost development

### Sensitive Data Handling

```rust
// Credentials redacted in logs
impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ApiKey {{ prefix: {}, secret: [REDACTED] }}", self.prefix)
    }
}
```

## Audit Trail

All security-relevant actions logged:

| Event | Data Captured |
|-------|---------------|
| Login | user_id, ip_address, success, timestamp |
| Logout | user_id, session_duration |
| Action executed | action_id, user_id, incident_id, result |
| Action approved | action_id, approver_id, decision |
| Policy change | user_id, old_value, new_value |
| User management | admin_id, target_user, operation |

Audit log retention: 90 days (configurable)

## Connector Security

### Credential Management

Connector credentials stored encrypted:

```bash
# Environment variables (recommended)
TW_VIRUSTOTAL_API_KEY=your-key

# Or encrypted in database
tw-cli connector set virustotal --api-key "$(read -s)"
```

### Rate Limiting

Built-in rate limiting prevents API abuse:

| Connector | Default Limit |
|-----------|---------------|
| VirusTotal | 4 req/min (free tier) |
| Splunk | 100 req/min |
| CrowdStrike | 50 req/min |

### Circuit Breaker

Automatic failure handling:

```rust
// After 5 consecutive failures, circuit opens
// Requests fail fast for 30 seconds
// Then half-open state allows test requests
```

## Input Validation

### API Requests

- JSON schema validation on all endpoints
- Size limits on request bodies (1MB default)
- Type coercion disabled (strict typing)

### Webhook Payloads

- HMAC signature verification
- Replay attack prevention (timestamp validation)
- Payload size limits

```rust
// Webhook signature verification
fn verify_webhook(payload: &[u8], signature: &str, secret: &str) -> bool {
    let expected = hmac_sha256(secret, payload);
    constant_time_compare(signature, &expected)
}
```

## Secure Defaults

- HTTPS enforced in production
- Secure cookie flags enabled
- CORS restricted to configured origins
- Debug endpoints disabled in production
- Verbose errors only in development

## Security Headers

Default response headers:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Content-Security-Policy: default-src 'self'
```

## Vulnerability Disclosure

Report security vulnerabilities to: security@example.com

We follow responsible disclosure practices and aim to respond within 48 hours.
