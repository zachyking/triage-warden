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

## Multi-Tenant Isolation

Triage Warden supports multi-tenancy with strong data isolation guarantees.

### Row-Level Security (RLS)

PostgreSQL Row-Level Security provides database-level tenant isolation:

```sql
-- Each table has RLS policies that filter by tenant
-- Application sets tenant context at the start of each request
SELECT set_tenant_context('tenant-uuid-here');

-- All subsequent queries automatically filtered
SELECT * FROM incidents;  -- Only returns current tenant's data
```

**Key Features:**

| Feature | Description |
|---------|-------------|
| **Automatic filtering** | All SELECT/UPDATE/DELETE queries filtered by tenant |
| **Insert validation** | INSERT must match current tenant context |
| **Fail-secure** | No tenant context = no data access |
| **Defense-in-depth** | Database enforces isolation even if app has bugs |

### Tenant Context Management

The application manages tenant context through several mechanisms:

1. **Request Middleware**: Resolves tenant from subdomain, header, or JWT
2. **Session Variable**: Sets `app.current_tenant` on each database connection
3. **Context Guard**: RAII pattern ensures cleanup

```rust
// Using the tenant context guard
async fn handle_request(pool: &TenantAwarePool, tenant_id: Uuid) {
    let _guard = TenantContextGuard::new(pool, tenant_id).await?;

    // All queries here are automatically filtered by tenant
    let incidents = incident_repo.list_all().await?;

    // Context cleared when guard drops
}
```

### Admin Operations

Admin operations that need to bypass RLS use a separate connection pool:

- **Admin pool**: Superuser role that bypasses RLS policies
- **Use cases**: Tenant management, cross-tenant reporting, maintenance
- **Access control**: Restricted to Admin role users only

### Tables Protected by RLS

All tenant-scoped data tables have RLS enabled:

- `incidents`, `actions`, `approvals`, `audit_logs`
- `users`, `api_keys`, `sessions`
- `playbooks`, `policies`, `connectors`
- `notification_channels`, `settings`

System tables (`tenants`, `feature_flags`) do NOT have RLS.

### Debugging RLS Issues

```sql
-- Check current tenant context
SELECT get_current_tenant();

-- View RLS policies for a table
SELECT * FROM pg_policies WHERE tablename = 'incidents';

-- Check if RLS is enabled
SELECT relname, relrowsecurity
FROM pg_class
WHERE relname IN ('incidents', 'tenants');
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
