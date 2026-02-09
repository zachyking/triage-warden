# ADR-004: Session Management Strategy

## Status

Accepted

## Context

The dashboard requires user authentication with session management. We needed to decide between:

1. JWT tokens (stateless)
2. Server-side sessions (stateful)
3. Hybrid approach

Requirements:
- Secure authentication for web dashboard
- Support for session revocation
- CSRF protection for form submissions
- Reasonable session lifetime

## Decision

We chose server-side sessions stored in the database using `tower-sessions`:

### Session Architecture

```
Browser                          Server
   │                                │
   │  POST /auth/login              │
   │  (username, password)          │
   ├───────────────────────────────►│
   │                                │ Validate credentials
   │                                │ Create session in DB
   │  Set-Cookie: id=session_id     │
   │◄───────────────────────────────┤
   │                                │
   │  GET /dashboard                │
   │  Cookie: id=session_id         │
   ├───────────────────────────────►│
   │                                │ Load session from DB
   │                                │ Verify not expired
   │  200 OK                        │
   │◄───────────────────────────────┤
```

### Session Storage

Sessions are stored in the `sessions` table:

| Column | Type | Description |
|--------|------|-------------|
| id | TEXT | Session ID (secure random) |
| data | BLOB | Encrypted session data |
| expiry_date | INTEGER | Unix timestamp |

### Session Data

```rust
struct SessionData {
    user_id: Uuid,
    username: String,
    role: UserRole,
    login_csrf: String,  // CSRF token for sensitive actions
}
```

### Security Measures

1. **Secure Cookies**: HttpOnly, Secure (in production), SameSite=Lax
2. **CSRF Protection**: Token in session, validated on state-changing requests
3. **Session Expiry**: 24-hour default, configurable
4. **Rotation**: New session ID on privilege changes

## Consequences

### Positive

- Sessions can be revoked immediately
- No token size limits for session data
- CSRF tokens integrated naturally
- Easy to implement "logout all devices"

### Negative

- Database read on every authenticated request
- Session table requires cleanup (expired sessions)
- Horizontal scaling requires shared database
- Slightly higher latency than JWTs

### Comparison with JWTs

| Aspect | Sessions | JWTs |
|--------|----------|------|
| Revocation | Immediate | Requires blacklist |
| Storage | Server | Client |
| Scalability | Requires shared store | Stateless |
| Size | Cookie only | Full payload |
| Security | Keys in DB | Signature verification |
