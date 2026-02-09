# ADR-005: API Key Format and Security

## Status

Accepted

## Context

Triage Warden exposes a REST API that needs programmatic authentication. We needed to design an API key format that is:

1. Secure against brute-force attacks
2. Easily identifiable (for revocation)
3. User-friendly for debugging
4. Compatible with common tooling

## Decision

We adopted a prefixed API key format similar to GitHub and Stripe:

### Key Format

```
tw_<user_prefix>_<random_secret>
```

Example: `tw_abc12345_9f8e7d6c5b4a3210fedcba9876543210`

Components:
- `tw_` - Application prefix (identifies Triage Warden keys)
- `<user_prefix>` - First 8 chars for identification (stored in DB)
- `<random_secret>` - 32 bytes of cryptographic randomness

### Storage

Only the hash is stored, never the raw key:

| Column | Value |
|--------|-------|
| key_prefix | `tw_abc12345` (for lookup) |
| key_hash | SHA-256(full_key) |

### Authentication Flow

```
1. Extract key from Authorization header
2. Parse prefix (first 11 chars)
3. Look up by prefix in database
4. Compute SHA-256 of provided key
5. Compare with stored hash (constant-time)
6. Check expiration and scopes
```

### Key Generation

```rust
use rand::Rng;
use sha2::{Sha256, Digest};

fn generate_api_key(user_id: Uuid) -> (String, String, String) {
    let secret: [u8; 32] = rand::thread_rng().gen();
    let secret_hex = hex::encode(secret);

    let prefix = format!("tw_{}", &user_id.to_string()[..8]);
    let full_key = format!("{}_{}", prefix, secret_hex);
    let key_hash = hex::encode(Sha256::digest(full_key.as_bytes()));

    (full_key, prefix, key_hash)  // Return key once, store prefix + hash
}
```

## Consequences

### Positive

- Keys are identifiable without exposing secrets
- Prefix enables efficient database lookup
- Format is familiar to developers
- Hash storage protects against database leaks
- Constant-time comparison prevents timing attacks

### Negative

- Keys must be stored securely by users (cannot be recovered)
- Prefix lookup could reveal key existence (minor info leak)
- Longer keys than simple tokens

### Security Properties

| Property | Implementation |
|----------|----------------|
| Entropy | 256 bits (32 random bytes) |
| Storage | SHA-256 hash only |
| Comparison | Constant-time |
| Revocation | Delete from database |
| Expiration | Optional expiry_at field |
| Scopes | JSON array of allowed operations |
