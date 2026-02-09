# ADR-003: Credential Encryption at Rest

## Status

Accepted

## Context

Triage Warden stores sensitive credentials for external integrations:

- API keys for threat intelligence services (VirusTotal, etc.)
- OAuth tokens for cloud services (Microsoft, Google)
- Webhook secrets for SIEM integrations
- SMTP credentials for email notifications

These credentials must be protected at rest in the database.

## Decision

We implemented AES-256-GCM encryption for sensitive fields:

### Encryption Scheme

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: HKDF from master key + unique salt per value
- **Nonce**: 96-bit random nonce per encryption
- **Storage Format**: Base64(nonce || ciphertext || auth_tag)

### Key Management

```
ENCRYPTION_KEY (env var)
        │
        ▼
    HKDF-SHA256
        │
    ┌───┴───┐
    │ Salt  │ (per-value, stored with ciphertext)
    └───┬───┘
        ▼
   Derived Key
        │
        ▼
   AES-256-GCM
```

### Implementation

```rust
pub trait CredentialEncryptor: Send + Sync {
    fn encrypt(&self, plaintext: &str) -> Result<String, EncryptionError>;
    fn decrypt(&self, ciphertext: &str) -> Result<String, EncryptionError>;
}
```

Two implementations:
- `Aes256GcmEncryptor` - Production encryption
- `NoOpEncryptor` - Development mode (disabled encryption)

### Encrypted Fields

| Table | Field | Contains |
|-------|-------|----------|
| connectors | config.api_key | API keys |
| connectors | config.client_secret | OAuth secrets |
| settings | llm.api_key | LLM provider API key |
| notification_channels | config.webhook_url | Webhook URLs with tokens |

## Consequences

### Positive

- Credentials protected if database is compromised
- Authenticated encryption prevents tampering
- Per-value salt prevents rainbow table attacks
- Key rotation possible without re-encrypting all values

### Negative

- Cannot search encrypted fields
- Master key must be securely managed
- Performance overhead for encryption/decryption
- Key loss = data loss (no recovery without key)

### Security Considerations

1. **Key Storage**: Use environment variable or secrets manager
2. **Key Rotation**: Implement key versioning for rotation
3. **Audit**: Log all decryption operations
4. **Memory**: Clear sensitive data from memory after use
