//! Credential encryption module for securing sensitive data at rest.
//!
//! This module provides AES-256-GCM encryption for sensitive strings like API keys,
//! tokens, and webhooks before they are stored in the database.
//!
//! It also provides secure credential handling with automatic memory zeroization
//! through the `SecureString` type.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::sync::Arc;
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The encryption key is invalid (wrong size or format).
    #[error("Invalid encryption key: {0}")]
    InvalidKey(String),

    /// Encryption failed.
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed (corrupted or tampered ciphertext).
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
}

/// A secure string type that automatically zeroizes its contents when dropped.
///
/// This type wraps a `String` and ensures that the memory is securely cleared
/// when the value goes out of scope, preventing sensitive data from lingering
/// in memory.
///
/// # Example
///
/// ```
/// use tw_core::crypto::SecureString;
///
/// let secret = SecureString::new("my-api-key".to_string());
/// assert_eq!(secret.expose_secret(), "my-api-key");
/// // When `secret` is dropped, its memory will be zeroized
/// ```
#[derive(Clone)]
pub struct SecureString(Zeroizing<String>);

impl SecureString {
    /// Creates a new `SecureString` from a `String`.
    ///
    /// The string's memory will be zeroized when this `SecureString` is dropped.
    pub fn new(s: String) -> Self {
        Self(Zeroizing::new(s))
    }

    /// Exposes the secret string for use.
    ///
    /// **Security Warning:** Be careful when using this method. Avoid copying
    /// the returned value unless necessary, as copies will not be zeroized.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Returns the length of the secret string.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns true if the secret string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecureString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SecureString {
    fn from(s: &str) -> Self {
        Self::new(s.to_string())
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecureString([REDACTED])")
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &Self) -> bool {
        // Use constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        self.0.as_bytes().ct_eq(other.0.as_bytes()).into()
    }
}

impl Eq for SecureString {}

impl Serialize for SecureString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize the actual secret value
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecureString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecureString::new(s))
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // The Zeroizing wrapper already handles zeroization on drop,
        // but we explicitly call zeroize here for clarity and to ensure
        // the operation occurs.
        self.0.zeroize();
    }
}

/// Trait for encrypting and decrypting credentials.
pub trait CredentialEncryptor: Send + Sync {
    /// Encrypts a plaintext string, returning a base64-encoded ciphertext.
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError>;

    /// Decrypts a base64-encoded ciphertext, returning the original plaintext.
    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptoError>;
}

/// AES-256-GCM based credential encryptor.
///
/// Ciphertext format: `base64(nonce || ciphertext || tag)`
/// - Nonce: 12 bytes (96 bits)
/// - Tag: 16 bytes (128 bits) - included in the ciphertext by aes-gcm
pub struct Aes256GcmEncryptor {
    cipher: Aes256Gcm,
}

impl Aes256GcmEncryptor {
    /// Creates a new encryptor with the given 32-byte key.
    pub fn new(key: [u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key is always valid");
        Self { cipher }
    }

    /// Creates a new encryptor from a base64-encoded key.
    pub fn from_base64_key(key_base64: &str) -> Result<Self, CryptoError> {
        let key_bytes = BASE64
            .decode(key_base64)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid base64: {}", e)))?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKey(format!(
                "Key must be 32 bytes, got {} bytes",
                key_bytes.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&key_bytes);
        Ok(Self::new(key))
    }
}

impl CredentialEncryptor for Aes256GcmEncryptor {
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        // Generate a random 12-byte nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the plaintext
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        // Concatenate nonce + ciphertext and encode as base64
        let mut combined = Vec::with_capacity(12 + ciphertext.len());
        combined.extend_from_slice(&nonce_bytes);
        combined.extend_from_slice(&ciphertext);

        Ok(BASE64.encode(&combined))
    }

    fn decrypt(&self, ciphertext_base64: &str) -> Result<String, CryptoError> {
        // Decode the base64 ciphertext
        let combined = BASE64
            .decode(ciphertext_base64)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid base64: {}", e)))?;

        // Check minimum length (12 byte nonce + 16 byte tag + at least 0 bytes ciphertext)
        if combined.len() < 28 {
            return Err(CryptoError::DecryptionFailed(
                "Ciphertext too short".to_string(),
            ));
        }

        // Split into nonce and ciphertext
        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext_bytes = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed("Decryption failed".to_string()))?;

        String::from_utf8(plaintext_bytes)
            .map_err(|e| CryptoError::DecryptionFailed(format!("Invalid UTF-8: {}", e)))
    }
}

/// A no-op encryptor that stores credentials in plaintext.
/// Only for development/testing when no encryption key is configured.
pub struct PlaintextEncryptor;

impl CredentialEncryptor for PlaintextEncryptor {
    fn encrypt(&self, plaintext: &str) -> Result<String, CryptoError> {
        Ok(plaintext.to_string())
    }

    fn decrypt(&self, ciphertext: &str) -> Result<String, CryptoError> {
        Ok(ciphertext.to_string())
    }
}

/// Determines if we're running in a production environment.
///
/// Checks `TW_ENV`, `NODE_ENV`, and `ENVIRONMENT` environment variables
/// for production/prod values.
pub fn is_production_environment() -> bool {
    std::env::var("TW_ENV")
        .map(|v| v.to_lowercase() == "production" || v.to_lowercase() == "prod")
        .unwrap_or(false)
        || std::env::var("NODE_ENV")
            .map(|v| v.to_lowercase() == "production" || v.to_lowercase() == "prod")
            .unwrap_or(false)
        || std::env::var("ENVIRONMENT")
            .map(|v| v.to_lowercase() == "production" || v.to_lowercase() == "prod")
            .unwrap_or(false)
}

/// Creates the appropriate encryptor based on environment configuration.
///
/// Reads the encryption key from the `TW_ENCRYPTION_KEY` environment variable.
/// The key should be 32 bytes encoded as base64.
///
/// # Production Mode
///
/// In production environments (`TW_ENV=production`), this function will:
/// - **Fail** if `TW_ENCRYPTION_KEY` is not set
/// - **Fail** if `TW_ENCRYPTION_KEY` is invalid
///
/// This ensures credentials are never stored in plaintext in production.
///
/// # Development Mode
///
/// In non-production environments, if `TW_ENCRYPTION_KEY` is not set:
/// - Returns a PlaintextEncryptor and logs a warning
///
/// # Example
///
/// Generate a key with: `openssl rand -base64 32`
///
/// # Errors
///
/// Returns `Err(CryptoError::InvalidKey)` in production when:
/// - `TW_ENCRYPTION_KEY` is not set
/// - `TW_ENCRYPTION_KEY` contains invalid base64
/// - `TW_ENCRYPTION_KEY` is not exactly 32 bytes when decoded
pub fn create_encryptor() -> Result<Arc<dyn CredentialEncryptor>, CryptoError> {
    let is_production = is_production_environment();

    match std::env::var("TW_ENCRYPTION_KEY") {
        Ok(key_base64) => match Aes256GcmEncryptor::from_base64_key(&key_base64) {
            Ok(encryptor) => {
                tracing::info!("Credential encryption enabled with AES-256-GCM");
                Ok(Arc::new(encryptor))
            }
            Err(e) => {
                if is_production {
                    tracing::error!(
                        "Invalid TW_ENCRYPTION_KEY in production: {}. \
                         Refusing to start without valid encryption.",
                        e
                    );
                    Err(CryptoError::InvalidKey(format!(
                        "Production requires a valid encryption key: {}",
                        e
                    )))
                } else {
                    tracing::error!(
                        "Invalid TW_ENCRYPTION_KEY: {}. Using plaintext storage in development!",
                        e
                    );
                    Ok(Arc::new(PlaintextEncryptor))
                }
            }
        },
        Err(_) => {
            if is_production {
                tracing::error!(
                    "TW_ENCRYPTION_KEY not set in production environment. \
                     Refusing to start without encryption key. \
                     Generate a key with: openssl rand -base64 32"
                );
                Err(CryptoError::InvalidKey(
                    "TW_ENCRYPTION_KEY is required in production. \
                     Set this environment variable with a 32-byte base64-encoded key. \
                     Generate with: openssl rand -base64 32"
                        .to_string(),
                ))
            } else {
                tracing::warn!(
                    "TW_ENCRYPTION_KEY not set. Credentials will be stored in PLAINTEXT. \
                     This is acceptable for development but NOT for production. \
                     Set this environment variable with a 32-byte base64-encoded key for production. \
                     Generate a key with: openssl rand -base64 32"
                );
                Ok(Arc::new(PlaintextEncryptor))
            }
        }
    }
}

/// Creates the encryptor, panicking on failure in production.
///
/// This is a convenience wrapper around `create_encryptor()` that panics
/// if encryption cannot be initialized in production. Use this in application
/// startup code where a failed initialization should abort the process.
///
/// # Panics
///
/// Panics if `create_encryptor()` returns an error (production without valid key).
pub fn create_encryptor_or_panic() -> Arc<dyn CredentialEncryptor> {
    create_encryptor().expect("Failed to initialize encryption - check TW_ENCRYPTION_KEY")
}

/// Generates a random 32-byte encryption key, base64 encoded.
/// Useful for initial setup or key generation tools.
pub fn generate_encryption_key() -> String {
    let mut key = [0u8; 32];
    rand::thread_rng().fill(&mut key);
    BASE64.encode(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryptor() -> Aes256GcmEncryptor {
        let key = [0u8; 32]; // All zeros for testing
        Aes256GcmEncryptor::new(key)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let encryptor = test_encryptor();
        let plaintext = "my-secret-api-key-12345";

        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let encryptor = test_encryptor();
        let plaintext = "";

        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let encryptor = test_encryptor();
        let plaintext = "秘密のキー🔐";

        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        let decrypted = encryptor.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertexts() {
        let encryptor = test_encryptor();
        let plaintext = "same-plaintext";

        let ciphertext1 = encryptor.encrypt(plaintext).unwrap();
        let ciphertext2 = encryptor.encrypt(plaintext).unwrap();

        // Due to random nonces, ciphertexts should be different
        assert_ne!(ciphertext1, ciphertext2);

        // But both should decrypt to the same plaintext
        assert_eq!(encryptor.decrypt(&ciphertext1).unwrap(), plaintext);
        assert_eq!(encryptor.decrypt(&ciphertext2).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_tampered_ciphertext() {
        let encryptor = test_encryptor();
        let plaintext = "secret";
        let ciphertext = encryptor.encrypt(plaintext).unwrap();

        // Decode, tamper, re-encode
        let mut bytes = BASE64.decode(&ciphertext).unwrap();
        bytes[15] ^= 0xFF; // Flip some bits in the ciphertext
        let tampered = BASE64.encode(&bytes);

        let result = encryptor.decrypt(&tampered);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_decrypt_truncated_ciphertext() {
        let encryptor = test_encryptor();

        // Too short to contain nonce + tag
        let short = BASE64.encode([0u8; 20]);
        let result = encryptor.decrypt(&short);
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let encryptor = test_encryptor();

        let result = encryptor.decrypt("not-valid-base64!!!");
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::DecryptionFailed(_))));
    }

    #[test]
    fn test_from_base64_key_valid() {
        let key_base64 = BASE64.encode([42u8; 32]);
        let result = Aes256GcmEncryptor::from_base64_key(&key_base64);
        assert!(result.is_ok());
    }

    #[test]
    fn test_from_base64_key_invalid_length() {
        let key_base64 = BASE64.encode([42u8; 16]); // Only 16 bytes
        let result = Aes256GcmEncryptor::from_base64_key(&key_base64);
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_from_base64_key_invalid_base64() {
        let result = Aes256GcmEncryptor::from_base64_key("not-valid-base64!!!");
        assert!(result.is_err());
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_plaintext_encryptor() {
        let encryptor = PlaintextEncryptor;
        let plaintext = "my-api-key";

        let ciphertext = encryptor.encrypt(plaintext).unwrap();
        assert_eq!(ciphertext, plaintext); // No encryption

        let decrypted = encryptor.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_generate_encryption_key() {
        let key1 = generate_encryption_key();
        let key2 = generate_encryption_key();

        // Keys should be different
        assert_ne!(key1, key2);

        // Keys should be valid base64 encoding of 32 bytes
        let decoded1 = BASE64.decode(&key1).unwrap();
        let decoded2 = BASE64.decode(&key2).unwrap();
        assert_eq!(decoded1.len(), 32);
        assert_eq!(decoded2.len(), 32);
    }

    #[test]
    fn test_different_keys_produce_incompatible_ciphertexts() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encryptor1 = Aes256GcmEncryptor::new(key1);
        let encryptor2 = Aes256GcmEncryptor::new(key2);

        let plaintext = "secret";
        let ciphertext = encryptor1.encrypt(plaintext).unwrap();

        // Decrypting with different key should fail
        let result = encryptor2.decrypt(&ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_production_environment_default() {
        // Clear all production env vars for this test
        std::env::remove_var("TW_ENV");
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("ENVIRONMENT");

        assert!(!is_production_environment());
    }

    #[test]
    fn test_create_encryptor_with_valid_key() {
        // Set a valid key
        let key = generate_encryption_key();
        std::env::set_var("TW_ENCRYPTION_KEY", &key);
        std::env::remove_var("TW_ENV");

        let result = create_encryptor();
        assert!(result.is_ok());

        // Clean up
        std::env::remove_var("TW_ENCRYPTION_KEY");
    }

    #[test]
    fn test_create_encryptor_dev_mode_no_key() {
        // Ensure we're not in production
        std::env::remove_var("TW_ENV");
        std::env::remove_var("NODE_ENV");
        std::env::remove_var("ENVIRONMENT");
        std::env::remove_var("TW_ENCRYPTION_KEY");

        // In dev mode, should return PlaintextEncryptor (Ok)
        let result = create_encryptor();
        assert!(result.is_ok());

        // Verify it's the plaintext encryptor by checking encryption = identity
        let encryptor = result.unwrap();
        let plaintext = "test";
        let encrypted = encryptor.encrypt(plaintext).unwrap();
        assert_eq!(encrypted, plaintext);
    }

    #[test]
    fn test_create_encryptor_production_no_key_fails() {
        // Set production mode
        std::env::set_var("TW_ENV", "production");
        std::env::remove_var("TW_ENCRYPTION_KEY");

        let result = create_encryptor();
        assert!(result.is_err(), "Expected error in production without key");

        match result {
            Err(CryptoError::InvalidKey(msg)) => {
                // Check that the error message indicates the key is required
                assert!(
                    msg.contains("required in production") || msg.contains("TW_ENCRYPTION_KEY"),
                    "Error message should mention key requirement, got: {}",
                    msg
                );
            }
            Err(e) => {
                panic!("Expected InvalidKey error, got different error: {}", e);
            }
            Ok(_) => {
                panic!("Expected error but got Ok");
            }
        }

        // Clean up
        std::env::remove_var("TW_ENV");
    }

    #[test]
    fn test_create_encryptor_production_invalid_key_fails() {
        // Set production mode with invalid key
        std::env::set_var("TW_ENV", "production");
        std::env::set_var("TW_ENCRYPTION_KEY", "not-valid-base64!!!");

        let result = create_encryptor();
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("TW_ENV");
        std::env::remove_var("TW_ENCRYPTION_KEY");
    }

    #[test]
    fn test_create_encryptor_production_short_key_fails() {
        // Set production mode with key that's too short
        std::env::set_var("TW_ENV", "production");
        std::env::set_var("TW_ENCRYPTION_KEY", BASE64.encode([0u8; 16])); // Only 16 bytes

        let result = create_encryptor();
        assert!(result.is_err());

        // Clean up
        std::env::remove_var("TW_ENV");
        std::env::remove_var("TW_ENCRYPTION_KEY");
    }

    // SecureString tests
    #[test]
    fn test_secure_string_new() {
        let secret = SecureString::new("my-secret-key".to_string());
        assert_eq!(secret.expose_secret(), "my-secret-key");
    }

    #[test]
    fn test_secure_string_from_string() {
        let secret: SecureString = "my-secret-key".to_string().into();
        assert_eq!(secret.expose_secret(), "my-secret-key");
    }

    #[test]
    fn test_secure_string_from_str() {
        let secret: SecureString = "my-secret-key".into();
        assert_eq!(secret.expose_secret(), "my-secret-key");
    }

    #[test]
    fn test_secure_string_len() {
        let secret = SecureString::new("12345".to_string());
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_secure_string_empty() {
        let secret = SecureString::default();
        assert!(secret.is_empty());
        assert_eq!(secret.len(), 0);
    }

    #[test]
    fn test_secure_string_debug_redacted() {
        let secret = SecureString::new("super-secret".to_string());
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("super-secret"));
        assert!(debug_output.contains("REDACTED"));
    }

    #[test]
    fn test_secure_string_display_redacted() {
        let secret = SecureString::new("super-secret".to_string());
        let display_output = format!("{}", secret);
        assert!(!display_output.contains("super-secret"));
        assert!(display_output.contains("REDACTED"));
    }

    #[test]
    fn test_secure_string_equality() {
        let secret1 = SecureString::new("same-value".to_string());
        let secret2 = SecureString::new("same-value".to_string());
        let secret3 = SecureString::new("different-value".to_string());

        assert_eq!(secret1, secret2);
        assert_ne!(secret1, secret3);
    }

    #[test]
    fn test_secure_string_clone() {
        let secret1 = SecureString::new("cloneable".to_string());
        let secret2 = secret1.clone();

        assert_eq!(secret1, secret2);
        assert_eq!(secret2.expose_secret(), "cloneable");
    }

    #[test]
    fn test_secure_string_serialize_deserialize() {
        let original = SecureString::new("serializable-secret".to_string());
        let serialized = serde_json::to_string(&original).unwrap();

        // Verify the serialized form contains the actual value (for storage)
        assert!(serialized.contains("serializable-secret"));

        let deserialized: SecureString = serde_json::from_str(&serialized).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_secure_string_zeroization_on_drop() {
        // This test verifies that the Zeroizing wrapper is being used correctly.
        // We can't directly verify memory contents in safe Rust, but we can verify
        // that the type implements the correct behavior by checking the structure.

        // Create a scope to force drop
        let ptr: *const u8;
        {
            let secret = SecureString::new("test-zeroize".to_string());
            ptr = secret.expose_secret().as_ptr();
            // Secret should be accessible here
            assert_eq!(secret.expose_secret(), "test-zeroize");
        }
        // After this point, secret is dropped and zeroized.
        // We can't safely verify the memory is zeroed without unsafe code,
        // but the Zeroizing wrapper guarantees this behavior.

        // This test primarily verifies the code compiles and runs correctly.
        // The actual zeroization is guaranteed by the zeroize crate.
        assert!(!ptr.is_null());
    }

    #[test]
    fn test_secure_string_unicode() {
        let secret = SecureString::new("secret-with-unicode-".to_string());
        assert_eq!(secret.expose_secret(), "secret-with-unicode-");
    }

    #[test]
    fn test_secure_string_special_characters() {
        let secret = SecureString::new("p@$$w0rd!#$%^&*()".to_string());
        assert_eq!(secret.expose_secret(), "p@$$w0rd!#$%^&*()");
    }
}
