//! Credential encryption module for securing sensitive data at rest.
//!
//! This module provides AES-256-GCM encryption for sensitive strings like API keys,
//! tokens, and webhooks before they are stored in the database.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use rand::Rng;
use std::sync::Arc;
use thiserror::Error;

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

/// Creates the appropriate encryptor based on environment configuration.
///
/// Reads the encryption key from the `TW_ENCRYPTION_KEY` environment variable.
/// The key should be 32 bytes encoded as base64.
///
/// If the environment variable is not set:
/// - Returns a PlaintextEncryptor and logs a warning (suitable for development)
///
/// # Example
///
/// Generate a key with: `openssl rand -base64 32`
pub fn create_encryptor() -> Arc<dyn CredentialEncryptor> {
    match std::env::var("TW_ENCRYPTION_KEY") {
        Ok(key_base64) => match Aes256GcmEncryptor::from_base64_key(&key_base64) {
            Ok(encryptor) => {
                tracing::info!("Credential encryption enabled with AES-256-GCM");
                Arc::new(encryptor)
            }
            Err(e) => {
                tracing::error!("Invalid TW_ENCRYPTION_KEY: {}. Using plaintext storage!", e);
                Arc::new(PlaintextEncryptor)
            }
        },
        Err(_) => {
            tracing::warn!(
                "TW_ENCRYPTION_KEY not set. Credentials will be stored in PLAINTEXT. \
                 Set this environment variable with a 32-byte base64-encoded key for production. \
                 Generate a key with: openssl rand -base64 32"
            );
            Arc::new(PlaintextEncryptor)
        }
    }
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
}
