//! Secure string type for credential handling with automatic memory zeroization.
//!
//! This module provides a `SecureString` type that wraps sensitive data and ensures
//! the memory is securely cleared when the value is dropped.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// A secure string type that automatically zeroizes its contents when dropped.
///
/// This type wraps a `String` and ensures that the memory is securely cleared
/// when the value goes out of scope, preventing sensitive data from lingering
/// in memory.
///
/// # Example
///
/// ```
/// use tw_connectors::SecureString;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
