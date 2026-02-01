//! Password hashing utilities using Argon2.
//!
//! This module provides secure password hashing using Argon2id,
//! the recommended algorithm for password storage.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;

/// Password hashing errors.
#[derive(Error, Debug)]
pub enum PasswordError {
    /// Error during password hashing.
    #[error("Failed to hash password: {0}")]
    HashError(String),

    /// Error during password verification.
    #[error("Failed to verify password: {0}")]
    VerifyError(String),

    /// Invalid password hash format.
    #[error("Invalid password hash format")]
    InvalidHash,
}

/// Hashes a password using Argon2id.
///
/// # Arguments
///
/// * `password` - The plain text password to hash
///
/// # Returns
///
/// The password hash as a PHC string format.
///
/// # Example
///
/// ```
/// use tw_core::auth::password::hash_password;
///
/// let hash = hash_password("my_secure_password").unwrap();
/// assert!(hash.starts_with("$argon2id$"));
/// ```
pub fn hash_password(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| PasswordError::HashError(e.to_string()))
}

/// Verifies a password against a stored hash.
///
/// # Arguments
///
/// * `password` - The plain text password to verify
/// * `hash` - The stored password hash (PHC string format)
///
/// # Returns
///
/// `true` if the password matches, `false` otherwise.
///
/// # Example
///
/// ```
/// use tw_core::auth::password::{hash_password, verify_password};
///
/// let hash = hash_password("my_secure_password").unwrap();
/// assert!(verify_password("my_secure_password", &hash).unwrap());
/// assert!(!verify_password("wrong_password", &hash).unwrap());
/// ```
pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
    let parsed_hash = PasswordHash::new(hash).map_err(|_| PasswordError::InvalidHash)?;

    let argon2 = Argon2::default();

    match argon2.verify_password(password.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(PasswordError::VerifyError(e.to_string())),
    }
}

/// Checks if a password meets minimum security requirements.
///
/// Requirements:
/// - At least 8 characters long
/// - Contains at least one lowercase letter
/// - Contains at least one uppercase letter
/// - Contains at least one digit
///
/// # Arguments
///
/// * `password` - The password to validate
///
/// # Returns
///
/// A list of validation error messages, empty if valid.
pub fn validate_password_strength(password: &str) -> Vec<&'static str> {
    let mut errors = Vec::new();

    if password.len() < 8 {
        errors.push("Password must be at least 8 characters long");
    }

    if !password.chars().any(|c| c.is_lowercase()) {
        errors.push("Password must contain at least one lowercase letter");
    }

    if !password.chars().any(|c| c.is_uppercase()) {
        errors.push("Password must contain at least one uppercase letter");
    }

    if !password.chars().any(|c| c.is_ascii_digit()) {
        errors.push("Password must contain at least one digit");
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify() {
        let password = "SecurePass123";
        let hash = hash_password(password).unwrap();

        // Hash should be in PHC format
        assert!(hash.starts_with("$argon2id$"));

        // Correct password should verify
        assert!(verify_password(password, &hash).unwrap());

        // Wrong password should not verify
        assert!(!verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_hash_uniqueness() {
        let password = "TestPassword123";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Same password should produce different hashes (different salts)
        assert_ne!(hash1, hash2);

        // Both should still verify
        assert!(verify_password(password, &hash1).unwrap());
        assert!(verify_password(password, &hash2).unwrap());
    }

    #[test]
    fn test_invalid_hash_format() {
        let result = verify_password("password", "not_a_valid_hash");
        assert!(matches!(result, Err(PasswordError::InvalidHash)));
    }

    #[test]
    fn test_password_strength_valid() {
        let errors = validate_password_strength("SecurePass123");
        assert!(errors.is_empty());
    }

    #[test]
    fn test_password_strength_too_short() {
        let errors = validate_password_strength("Short1");
        assert!(errors.contains(&"Password must be at least 8 characters long"));
    }

    #[test]
    fn test_password_strength_no_lowercase() {
        let errors = validate_password_strength("UPPERCASE123");
        assert!(errors.contains(&"Password must contain at least one lowercase letter"));
    }

    #[test]
    fn test_password_strength_no_uppercase() {
        let errors = validate_password_strength("lowercase123");
        assert!(errors.contains(&"Password must contain at least one uppercase letter"));
    }

    #[test]
    fn test_password_strength_no_digit() {
        let errors = validate_password_strength("NoDigitsHere");
        assert!(errors.contains(&"Password must contain at least one digit"));
    }
}
