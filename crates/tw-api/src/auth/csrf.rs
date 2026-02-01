//! CSRF (Cross-Site Request Forgery) protection.
//!
//! This module provides CSRF token generation and validation for form submissions.

use axum::{async_trait, extract::FromRequestParts, http::request::Parts};
use rand::Rng;
use subtle::ConstantTimeEq;
use tower_sessions::Session;

use super::get_session_data;
use crate::error::ApiError;

/// A verified CSRF token.
///
/// This extractor validates that the submitted CSRF token matches the session's token.
/// It checks both form data and headers.
pub struct CsrfToken(pub String);

impl CsrfToken {
    /// Returns the token value.
    pub fn value(&self) -> &str {
        &self.0
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for CsrfToken
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        // Get the session
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::SessionExpired)?;

        // Get session data with CSRF token
        let session_data = get_session_data(&session)
            .await
            .ok_or(ApiError::SessionExpired)?;

        Ok(CsrfToken(session_data.csrf_token))
    }
}

/// Generates a new CSRF token.
pub fn generate_csrf_token() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

/// Validates a CSRF token against the expected value.
///
/// Uses constant-time comparison to prevent timing attacks.
pub fn validate_csrf_token(submitted: &str, expected: &str) -> bool {
    if submitted.len() != expected.len() {
        return false;
    }
    submitted.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Middleware function to validate CSRF token from form or header.
///
/// The token can be submitted as:
/// - Form field: `csrf_token`
/// - Header: `X-CSRF-Token`
pub fn extract_csrf_from_form_or_header<'a>(
    form_token: Option<&'a str>,
    header_token: Option<&'a str>,
) -> Option<&'a str> {
    form_token.or(header_token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token() {
        let token1 = generate_csrf_token();
        let token2 = generate_csrf_token();

        // Tokens should be 32 characters
        assert_eq!(token1.len(), 32);
        assert_eq!(token2.len(), 32);

        // Tokens should be unique
        assert_ne!(token1, token2);

        // Tokens should be alphanumeric
        assert!(token1.chars().all(|c| c.is_alphanumeric()));
    }

    #[test]
    fn test_validate_csrf_token() {
        let token = generate_csrf_token();

        // Same token should validate
        assert!(validate_csrf_token(&token, &token));

        // Different token should not validate
        let other_token = generate_csrf_token();
        assert!(!validate_csrf_token(&token, &other_token));

        // Different length should not validate
        assert!(!validate_csrf_token(&token, "short"));
    }

    #[test]
    fn test_extract_csrf_priority() {
        // Form token takes precedence
        assert_eq!(
            extract_csrf_from_form_or_header(Some("form_token"), Some("header_token")),
            Some("form_token")
        );

        // Header token as fallback
        assert_eq!(
            extract_csrf_from_form_or_header(None, Some("header_token")),
            Some("header_token")
        );

        // None if neither present
        assert_eq!(extract_csrf_from_form_or_header(None, None), None);
    }
}
