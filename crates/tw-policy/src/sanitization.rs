//! Data sanitization module for Triage Warden.
//!
//! This module provides PII and secrets redaction capabilities to protect
//! sensitive data in logs, LLM prompts, and other outputs.

use regex::Regex;
use thiserror::Error;

/// Errors that can occur during sanitization.
#[derive(Error, Debug)]
pub enum SanitizationError {
    #[error("Invalid regex pattern: {0}")]
    InvalidPattern(String),
}

/// Result of sanitization operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizationResult {
    /// The text with sensitive data redacted.
    pub redacted_text: String,
    /// Total number of redactions made.
    pub redaction_count: usize,
    /// Whether any PII was detected and redacted.
    pub has_pii: bool,
    /// Whether any secrets were detected and redacted.
    pub has_secrets: bool,
}

impl SanitizationResult {
    /// Creates a new sanitization result with no redactions.
    pub fn unchanged(text: String) -> Self {
        Self {
            redacted_text: text,
            redaction_count: 0,
            has_pii: false,
            has_secrets: false,
        }
    }
}

/// Sanitizer for redacting PII and secrets from text.
///
/// The sanitizer uses regex patterns to identify and redact sensitive
/// information such as SSNs, credit cards, emails, API keys, passwords,
/// and bearer tokens.
pub struct Sanitizer {
    /// Patterns for PII detection.
    pii_patterns: Vec<Regex>,
    /// Patterns for secrets detection.
    secret_patterns: Vec<Regex>,
    /// Text to replace sensitive data with.
    replacement_text: String,
}

impl Sanitizer {
    /// Default patterns for PII detection.
    const DEFAULT_PII_PATTERNS: &'static [&'static str] = &[
        // SSN: XXX-XX-XXXX
        r"\b\d{3}-\d{2}-\d{4}\b",
        // Credit card: XXXX-XXXX-XXXX-XXXX or XXXX XXXX XXXX XXXX or XXXXXXXXXXXXXXXX
        r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
        // Email addresses
        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ];

    /// Default patterns for secrets detection.
    const DEFAULT_SECRET_PATTERNS: &'static [&'static str] = &[
        // API keys: api_key=value, api-key=value, apikey=value (with optional quotes)
        r#"(?i)(api[_-]?key|apikey)\s*[:=]\s*['"]?[\w-]+['"]?"#,
        // Passwords: password=value, passwd=value, pwd=value (with optional quotes)
        r#"(?i)(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"]+['"]?"#,
        // Bearer tokens
        r"(?i)bearer\s+[\w-]+",
    ];

    /// Creates a new sanitizer with default patterns.
    pub fn new() -> Self {
        // Safe to unwrap since these are compile-time validated patterns
        let pii_patterns: Vec<Regex> = Self::DEFAULT_PII_PATTERNS
            .iter()
            .map(|p| Regex::new(p).expect("Invalid default PII pattern"))
            .collect();

        let secret_patterns: Vec<Regex> = Self::DEFAULT_SECRET_PATTERNS
            .iter()
            .map(|p| Regex::new(p).expect("Invalid default secret pattern"))
            .collect();

        Self {
            pii_patterns,
            secret_patterns,
            replacement_text: "[REDACTED]".to_string(),
        }
    }

    /// Creates a sanitizer from custom patterns.
    ///
    /// # Arguments
    ///
    /// * `pii` - Regex patterns for PII detection
    /// * `secrets` - Regex patterns for secrets detection
    ///
    /// # Returns
    ///
    /// A `Result` containing the sanitizer or a `SanitizationError` if any pattern is invalid.
    pub fn from_patterns(pii: Vec<&str>, secrets: Vec<&str>) -> Result<Self, SanitizationError> {
        let pii_patterns: Result<Vec<Regex>, _> = pii
            .iter()
            .map(|p| Regex::new(p).map_err(|e| SanitizationError::InvalidPattern(e.to_string())))
            .collect();

        let secret_patterns: Result<Vec<Regex>, _> = secrets
            .iter()
            .map(|p| Regex::new(p).map_err(|e| SanitizationError::InvalidPattern(e.to_string())))
            .collect();

        Ok(Self {
            pii_patterns: pii_patterns?,
            secret_patterns: secret_patterns?,
            replacement_text: "[REDACTED]".to_string(),
        })
    }

    /// Sets a custom replacement text.
    ///
    /// # Arguments
    ///
    /// * `replacement` - The text to use for redaction
    pub fn with_replacement_text(mut self, replacement: &str) -> Self {
        self.replacement_text = replacement.to_string();
        self
    }

    /// Sanitizes text by redacting PII and secrets.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to sanitize
    ///
    /// # Returns
    ///
    /// A `SanitizationResult` containing the redacted text and metadata.
    pub fn sanitize(&self, text: &str) -> SanitizationResult {
        let mut result_text = text.to_string();
        let mut pii_count = 0usize;
        let mut secret_count = 0usize;

        // Apply PII patterns
        for pattern in &self.pii_patterns {
            let matches: Vec<_> = pattern.find_iter(&result_text).collect();
            pii_count += matches.len();
            result_text = pattern
                .replace_all(&result_text, &self.replacement_text)
                .to_string();
        }

        // Apply secret patterns
        for pattern in &self.secret_patterns {
            let matches: Vec<_> = pattern.find_iter(&result_text).collect();
            secret_count += matches.len();
            result_text = pattern
                .replace_all(&result_text, &self.replacement_text)
                .to_string();
        }

        let total_count = pii_count + secret_count;

        SanitizationResult {
            redacted_text: result_text,
            redaction_count: total_count,
            has_pii: pii_count > 0,
            has_secrets: secret_count > 0,
        }
    }

    /// Checks if text contains PII without redacting.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to check
    ///
    /// # Returns
    ///
    /// `true` if PII is detected, `false` otherwise.
    pub fn contains_pii(&self, text: &str) -> bool {
        self.pii_patterns.iter().any(|p| p.is_match(text))
    }

    /// Checks if text contains secrets without redacting.
    ///
    /// # Arguments
    ///
    /// * `text` - The text to check
    ///
    /// # Returns
    ///
    /// `true` if secrets are detected, `false` otherwise.
    pub fn contains_secrets(&self, text: &str) -> bool {
        self.secret_patterns.iter().any(|p| p.is_match(text))
    }
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitizer_default_creation() {
        let sanitizer = Sanitizer::new();
        assert!(!sanitizer.pii_patterns.is_empty());
        assert!(!sanitizer.secret_patterns.is_empty());
        assert_eq!(sanitizer.replacement_text, "[REDACTED]");
    }

    #[test]
    fn test_sanitizer_from_patterns() {
        let sanitizer =
            Sanitizer::from_patterns(vec![r"\b\d{3}-\d{2}-\d{4}\b"], vec![r"(?i)secret"]).unwrap();

        assert_eq!(sanitizer.pii_patterns.len(), 1);
        assert_eq!(sanitizer.secret_patterns.len(), 1);
    }

    #[test]
    fn test_sanitizer_invalid_pattern() {
        let result = Sanitizer::from_patterns(vec![r"[invalid"], vec![]);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(matches!(err, SanitizationError::InvalidPattern(_)));
    }

    #[test]
    fn test_custom_replacement_text() {
        let sanitizer = Sanitizer::new().with_replacement_text("***");
        assert_eq!(sanitizer.replacement_text, "***");
    }

    #[test]
    fn test_ssn_redaction() {
        let sanitizer = Sanitizer::new();
        let text = "My SSN is 123-45-6789 and my friend's is 987-65-4321.";

        let result = sanitizer.sanitize(text);

        assert_eq!(
            result.redacted_text,
            "My SSN is [REDACTED] and my friend's is [REDACTED]."
        );
        assert_eq!(result.redaction_count, 2);
        assert!(result.has_pii);
        assert!(!result.has_secrets);
    }

    #[test]
    fn test_credit_card_redaction() {
        let sanitizer = Sanitizer::new();

        // Test with dashes
        let text1 = "Card: 1234-5678-9012-3456";
        let result1 = sanitizer.sanitize(text1);
        assert_eq!(result1.redacted_text, "Card: [REDACTED]");
        assert!(result1.has_pii);

        // Test with spaces
        let text2 = "Card: 1234 5678 9012 3456";
        let result2 = sanitizer.sanitize(text2);
        assert_eq!(result2.redacted_text, "Card: [REDACTED]");
        assert!(result2.has_pii);

        // Test without separators
        let text3 = "Card: 1234567890123456";
        let result3 = sanitizer.sanitize(text3);
        assert_eq!(result3.redacted_text, "Card: [REDACTED]");
        assert!(result3.has_pii);
    }

    #[test]
    fn test_email_redaction() {
        let sanitizer = Sanitizer::new();
        let text = "Contact me at john.doe@example.com or jane_doe123@company.org.";

        let result = sanitizer.sanitize(text);

        assert_eq!(
            result.redacted_text,
            "Contact me at [REDACTED] or [REDACTED]."
        );
        assert_eq!(result.redaction_count, 2);
        assert!(result.has_pii);
    }

    #[test]
    fn test_api_key_redaction() {
        let sanitizer = Sanitizer::new();

        // Various API key formats
        let test_cases = vec![
            ("api_key=abc123def456", "[REDACTED]"),
            ("api-key: xyz789", "[REDACTED]"),
            ("apikey='secret-key-value'", "[REDACTED]"),
            ("API_KEY=\"my-api-key\"", "[REDACTED]"),
        ];

        for (input, expected) in test_cases {
            let result = sanitizer.sanitize(input);
            assert_eq!(
                result.redacted_text, expected,
                "Failed for input: {}",
                input
            );
            assert!(result.has_secrets, "Expected secrets for input: {}", input);
        }
    }

    #[test]
    fn test_password_redaction() {
        let sanitizer = Sanitizer::new();

        let test_cases = vec![
            ("password=supersecret123", "[REDACTED]"),
            ("passwd: mypassword", "[REDACTED]"),
            ("pwd='secret'", "[REDACTED]"),
            ("PASSWORD=\"ComplexP@ss!\"", "[REDACTED]"),
        ];

        for (input, expected) in test_cases {
            let result = sanitizer.sanitize(input);
            assert_eq!(
                result.redacted_text, expected,
                "Failed for input: {}",
                input
            );
            assert!(result.has_secrets, "Expected secrets for input: {}", input);
        }
    }

    #[test]
    fn test_bearer_token_redaction() {
        let sanitizer = Sanitizer::new();

        let test_cases = vec![
            ("Bearer abc123xyz789", "[REDACTED]"),
            ("bearer token-value-123", "[REDACTED]"),
            ("BEARER my-jwt-token", "[REDACTED]"),
        ];

        for (input, expected) in test_cases {
            let result = sanitizer.sanitize(input);
            assert_eq!(
                result.redacted_text, expected,
                "Failed for input: {}",
                input
            );
            assert!(result.has_secrets, "Expected secrets for input: {}", input);
        }
    }

    #[test]
    fn test_mixed_content() {
        let sanitizer = Sanitizer::new();
        let text = "User email: test@example.com, SSN: 123-45-6789, api_key=secret123";

        let result = sanitizer.sanitize(text);

        assert_eq!(
            result.redacted_text,
            "User email: [REDACTED], SSN: [REDACTED], [REDACTED]"
        );
        assert_eq!(result.redaction_count, 3);
        assert!(result.has_pii);
        assert!(result.has_secrets);
    }

    #[test]
    fn test_no_sensitive_data() {
        let sanitizer = Sanitizer::new();
        let text = "This is a normal message with no sensitive data.";

        let result = sanitizer.sanitize(text);

        assert_eq!(result.redacted_text, text);
        assert_eq!(result.redaction_count, 0);
        assert!(!result.has_pii);
        assert!(!result.has_secrets);
    }

    #[test]
    fn test_contains_pii() {
        let sanitizer = Sanitizer::new();

        assert!(sanitizer.contains_pii("SSN: 123-45-6789"));
        assert!(sanitizer.contains_pii("Email: test@example.com"));
        assert!(!sanitizer.contains_pii("No PII here"));
    }

    #[test]
    fn test_contains_secrets() {
        let sanitizer = Sanitizer::new();

        assert!(sanitizer.contains_secrets("api_key=abc123"));
        assert!(sanitizer.contains_secrets("password=secret"));
        assert!(sanitizer.contains_secrets("Bearer token123"));
        assert!(!sanitizer.contains_secrets("No secrets here"));
    }

    #[test]
    fn test_empty_string() {
        let sanitizer = Sanitizer::new();
        let result = sanitizer.sanitize("");

        assert_eq!(result.redacted_text, "");
        assert_eq!(result.redaction_count, 0);
        assert!(!result.has_pii);
        assert!(!result.has_secrets);
    }

    #[test]
    fn test_sanitization_result_unchanged() {
        let text = "No sensitive data".to_string();
        let result = SanitizationResult::unchanged(text.clone());

        assert_eq!(result.redacted_text, text);
        assert_eq!(result.redaction_count, 0);
        assert!(!result.has_pii);
        assert!(!result.has_secrets);
    }

    #[test]
    fn test_multiline_content() {
        let sanitizer = Sanitizer::new();
        let text = r#"
            User Profile:
            - Email: john@example.com
            - SSN: 111-22-3333

            Credentials:
            - api_key=secret-api-key-value
            - password=P@ssw0rd123
        "#;

        let result = sanitizer.sanitize(text);

        assert!(!result.redacted_text.contains("john@example.com"));
        assert!(!result.redacted_text.contains("111-22-3333"));
        assert!(!result.redacted_text.contains("secret-api-key-value"));
        assert!(!result.redacted_text.contains("P@ssw0rd123"));
        assert_eq!(result.redaction_count, 4);
        assert!(result.has_pii);
        assert!(result.has_secrets);
    }

    #[test]
    fn test_custom_patterns() {
        // Test with custom patterns for phone numbers
        let sanitizer = Sanitizer::from_patterns(
            vec![r"\b\d{3}-\d{3}-\d{4}\b"], // US phone number
            vec![r"(?i)token\s*=\s*[\w-]+"],
        )
        .unwrap();

        let text = "Phone: 555-123-4567, token=my-custom-token";
        let result = sanitizer.sanitize(text);

        assert_eq!(result.redacted_text, "Phone: [REDACTED], [REDACTED]");
        assert_eq!(result.redaction_count, 2);
    }
}
