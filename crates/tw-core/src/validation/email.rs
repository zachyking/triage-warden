//! Centralized email validation for Triage Warden.
//!
//! This module provides RFC 5321-compliant email validation with a `ValidatedEmail`
//! newtype that guarantees the email address has been validated before use.
//!
//! # Security Considerations
//!
//! Email validation is critical for security operations. This module:
//! - Validates email format according to RFC 5321
//! - Rejects obviously invalid formats (empty local/domain, invalid chars)
//! - Optionally validates MX records for high-security contexts
//! - Provides a type-safe wrapper to prevent use of unvalidated emails

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Maximum length of an email address per RFC 5321
const MAX_EMAIL_LENGTH: usize = 254;
/// Maximum length of the local part (before @)
const MAX_LOCAL_PART_LENGTH: usize = 64;
/// Maximum length of the domain part
const MAX_DOMAIN_LENGTH: usize = 253;
/// Maximum length of a single domain label
const MAX_LABEL_LENGTH: usize = 63;

/// Errors that can occur during email validation.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EmailValidationError {
    #[error("Email address is empty")]
    Empty,

    #[error("Email address exceeds maximum length of {MAX_EMAIL_LENGTH} characters")]
    TooLong,

    #[error("Email address missing '@' symbol")]
    MissingAtSymbol,

    #[error("Email address contains multiple '@' symbols")]
    MultipleAtSymbols,

    #[error("Local part (before @) is empty")]
    EmptyLocalPart,

    #[error("Local part exceeds maximum length of {MAX_LOCAL_PART_LENGTH} characters")]
    LocalPartTooLong,

    #[error("Domain part (after @) is empty")]
    EmptyDomain,

    #[error("Domain exceeds maximum length of {MAX_DOMAIN_LENGTH} characters")]
    DomainTooLong,

    #[error("Domain label exceeds maximum length of {MAX_LABEL_LENGTH} characters")]
    DomainLabelTooLong,

    #[error("Invalid character in local part: '{0}'")]
    InvalidLocalPartChar(char),

    #[error("Invalid character in domain: '{0}'")]
    InvalidDomainChar(char),

    #[error("Domain must contain at least one dot")]
    DomainMissingDot,

    #[error("Domain cannot start or end with a dot")]
    DomainInvalidDotPosition,

    #[error("Domain cannot have consecutive dots")]
    DomainConsecutiveDots,

    #[error("Domain label cannot start or end with a hyphen")]
    DomainLabelInvalidHyphen,

    #[error("Local part cannot start or end with a dot")]
    LocalPartInvalidDotPosition,

    #[error("Local part cannot have consecutive dots")]
    LocalPartConsecutiveDots,

    #[error("MX record validation failed: {0}")]
    MxValidationFailed(String),

    #[error("No MX records found for domain: {0}")]
    NoMxRecords(String),
}

/// Options for email validation.
#[derive(Debug, Clone, Default)]
pub struct EmailValidationOptions {
    /// Whether to require MX record validation for the domain.
    /// This performs a DNS lookup and should only be used when network access is available.
    pub require_mx_validation: bool,

    /// Whether to allow IP address literals in the domain part (e.g., user@[192.168.1.1]).
    /// Disabled by default for security reasons.
    pub allow_ip_literal: bool,

    /// Whether to allow quoted local parts (e.g., "john doe"@example.com).
    /// Disabled by default for simplicity.
    pub allow_quoted_local: bool,
}

/// A validated email address.
///
/// This type guarantees that the contained email address has been validated
/// according to RFC 5321 rules. It can only be constructed through validation,
/// ensuring that any `ValidatedEmail` instance represents a valid address.
///
/// # Example
///
/// ```
/// use tw_core::validation::email::ValidatedEmail;
///
/// let email = ValidatedEmail::new("user@example.com").expect("valid email");
/// assert_eq!(email.as_str(), "user@example.com");
/// assert_eq!(email.local_part(), "user");
/// assert_eq!(email.domain(), "example.com");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ValidatedEmail {
    /// The full validated email address
    email: String,
    /// Index of the @ symbol for efficient splitting
    at_index: usize,
}

impl ValidatedEmail {
    /// Creates a new ValidatedEmail by validating the input string.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to validate
    ///
    /// # Returns
    ///
    /// Returns `Ok(ValidatedEmail)` if the email is valid, or an error describing
    /// the validation failure.
    ///
    /// # Example
    ///
    /// ```
    /// use tw_core::validation::email::ValidatedEmail;
    ///
    /// let valid = ValidatedEmail::new("user@example.com");
    /// assert!(valid.is_ok());
    ///
    /// let invalid = ValidatedEmail::new("invalid-email");
    /// assert!(invalid.is_err());
    /// ```
    pub fn new(email: &str) -> Result<Self, EmailValidationError> {
        Self::with_options(email, &EmailValidationOptions::default())
    }

    /// Creates a new ValidatedEmail with custom validation options.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to validate
    /// * `options` - Validation options
    ///
    /// # Returns
    ///
    /// Returns `Ok(ValidatedEmail)` if the email passes all validation checks.
    pub fn with_options(
        email: &str,
        options: &EmailValidationOptions,
    ) -> Result<Self, EmailValidationError> {
        // Trim whitespace
        let email = email.trim();

        // Check for empty input
        if email.is_empty() {
            return Err(EmailValidationError::Empty);
        }

        // Check overall length
        if email.len() > MAX_EMAIL_LENGTH {
            return Err(EmailValidationError::TooLong);
        }

        // Find the @ symbol
        let at_positions: Vec<_> = email.match_indices('@').collect();

        match at_positions.len() {
            0 => return Err(EmailValidationError::MissingAtSymbol),
            1 => {}
            _ => return Err(EmailValidationError::MultipleAtSymbols),
        }

        let at_index = at_positions[0].0;
        let local_part = &email[..at_index];
        let domain = &email[at_index + 1..];

        // Validate local part
        Self::validate_local_part(local_part, options)?;

        // Validate domain
        Self::validate_domain(domain, options)?;

        Ok(ValidatedEmail {
            email: email.to_lowercase(),
            at_index,
        })
    }

    /// Validates the local part of an email address.
    fn validate_local_part(
        local: &str,
        options: &EmailValidationOptions,
    ) -> Result<(), EmailValidationError> {
        if local.is_empty() {
            return Err(EmailValidationError::EmptyLocalPart);
        }

        if local.len() > MAX_LOCAL_PART_LENGTH {
            return Err(EmailValidationError::LocalPartTooLong);
        }

        // Check for quoted string (only if allowed)
        if local.starts_with('"') && local.ends_with('"') {
            if options.allow_quoted_local {
                // For quoted strings, most characters are allowed
                return Ok(());
            } else {
                return Err(EmailValidationError::InvalidLocalPartChar('"'));
            }
        }

        // Check for invalid dot positions
        if local.starts_with('.') || local.ends_with('.') {
            return Err(EmailValidationError::LocalPartInvalidDotPosition);
        }

        // Check for consecutive dots
        if local.contains("..") {
            return Err(EmailValidationError::LocalPartConsecutiveDots);
        }

        // Validate each character
        for c in local.chars() {
            if !Self::is_valid_local_char(c) {
                return Err(EmailValidationError::InvalidLocalPartChar(c));
            }
        }

        Ok(())
    }

    /// Validates the domain part of an email address.
    fn validate_domain(
        domain: &str,
        options: &EmailValidationOptions,
    ) -> Result<(), EmailValidationError> {
        if domain.is_empty() {
            return Err(EmailValidationError::EmptyDomain);
        }

        if domain.len() > MAX_DOMAIN_LENGTH {
            return Err(EmailValidationError::DomainTooLong);
        }

        // Check for IP literal (e.g., [192.168.1.1])
        if domain.starts_with('[') && domain.ends_with(']') {
            if options.allow_ip_literal {
                // Basic IP literal validation
                let ip = &domain[1..domain.len() - 1];
                // Check if it looks like an IP address
                if ip
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == '.' || c == ':')
                {
                    return Ok(());
                }
            }
            return Err(EmailValidationError::InvalidDomainChar('['));
        }

        // Check for at least one dot (TLD requirement)
        if !domain.contains('.') {
            return Err(EmailValidationError::DomainMissingDot);
        }

        // Check for invalid dot positions
        if domain.starts_with('.') || domain.ends_with('.') {
            return Err(EmailValidationError::DomainInvalidDotPosition);
        }

        // Check for consecutive dots
        if domain.contains("..") {
            return Err(EmailValidationError::DomainConsecutiveDots);
        }

        // Validate each label
        for label in domain.split('.') {
            Self::validate_domain_label(label)?;
        }

        Ok(())
    }

    /// Validates a single domain label.
    fn validate_domain_label(label: &str) -> Result<(), EmailValidationError> {
        if label.is_empty() {
            return Err(EmailValidationError::DomainConsecutiveDots);
        }

        if label.len() > MAX_LABEL_LENGTH {
            return Err(EmailValidationError::DomainLabelTooLong);
        }

        // Labels cannot start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return Err(EmailValidationError::DomainLabelInvalidHyphen);
        }

        // Validate each character
        for c in label.chars() {
            if !Self::is_valid_domain_char(c) {
                return Err(EmailValidationError::InvalidDomainChar(c));
            }
        }

        Ok(())
    }

    /// Checks if a character is valid in the local part of an email.
    fn is_valid_local_char(c: char) -> bool {
        // RFC 5321 allows:
        // - Alphanumeric characters
        // - Special characters: !#$%&'*+/=?^_`{|}~-
        // - Dot (.) but not at start/end or consecutive
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '.' | '!'
                    | '#'
                    | '$'
                    | '%'
                    | '&'
                    | '\''
                    | '*'
                    | '+'
                    | '-'
                    | '/'
                    | '='
                    | '?'
                    | '^'
                    | '_'
                    | '`'
                    | '{'
                    | '|'
                    | '}'
                    | '~'
            )
    }

    /// Checks if a character is valid in a domain name.
    fn is_valid_domain_char(c: char) -> bool {
        // Domain names allow alphanumeric and hyphens
        c.is_ascii_alphanumeric() || c == '-'
    }

    /// Returns the full email address as a string slice.
    pub fn as_str(&self) -> &str {
        &self.email
    }

    /// Returns the local part of the email (before @).
    pub fn local_part(&self) -> &str {
        &self.email[..self.at_index]
    }

    /// Returns the domain part of the email (after @).
    pub fn domain(&self) -> &str {
        &self.email[self.at_index + 1..]
    }

    /// Consumes the ValidatedEmail and returns the underlying String.
    pub fn into_string(self) -> String {
        self.email
    }
}

impl fmt::Display for ValidatedEmail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.email)
    }
}

impl AsRef<str> for ValidatedEmail {
    fn as_ref(&self) -> &str {
        &self.email
    }
}

impl FromStr for ValidatedEmail {
    type Err = EmailValidationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ValidatedEmail::new(s)
    }
}

impl TryFrom<String> for ValidatedEmail {
    type Error = EmailValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        ValidatedEmail::new(&value)
    }
}

impl TryFrom<&str> for ValidatedEmail {
    type Error = EmailValidationError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        ValidatedEmail::new(value)
    }
}

impl From<ValidatedEmail> for String {
    fn from(email: ValidatedEmail) -> String {
        email.email
    }
}

/// Validates an email address and returns a result.
///
/// This is a convenience function for one-off validation without needing
/// to construct a `ValidatedEmail` instance.
///
/// # Example
///
/// ```
/// use tw_core::validation::email::validate_email;
///
/// assert!(validate_email("user@example.com").is_ok());
/// assert!(validate_email("invalid").is_err());
/// ```
pub fn validate_email(email: &str) -> Result<ValidatedEmail, EmailValidationError> {
    ValidatedEmail::new(email)
}

/// Validates an email address with custom options.
///
/// # Example
///
/// ```
/// use tw_core::validation::email::{validate_email_with_options, EmailValidationOptions};
///
/// let options = EmailValidationOptions {
///     require_mx_validation: false,
///     allow_ip_literal: true,
///     ..Default::default()
/// };
///
/// let result = validate_email_with_options("user@example.com", &options);
/// assert!(result.is_ok());
/// ```
pub fn validate_email_with_options(
    email: &str,
    options: &EmailValidationOptions,
) -> Result<ValidatedEmail, EmailValidationError> {
    ValidatedEmail::with_options(email, options)
}

/// Performs MX record validation for a domain.
///
/// This function attempts to look up MX records for the given domain.
/// It should only be used in contexts where network access is available
/// and high-security validation is required.
///
/// # Note
///
/// This is an async function that performs DNS lookups. It may be slow
/// and should not be used in performance-critical paths.
#[cfg(feature = "mx-validation")]
pub async fn validate_mx_records(domain: &str) -> Result<Vec<String>, EmailValidationError> {
    use trust_dns_resolver::config::*;
    use trust_dns_resolver::TokioAsyncResolver;

    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    match resolver.mx_lookup(domain).await {
        Ok(response) => {
            let records: Vec<String> = response
                .iter()
                .map(|mx| mx.exchange().to_string())
                .collect();

            if records.is_empty() {
                Err(EmailValidationError::NoMxRecords(domain.to_string()))
            } else {
                Ok(records)
            }
        }
        Err(e) => Err(EmailValidationError::MxValidationFailed(e.to_string())),
    }
}

/// Stub for MX validation when the feature is not enabled.
/// Returns Ok with an empty vec to indicate MX validation was skipped.
#[cfg(not(feature = "mx-validation"))]
pub async fn validate_mx_records(_domain: &str) -> Result<Vec<String>, EmailValidationError> {
    // MX validation is disabled, return success with empty records
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    // Valid email tests
    #[test]
    fn test_valid_simple_email() {
        let email = ValidatedEmail::new("user@example.com");
        assert!(email.is_ok());
        let email = email.unwrap();
        assert_eq!(email.local_part(), "user");
        assert_eq!(email.domain(), "example.com");
    }

    #[test]
    fn test_valid_email_with_subdomain() {
        assert!(ValidatedEmail::new("user@mail.example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_plus() {
        let email = ValidatedEmail::new("user+tag@example.com").unwrap();
        assert_eq!(email.local_part(), "user+tag");
    }

    #[test]
    fn test_valid_email_with_dots_in_local() {
        assert!(ValidatedEmail::new("first.last@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_with_hyphen_in_domain() {
        assert!(ValidatedEmail::new("user@my-domain.com").is_ok());
    }

    #[test]
    fn test_valid_email_numeric_local() {
        assert!(ValidatedEmail::new("12345@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_special_chars() {
        assert!(ValidatedEmail::new("user!def#abc$xyz@example.com").is_ok());
    }

    #[test]
    fn test_valid_email_case_normalization() {
        let email = ValidatedEmail::new("User@EXAMPLE.COM").unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }

    #[test]
    fn test_valid_email_with_whitespace_trimming() {
        let email = ValidatedEmail::new("  user@example.com  ");
        assert!(email.is_ok());
        assert_eq!(email.unwrap().as_str(), "user@example.com");
    }

    // Invalid email tests
    #[test]
    fn test_invalid_empty() {
        let result = ValidatedEmail::new("");
        assert!(matches!(result, Err(EmailValidationError::Empty)));
    }

    #[test]
    fn test_invalid_whitespace_only() {
        let result = ValidatedEmail::new("   ");
        assert!(matches!(result, Err(EmailValidationError::Empty)));
    }

    #[test]
    fn test_invalid_no_at_symbol() {
        let result = ValidatedEmail::new("userexample.com");
        assert!(matches!(result, Err(EmailValidationError::MissingAtSymbol)));
    }

    #[test]
    fn test_invalid_multiple_at_symbols() {
        let result = ValidatedEmail::new("user@domain@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::MultipleAtSymbols)
        ));
    }

    #[test]
    fn test_invalid_empty_local_part() {
        let result = ValidatedEmail::new("@example.com");
        assert!(matches!(result, Err(EmailValidationError::EmptyLocalPart)));
    }

    #[test]
    fn test_invalid_empty_domain() {
        let result = ValidatedEmail::new("user@");
        assert!(matches!(result, Err(EmailValidationError::EmptyDomain)));
    }

    #[test]
    fn test_invalid_domain_no_tld() {
        let result = ValidatedEmail::new("user@localhost");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainMissingDot)
        ));
    }

    #[test]
    fn test_invalid_local_starts_with_dot() {
        let result = ValidatedEmail::new(".user@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::LocalPartInvalidDotPosition)
        ));
    }

    #[test]
    fn test_invalid_local_ends_with_dot() {
        let result = ValidatedEmail::new("user.@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::LocalPartInvalidDotPosition)
        ));
    }

    #[test]
    fn test_invalid_local_consecutive_dots() {
        let result = ValidatedEmail::new("user..name@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::LocalPartConsecutiveDots)
        ));
    }

    #[test]
    fn test_invalid_domain_starts_with_dot() {
        let result = ValidatedEmail::new("user@.example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainInvalidDotPosition)
        ));
    }

    #[test]
    fn test_invalid_domain_ends_with_dot() {
        let result = ValidatedEmail::new("user@example.com.");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainInvalidDotPosition)
        ));
    }

    #[test]
    fn test_invalid_domain_consecutive_dots() {
        let result = ValidatedEmail::new("user@example..com");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainConsecutiveDots)
        ));
    }

    #[test]
    fn test_invalid_domain_label_starts_with_hyphen() {
        let result = ValidatedEmail::new("user@-example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainLabelInvalidHyphen)
        ));
    }

    #[test]
    fn test_invalid_domain_label_ends_with_hyphen() {
        let result = ValidatedEmail::new("user@example-.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainLabelInvalidHyphen)
        ));
    }

    #[test]
    fn test_invalid_local_part_space() {
        let result = ValidatedEmail::new("user name@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::InvalidLocalPartChar(' '))
        ));
    }

    #[test]
    fn test_invalid_domain_space() {
        let result = ValidatedEmail::new("user@example .com");
        assert!(matches!(
            result,
            Err(EmailValidationError::InvalidDomainChar(' '))
        ));
    }

    #[test]
    fn test_invalid_domain_underscore() {
        let result = ValidatedEmail::new("user@example_domain.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::InvalidDomainChar('_'))
        ));
    }

    // Length limit tests
    #[test]
    fn test_invalid_email_too_long() {
        let local = "a".repeat(65);
        let email = format!("{}@example.com", local);
        let result = ValidatedEmail::new(&email);
        assert!(matches!(
            result,
            Err(EmailValidationError::LocalPartTooLong)
        ));
    }

    #[test]
    fn test_invalid_domain_too_long() {
        // Create a domain with many short labels that exceeds 253 characters total
        // Using labels like "aaa.aaa.aaa..." where each label is 63 chars or less
        let label = "a".repeat(50);
        let domain = format!(
            "{}.{}.{}.{}.{}.{}.com",
            label, label, label, label, label, label
        );
        assert!(domain.len() > 253);
        let email = format!("user@{}", domain);
        let result = ValidatedEmail::new(&email);
        // This could fail with either DomainTooLong or TooLong (overall email length)
        assert!(
            matches!(result, Err(EmailValidationError::DomainTooLong))
                || matches!(result, Err(EmailValidationError::TooLong)),
            "Expected DomainTooLong or TooLong, got: {:?}",
            result
        );
    }

    #[test]
    fn test_invalid_domain_label_too_long() {
        let label = "a".repeat(64);
        let email = format!("user@{}.com", label);
        let result = ValidatedEmail::new(&email);
        assert!(matches!(
            result,
            Err(EmailValidationError::DomainLabelTooLong)
        ));
    }

    // Edge cases
    #[test]
    fn test_just_at_symbol() {
        let result = ValidatedEmail::new("@");
        assert!(matches!(result, Err(EmailValidationError::EmptyLocalPart)));
    }

    #[test]
    fn test_valid_max_length_local() {
        let local = "a".repeat(64);
        let email = format!("{}@example.com", local);
        assert!(ValidatedEmail::new(&email).is_ok());
    }

    #[test]
    fn test_valid_max_length_label() {
        let label = "a".repeat(63);
        let email = format!("user@{}.com", label);
        assert!(ValidatedEmail::new(&email).is_ok());
    }

    // IP literal tests
    #[test]
    fn test_ip_literal_rejected_by_default() {
        let result = ValidatedEmail::new("user@[192.168.1.1]");
        assert!(matches!(
            result,
            Err(EmailValidationError::InvalidDomainChar('['))
        ));
    }

    #[test]
    fn test_ip_literal_allowed_with_option() {
        let options = EmailValidationOptions {
            allow_ip_literal: true,
            ..Default::default()
        };
        let result = ValidatedEmail::with_options("user@[192.168.1.1]", &options);
        assert!(result.is_ok());
    }

    // Quoted local part tests
    #[test]
    fn test_quoted_local_rejected_by_default() {
        let result = ValidatedEmail::new("\"john doe\"@example.com");
        assert!(matches!(
            result,
            Err(EmailValidationError::InvalidLocalPartChar('"'))
        ));
    }

    #[test]
    fn test_quoted_local_allowed_with_option() {
        let options = EmailValidationOptions {
            allow_quoted_local: true,
            ..Default::default()
        };
        let result = ValidatedEmail::with_options("\"john doe\"@example.com", &options);
        assert!(result.is_ok());
    }

    // Trait implementation tests
    #[test]
    fn test_from_str() {
        let email: Result<ValidatedEmail, _> = "user@example.com".parse();
        assert!(email.is_ok());
    }

    #[test]
    fn test_try_from_string() {
        let email: Result<ValidatedEmail, _> = String::from("user@example.com").try_into();
        assert!(email.is_ok());
    }

    #[test]
    fn test_try_from_str() {
        let email: Result<ValidatedEmail, _> = "user@example.com".try_into();
        assert!(email.is_ok());
    }

    #[test]
    fn test_into_string() {
        let email = ValidatedEmail::new("user@example.com").unwrap();
        let s: String = email.into();
        assert_eq!(s, "user@example.com");
    }

    #[test]
    fn test_display() {
        let email = ValidatedEmail::new("user@example.com").unwrap();
        assert_eq!(format!("{}", email), "user@example.com");
    }

    #[test]
    fn test_as_ref() {
        let email = ValidatedEmail::new("user@example.com").unwrap();
        let s: &str = email.as_ref();
        assert_eq!(s, "user@example.com");
    }

    // Serialization tests
    #[test]
    fn test_serialize() {
        let email = ValidatedEmail::new("user@example.com").unwrap();
        let json = serde_json::to_string(&email).unwrap();
        assert_eq!(json, "\"user@example.com\"");
    }

    #[test]
    fn test_deserialize_valid() {
        let json = "\"user@example.com\"";
        let email: Result<ValidatedEmail, _> = serde_json::from_str(json);
        assert!(email.is_ok());
    }

    #[test]
    fn test_deserialize_invalid() {
        let json = "\"invalid-email\"";
        let email: Result<ValidatedEmail, serde_json::Error> = serde_json::from_str(json);
        assert!(email.is_err());
    }

    // Convenience function tests
    #[test]
    fn test_validate_email_function() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("invalid").is_err());
    }

    #[test]
    fn test_validate_email_with_options_function() {
        let options = EmailValidationOptions::default();
        assert!(validate_email_with_options("user@example.com", &options).is_ok());
    }

    // Real-world email format tests
    #[test]
    fn test_gmail_style() {
        assert!(ValidatedEmail::new("user.name+tag@gmail.com").is_ok());
    }

    #[test]
    fn test_corporate_style() {
        assert!(ValidatedEmail::new("firstname.lastname@company.co.uk").is_ok());
    }

    #[test]
    fn test_numeric_domain() {
        assert!(ValidatedEmail::new("user@123.com").is_ok());
    }

    // Security edge cases
    #[test]
    fn test_unicode_rejected_in_local() {
        let result = ValidatedEmail::new("usér@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_unicode_rejected_in_domain() {
        let result = ValidatedEmail::new("user@exämple.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_null_byte_rejected() {
        let result = ValidatedEmail::new("user\0@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_newline_rejected() {
        let result = ValidatedEmail::new("user\n@example.com");
        assert!(result.is_err());
    }

    #[test]
    fn test_tab_rejected() {
        let result = ValidatedEmail::new("user\t@example.com");
        assert!(result.is_err());
    }

    // MX validation tests (stub)
    #[tokio::test]
    async fn test_mx_validation_stub() {
        // When mx-validation feature is disabled, this should return Ok with empty vec
        let result = validate_mx_records("example.com").await;
        assert!(result.is_ok());
    }
}
