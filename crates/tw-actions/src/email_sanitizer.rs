//! Email sanitization utilities for preventing header injection attacks.
//!
//! This module provides functions to sanitize email fields (subject, body)
//! to prevent header injection vulnerabilities where attackers inject CR/LF
//! characters or X-* header patterns to manipulate email headers.

use thiserror::Error;

/// Errors that can occur during email sanitization.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum EmailSanitizationError {
    /// Subject contains header injection attempt that cannot be safely sanitized.
    #[error("Subject contains potential header injection: {0}")]
    SubjectInjectionDetected(String),

    /// Body contains header injection attempt that cannot be safely sanitized.
    #[error("Body contains potential header injection: {0}")]
    BodyInjectionDetected(String),

    /// X-header injection pattern detected.
    #[error("X-header injection pattern detected: {0}")]
    XHeaderInjectionDetected(String),
}

/// Result of email sanitization.
#[derive(Debug, Clone)]
pub struct SanitizedEmail {
    /// The sanitized subject line.
    pub subject: String,
    /// The sanitized body content.
    pub body: String,
    /// Whether any sanitization was performed.
    pub was_sanitized: bool,
    /// Details of sanitization actions taken.
    pub sanitization_details: Vec<String>,
}

/// Patterns that indicate header injection attempts in single-line fields (subject).
const HEADER_INJECTION_PATTERNS: &[&str] = &[
    "\r\n", // CRLF
    "\n\r", // LFCR (rare but possible)
    "\r",   // CR alone
    "\n",   // LF alone
];

/// X-header patterns that could be injected.
const X_HEADER_PATTERNS: &[&str] = &[
    "x-priority:",
    "x-mailer:",
    "x-spam-status:",
    "x-spam-flag:",
    "x-originating-ip:",
    "x-forwarded-to:",
    "x-forwarded-for:",
    "x-custom-",
    "x-ms-",
    "x-google-",
    "x-received:",
];

/// Standard email header patterns that should not appear in body preamble.
const STANDARD_HEADER_PATTERNS: &[&str] = &[
    "from:",
    "to:",
    "cc:",
    "bcc:",
    "reply-to:",
    "subject:",
    "date:",
    "message-id:",
    "content-type:",
    "content-transfer-encoding:",
    "mime-version:",
    "return-path:",
    "received:",
];

/// Sanitizes an email subject line by stripping CR/LF characters.
///
/// # Arguments
/// * `subject` - The raw subject line to sanitize.
///
/// # Returns
/// The sanitized subject line with all CR/LF characters removed.
pub fn sanitize_subject(subject: &str) -> (String, bool, Vec<String>) {
    let mut sanitized = subject.to_string();
    let mut was_sanitized = false;
    let mut details = Vec::new();

    // Remove all CR and LF characters
    for pattern in HEADER_INJECTION_PATTERNS {
        if sanitized.contains(pattern) {
            was_sanitized = true;
            details.push(format!(
                "Removed '{}' from subject",
                escape_pattern(pattern)
            ));
            sanitized = sanitized.replace(pattern, " ");
        }
    }

    // Also check for null bytes which can cause issues
    if sanitized.contains('\0') {
        was_sanitized = true;
        details.push("Removed null bytes from subject".to_string());
        sanitized = sanitized.replace('\0', "");
    }

    // Trim excessive whitespace that might result from sanitization
    let trimmed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");

    if trimmed != sanitized {
        sanitized = trimmed;
    }

    (sanitized, was_sanitized, details)
}

/// Sanitizes an email body for header injection patterns.
///
/// The body is checked for patterns that could indicate header injection,
/// particularly at the beginning of the body where injected headers would
/// be effective.
///
/// # Arguments
/// * `body` - The raw body content to sanitize.
///
/// # Returns
/// A result containing either the sanitized body or an error if a severe
/// injection attempt is detected.
pub fn sanitize_body(body: &str) -> Result<(String, bool, Vec<String>), EmailSanitizationError> {
    let mut sanitized = body.to_string();
    let mut was_sanitized = false;
    let mut details = Vec::new();

    // Check for header injection at the start of the body
    // This is the most dangerous case as headers must come before the body
    let first_lines: Vec<&str> = body.lines().take(10).collect();

    for line in &first_lines {
        let line_lower = line.to_lowercase().trim_start().to_string();

        // Check for X-header patterns
        for pattern in X_HEADER_PATTERNS {
            if line_lower.starts_with(pattern) {
                return Err(EmailSanitizationError::XHeaderInjectionDetected(format!(
                    "Found '{}' pattern in body: '{}'",
                    pattern,
                    truncate_str(line, 50)
                )));
            }
        }

        // Check for standard headers being injected
        for pattern in STANDARD_HEADER_PATTERNS {
            if line_lower.starts_with(pattern) {
                // Only flag if it looks like an actual header (has colon and value)
                if line.contains(':') && line.len() > pattern.len() + 1 {
                    return Err(EmailSanitizationError::BodyInjectionDetected(format!(
                        "Found potential header injection '{}' in body",
                        pattern
                    )));
                }
            }
        }
    }

    // Check for CRLF sequences that could be used to inject headers mid-body
    // Pattern: text\r\n\r\nHeader: value  (double CRLF creates header boundary)
    if body.contains("\r\n\r\n") {
        // Check what follows the double CRLF
        for part in body.split("\r\n\r\n").skip(1) {
            let part_lower = part.to_lowercase();
            for pattern in X_HEADER_PATTERNS {
                if part_lower.trim_start().starts_with(pattern) {
                    return Err(EmailSanitizationError::XHeaderInjectionDetected(format!(
                        "Found header injection after CRLF boundary: '{}'",
                        pattern
                    )));
                }
            }
            for pattern in STANDARD_HEADER_PATTERNS {
                if part_lower.trim_start().starts_with(pattern) {
                    return Err(EmailSanitizationError::BodyInjectionDetected(format!(
                        "Found header injection after CRLF boundary: '{}'",
                        pattern
                    )));
                }
            }
        }
    }

    // Normalize line endings to prevent any edge cases
    // Convert \r\n to \n, then \r to \n
    if sanitized.contains("\r\n") {
        sanitized = sanitized.replace("\r\n", "\n");
        was_sanitized = true;
        details.push("Normalized CRLF to LF in body".to_string());
    }
    if sanitized.contains('\r') {
        sanitized = sanitized.replace('\r', "\n");
        was_sanitized = true;
        details.push("Converted standalone CR to LF in body".to_string());
    }

    // Remove null bytes
    if sanitized.contains('\0') {
        was_sanitized = true;
        details.push("Removed null bytes from body".to_string());
        sanitized = sanitized.replace('\0', "");
    }

    Ok((sanitized, was_sanitized, details))
}

/// Sanitizes both subject and body for an email.
///
/// # Arguments
/// * `subject` - The raw subject line.
/// * `body` - The raw body content.
///
/// # Returns
/// A `SanitizedEmail` struct with the sanitized content or an error.
pub fn sanitize_email(subject: &str, body: &str) -> Result<SanitizedEmail, EmailSanitizationError> {
    let (sanitized_subject, subject_sanitized, subject_details) = sanitize_subject(subject);
    let (sanitized_body, body_sanitized, body_details) = sanitize_body(body)?;

    let mut all_details = subject_details;
    all_details.extend(body_details);

    Ok(SanitizedEmail {
        subject: sanitized_subject,
        body: sanitized_body,
        was_sanitized: subject_sanitized || body_sanitized,
        sanitization_details: all_details,
    })
}

/// Escapes a pattern for display purposes.
fn escape_pattern(pattern: &str) -> String {
    pattern
        .replace('\r', "\\r")
        .replace('\n', "\\n")
        .replace('\0', "\\0")
}

/// Truncates a string for display in error messages.
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Subject Sanitization Tests ====================

    #[test]
    fn test_sanitize_subject_clean() {
        let (sanitized, was_sanitized, details) = sanitize_subject("Normal Subject Line");
        assert_eq!(sanitized, "Normal Subject Line");
        assert!(!was_sanitized);
        assert!(details.is_empty());
    }

    #[test]
    fn test_sanitize_subject_with_crlf() {
        let (sanitized, was_sanitized, details) =
            sanitize_subject("Subject\r\nBcc: attacker@evil.com");
        assert_eq!(sanitized, "Subject Bcc: attacker@evil.com");
        assert!(was_sanitized);
        assert!(!details.is_empty());
    }

    #[test]
    fn test_sanitize_subject_with_lf_only() {
        let (sanitized, was_sanitized, details) = sanitize_subject("Subject\nX-Spam-Flag: NO");
        assert_eq!(sanitized, "Subject X-Spam-Flag: NO");
        assert!(was_sanitized);
        assert!(!details.is_empty());
    }

    #[test]
    fn test_sanitize_subject_with_cr_only() {
        let (sanitized, was_sanitized, details) = sanitize_subject("Subject\rX-Priority: 1");
        assert_eq!(sanitized, "Subject X-Priority: 1");
        assert!(was_sanitized);
        assert!(!details.is_empty());
    }

    #[test]
    fn test_sanitize_subject_with_null_byte() {
        let (sanitized, was_sanitized, details) = sanitize_subject("Subject\0Hidden");
        assert_eq!(sanitized, "SubjectHidden");
        assert!(was_sanitized);
        assert!(details.iter().any(|d| d.contains("null")));
    }

    #[test]
    fn test_sanitize_subject_multiple_injections() {
        let (sanitized, was_sanitized, _) =
            sanitize_subject("Subject\r\nTo: victim@test.com\r\nBcc: spy@evil.com");
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(was_sanitized);
    }

    // ==================== Body Sanitization Tests ====================

    #[test]
    fn test_sanitize_body_clean() {
        let body = "This is a normal email body.\n\nWith some paragraphs.";
        let result = sanitize_body(body);
        assert!(result.is_ok());
        let (sanitized, _, _) = result.unwrap();
        assert!(sanitized.contains("This is a normal"));
    }

    #[test]
    fn test_sanitize_body_x_header_injection_at_start() {
        let body = "X-Priority: 1\nThis is the real body";
        let result = sanitize_body(body);
        assert!(result.is_err());
        match result {
            Err(EmailSanitizationError::XHeaderInjectionDetected(msg)) => {
                assert!(msg.contains("x-priority"));
            }
            _ => panic!("Expected XHeaderInjectionDetected error"),
        }
    }

    #[test]
    fn test_sanitize_body_x_spam_injection() {
        let body = "  X-Spam-Status: No, score=-100\nBody text";
        let result = sanitize_body(body);
        assert!(result.is_err());
        match result {
            Err(EmailSanitizationError::XHeaderInjectionDetected(_)) => {}
            _ => panic!("Expected XHeaderInjectionDetected error"),
        }
    }

    #[test]
    fn test_sanitize_body_x_mailer_injection() {
        let body = "X-Mailer: EvilBot 1.0\nLegitimate content";
        let result = sanitize_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_body_from_header_injection() {
        let body = "From: spoofed@attacker.com\nReal body content";
        let result = sanitize_body(body);
        assert!(result.is_err());
        match result {
            Err(EmailSanitizationError::BodyInjectionDetected(msg)) => {
                assert!(msg.contains("from:"));
            }
            _ => panic!("Expected BodyInjectionDetected error"),
        }
    }

    #[test]
    fn test_sanitize_body_to_header_injection() {
        let body = "To: victim@target.com\nActual body";
        let result = sanitize_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_body_bcc_header_injection() {
        let body = "Bcc: hidden@attacker.com\nBody text";
        let result = sanitize_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_body_header_after_crlf_boundary() {
        let body = "Normal text\r\n\r\nX-Priority: 1\r\nMore text";
        let result = sanitize_body(body);
        assert!(result.is_err());
        match result {
            Err(EmailSanitizationError::XHeaderInjectionDetected(msg)) => {
                // The error should indicate a header injection was detected
                assert!(msg.contains("x-priority") || msg.contains("CRLF"));
            }
            _ => panic!("Expected XHeaderInjectionDetected error"),
        }
    }

    #[test]
    fn test_sanitize_body_content_type_injection() {
        let body = "Content-Type: text/html\nBody";
        let result = sanitize_body(body);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_body_normalizes_crlf() {
        let body = "Line one\r\nLine two\r\nLine three";
        let result = sanitize_body(body);
        assert!(result.is_ok());
        let (sanitized, was_sanitized, _) = result.unwrap();
        assert!(!sanitized.contains("\r\n"));
        assert!(sanitized.contains('\n'));
        assert!(was_sanitized);
    }

    #[test]
    fn test_sanitize_body_with_null_byte() {
        let body = "Body with\0null byte";
        let result = sanitize_body(body);
        assert!(result.is_ok());
        let (sanitized, was_sanitized, _) = result.unwrap();
        assert!(!sanitized.contains('\0'));
        assert!(was_sanitized);
    }

    #[test]
    fn test_sanitize_body_allows_header_like_text_in_content() {
        // Headers mentioned in the middle of text should be fine
        let body = "Please check your email settings.\n\nThe From: field should show your name.";
        let result = sanitize_body(body);
        // This should be OK because "From:" appears in line 3, not at the start
        // and is part of normal text
        assert!(result.is_ok());
    }

    #[test]
    fn test_sanitize_body_x_header_mid_content_ok() {
        // X-header patterns in the middle of text are generally OK
        let body =
            "The email had an x-priority: setting that was unusual.\nThis is just discussion.";
        let result = sanitize_body(body);
        assert!(result.is_ok());
    }

    // ==================== Combined Email Sanitization Tests ====================

    #[test]
    fn test_sanitize_email_clean() {
        let result = sanitize_email("Clean Subject", "Clean body content");
        assert!(result.is_ok());
        let email = result.unwrap();
        assert_eq!(email.subject, "Clean Subject");
        assert_eq!(email.body, "Clean body content");
        assert!(!email.was_sanitized);
    }

    #[test]
    fn test_sanitize_email_subject_injection() {
        let result = sanitize_email("Subject\r\nBcc: attacker@evil.com", "Normal body");
        assert!(result.is_ok());
        let email = result.unwrap();
        assert!(!email.subject.contains('\r'));
        assert!(!email.subject.contains('\n'));
        assert!(email.was_sanitized);
    }

    #[test]
    fn test_sanitize_email_body_injection() {
        let result = sanitize_email("Normal Subject", "X-Spam-Flag: NO\nMalicious body");
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_email_both_sanitized() {
        let result = sanitize_email("Subject\r\nwith newline", "Body\r\nwith CRLF");
        assert!(result.is_ok());
        let email = result.unwrap();
        assert!(!email.subject.contains('\r'));
        assert!(!email.body.contains("\r\n"));
        assert!(email.was_sanitized);
    }

    // ==================== Edge Cases and Attack Vectors ====================

    #[test]
    fn test_smtp_smuggling_attempt() {
        // SMTP smuggling uses \r.\r to inject additional emails
        let body = "Normal text\r.\rMAIL FROM:<attacker@evil.com>";
        let result = sanitize_body(body);
        assert!(result.is_ok());
        let (_sanitized, was_sanitized, _) = result.unwrap();
        // The \r characters should be converted
        assert!(was_sanitized);
    }

    #[test]
    fn test_unicode_newlines_subject() {
        // Some systems might interpret unicode line separators
        let subject = "Subject\u{2028}X-Header: value"; // Line separator
        let (sanitized, _, _) = sanitize_subject(subject);
        // Basic sanitization doesn't handle unicode line separators (U+2028, U+2029)
        // The subject should still contain all original characters
        // Note: In production, you might want to add unicode line separator handling
        assert!(sanitized.contains("Subject"));
        assert!(sanitized.contains("X-Header"));
    }

    #[test]
    fn test_case_insensitive_header_detection() {
        let body = "X-PRIORITY: 1\nBody";
        let result = sanitize_body(body);
        assert!(result.is_err());

        let body2 = "x-priority: 1\nBody";
        let result2 = sanitize_body(body2);
        assert!(result2.is_err());

        let body3 = "X-Priority: 1\nBody";
        let result3 = sanitize_body(body3);
        assert!(result3.is_err());
    }

    #[test]
    fn test_whitespace_before_header() {
        let body = "   X-Priority: 1\nBody";
        let result = sanitize_body(body);
        assert!(result.is_err());

        let body2 = "\t\tFrom: attacker@evil.com\nBody";
        let result2 = sanitize_body(body2);
        assert!(result2.is_err());
    }

    #[test]
    fn test_multiple_crlf_sequences() {
        let body = "Text\r\n\r\n\r\nMore text";
        let result = sanitize_body(body);
        // Should be OK as long as no headers follow
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_subject() {
        let (sanitized, was_sanitized, _) = sanitize_subject("");
        assert_eq!(sanitized, "");
        assert!(!was_sanitized);
    }

    #[test]
    fn test_empty_body() {
        let result = sanitize_body("");
        assert!(result.is_ok());
        let (sanitized, was_sanitized, _) = result.unwrap();
        assert_eq!(sanitized, "");
        assert!(!was_sanitized);
    }

    #[test]
    fn test_very_long_subject_with_injection() {
        let long_prefix = "A".repeat(1000);
        let subject = format!("{}\r\nX-Spam: NO", long_prefix);
        let (sanitized, was_sanitized, _) = sanitize_subject(&subject);
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(was_sanitized);
    }
}
