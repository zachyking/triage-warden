//! Email Header Injection Prevention Tests
//!
//! Tests that verify email-related inputs are properly sanitized to prevent
//! header injection attacks (CRLF injection) against email systems.
//! Reference: https://owasp.org/www-community/attacks/HTTP_Response_Splitting

/// Real-world email header injection attack payloads.
mod attack_payloads {
    /// CRLF injection attempts (carriage return / line feed)
    pub const CRLF_INJECTIONS: &[&str] = &[
        // Standard CRLF
        "test\r\nBcc: attacker@evil.com",
        "test\r\nCc: attacker@evil.com",
        "test\r\nTo: attacker@evil.com",
        // LF only (Unix style)
        "test\nBcc: attacker@evil.com",
        "test\nCc: attacker@evil.com",
        // CR only
        "test\rBcc: attacker@evil.com",
        // URL encoded
        "test%0D%0ABcc: attacker@evil.com",
        "test%0ABcc: attacker@evil.com",
        "test%0DBcc: attacker@evil.com",
        // Double URL encoded
        "test%250D%250ABcc: attacker@evil.com",
        // Unicode variants
        "test\u{000D}\u{000A}Bcc: evil@evil.com",
        "test\u{0085}Bcc: evil@evil.com",      // NEL (Next Line)
        "test\u{2028}Bcc: evil@evil.com",      // Line Separator
        "test\u{2029}Bcc: evil@evil.com",      // Paragraph Separator
    ];

    /// Header field injection attempts
    pub const HEADER_INJECTIONS: &[&str] = &[
        // Inject additional headers
        "test\r\nX-Injected: true",
        "test\r\nSubject: Malicious Subject",
        "test\r\nFrom: attacker@evil.com",
        "test\r\nReply-To: attacker@evil.com",
        "test\r\nReturn-Path: attacker@evil.com",
        // Multiple header injection
        "test\r\nBcc: victim1@test.com\r\nBcc: victim2@test.com",
        // Content-Type manipulation
        "test\r\nContent-Type: text/html",
        "test\r\nContent-Type: multipart/mixed",
        // MIME boundary injection
        "test\r\nContent-Type: multipart/mixed; boundary=evil",
    ];

    /// Body injection attempts (blank line followed by content)
    pub const BODY_INJECTIONS: &[&str] = &[
        // Inject email body
        "test\r\n\r\nMalicious body content",
        "test\n\nMalicious body content",
        "test\r\n\r\n<html>Phishing content</html>",
        // Inject attachments via MIME
        "test\r\n\r\n--boundary\r\nContent-Disposition: attachment",
    ];

    /// Null byte injection attempts
    pub const NULL_BYTE_INJECTIONS: &[&str] = &[
        "test\x00\r\nBcc: attacker@evil.com",
        "test\0Bcc: attacker@evil.com",
        "test%00Bcc: attacker@evil.com",
    ];

    /// Email address format attacks
    pub const EMAIL_FORMAT_ATTACKS: &[&str] = &[
        // Angle bracket injection
        "attacker@evil.com>\r\nBcc: victim@test.com<",
        "<attacker@evil.com>\r\nBcc: victim",
        // Display name injection
        "\"Name\r\nBcc: victim@test.com\" <attacker@evil.com>",
        // Comment injection (RFC 5322)
        "attacker@evil.com (comment\r\nBcc: victim)",
        // Multiple @ signs
        "a@b.com@c.com",
        // Backtick injection
        "`command`@evil.com",
        // Pipe injection
        "user|malicious@evil.com",
    ];

    /// Subject line injection attempts
    pub const SUBJECT_INJECTIONS: &[&str] = &[
        "Test Subject\r\nBcc: attacker@evil.com",
        "Subject: Fake\r\n\r\nFake body",
        "RE: Important\nBcc: attacker@evil.com",
        // Encoded newline in subject
        "Test Subject=?UTF-8?Q?=0D=0A?=Bcc: evil@evil.com",
    ];

    /// Safe inputs that should NOT be flagged (false positive prevention)
    pub const SAFE_INPUTS: &[&str] = &[
        "Normal subject line",
        "user@example.com",
        "admin@company.org",
        "This is a test message",
        "Meeting at 2pm - Conference Room B",
        "RE: Your inquiry about product X",
        "John Doe <john.doe@company.com>",
        "support+ticket123@company.com",
    ];
}

#[cfg(test)]
mod tests {
    use super::attack_payloads;

    /// Characters that indicate potential header injection
    const HEADER_INJECTION_CHARS: &[char] = &['\r', '\n', '\0'];

    /// Checks if a string contains potential header injection characters
    fn contains_injection_chars(value: &str) -> bool {
        value.chars().any(|c| HEADER_INJECTION_CHARS.contains(&c))
    }

    /// Checks for URL-encoded injection sequences
    fn contains_encoded_injection(value: &str) -> bool {
        let lower = value.to_lowercase();

        // Check for URL-encoded CR/LF
        let encoded_patterns = [
            "%0d", "%0a",       // URL encoded CR/LF
            "%0D", "%0A",       // Uppercase
            "%250d", "%250a",   // Double encoded
            "%00",              // Null byte
        ];

        for pattern in encoded_patterns {
            if lower.contains(pattern) {
                return true;
            }
        }

        false
    }

    /// Checks for Unicode newline variants
    fn contains_unicode_newlines(value: &str) -> bool {
        value.chars().any(|c| matches!(c,
            '\u{0085}' |  // NEL (Next Line)
            '\u{2028}' |  // Line Separator
            '\u{2029}'    // Paragraph Separator
        ))
    }

    /// Comprehensive header injection detection
    fn is_header_injection_attempt(value: &str) -> bool {
        contains_injection_chars(value)
            || contains_encoded_injection(value)
            || contains_unicode_newlines(value)
    }

    /// Validates email address format (basic check)
    fn is_valid_email_format(email: &str) -> bool {
        if email.is_empty() || email.len() > 320 {
            return false;
        }

        // Check for injection characters
        if is_header_injection_attempt(email) {
            return false;
        }

        // Must have exactly one @ not at start or end
        let at_count = email.chars().filter(|&c| c == '@').count();
        if at_count != 1 || email.starts_with('@') || email.ends_with('@') {
            return false;
        }

        // No angle brackets (can be used for injection)
        if email.contains('<') || email.contains('>') {
            return false;
        }

        // No dangerous characters
        let dangerous_chars = ['|', '`', ';', '(', ')'];
        if email.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }

        true
    }

    /// Validates subject line
    fn is_valid_subject(subject: &str) -> bool {
        if subject.len() > 998 {  // RFC 5322 line limit
            return false;
        }

        !is_header_injection_attempt(subject)
    }

    /// Sanitizes input by removing dangerous characters
    fn sanitize_header_value(value: &str) -> String {
        value
            .chars()
            .filter(|&c| !HEADER_INJECTION_CHARS.contains(&c))
            .filter(|c| !matches!(c, '\u{0085}' | '\u{2028}' | '\u{2029}'))
            .collect()
    }

    // ==================================================
    // CRLF Injection Tests
    // ==================================================

    #[test]
    fn test_crlf_injections_detected() {
        for payload in attack_payloads::CRLF_INJECTIONS {
            let detected = is_header_injection_attempt(payload);
            assert!(
                detected,
                "CRLF injection not detected: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_carriage_return_detected() {
        assert!(contains_injection_chars("test\rvalue"));
    }

    #[test]
    fn test_line_feed_detected() {
        assert!(contains_injection_chars("test\nvalue"));
    }

    #[test]
    fn test_crlf_sequence_detected() {
        assert!(contains_injection_chars("test\r\nvalue"));
    }

    #[test]
    fn test_url_encoded_crlf_detected() {
        assert!(contains_encoded_injection("test%0D%0Avalue"));
        assert!(contains_encoded_injection("test%0d%0avalue"));
    }

    #[test]
    fn test_double_encoded_crlf_detected() {
        assert!(contains_encoded_injection("test%250D%250Avalue"));
    }

    // ==================================================
    // Unicode Newline Tests
    // ==================================================

    #[test]
    fn test_unicode_newlines_detected() {
        assert!(contains_unicode_newlines("test\u{0085}value"));  // NEL
        assert!(contains_unicode_newlines("test\u{2028}value"));  // Line Sep
        assert!(contains_unicode_newlines("test\u{2029}value"));  // Para Sep
    }

    #[test]
    fn test_nel_character_detected() {
        let value = "test\u{0085}Bcc: evil@evil.com";
        assert!(is_header_injection_attempt(value));
    }

    #[test]
    fn test_line_separator_detected() {
        let value = "test\u{2028}Bcc: evil@evil.com";
        assert!(is_header_injection_attempt(value));
    }

    // ==================================================
    // Header Injection Tests
    // ==================================================

    #[test]
    fn test_header_injections_detected() {
        for payload in attack_payloads::HEADER_INJECTIONS {
            let detected = is_header_injection_attempt(payload);
            assert!(
                detected,
                "Header injection not detected: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_bcc_injection_detected() {
        let payload = "test\r\nBcc: attacker@evil.com";
        assert!(is_header_injection_attempt(payload));
    }

    #[test]
    fn test_cc_injection_detected() {
        let payload = "test\r\nCc: attacker@evil.com";
        assert!(is_header_injection_attempt(payload));
    }

    #[test]
    fn test_content_type_injection_detected() {
        let payload = "test\r\nContent-Type: text/html";
        assert!(is_header_injection_attempt(payload));
    }

    // ==================================================
    // Body Injection Tests
    // ==================================================

    #[test]
    fn test_body_injections_detected() {
        for payload in attack_payloads::BODY_INJECTIONS {
            let detected = is_header_injection_attempt(payload);
            assert!(
                detected,
                "Body injection not detected: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_blank_line_body_injection_detected() {
        let payload = "test\r\n\r\nMalicious body";
        assert!(is_header_injection_attempt(payload));
    }

    // ==================================================
    // Null Byte Injection Tests
    // ==================================================

    #[test]
    fn test_null_byte_injections_detected() {
        for payload in attack_payloads::NULL_BYTE_INJECTIONS {
            let detected = is_header_injection_attempt(payload);
            assert!(
                detected,
                "Null byte injection not detected: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_null_byte_detected() {
        assert!(contains_injection_chars("test\x00value"));
    }

    #[test]
    fn test_encoded_null_byte_detected() {
        assert!(contains_encoded_injection("test%00value"));
    }

    // ==================================================
    // Email Format Attack Tests
    // ==================================================

    #[test]
    fn test_email_format_attacks_blocked() {
        for payload in attack_payloads::EMAIL_FORMAT_ATTACKS {
            let valid = is_valid_email_format(payload);
            assert!(
                !valid,
                "Email format attack should be rejected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_angle_bracket_injection_blocked() {
        assert!(!is_valid_email_format("<attacker@evil.com>"));
        assert!(!is_valid_email_format("user@example.com>"));
    }

    #[test]
    fn test_pipe_in_email_blocked() {
        assert!(!is_valid_email_format("user|command@evil.com"));
    }

    #[test]
    fn test_backtick_in_email_blocked() {
        assert!(!is_valid_email_format("`whoami`@evil.com"));
    }

    #[test]
    fn test_multiple_at_signs_blocked() {
        assert!(!is_valid_email_format("a@b.com@c.com"));
    }

    // ==================================================
    // Subject Line Injection Tests
    // ==================================================

    #[test]
    fn test_subject_injections_blocked() {
        for payload in attack_payloads::SUBJECT_INJECTIONS {
            let valid = is_valid_subject(payload);
            assert!(
                !valid,
                "Subject injection should be rejected: {:?}",
                payload
            );
        }
    }

    #[test]
    fn test_subject_with_crlf_blocked() {
        assert!(!is_valid_subject("Test\r\nBcc: attacker@evil.com"));
    }

    #[test]
    fn test_subject_with_lf_blocked() {
        assert!(!is_valid_subject("Test\nBcc: attacker@evil.com"));
    }

    #[test]
    fn test_excessively_long_subject_blocked() {
        let long_subject = "x".repeat(999);
        assert!(!is_valid_subject(&long_subject));
    }

    // ==================================================
    // Safe Input Tests (False Positive Prevention)
    // ==================================================

    #[test]
    fn test_safe_inputs_accepted() {
        for input in attack_payloads::SAFE_INPUTS {
            assert!(
                !is_header_injection_attempt(input),
                "Safe input incorrectly flagged: {}",
                input
            );
        }
    }

    #[test]
    fn test_normal_subject_accepted() {
        assert!(is_valid_subject("Meeting reminder"));
        assert!(is_valid_subject("RE: Your inquiry"));
        assert!(is_valid_subject("Urgent: Action Required"));
    }

    #[test]
    fn test_normal_email_accepted() {
        assert!(is_valid_email_format("user@example.com"));
        assert!(is_valid_email_format("admin@company.org"));
        assert!(is_valid_email_format("test.user@subdomain.example.com"));
    }

    #[test]
    fn test_email_with_plus_accepted() {
        assert!(is_valid_email_format("user+tag@example.com"));
    }

    #[test]
    fn test_email_with_dots_accepted() {
        assert!(is_valid_email_format("first.last@example.com"));
    }

    // ==================================================
    // Sanitization Tests
    // ==================================================

    #[test]
    fn test_sanitize_removes_cr() {
        let sanitized = sanitize_header_value("test\rvalue");
        assert_eq!(sanitized, "testvalue");
    }

    #[test]
    fn test_sanitize_removes_lf() {
        let sanitized = sanitize_header_value("test\nvalue");
        assert_eq!(sanitized, "testvalue");
    }

    #[test]
    fn test_sanitize_removes_crlf() {
        let sanitized = sanitize_header_value("test\r\nBcc: evil@evil.com");
        assert_eq!(sanitized, "testBcc: evil@evil.com");
    }

    #[test]
    fn test_sanitize_removes_null() {
        let sanitized = sanitize_header_value("test\x00value");
        assert_eq!(sanitized, "testvalue");
    }

    #[test]
    fn test_sanitize_removes_unicode_newlines() {
        let sanitized = sanitize_header_value("test\u{0085}value");
        assert_eq!(sanitized, "testvalue");

        let sanitized = sanitize_header_value("test\u{2028}value");
        assert_eq!(sanitized, "testvalue");
    }

    #[test]
    fn test_sanitize_preserves_safe_content() {
        let safe = "Normal email subject line";
        assert_eq!(sanitize_header_value(safe), safe);
    }

    // ==================================================
    // Integration Tests
    // ==================================================

    #[test]
    fn test_email_workflow_validation() {
        // Simulating email sending workflow

        // Valid email and subject
        let email = "recipient@example.com";
        let subject = "Meeting at 3pm";

        assert!(is_valid_email_format(email));
        assert!(is_valid_subject(subject));

        // Attack attempt should be blocked at validation
        let malicious_subject = "Meeting\r\nBcc: attacker@evil.com";
        assert!(!is_valid_subject(malicious_subject));
    }

    #[test]
    fn test_multiple_recipients_validation() {
        // Each recipient should be validated individually
        let recipients = [
            "user1@example.com",
            "user2@example.com",
            "admin@company.org",
        ];

        for recipient in recipients {
            assert!(is_valid_email_format(recipient));
        }
    }

    #[test]
    fn test_header_value_builder() {
        // When building headers, values should be sanitized
        let user_input = "Reply requested\r\nBcc: attacker@evil.com";
        let sanitized = sanitize_header_value(user_input);

        // The sanitized value should not contain newlines
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(!is_header_injection_attempt(&sanitized));
    }

    // ==================================================
    // Edge Case Tests
    // ==================================================

    #[test]
    fn test_empty_string_safe() {
        assert!(!is_header_injection_attempt(""));
    }

    #[test]
    fn test_whitespace_only_safe() {
        assert!(!is_header_injection_attempt("   "));
        assert!(!is_header_injection_attempt("\t\t"));
    }

    #[test]
    fn test_tab_character_safe() {
        // Tab is often allowed in headers (as folding whitespace)
        assert!(!contains_injection_chars("test\tvalue"));
    }

    #[test]
    fn test_space_character_safe() {
        assert!(!contains_injection_chars("test value"));
    }

    #[test]
    fn test_mixed_case_encoding_detected() {
        assert!(contains_encoded_injection("test%0d%0Avalue"));
        assert!(contains_encoded_injection("test%0D%0avalue"));
    }

    // ==================================================
    // Specific Attack Scenario Tests
    // ==================================================

    #[test]
    fn test_blind_bcc_attack_blocked() {
        // Attacker tries to add themselves as BCC
        let attack = "Important Update\r\nBcc: attacker@evil.com";
        assert!(is_header_injection_attempt(attack));
        assert!(!is_valid_subject(attack));
    }

    #[test]
    fn test_reply_to_hijack_blocked() {
        // Attacker tries to change reply-to
        let attack = "Question\r\nReply-To: attacker@evil.com";
        assert!(is_header_injection_attempt(attack));
    }

    #[test]
    fn test_phishing_body_injection_blocked() {
        // Attacker tries to inject HTML body
        let attack = "Subject\r\n\r\n<html><body>Click here for prize!</body></html>";
        assert!(is_header_injection_attempt(attack));
    }

    #[test]
    fn test_attachment_injection_blocked() {
        // Attacker tries to inject attachment via MIME
        let attack = "Notice\r\n\r\n--boundary\r\nContent-Disposition: attachment; filename=malware.exe";
        assert!(is_header_injection_attempt(attack));
    }
}
