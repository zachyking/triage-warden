//! FQL (Falcon Query Language) Injection Prevention Tests
//!
//! Tests that verify CrowdStrike FQL queries are properly sanitized
//! to prevent injection attacks against the Falcon API.

/// Real-world FQL injection attack payloads.
mod attack_payloads {
    /// Quote escape injection attempts
    pub const QUOTE_ESCAPES: &[&str] = &[
        // Quote escape attempts
        "host'name",
        "host\"name",
        "test\\\"escape",
        "\\' OR hostname:'*'",
        // Nested quotes
        "host'\\\"name",
    ];

    /// Wildcard abuse attempts
    pub const WILDCARD_ABUSE: &[&str] = &[
        // Asterisk wildcards
        "*",
        "test*",
        "*test*",
        "a*b*c*d",
        // Question mark wildcards
        "?",
        "test?",
        "????",
        "host?name",
        // Combined
        "test*?",
        "*?*",
    ];

    /// Boolean operator injection
    pub const OPERATOR_INJECTIONS: &[&str] = &[
        // Common FQL operators
        "test+OR+other",
        "host:test,host:other",
        "hostname:'test'+status:'normal'",
    ];

    /// Field manipulation attempts
    pub const FIELD_INJECTIONS: &[&str] = &[
        // Attempting to query unauthorized fields
        "hostname:'test'+secret_field:'value'",
        // Field value escape
        "hostname:'test']+[cid:'sensitive'",
    ];

    /// Special character sequences
    pub const SPECIAL_CHAR_SEQUENCES: &[&str] = &[
        // FQL special chars
        "test'value",
        "test\"value",
        "test\\value",
        "test*value",
        "test?value",
        "test[value]",
        "test+value",
        "test:value",
        "test/value",
        "test(value)",
        "test)value",
    ];

    /// Unicode lookalike attacks
    pub const UNICODE_LOOKALIKES: &[&str] = &[
        // Cyrillic lookalikes for ASCII characters
        "workst\u{0430}tion",  // Cyrillic 'a' instead of ASCII 'a'
        "workstati\u{03BF}n",  // Greek 'o' instead of ASCII 'o'
        "\u{FF21}dmin",        // Fullwidth 'A'
        // Invisible characters
        "work\u{200B}station",  // Zero-width space
        "work\u{200D}station",  // Zero-width joiner
        "work\u{FEFF}station",  // Byte order mark
        // Combining characters
        "workstation\u{0301}",  // Combining acute accent
    ];

    /// Hostname format attacks
    pub const HOSTNAME_FORMAT_ATTACKS: &[&str] = &[
        // Invalid start/end
        "-hostname",
        "hostname-",
        ".hostname",
        "hostname.",
        // Consecutive dots
        "host..name",
        "sub...domain.com",
        // Too long (>253 chars)
        // (will be generated in test)
    ];

    /// Path traversal attempts
    pub const PATH_TRAVERSAL: &[&str] = &[
        "../etc/passwd",
        "..\\windows\\system32",
        "hostname/../../",
    ];
}

#[cfg(test)]
mod tests {
    use super::attack_payloads;

    /// FQL special characters that need escaping
    const FQL_SPECIAL_CHARS: &[char] = &[
        '\'', '"', '\\', '*', '?', '[', ']', '+', ':', '/', '(', ')',
    ];

    /// Validates hostname - only ASCII alphanumeric, hyphen, underscore, and dot allowed
    fn is_valid_hostname(hostname: &str) -> Result<String, String> {
        if hostname.is_empty() {
            return Err("Hostname cannot be empty".to_string());
        }

        // RFC 1035 max length
        if hostname.len() > 253 {
            return Err("Hostname exceeds maximum length".to_string());
        }

        // Normalize to lowercase
        let normalized = hostname.to_lowercase();

        // Validate each character
        for c in normalized.chars() {
            // Reject non-ASCII first
            if !c.is_ascii() {
                return Err(format!("Non-ASCII character in hostname: '{}'", c));
            }

            // Then check allowed characters
            if !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.' {
                return Err(format!("Invalid character '{}' in hostname", c));
            }
        }

        // Format validation
        if normalized.starts_with('-') || normalized.ends_with('-')
            || normalized.starts_with('.') || normalized.ends_with('.')
        {
            return Err("Hostname cannot start or end with hyphen or dot".to_string());
        }

        if normalized.contains("..") {
            return Err("Hostname cannot contain consecutive dots".to_string());
        }

        Ok(normalized)
    }

    /// Escapes FQL special characters
    fn escape_fql(value: &str) -> String {
        let mut result = String::with_capacity(value.len() * 2);
        for c in value.chars() {
            if FQL_SPECIAL_CHARS.contains(&c) {
                result.push('\\');
            }
            result.push(c);
        }
        result
    }

    /// Checks if value contains FQL wildcards
    fn contains_wildcard(value: &str) -> bool {
        value.chars().any(|c| c == '*' || c == '?')
    }

    // ==================================================
    // Quote Escape Tests
    // ==================================================

    #[test]
    fn test_quote_escapes_handled() {
        for payload in attack_payloads::QUOTE_ESCAPES {
            // Single quotes should be escaped
            if payload.contains('\'') {
                let escaped = escape_fql(payload);
                assert!(
                    escaped.contains("\\'"),
                    "Single quote not escaped in: {}",
                    payload
                );
            }
            // Double quotes should be escaped
            if payload.contains('"') {
                let escaped = escape_fql(payload);
                assert!(
                    escaped.contains("\\\""),
                    "Double quote not escaped in: {}",
                    payload
                );
            }
        }
    }

    #[test]
    fn test_single_quote_escaped() {
        let result = escape_fql("test'value");
        assert_eq!(result, "test\\'value");
    }

    #[test]
    fn test_double_quote_escaped() {
        let result = escape_fql("test\"value");
        assert_eq!(result, "test\\\"value");
    }

    #[test]
    fn test_backslash_escaped() {
        let result = escape_fql("test\\value");
        assert_eq!(result, "test\\\\value");
    }

    // ==================================================
    // Wildcard Abuse Tests
    // ==================================================

    #[test]
    fn test_wildcard_abuse_detected() {
        for payload in attack_payloads::WILDCARD_ABUSE {
            assert!(
                contains_wildcard(payload),
                "Wildcard not detected in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_asterisk_detected() {
        assert!(contains_wildcard("test*"));
        assert!(contains_wildcard("*"));
        assert!(contains_wildcard("*admin*"));
    }

    #[test]
    fn test_question_mark_detected() {
        assert!(contains_wildcard("test?"));
        assert!(contains_wildcard("????"));
    }

    // ==================================================
    // Special Character Escaping Tests
    // ==================================================

    #[test]
    fn test_all_special_chars_escaped() {
        for payload in attack_payloads::SPECIAL_CHAR_SEQUENCES {
            let escaped = escape_fql(payload);

            // Each special character should be preceded by backslash
            for c in FQL_SPECIAL_CHARS {
                if payload.contains(*c) {
                    let escaped_char = format!("\\{}", c);
                    assert!(
                        escaped.contains(&escaped_char) || !payload.contains(*c),
                        "Character '{}' not escaped in: {} -> {}",
                        c, payload, escaped
                    );
                }
            }
        }
    }

    #[test]
    fn test_colon_escaped() {
        let result = escape_fql("test:value");
        assert_eq!(result, "test\\:value");
    }

    #[test]
    fn test_plus_escaped() {
        let result = escape_fql("test+value");
        assert_eq!(result, "test\\+value");
    }

    #[test]
    fn test_brackets_escaped() {
        let result = escape_fql("test[value]");
        assert_eq!(result, "test\\[value\\]");
    }

    #[test]
    fn test_parentheses_escaped() {
        let result = escape_fql("test(value)");
        assert_eq!(result, "test\\(value\\)");
    }

    // ==================================================
    // Unicode Lookalike Tests
    // ==================================================

    #[test]
    fn test_cyrillic_a_rejected() {
        let hostname = "workst\u{0430}tion";  // Cyrillic 'a'
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Cyrillic 'a' should be rejected in hostname"
        );
    }

    #[test]
    fn test_greek_o_rejected() {
        let hostname = "workstati\u{03BF}n";  // Greek 'o'
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Greek 'o' should be rejected in hostname"
        );
    }

    #[test]
    fn test_fullwidth_chars_rejected() {
        let hostname = "\u{FF21}dmin";  // Fullwidth 'A'
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Fullwidth characters should be rejected"
        );
    }

    #[test]
    fn test_zero_width_space_rejected() {
        let hostname = "work\u{200B}station";
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Zero-width space should be rejected"
        );
    }

    #[test]
    fn test_zero_width_joiner_rejected() {
        let hostname = "work\u{200D}station";
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Zero-width joiner should be rejected"
        );
    }

    #[test]
    fn test_combining_chars_rejected() {
        let hostname = "workstation\u{0301}";  // Combining acute
        let result = is_valid_hostname(hostname);
        assert!(
            result.is_err(),
            "Combining characters should be rejected"
        );
    }

    #[test]
    fn test_all_unicode_lookalikes_rejected() {
        for payload in attack_payloads::UNICODE_LOOKALIKES {
            let result = is_valid_hostname(payload);
            assert!(
                result.is_err(),
                "Unicode lookalike should be rejected: {:?}",
                payload
            );
        }
    }

    // ==================================================
    // Hostname Format Tests
    // ==================================================

    #[test]
    fn test_valid_hostnames_accepted() {
        let valid = [
            "workstation-001",
            "server.domain.com",
            "host_name_123",
            "UPPERCASE",
            "MixedCase",
        ];

        for hostname in valid {
            let result = is_valid_hostname(hostname);
            assert!(
                result.is_ok(),
                "Valid hostname rejected: {}",
                hostname
            );
        }
    }

    #[test]
    fn test_hostname_normalized_to_lowercase() {
        let result = is_valid_hostname("WORKSTATION-001");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "workstation-001");
    }

    #[test]
    fn test_empty_hostname_rejected() {
        let result = is_valid_hostname("");
        assert!(result.is_err());
    }

    #[test]
    fn test_long_hostname_rejected() {
        let long_hostname = "a".repeat(254);
        let result = is_valid_hostname(&long_hostname);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_length_hostname_accepted() {
        let max_hostname = "a".repeat(253);
        let result = is_valid_hostname(&max_hostname);
        assert!(result.is_ok());
    }

    #[test]
    fn test_hostname_leading_hyphen_rejected() {
        let result = is_valid_hostname("-hostname");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_trailing_hyphen_rejected() {
        let result = is_valid_hostname("hostname-");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_leading_dot_rejected() {
        let result = is_valid_hostname(".hostname");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_trailing_dot_rejected() {
        let result = is_valid_hostname("hostname.");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_consecutive_dots_rejected() {
        let result = is_valid_hostname("host..name");
        assert!(result.is_err());
    }

    #[test]
    fn test_hostname_format_attacks_rejected() {
        for payload in attack_payloads::HOSTNAME_FORMAT_ATTACKS {
            let result = is_valid_hostname(payload);
            assert!(
                result.is_err(),
                "Hostname format attack should be rejected: {}",
                payload
            );
        }
    }

    // ==================================================
    // FQL Special Character Tests in Hostnames
    // ==================================================

    #[test]
    fn test_hostname_with_fql_chars_rejected() {
        let invalid_hostnames = [
            "host'name",        // Single quote
            "host\"name",       // Double quote
            "host\\name",       // Backslash
            "host*name",        // Asterisk
            "host?name",        // Question mark
            "host[0]",          // Square brackets
            "host+name",        // Plus
            "host:name",        // Colon
            "host/name",        // Slash
            "host(name)",       // Parentheses
        ];

        for hostname in invalid_hostnames {
            let result = is_valid_hostname(hostname);
            assert!(
                result.is_err(),
                "Hostname with FQL char should be rejected: {}",
                hostname
            );
        }
    }

    // ==================================================
    // FQL Filter Building Tests
    // ==================================================

    #[test]
    fn test_build_host_filter_escapes() {
        let hostname = "workstation-001";
        // Simulating the filter building from the connector
        let escaped = escape_fql(hostname);
        let filter = format!("hostname:*'{}*'+status:'normal'", escaped);

        // Verify the filter structure
        assert!(filter.contains("hostname:"));
        assert!(filter.contains("status:"));
        assert!(!filter.contains("OR"));
        assert!(!filter.contains("AND"));
    }

    #[test]
    fn test_build_detection_filter() {
        let hostname = "workstation-001";
        let escaped = escape_fql(hostname);
        let filter = format!("device.hostname:'{}'", escaped);

        assert!(filter.contains("device.hostname:"));
        assert!(filter.contains("workstation-001"));
    }

    // ==================================================
    // Integration Tests
    // ==================================================

    #[test]
    fn test_validate_then_escape_workflow() {
        // Normal workflow: validate first, then escape
        let hostname = "WORKSTATION-001";

        // Step 1: Validate and normalize
        let validated = is_valid_hostname(hostname).unwrap();
        assert_eq!(validated, "workstation-001");

        // Step 2: Escape for FQL (safe because validation passed)
        let escaped = escape_fql(&validated);
        assert_eq!(escaped, "workstation-001");  // No special chars to escape

        // Step 3: Build filter
        let filter = format!("hostname:'{}'", escaped);
        assert_eq!(filter, "hostname:'workstation-001'");
    }

    #[test]
    fn test_attack_payload_blocked_by_validation() {
        // Attack payload should fail at validation step
        let attack = "workst\u{0430}tion";  // Contains Cyrillic

        let result = is_valid_hostname(attack);
        assert!(result.is_err());

        // Should never reach the escaping step
    }

    #[test]
    fn test_path_traversal_in_hostname_rejected() {
        for payload in attack_payloads::PATH_TRAVERSAL {
            let result = is_valid_hostname(payload);
            assert!(
                result.is_err(),
                "Path traversal should be rejected: {}",
                payload
            );
        }
    }
}
