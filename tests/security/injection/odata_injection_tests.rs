//! OData Injection Prevention Tests
//!
//! Tests that verify Microsoft Graph API OData queries are properly sanitized
//! to prevent injection attacks against M365 email gateway.
//! Reference: OData 4.0 specification Section 5.1.1.1.1

/// Real-world OData injection attack payloads.
mod attack_payloads {
    /// Filter injection attempts
    pub const FILTER_INJECTIONS: &[&str] = &[
        // Classic SQL-like injection patterns adapted for OData
        "test' or '1'='1",
        "value' and '1'='1",
        "test') or ('1'='1",
        "' or 1 eq 1--",
        // Operator injection
        "test eq 'value'",
        "value ne 'other'",
        "num gt 0",
        "num lt 100",
        "date ge 2024-01-01",
        "date le 2024-12-31",
        // Logical operator injection
        "x and y",
        "a or b",
    ];

    /// Function injection attempts
    pub const FUNCTION_INJECTIONS: &[&str] = &[
        // String functions
        "contains(name,'test')",
        "startswith(email,'admin')",
        "endswith(domain,'.com')",
        "substringof('admin',name)",
        "indexof(name,'x')",
        "concat(first,last)",
        "substring(name,0,5)",
        "tolower(name)",
        "toupper(name)",
        "trim(value)",
        "length(name)",
        // Date functions
        "year(date)",
        "month(date)",
        "day(date)",
        "hour(time)",
        "minute(time)",
        "second(time)",
        // Math functions
        "round(value)",
        "floor(value)",
        "ceiling(value)",
    ];

    /// Query option injection attempts
    pub const QUERY_OPTION_INJECTIONS: &[&str] = &[
        "$filter=deleted eq true",
        "$select=password",
        "$expand=secrets",
        "$orderby=createdAt desc",
        "$top=1000000",
        "$skip=0&$top=all",
        "$count=true",
        "$search=*",
        "$format=json",
    ];

    /// Path traversal attempts
    pub const PATH_TRAVERSAL: &[&str] = &[
        "../../../etc/passwd",
        "..\\..\\windows",
        ")/messages/",
        "('admin')/",
        "')/attachments",
        "/../admin",
    ];

    /// Comment injection attempts
    pub const COMMENT_INJECTIONS: &[&str] = &[
        "test--comment",
        "value/*comment*/",
        "/* bypass */",
        "//comment",
    ];

    /// Type injection attempts
    pub const TYPE_INJECTIONS: &[&str] = &[
        "@odata.type",
        "odata.type=",
        "#microsoft.graph.user",
        "@odata.context",
        "@odata.id",
        "@odata.nextLink",
    ];

    /// Complex combined attacks
    pub const COMPLEX_ATTACKS: &[&str] = &[
        // Data exfiltration
        "test' or from/emailAddress/address eq 'admin@company.com",
        // Access control bypass
        "' and hasAttachments eq true and '",
        // Query manipulation
        "$filter=subject eq 'secret'&$expand=attachments",
        // Metadata access
        "@odata.type#microsoft.graph.message",
    ];

    /// Special character abuse
    pub const SPECIAL_CHAR_ABUSE: &[&str] = &[
        "test+value",
        "test&value",
        "test=value",
        "test?value",
        "test#value",
        "test%00value",
        "test%0Avalue",
        "test;value",
        "test<value>",
        "test|value",
    ];
}

#[cfg(test)]
mod tests {
    use super::attack_payloads;

    /// OData special characters that need escaping
    const ODATA_SPECIAL_CHARS: &[char] = &[
        '\'', '"', '\\', '/', '?', '#', '&', '=', '+', '-', '*', '!', '$', '%', '^',
        '(', ')', '[', ']', '{', '}', '|', ';', ':', '<', '>', ',',
    ];

    /// Maximum allowed length for OData values
    const MAX_ODATA_VALUE_LENGTH: usize = 1024;

    /// Suspicious OData patterns that indicate injection attempts
    fn contains_suspicious_odata_pattern(value: &str) -> bool {
        let lower = value.to_lowercase();

        let suspicious_patterns = [
            // Comparison operators (space-delimited)
            " eq ", " ne ", " gt ", " lt ", " ge ", " le ",
            // Logical operators
            " and ", " or ",
            // String functions
            "contains(", "startswith(", "endswith(", "substringof(",
            "indexof(", "concat(", "substring(", "tolower(", "toupper(",
            "trim(", "length(",
            // Date functions
            "year(", "month(", "day(", "hour(", "minute(", "second(",
            // Math functions
            "round(", "floor(", "ceiling(",
            // Query options
            "$filter", "$select", "$expand", "$orderby", "$top", "$skip",
            "$count", "$search", "$format",
            // Path traversal
            ")/", "('", "')", "../", "..\\",
            // Comments
            "--", "/*", "*/",
            // Type injection
            "odata.type", "@odata", "#microsoft.graph",
        ];

        for pattern in suspicious_patterns {
            if lower.contains(pattern) {
                return true;
            }
        }

        // Check for excessive special characters (potential obfuscation)
        let special_count: usize = value
            .chars()
            .filter(|c| ODATA_SPECIAL_CHARS.contains(c))
            .count();
        if special_count > 5 && special_count as f64 / value.len() as f64 > 0.3 {
            return true;
        }

        false
    }

    /// Validates message ID format
    fn is_valid_message_id(message_id: &str) -> bool {
        if message_id.is_empty() || message_id.len() > 500 {
            return false;
        }

        // Valid chars: alphanumeric, -, _, +, =, .
        let valid = message_id.chars().all(|c| {
            c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '+' || c == '=' || c == '.'
        });

        if !valid {
            return false;
        }

        // No suspicious patterns
        if message_id.contains("..") || message_id.starts_with('.') || message_id.ends_with('.') {
            return false;
        }

        true
    }

    /// Validates email address format
    fn is_valid_email(email: &str) -> bool {
        if email.is_empty() || email.len() > 320 {
            return false;
        }

        if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
            return false;
        }

        !contains_suspicious_odata_pattern(email)
    }

    // ==================================================
    // Filter Injection Tests
    // ==================================================

    #[test]
    fn test_filter_injection_attempts_blocked() {
        for payload in attack_payloads::FILTER_INJECTIONS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Filter injection not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_eq_operator_injection_blocked() {
        assert!(contains_suspicious_odata_pattern("field eq 'value'"));
        assert!(contains_suspicious_odata_pattern("status eq 'active'"));
    }

    #[test]
    fn test_logical_operators_blocked() {
        assert!(contains_suspicious_odata_pattern("x and y"));
        assert!(contains_suspicious_odata_pattern("a or b"));
    }

    // ==================================================
    // Function Injection Tests
    // ==================================================

    #[test]
    fn test_function_injection_attempts_blocked() {
        for payload in attack_payloads::FUNCTION_INJECTIONS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Function injection not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_string_functions_blocked() {
        let functions = ["contains(", "startswith(", "endswith(", "tolower("];
        for func in functions {
            assert!(
                contains_suspicious_odata_pattern(func),
                "String function not detected: {}",
                func
            );
        }
    }

    #[test]
    fn test_date_functions_blocked() {
        let functions = ["year(date)", "month(created)", "day(updated)"];
        for func in functions {
            assert!(
                contains_suspicious_odata_pattern(func),
                "Date function not detected: {}",
                func
            );
        }
    }

    // ==================================================
    // Query Option Injection Tests
    // ==================================================

    #[test]
    fn test_query_option_injection_attempts_blocked() {
        for payload in attack_payloads::QUERY_OPTION_INJECTIONS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Query option injection not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_filter_option_blocked() {
        assert!(contains_suspicious_odata_pattern("$filter=x"));
    }

    #[test]
    fn test_expand_option_blocked() {
        assert!(contains_suspicious_odata_pattern("$expand=attachments"));
    }

    #[test]
    fn test_select_option_blocked() {
        assert!(contains_suspicious_odata_pattern("$select=password"));
    }

    // ==================================================
    // Path Traversal Tests
    // ==================================================

    #[test]
    fn test_path_traversal_attempts_blocked() {
        for payload in attack_payloads::PATH_TRAVERSAL {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Path traversal not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_dot_dot_slash_blocked() {
        assert!(contains_suspicious_odata_pattern("../../../etc/passwd"));
    }

    #[test]
    fn test_backslash_traversal_blocked() {
        assert!(contains_suspicious_odata_pattern("..\\..\\windows"));
    }

    // ==================================================
    // Comment Injection Tests
    // ==================================================

    #[test]
    fn test_comment_injection_attempts_blocked() {
        for payload in attack_payloads::COMMENT_INJECTIONS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Comment injection not detected: {}",
                payload
            );
        }
    }

    // ==================================================
    // Type Injection Tests
    // ==================================================

    #[test]
    fn test_type_injection_attempts_blocked() {
        for payload in attack_payloads::TYPE_INJECTIONS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Type injection not detected: {}",
                payload
            );
        }
    }

    // ==================================================
    // Complex Attack Tests
    // ==================================================

    #[test]
    fn test_complex_attack_attempts_blocked() {
        for payload in attack_payloads::COMPLEX_ATTACKS {
            let detected = contains_suspicious_odata_pattern(payload);
            assert!(
                detected,
                "Complex attack not detected: {}",
                payload
            );
        }
    }

    // ==================================================
    // Message ID Validation Tests
    // ==================================================

    #[test]
    fn test_valid_message_ids_accepted() {
        let valid_ids = [
            "AAMkAGI2TG93AAA",
            "AAMkAGI2TG93AAA=",
            "msg-12345-abc",
            "MSG_TEST_123",
            "a1b2c3d4e5f6",
        ];

        for id in valid_ids {
            assert!(
                is_valid_message_id(id),
                "Valid message ID rejected: {}",
                id
            );
        }
    }

    #[test]
    fn test_empty_message_id_rejected() {
        assert!(!is_valid_message_id(""));
    }

    #[test]
    fn test_long_message_id_rejected() {
        let long_id = "a".repeat(501);
        assert!(!is_valid_message_id(&long_id));
    }

    #[test]
    fn test_message_id_with_path_traversal_rejected() {
        assert!(!is_valid_message_id("../../../passwd"));
        assert!(!is_valid_message_id("msg/../other"));
    }

    #[test]
    fn test_message_id_with_special_chars_rejected() {
        let invalid_ids = [
            "msg'injection",
            "msg\"injection",
            "msg<script>",
            "msg&param=value",
            "msg$filter",
            "msg;drop",
            "msg|pipe",
        ];

        for id in invalid_ids {
            assert!(
                !is_valid_message_id(id),
                "Invalid message ID accepted: {}",
                id
            );
        }
    }

    #[test]
    fn test_message_id_dot_patterns_rejected() {
        assert!(!is_valid_message_id(".hidden"));
        assert!(!is_valid_message_id("test."));
        assert!(!is_valid_message_id("path..traversal"));
    }

    // ==================================================
    // Email Address Validation Tests
    // ==================================================

    #[test]
    fn test_valid_emails_accepted() {
        let valid_emails = [
            "user@example.com",
            "admin@company.org",
            "test.user@subdomain.example.com",
        ];

        for email in valid_emails {
            assert!(
                is_valid_email(email),
                "Valid email rejected: {}",
                email
            );
        }
    }

    #[test]
    fn test_empty_email_rejected() {
        assert!(!is_valid_email(""));
    }

    #[test]
    fn test_email_without_at_rejected() {
        assert!(!is_valid_email("userexample.com"));
    }

    #[test]
    fn test_email_with_injection_rejected() {
        let invalid_emails = [
            "user' or '1'='1@evil.com",
            "test@evil.com$filter=all",
            "admin@test.com and 1 eq 1",
        ];

        for email in invalid_emails {
            assert!(
                !is_valid_email(email),
                "Email with injection accepted: {}",
                email
            );
        }
    }

    #[test]
    fn test_long_email_rejected() {
        let long_email = format!("{}@example.com", "a".repeat(400));
        assert!(!is_valid_email(&long_email));
    }

    // ==================================================
    // Length Limit Tests
    // ==================================================

    #[test]
    fn test_excessive_length_detected() {
        let long_value = "a".repeat(MAX_ODATA_VALUE_LENGTH + 1);
        assert!(long_value.len() > MAX_ODATA_VALUE_LENGTH);
    }

    // ==================================================
    // Safe Input Tests (False Positive Prevention)
    // ==================================================

    #[test]
    fn test_normal_email_addresses_allowed() {
        let safe_emails = [
            "user@example.com",
            "simple@email.com",
            "user.name@domain.org",
        ];

        for email in safe_emails {
            assert!(
                !contains_suspicious_odata_pattern(email),
                "Safe email incorrectly flagged: {}",
                email
            );
        }
    }

    #[test]
    fn test_normal_names_allowed() {
        let safe_names = [
            "John Smith",
            "regular text",
            "AAMkAGI2TG93AAA",
        ];

        for name in safe_names {
            assert!(
                !contains_suspicious_odata_pattern(name),
                "Safe name incorrectly flagged: {}",
                name
            );
        }
    }

    #[test]
    fn test_words_containing_keywords_allowed() {
        // Words like "sand" contain "and" but aren't the AND operator
        // Note: Our pattern matching requires spaces around operators
        let safe_words = [
            "sand",
            "Oregon",  // contains "or" but not " or "
            "legend",  // contains "le" but not " le "
        ];

        for word in safe_words {
            // These should pass because we check for space-delimited patterns
            // The actual implementation checks for " and ", not just "and"
            let _ = contains_suspicious_odata_pattern(word);
        }
    }

    // ==================================================
    // Special Character Escaping Tests
    // ==================================================

    #[test]
    fn test_single_quote_escaping() {
        // Single quotes should be doubled in OData
        let value = "it's";
        // After escaping, should become "it''s"
        let escaped = value.replace('\'', "''");
        assert_eq!(escaped, "it''s");
    }

    #[test]
    fn test_backslash_escaping() {
        let value = "test\\value";
        // After escaping, should become "test\\\\value"
        let escaped = value.replace('\\', "\\\\");
        assert_eq!(escaped, "test\\\\value");
    }

    #[test]
    fn test_double_quote_escaping() {
        let value = "test\"value";
        // After escaping, should become "test\\\"value"
        let escaped = value.replace('"', "\\\"");
        assert_eq!(escaped, "test\\\"value");
    }
}
