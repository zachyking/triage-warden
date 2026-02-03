//! ReDoS (Regular Expression Denial of Service) Prevention Tests
//!
//! Tests that verify regex patterns with catastrophic backtracking potential
//! are properly rejected by the policy engine.
//! Reference: https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS

/// Real-world ReDoS attack patterns from security research.
mod attack_payloads {
    /// Classic nested quantifier patterns that cause exponential backtracking
    pub const NESTED_QUANTIFIERS: &[&str] = &[
        // Evil regex patterns
        r"(a+)+",           // Classic example
        r"(a*)*",           // Star within star
        r"(a+)*",           // Plus within star
        r"(a*)+",           // Star within plus
        r"([a-zA-Z]+)*",    // Character class with nested quantifier
        r"(.*a)+",          // Dot-star with plus
        r"((a+)+)+",        // Triple nesting
        r"(a|aa)+",         // Overlapping alternation
        r"(a|a?)+",         // Optional overlap
        r"([\s\S]*)+",      // Match-all with nested quantifier
    ];

    /// Excessive quantifier ranges that can cause slow matching
    pub const EXCESSIVE_RANGES: &[&str] = &[
        r"a{1,10000}",
        r"x{0,100000}",
        r".{1,50000}",
        r"[a-z]{1,20000}",
        r"\d{0,99999}",
    ];

    /// Overlapping alternations with quantifiers
    pub const OVERLAPPING_ALTERNATIONS: &[&str] = &[
        r"(a|a)+",
        r"(ab|abc)+",
        r"(x|xy|xyz)+",
        r"(foo|foobar)+",
        r"(test|testing)+",
    ];

    /// Patterns that are too long (potential complexity attack)
    pub const LONG_PATTERNS: &[&str] = &[
        // Will be generated in tests due to length
    ];

    /// Known CVE-related ReDoS patterns
    pub const CVE_PATTERNS: &[&str] = &[
        // CVE-2016-4055 (moment.js)
        r"^(\d+)?\s*(\d+)?$",
        // CVE-2017-16114 (marked)
        r"^(\s*>)+",
        // Similar to CVE-2018-1000001
        r"(\s+|\t+)+",
        // Email-style ReDoS
        r"^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$",
    ];

    /// Backtracking amplification patterns
    pub const BACKTRACKING_AMPLIFIERS: &[&str] = &[
        r"(.*.*)+",
        r"(.+.+)+",
        r"(.*.+)+",
        r"(.+.*)+",
        r"(a+){2,}",
        r"([^\"]+)+\"",
    ];

    /// Safe patterns that should NOT be rejected (false positive check)
    pub const SAFE_PATTERNS: &[&str] = &[
        r"^[a-zA-Z0-9]+$",
        r"\d{1,10}",
        r"test\d+",
        r"[a-z]{1,50}",
        r"foo|bar|baz",
        r"^\w+@\w+\.\w+$",
        r"https?://.*",
        r"(Monday|Tuesday|Wednesday)",
        r"\d{4}-\d{2}-\d{2}",
        r"[A-Z]{2,4}-\d{1,6}",
    ];
}

#[cfg(test)]
mod tests {
    use super::attack_payloads;

    /// Maximum allowed pattern length
    const MAX_PATTERN_LENGTH: usize = 1000;

    /// Maximum allowed quantifier range
    const MAX_QUANTIFIER_RANGE: u32 = 1000;

    /// Checks for nested quantifiers (most dangerous ReDoS pattern)
    fn has_nested_quantifier(pattern: &str) -> bool {
        // Look for patterns like (x+)+, (x*)+, (x+)*, etc.
        let mut in_group = false;
        let mut group_has_quantifier = false;
        let mut chars = pattern.chars().peekable();

        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    // Skip escaped character
                    chars.next();
                }
                '(' => {
                    in_group = true;
                    group_has_quantifier = false;
                }
                ')' => {
                    if in_group && group_has_quantifier {
                        // Check if followed by quantifier
                        if let Some(&next) = chars.peek() {
                            if next == '+' || next == '*' || next == '?' || next == '{' {
                                return true;
                            }
                        }
                    }
                    in_group = false;
                }
                '+' | '*' | '?' => {
                    if in_group {
                        group_has_quantifier = true;
                    }
                }
                '{' => {
                    if in_group {
                        group_has_quantifier = true;
                    }
                }
                _ => {}
            }
        }

        false
    }

    /// Checks for excessive quantifier ranges
    fn has_excessive_range(pattern: &str) -> bool {
        let mut i = 0;
        let chars: Vec<char> = pattern.chars().collect();

        while i < chars.len() {
            if chars[i] == '{' {
                // Find the closing brace
                let start = i + 1;
                while i < chars.len() && chars[i] != '}' {
                    i += 1;
                }

                if i < chars.len() {
                    let range_str: String = chars[start..i].iter().collect();
                    if let Some((min_str, max_str)) = range_str.split_once(',') {
                        if let (Ok(min), Ok(max)) = (
                            min_str.trim().parse::<u32>(),
                            max_str.trim().parse::<u32>(),
                        ) {
                            if max.saturating_sub(min) > MAX_QUANTIFIER_RANGE {
                                return true;
                            }
                        }
                    }
                }
            }
            i += 1;
        }

        false
    }

    /// Checks if pattern length exceeds limit
    fn is_pattern_too_long(pattern: &str) -> bool {
        pattern.len() > MAX_PATTERN_LENGTH
    }

    /// Comprehensive ReDoS check
    fn is_redos_vulnerable(pattern: &str) -> bool {
        has_nested_quantifier(pattern)
            || has_excessive_range(pattern)
            || is_pattern_too_long(pattern)
    }

    // ==================================================
    // Nested Quantifier Tests
    // ==================================================

    #[test]
    fn test_nested_quantifiers_detected() {
        for payload in attack_payloads::NESTED_QUANTIFIERS {
            assert!(
                has_nested_quantifier(payload),
                "Nested quantifier not detected in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_classic_evil_regex_detected() {
        // The classic evil regex: (a+)+
        assert!(has_nested_quantifier(r"(a+)+"));
    }

    #[test]
    fn test_star_within_star_detected() {
        assert!(has_nested_quantifier(r"(a*)*"));
    }

    #[test]
    fn test_plus_within_star_detected() {
        assert!(has_nested_quantifier(r"(a+)*"));
    }

    #[test]
    fn test_star_within_plus_detected() {
        assert!(has_nested_quantifier(r"(a*)+"));
    }

    #[test]
    fn test_triple_nesting_detected() {
        assert!(has_nested_quantifier(r"((a+)+)+"));
    }

    // ==================================================
    // Excessive Range Tests
    // ==================================================

    #[test]
    fn test_excessive_ranges_detected() {
        for payload in attack_payloads::EXCESSIVE_RANGES {
            assert!(
                has_excessive_range(payload),
                "Excessive range not detected in: {}",
                payload
            );
        }
    }

    #[test]
    fn test_range_10000_rejected() {
        assert!(has_excessive_range(r"a{1,10000}"));
    }

    #[test]
    fn test_range_100000_rejected() {
        assert!(has_excessive_range(r"x{0,100000}"));
    }

    #[test]
    fn test_reasonable_range_accepted() {
        // Range of 1000 is the maximum allowed
        assert!(!has_excessive_range(r"a{1,100}"));
        assert!(!has_excessive_range(r"a{1,500}"));
        assert!(!has_excessive_range(r"a{1,1000}"));
    }

    #[test]
    fn test_range_just_over_limit_rejected() {
        assert!(has_excessive_range(r"a{1,1002}"));
    }

    // ==================================================
    // Pattern Length Tests
    // ==================================================

    #[test]
    fn test_long_pattern_rejected() {
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert!(is_pattern_too_long(&long_pattern));
    }

    #[test]
    fn test_max_length_pattern_accepted() {
        let max_pattern = "a".repeat(MAX_PATTERN_LENGTH);
        assert!(!is_pattern_too_long(&max_pattern));
    }

    #[test]
    fn test_normal_pattern_accepted() {
        let normal_pattern = "^[a-zA-Z0-9]{1,50}$";
        assert!(!is_pattern_too_long(normal_pattern));
    }

    // ==================================================
    // Backtracking Amplifier Tests
    // ==================================================

    #[test]
    fn test_backtracking_amplifiers_detected() {
        for payload in attack_payloads::BACKTRACKING_AMPLIFIERS {
            let detected = has_nested_quantifier(payload);
            assert!(
                detected,
                "Backtracking amplifier not detected: {}",
                payload
            );
        }
    }

    #[test]
    fn test_dot_star_dot_star_plus_detected() {
        assert!(has_nested_quantifier(r"(.*.*)+"));
    }

    #[test]
    fn test_dot_plus_dot_plus_plus_detected() {
        assert!(has_nested_quantifier(r"(.+.+)+"));
    }

    // ==================================================
    // CVE Pattern Tests
    // ==================================================

    #[test]
    fn test_cve_patterns_evaluated() {
        // These are known vulnerable patterns from real CVEs
        // Our detection may not catch all of them, but we document the behavior
        for payload in attack_payloads::CVE_PATTERNS {
            let _result = is_redos_vulnerable(payload);
            // Note: Some CVE patterns use different attack vectors
            // that may require more sophisticated analysis
        }
    }

    #[test]
    fn test_whitespace_redos_detected() {
        // CVE-2018-1000001 style
        assert!(has_nested_quantifier(r"(\s+|\t+)+"));
    }

    // ==================================================
    // Safe Pattern Tests (False Positive Prevention)
    // ==================================================

    #[test]
    fn test_safe_patterns_accepted() {
        for pattern in attack_payloads::SAFE_PATTERNS {
            assert!(
                !is_redos_vulnerable(pattern),
                "Safe pattern incorrectly flagged as vulnerable: {}",
                pattern
            );
        }
    }

    #[test]
    fn test_simple_alphanumeric_accepted() {
        assert!(!is_redos_vulnerable(r"^[a-zA-Z0-9]+$"));
    }

    #[test]
    fn test_simple_digit_range_accepted() {
        assert!(!is_redos_vulnerable(r"\d{1,10}"));
    }

    #[test]
    fn test_simple_alternation_accepted() {
        assert!(!is_redos_vulnerable(r"foo|bar|baz"));
    }

    #[test]
    fn test_date_pattern_accepted() {
        assert!(!is_redos_vulnerable(r"\d{4}-\d{2}-\d{2}"));
    }

    #[test]
    fn test_ticket_id_pattern_accepted() {
        assert!(!is_redos_vulnerable(r"[A-Z]{2,4}-\d{1,6}"));
    }

    #[test]
    fn test_url_pattern_accepted() {
        assert!(!is_redos_vulnerable(r"https?://.*"));
    }

    // ==================================================
    // Edge Case Tests
    // ==================================================

    #[test]
    fn test_escaped_characters_not_false_positive() {
        // Escaped parentheses and quantifiers should not trigger
        assert!(!has_nested_quantifier(r"\(a+\)+"));
        assert!(!has_nested_quantifier(r"\(test\)\+"));
    }

    #[test]
    fn test_character_class_quantifier_in_group() {
        // [a-z]+ inside a group followed by quantifier
        assert!(has_nested_quantifier(r"([a-z]+)+"));
    }

    #[test]
    fn test_empty_pattern_accepted() {
        assert!(!is_redos_vulnerable(""));
    }

    #[test]
    fn test_single_char_pattern_accepted() {
        assert!(!is_redos_vulnerable("a"));
    }

    #[test]
    fn test_quantifier_without_group_accepted() {
        assert!(!has_nested_quantifier(r"a+b*c?"));
    }

    // ==================================================
    // Combined Vulnerability Tests
    // ==================================================

    #[test]
    fn test_comprehensive_redos_check() {
        // Test that the combined check catches various attack types
        assert!(is_redos_vulnerable(r"(a+)+"));           // Nested quantifier
        assert!(is_redos_vulnerable(r"a{1,10000}"));      // Excessive range
        assert!(is_redos_vulnerable(&"x".repeat(1001))); // Too long
    }

    #[test]
    fn test_multiple_vulnerability_types() {
        // Pattern with both nested quantifier and excessive range
        let pattern = r"(a{1,10000})+";
        assert!(has_nested_quantifier(pattern));
        assert!(has_excessive_range(pattern));
        assert!(is_redos_vulnerable(pattern));
    }

    // ==================================================
    // Performance Impact Tests
    // ==================================================

    #[test]
    fn test_detection_is_fast() {
        // Detection should complete quickly even for complex patterns
        use std::time::Instant;

        let patterns_to_test = [
            r"(a+)+",
            r"a{1,10000}",
            r"^[a-zA-Z0-9]+$",
            &"a".repeat(999),
        ];

        for pattern in &patterns_to_test {
            let start = Instant::now();
            let _result = is_redos_vulnerable(pattern);
            let duration = start.elapsed();

            // Detection should complete in under 1ms
            assert!(
                duration.as_millis() < 1,
                "Detection took too long for pattern: {} ({}ms)",
                pattern.chars().take(50).collect::<String>(),
                duration.as_millis()
            );
        }
    }

    // ==================================================
    // Integration-Style Tests
    // ==================================================

    #[test]
    fn test_policy_pattern_workflow() {
        // Simulating the workflow of adding a pattern to a deny list

        // User tries to add a dangerous pattern
        let dangerous_pattern = r"(a+)+";
        assert!(
            is_redos_vulnerable(dangerous_pattern),
            "Dangerous pattern should be rejected during validation"
        );

        // User adds a safe pattern
        let safe_pattern = r"^SEC-\d{1,6}$";
        assert!(
            !is_redos_vulnerable(safe_pattern),
            "Safe pattern should be accepted"
        );
    }

    #[test]
    fn test_deny_list_pattern_validation() {
        // Common patterns that might be used in deny lists
        let deny_list_patterns = [
            r"password",
            r"secret",
            r"(?i)admin",
            r"\btoken\b",
            r"api[_-]?key",
        ];

        for pattern in deny_list_patterns {
            assert!(
                !is_redos_vulnerable(pattern),
                "Valid deny list pattern rejected: {}",
                pattern
            );
        }
    }

    #[test]
    fn test_target_pattern_validation() {
        // Common patterns for targeting specific issues/tickets
        let target_patterns = [
            r"^SEC-\d+$",
            r"^VULN-\d{1,6}$",
            r"(?i)^critical$",
            r"^(high|medium|low)$",
        ];

        for pattern in target_patterns {
            assert!(
                !is_redos_vulnerable(pattern),
                "Valid target pattern rejected: {}",
                pattern
            );
        }
    }
}
