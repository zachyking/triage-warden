//! Sensitive data classifier with built-in enterprise patterns.

use regex::Regex;
use serde::{Deserialize, Serialize};

/// Category of sensitive data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    Pii,
    Credential,
    Financial,
    Health,
    Internal,
    Custom(String),
}

impl DataCategory {
    /// Stable category key.
    pub fn as_key(&self) -> String {
        match self {
            DataCategory::Pii => "pii".to_string(),
            DataCategory::Credential => "credential".to_string(),
            DataCategory::Financial => "financial".to_string(),
            DataCategory::Health => "health".to_string(),
            DataCategory::Internal => "internal".to_string(),
            DataCategory::Custom(v) => format!("custom:{v}"),
        }
    }
}

/// Match produced by sensitive data classification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SensitiveDataMatch {
    pub category: DataCategory,
    pub pattern_name: String,
    pub start: usize,
    pub end: usize,
    pub confidence: f32,
}

/// Compiled classification pattern.
#[derive(Debug, Clone)]
pub struct ClassificationPattern {
    pub name: String,
    pub category: DataCategory,
    pub regex: Regex,
    validator: Option<fn(&str) -> bool>,
}

impl ClassificationPattern {
    /// Creates a pattern from regex and optional validator.
    pub fn new(
        name: impl Into<String>,
        category: DataCategory,
        regex: &str,
        validator: Option<fn(&str) -> bool>,
    ) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.into(),
            category,
            regex: Regex::new(regex)?,
            validator,
        })
    }
}

/// Classifier implementation.
#[derive(Debug, Clone)]
pub struct SensitiveDataClassifier {
    patterns: Vec<ClassificationPattern>,
}

impl Default for SensitiveDataClassifier {
    fn default() -> Self {
        Self::with_default_patterns()
    }
}

impl SensitiveDataClassifier {
    /// Creates classifier with no patterns.
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    /// Creates classifier with built-in patterns.
    pub fn with_default_patterns() -> Self {
        let mut classifier = Self::empty();
        add_builtin_pattern(
            &mut classifier,
            "email",
            DataCategory::Pii,
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "phone",
            DataCategory::Pii,
            r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "ssn",
            DataCategory::Pii,
            r"\b\d{3}-\d{2}-\d{4}\b",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "credit_card",
            DataCategory::Financial,
            r"\b(?:\d[ -]*?){13,19}\b",
            Some(is_luhn_card),
        );
        add_builtin_pattern(
            &mut classifier,
            "api_key",
            DataCategory::Credential,
            r#"(?i)\b(?:api[_-]?key|token|secret|password)\b[:=]?\s*['"]?[A-Za-z0-9_-]{12,}['"]?"#,
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "internal_ipv4",
            DataCategory::Internal,
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "internal_hostname",
            DataCategory::Internal,
            r"\b[a-zA-Z0-9][a-zA-Z0-9\-.]{0,61}\.(?:corp|internal|local)\b",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "file_path_unix",
            DataCategory::Internal,
            r"(?:/[^/\s]+)+",
            None,
        );
        add_builtin_pattern(
            &mut classifier,
            "file_path_windows",
            DataCategory::Internal,
            r#"[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*"#,
            None,
        );
        classifier
    }

    /// Adds a custom pattern.
    pub fn add_pattern(
        &mut self,
        name: impl Into<String>,
        category: DataCategory,
        regex: &str,
        validator: Option<fn(&str) -> bool>,
    ) -> Result<(), regex::Error> {
        let pattern = ClassificationPattern::new(name, category, regex, validator)?;
        self.patterns.push(pattern);
        Ok(())
    }

    /// Classifies sensitive data in the provided text.
    pub fn classify(&self, text: &str) -> Vec<SensitiveDataMatch> {
        let mut matches = Vec::new();
        for pattern in &self.patterns {
            for capture in pattern.regex.find_iter(text) {
                let value = capture.as_str();
                if pattern.validator.map(|f| f(value)).unwrap_or(true) {
                    matches.push(SensitiveDataMatch {
                        category: pattern.category.clone(),
                        pattern_name: pattern.name.clone(),
                        start: capture.start(),
                        end: capture.end(),
                        confidence: 1.0,
                    });
                }
            }
        }
        matches.sort_by_key(|m| (m.start, m.end));
        matches
    }
}

fn is_luhn_card(value: &str) -> bool {
    let digits: Vec<u32> = value
        .chars()
        .filter(|c| c.is_ascii_digit())
        .filter_map(|c| c.to_digit(10))
        .collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let mut sum = 0u32;
    let mut alternate = false;
    for digit in digits.iter().rev() {
        let mut n = *digit;
        if alternate {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        alternate = !alternate;
    }
    sum.is_multiple_of(10)
}

fn add_builtin_pattern(
    classifier: &mut SensitiveDataClassifier,
    name: &str,
    category: DataCategory,
    regex: &str,
    validator: Option<fn(&str) -> bool>,
) {
    if let Err(error) = classifier.add_pattern(name, category, regex, validator) {
        tracing::warn!(
            pattern = name,
            %error,
            "failed to compile built-in sensitive data pattern"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classifier_detects_builtins() {
        let classifier = SensitiveDataClassifier::with_default_patterns();
        let input = "Contact a@example.com from 10.1.2.3 with card 4242 4242 4242 4242";
        let matches = classifier.classify(input);
        assert!(matches.iter().any(|m| m.pattern_name == "email"));
        assert!(matches.iter().any(|m| m.pattern_name == "internal_ipv4"));
        assert!(matches.iter().any(|m| m.pattern_name == "credit_card"));
    }

    #[test]
    fn test_luhn_validation_filters_false_card() {
        let classifier = SensitiveDataClassifier::with_default_patterns();
        let input = "fake number 1111 1111 1111 1111";
        let matches = classifier.classify(input);
        assert!(!matches.iter().any(|m| m.pattern_name == "credit_card"));
    }
}
