//! Condition evaluation for advanced playbook execution.
//!
//! Provides a flexible condition system for playbook branching and step guards.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A condition that can be evaluated against an execution context.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Condition {
    /// Compare a field value against an expected value.
    Field {
        path: String,
        op: CompareOp,
        value: serde_json::Value,
    },
    /// All sub-conditions must be true.
    And(Vec<Condition>),
    /// At least one sub-condition must be true.
    Or(Vec<Condition>),
    /// Negate a condition.
    Not(Box<Condition>),
    /// A simple expression string for evaluation.
    Expression(String),
}

/// Comparison operators for field conditions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum CompareOp {
    /// Equal.
    Eq,
    /// Not equal.
    Ne,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gte,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// String/array contains value.
    Contains,
    /// String starts with value.
    StartsWith,
    /// String ends with value.
    EndsWith,
    /// String matches regex pattern.
    Matches,
    /// Value is in a set.
    In,
    /// Value is not in a set.
    NotIn,
}

/// Execution context holding runtime values for condition evaluation.
pub struct ExecutionContext {
    values: HashMap<String, serde_json::Value>,
}

impl Default for ExecutionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionContext {
    /// Creates a new empty execution context.
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    /// Sets a value at the given path.
    pub fn set(&mut self, path: &str, value: serde_json::Value) {
        self.values.insert(path.to_string(), value);
    }

    /// Gets a value at the given path, supporting dotted path resolution.
    pub fn get(&self, path: &str) -> Option<&serde_json::Value> {
        // First try direct lookup
        if let Some(val) = self.values.get(path) {
            return Some(val);
        }

        // Try resolving dotted path through nested values
        let parts: Vec<&str> = path.splitn(2, '.').collect();
        if parts.len() == 2 {
            let root = parts[0];
            let rest = parts[1];
            if let Some(root_val) = self.values.get(root) {
                return resolve_json_path(root_val, rest);
            }
        }

        None
    }

    /// Merges a JSON object into the context. Top-level keys become context keys.
    pub fn merge(&mut self, data: serde_json::Value) {
        if let serde_json::Value::Object(map) = data {
            for (key, value) in map {
                self.values.insert(key, value);
            }
        }
    }
}

/// Resolves a dotted path within a JSON value.
fn resolve_json_path<'a>(
    value: &'a serde_json::Value,
    path: &str,
) -> Option<&'a serde_json::Value> {
    let mut current = value;
    for part in path.split('.') {
        match current {
            serde_json::Value::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(current)
}

/// Evaluates conditions against an execution context.
pub struct ConditionEvaluator;

impl ConditionEvaluator {
    /// Evaluates a condition against the given context.
    pub fn evaluate(condition: &Condition, context: &ExecutionContext) -> bool {
        match condition {
            Condition::Field { path, op, value } => {
                if let Some(actual) = context.get(path) {
                    Self::compare(actual, op, value)
                } else {
                    false
                }
            }
            Condition::And(conditions) => conditions.iter().all(|c| Self::evaluate(c, context)),
            Condition::Or(conditions) => conditions.iter().any(|c| Self::evaluate(c, context)),
            Condition::Not(condition) => !Self::evaluate(condition, context),
            Condition::Expression(expr) => Self::evaluate_expression(expr, context),
        }
    }

    /// Compares an actual JSON value against an expected value using the given operator.
    fn compare(actual: &serde_json::Value, op: &CompareOp, expected: &serde_json::Value) -> bool {
        match op {
            CompareOp::Eq => actual == expected,
            CompareOp::Ne => actual != expected,
            CompareOp::Gt => compare_numeric(actual, expected, |a, b| a > b),
            CompareOp::Gte => compare_numeric(actual, expected, |a, b| a >= b),
            CompareOp::Lt => compare_numeric(actual, expected, |a, b| a < b),
            CompareOp::Lte => compare_numeric(actual, expected, |a, b| a <= b),
            CompareOp::Contains => match (actual, expected) {
                (serde_json::Value::String(haystack), serde_json::Value::String(needle)) => {
                    haystack.contains(needle.as_str())
                }
                (serde_json::Value::Array(arr), _) => arr.contains(expected),
                _ => false,
            },
            CompareOp::StartsWith => match (actual, expected) {
                (serde_json::Value::String(s), serde_json::Value::String(prefix)) => {
                    s.starts_with(prefix.as_str())
                }
                _ => false,
            },
            CompareOp::EndsWith => match (actual, expected) {
                (serde_json::Value::String(s), serde_json::Value::String(suffix)) => {
                    s.ends_with(suffix.as_str())
                }
                _ => false,
            },
            CompareOp::Matches => match (actual, expected) {
                (serde_json::Value::String(s), serde_json::Value::String(pattern)) => {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(s))
                        .unwrap_or(false)
                }
                _ => false,
            },
            CompareOp::In => match expected {
                serde_json::Value::Array(arr) => arr.contains(actual),
                _ => false,
            },
            CompareOp::NotIn => match expected {
                serde_json::Value::Array(arr) => !arr.contains(actual),
                _ => true,
            },
        }
    }

    /// Evaluates a simple expression string against the context.
    fn evaluate_expression(expr: &str, context: &ExecutionContext) -> bool {
        let trimmed = expr.trim();

        // Handle "path not exists" pattern (must check before "exists")
        if trimmed.ends_with(" not exists") {
            let path = trimmed.trim_end_matches(" not exists").trim();
            return context.get(path).is_none();
        }

        // Handle "path exists" pattern
        if trimmed.ends_with(" exists") {
            let path = trimmed.trim_end_matches(" exists").trim();
            return context.get(path).is_some();
        }

        // Handle "path is true" pattern
        if trimmed.ends_with(" is true") {
            let path = trimmed.trim_end_matches(" is true").trim();
            return matches!(context.get(path), Some(serde_json::Value::Bool(true)));
        }

        // Handle "path is false" pattern
        if trimmed.ends_with(" is false") {
            let path = trimmed.trim_end_matches(" is false").trim();
            return matches!(context.get(path), Some(serde_json::Value::Bool(false)));
        }

        // Handle "path is not null" pattern (must check before "is null")
        if trimmed.ends_with(" is not null") {
            let path = trimmed.trim_end_matches(" is not null").trim();
            return context.get(path).is_some()
                && !matches!(context.get(path), Some(serde_json::Value::Null));
        }

        // Handle "path is null" pattern
        if trimmed.ends_with(" is null") {
            let path = trimmed.trim_end_matches(" is null").trim();
            return context.get(path).is_none()
                || matches!(context.get(path), Some(serde_json::Value::Null));
        }

        // Unknown expression, return false
        false
    }
}

/// Helper to compare two JSON values numerically.
fn compare_numeric(
    a: &serde_json::Value,
    b: &serde_json::Value,
    cmp: fn(f64, f64) -> bool,
) -> bool {
    match (as_f64(a), as_f64(b)) {
        (Some(a_num), Some(b_num)) => cmp(a_num, b_num),
        _ => {
            // Fall back to lexicographic string comparison for strings
            match (a.as_str(), b.as_str()) {
                (Some(a_str), Some(b_str)) => {
                    let ord = a_str.cmp(b_str);
                    cmp(ord as i8 as f64, 0.0)
                }
                _ => false,
            }
        }
    }
}

/// Extracts a numeric value from a JSON value.
fn as_f64(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        serde_json::Value::String(s) => s.parse::<f64>().ok(),
        serde_json::Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // ExecutionContext tests
    // ========================================================================

    #[test]
    fn test_context_new_is_empty() {
        let ctx = ExecutionContext::new();
        assert!(ctx.get("anything").is_none());
    }

    #[test]
    fn test_context_set_and_get() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("high"));
        assert_eq!(ctx.get("severity"), Some(&json!("high")));
    }

    #[test]
    fn test_context_get_missing() {
        let ctx = ExecutionContext::new();
        assert!(ctx.get("missing").is_none());
    }

    #[test]
    fn test_context_merge() {
        let mut ctx = ExecutionContext::new();
        ctx.merge(json!({
            "severity": "high",
            "score": 95
        }));
        assert_eq!(ctx.get("severity"), Some(&json!("high")));
        assert_eq!(ctx.get("score"), Some(&json!(95)));
    }

    #[test]
    fn test_context_merge_non_object() {
        let mut ctx = ExecutionContext::new();
        ctx.set("before", json!(1));
        ctx.merge(json!("not an object"));
        // Should not crash, and existing values preserved
        assert_eq!(ctx.get("before"), Some(&json!(1)));
    }

    #[test]
    fn test_context_nested_path_resolution() {
        let mut ctx = ExecutionContext::new();
        ctx.set(
            "incident",
            json!({
                "severity": "critical",
                "details": {
                    "source_ip": "10.0.0.1"
                }
            }),
        );
        assert_eq!(ctx.get("incident.severity"), Some(&json!("critical")));
        assert_eq!(
            ctx.get("incident.details.source_ip"),
            Some(&json!("10.0.0.1"))
        );
    }

    #[test]
    fn test_context_nested_path_missing() {
        let mut ctx = ExecutionContext::new();
        ctx.set("incident", json!({"severity": "high"}));
        assert!(ctx.get("incident.missing_field").is_none());
        assert!(ctx.get("nonexistent.path").is_none());
    }

    #[test]
    fn test_context_default() {
        let ctx = ExecutionContext::default();
        assert!(ctx.get("anything").is_none());
    }

    // ========================================================================
    // CompareOp tests - Eq / Ne
    // ========================================================================

    #[test]
    fn test_compare_eq_string() {
        let mut ctx = ExecutionContext::new();
        ctx.set("status", json!("active"));
        let cond = Condition::Field {
            path: "status".to_string(),
            op: CompareOp::Eq,
            value: json!("active"),
        };
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_compare_eq_number() {
        let mut ctx = ExecutionContext::new();
        ctx.set("count", json!(42));
        let cond = Condition::Field {
            path: "count".to_string(),
            op: CompareOp::Eq,
            value: json!(42),
        };
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_compare_eq_bool() {
        let mut ctx = ExecutionContext::new();
        ctx.set("enabled", json!(true));
        let cond = Condition::Field {
            path: "enabled".to_string(),
            op: CompareOp::Eq,
            value: json!(true),
        };
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_compare_ne() {
        let mut ctx = ExecutionContext::new();
        ctx.set("status", json!("active"));
        let cond = Condition::Field {
            path: "status".to_string(),
            op: CompareOp::Ne,
            value: json!("inactive"),
        };
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    // ========================================================================
    // CompareOp tests - Gt / Gte / Lt / Lte
    // ========================================================================

    #[test]
    fn test_compare_gt() {
        let mut ctx = ExecutionContext::new();
        ctx.set("score", json!(90));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(80),
            },
            &ctx,
        ));
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_gte() {
        let mut ctx = ExecutionContext::new();
        ctx.set("score", json!(90));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gte,
                value: json!(90),
            },
            &ctx,
        ));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gte,
                value: json!(89),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_lt() {
        let mut ctx = ExecutionContext::new();
        ctx.set("score", json!(10));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Lt,
                value: json!(20),
            },
            &ctx,
        ));
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Lt,
                value: json!(10),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_lte() {
        let mut ctx = ExecutionContext::new();
        ctx.set("score", json!(10));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Lte,
                value: json!(10),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_numeric_with_string_numbers() {
        let mut ctx = ExecutionContext::new();
        ctx.set("score", json!("95"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
            &ctx,
        ));
    }

    // ========================================================================
    // CompareOp tests - Contains / StartsWith / EndsWith
    // ========================================================================

    #[test]
    fn test_compare_contains_string() {
        let mut ctx = ExecutionContext::new();
        ctx.set("message", json!("malware detected in email"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "message".to_string(),
                op: CompareOp::Contains,
                value: json!("malware"),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_contains_array() {
        let mut ctx = ExecutionContext::new();
        ctx.set("tags", json!(["phishing", "high-priority", "external"]));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "tags".to_string(),
                op: CompareOp::Contains,
                value: json!("phishing"),
            },
            &ctx,
        ));
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "tags".to_string(),
                op: CompareOp::Contains,
                value: json!("internal"),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_starts_with() {
        let mut ctx = ExecutionContext::new();
        ctx.set("domain", json!("evil.example.com"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "domain".to_string(),
                op: CompareOp::StartsWith,
                value: json!("evil"),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_ends_with() {
        let mut ctx = ExecutionContext::new();
        ctx.set("filename", json!("report.pdf"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "filename".to_string(),
                op: CompareOp::EndsWith,
                value: json!(".pdf"),
            },
            &ctx,
        ));
    }

    // ========================================================================
    // CompareOp tests - Matches (regex)
    // ========================================================================

    #[test]
    fn test_compare_matches_regex() {
        let mut ctx = ExecutionContext::new();
        ctx.set("ip", json!("192.168.1.100"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "ip".to_string(),
                op: CompareOp::Matches,
                value: json!(r"^192\.168\.\d+\.\d+$"),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_matches_invalid_regex() {
        let mut ctx = ExecutionContext::new();
        ctx.set("ip", json!("192.168.1.100"));
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "ip".to_string(),
                op: CompareOp::Matches,
                value: json!("[invalid regex"),
            },
            &ctx,
        ));
    }

    // ========================================================================
    // CompareOp tests - In / NotIn
    // ========================================================================

    #[test]
    fn test_compare_in() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("high"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::In,
                value: json!(["high", "critical"]),
            },
            &ctx,
        ));
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::In,
                value: json!(["low", "medium"]),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_compare_not_in() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("low"));
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::NotIn,
                value: json!(["high", "critical"]),
            },
            &ctx,
        ));
    }

    // ========================================================================
    // Composite condition tests - And / Or / Not
    // ========================================================================

    #[test]
    fn test_and_condition() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("high"));
        ctx.set("score", json!(95));

        let cond = Condition::And(vec![
            Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::Eq,
                value: json!("high"),
            },
            Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
        ]);
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_and_condition_partial_fail() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("low"));
        ctx.set("score", json!(95));

        let cond = Condition::And(vec![
            Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::Eq,
                value: json!("high"),
            },
            Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
        ]);
        assert!(!ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_or_condition() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("low"));
        ctx.set("score", json!(95));

        let cond = Condition::Or(vec![
            Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::Eq,
                value: json!("high"),
            },
            Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
        ]);
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_or_condition_all_fail() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("low"));
        ctx.set("score", json!(50));

        let cond = Condition::Or(vec![
            Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::Eq,
                value: json!("high"),
            },
            Condition::Field {
                path: "score".to_string(),
                op: CompareOp::Gt,
                value: json!(90),
            },
        ]);
        assert!(!ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_not_condition() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("low"));

        let cond = Condition::Not(Box::new(Condition::Field {
            path: "severity".to_string(),
            op: CompareOp::Eq,
            value: json!("high"),
        }));
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_nested_composition() {
        let mut ctx = ExecutionContext::new();
        ctx.set("severity", json!("critical"));
        ctx.set("automated", json!(true));
        ctx.set("score", json!(98));

        // (severity == critical AND score > 90) OR automated == true
        let cond = Condition::Or(vec![
            Condition::And(vec![
                Condition::Field {
                    path: "severity".to_string(),
                    op: CompareOp::Eq,
                    value: json!("critical"),
                },
                Condition::Field {
                    path: "score".to_string(),
                    op: CompareOp::Gt,
                    value: json!(90),
                },
            ]),
            Condition::Field {
                path: "automated".to_string(),
                op: CompareOp::Eq,
                value: json!(true),
            },
        ]);
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    // ========================================================================
    // Expression evaluation tests
    // ========================================================================

    #[test]
    fn test_expression_exists() {
        let mut ctx = ExecutionContext::new();
        ctx.set("incident.ip", json!("10.0.0.1"));

        let cond = Condition::Expression("incident.ip exists".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));

        let cond = Condition::Expression("missing.field exists".to_string());
        assert!(!ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_not_exists() {
        let ctx = ExecutionContext::new();
        let cond = Condition::Expression("missing.field not exists".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_is_true() {
        let mut ctx = ExecutionContext::new();
        ctx.set("enabled", json!(true));
        let cond = Condition::Expression("enabled is true".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_is_false() {
        let mut ctx = ExecutionContext::new();
        ctx.set("enabled", json!(false));
        let cond = Condition::Expression("enabled is false".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_is_null() {
        let ctx = ExecutionContext::new();
        let cond = Condition::Expression("missing is null".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_is_not_null() {
        let mut ctx = ExecutionContext::new();
        ctx.set("value", json!(42));
        let cond = Condition::Expression("value is not null".to_string());
        assert!(ConditionEvaluator::evaluate(&cond, &ctx));
    }

    #[test]
    fn test_expression_unknown() {
        let ctx = ExecutionContext::new();
        let cond = Condition::Expression("some unknown expression".to_string());
        assert!(!ConditionEvaluator::evaluate(&cond, &ctx));
    }

    // ========================================================================
    // Missing field tests
    // ========================================================================

    #[test]
    fn test_missing_field_returns_false() {
        let ctx = ExecutionContext::new();
        let cond = Condition::Field {
            path: "missing".to_string(),
            op: CompareOp::Eq,
            value: json!("anything"),
        };
        assert!(!ConditionEvaluator::evaluate(&cond, &ctx));
    }

    // ========================================================================
    // Serialization tests
    // ========================================================================

    #[test]
    fn test_condition_serialization_roundtrip() {
        let cond = Condition::And(vec![
            Condition::Field {
                path: "severity".to_string(),
                op: CompareOp::Eq,
                value: json!("high"),
            },
            Condition::Not(Box::new(Condition::Expression(
                "disabled is true".to_string(),
            ))),
        ]);

        let json = serde_json::to_string(&cond).unwrap();
        let deserialized: Condition = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, cond);
    }

    #[test]
    fn test_compare_op_serialization() {
        let ops = vec![
            CompareOp::Eq,
            CompareOp::Ne,
            CompareOp::Gt,
            CompareOp::Gte,
            CompareOp::Lt,
            CompareOp::Lte,
            CompareOp::Contains,
            CompareOp::StartsWith,
            CompareOp::EndsWith,
            CompareOp::Matches,
            CompareOp::In,
            CompareOp::NotIn,
        ];
        for op in ops {
            let json = serde_json::to_string(&op).unwrap();
            let deserialized: CompareOp = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, op);
        }
    }

    #[test]
    fn test_in_with_non_array_expected() {
        let mut ctx = ExecutionContext::new();
        ctx.set("val", json!("hello"));
        // In with non-array expected should be false
        assert!(!ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "val".to_string(),
                op: CompareOp::In,
                value: json!("not-array"),
            },
            &ctx,
        ));
    }

    #[test]
    fn test_not_in_with_non_array_expected() {
        let mut ctx = ExecutionContext::new();
        ctx.set("val", json!("hello"));
        // NotIn with non-array expected should be true
        assert!(ConditionEvaluator::evaluate(
            &Condition::Field {
                path: "val".to_string(),
                op: CompareOp::NotIn,
                value: json!("not-array"),
            },
            &ctx,
        ));
    }
}
