//! Shared test fixtures for integration tests.
//!
//! This module provides access to standardized test data that is shared
//! between Rust and Python tests for consistency.
//!
//! Fixtures are stored as JSON files in `/tests/fixtures/` and can be
//! loaded at runtime or compile time.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Sample alerts loaded from the shared fixtures.
pub struct SampleAlerts;

impl SampleAlerts {
    /// Loads all sample alerts from the JSON file.
    pub fn load_all() -> HashMap<String, Value> {
        let json_str = include_str!("../../../../tests/fixtures/sample_alerts.json");
        serde_json::from_str(json_str).expect("Failed to parse sample_alerts.json")
    }

    /// Get a specific alert by name.
    pub fn get(name: &str) -> Option<Value> {
        Self::load_all().remove(name)
    }

    /// Get the phishing typosquat alert.
    pub fn phishing_typosquat() -> Value {
        Self::get("phishing_typosquat").expect("phishing_typosquat not found")
    }

    /// Get the legitimate email alert.
    pub fn phishing_legitimate() -> Value {
        Self::get("phishing_legitimate").expect("phishing_legitimate not found")
    }

    /// Get the EICAR malware alert.
    pub fn malware_eicar() -> Value {
        Self::get("malware_eicar").expect("malware_eicar not found")
    }

    /// Get the LSASS access alert.
    pub fn malware_lsass_access() -> Value {
        Self::get("malware_lsass_access").expect("malware_lsass_access not found")
    }

    /// Get the impossible travel auth alert.
    pub fn auth_impossible_travel() -> Value {
        Self::get("auth_impossible_travel").expect("auth_impossible_travel not found")
    }

    /// Get the brute force auth alert.
    pub fn auth_brute_force() -> Value {
        Self::get("auth_brute_force").expect("auth_brute_force not found")
    }

    /// Get the normal login auth alert.
    pub fn auth_normal_login() -> Value {
        Self::get("auth_normal_login").expect("auth_normal_login not found")
    }
}

/// Expected verdicts for sample alerts.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExpectedVerdict {
    pub expected_verdict: String,
    pub expected_severity: String,
    pub min_confidence: i32,
    pub expected_mitre_techniques: Vec<String>,
    pub expected_indicators: HashMap<String, Value>,
    pub expected_actions: Vec<String>,
}

/// Expected verdicts loaded from the shared fixtures.
pub struct ExpectedVerdicts;

impl ExpectedVerdicts {
    /// Loads all expected verdicts from the JSON file.
    pub fn load_all() -> HashMap<String, ExpectedVerdict> {
        let json_str = include_str!("../../../../tests/fixtures/expected_verdicts.json");
        let mut map: HashMap<String, Value> =
            serde_json::from_str(json_str).expect("Failed to parse expected_verdicts.json");

        // Remove the description field
        map.remove("_description");

        // Convert to ExpectedVerdict structs
        map.into_iter()
            .filter_map(|(k, v)| {
                serde_json::from_value::<ExpectedVerdict>(v)
                    .ok()
                    .map(|ev| (k, ev))
            })
            .collect()
    }

    /// Get expected verdict for a specific alert.
    pub fn get(name: &str) -> Option<ExpectedVerdict> {
        Self::load_all().remove(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_sample_alerts() {
        let alerts = SampleAlerts::load_all();
        assert!(alerts.contains_key("phishing_typosquat"));
        assert!(alerts.contains_key("malware_eicar"));
        assert!(alerts.contains_key("auth_impossible_travel"));
    }

    #[test]
    fn test_phishing_alert_structure() {
        let alert = SampleAlerts::phishing_typosquat();
        assert_eq!(alert["type"], "email_security");
        assert_eq!(alert["sender"], "support@paypa1.com");
        assert_eq!(alert["spf_result"], "fail");
    }

    #[test]
    fn test_malware_alert_structure() {
        let alert = SampleAlerts::malware_eicar();
        assert_eq!(alert["type"], "edr_detection");
        assert_eq!(alert["file_hash"], "44d88612fea8a8f36de82e1278abb02f");
    }

    #[test]
    fn test_load_expected_verdicts() {
        let verdicts = ExpectedVerdicts::load_all();
        assert!(verdicts.contains_key("phishing_typosquat"));
        assert!(verdicts.contains_key("malware_eicar"));
    }

    #[test]
    fn test_expected_verdict_structure() {
        let verdict = ExpectedVerdicts::get("phishing_typosquat").unwrap();
        assert_eq!(verdict.expected_verdict, "true_positive");
        assert_eq!(verdict.expected_severity, "high");
        assert!(verdict.min_confidence >= 85);
        assert!(verdict
            .expected_mitre_techniques
            .contains(&"T1566.002".to_string()));
    }

    #[test]
    fn test_all_alerts_have_verdicts() {
        let alerts = SampleAlerts::load_all();
        let verdicts = ExpectedVerdicts::load_all();

        for alert_name in alerts.keys() {
            assert!(
                verdicts.contains_key(alert_name),
                "Missing expected verdict for alert: {}",
                alert_name
            );
        }
    }
}
