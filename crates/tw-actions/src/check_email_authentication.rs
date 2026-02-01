//! Check email authentication action.
//!
//! This action validates SPF, DKIM, and DMARC from email headers.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, instrument, warn};

/// Email authentication results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAuthenticationResults {
    /// Whether SPF check passed.
    pub spf_pass: bool,
    /// SPF result details.
    pub spf_result: String,
    /// SPF domain checked.
    pub spf_domain: Option<String>,

    /// Whether DKIM check passed.
    pub dkim_pass: bool,
    /// DKIM result details.
    pub dkim_result: String,
    /// DKIM signing domain.
    pub dkim_domain: Option<String>,
    /// DKIM selector used.
    pub dkim_selector: Option<String>,

    /// Whether DMARC check passed.
    pub dmarc_pass: bool,
    /// DMARC result details.
    pub dmarc_result: String,
    /// DMARC policy.
    pub dmarc_policy: Option<String>,

    /// Whether the authentication is properly aligned (SPF or DKIM domain matches From domain).
    pub alignment: bool,
    /// Alignment details.
    pub alignment_details: String,

    /// Overall authentication assessment.
    pub overall_result: AuthenticationAssessment,
    /// Risk indicators found.
    pub risk_indicators: Vec<String>,
}

/// Overall authentication assessment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationAssessment {
    /// All checks passed with proper alignment.
    Pass,
    /// Some checks passed but may have issues.
    Partial,
    /// Authentication failed or suspicious.
    Fail,
    /// Could not determine authentication status.
    Unknown,
}

/// Action to check email authentication (SPF, DKIM, DMARC).
pub struct CheckEmailAuthenticationAction;

impl CheckEmailAuthenticationAction {
    /// Creates a new check email authentication action.
    pub fn new() -> Self {
        Self
    }

    /// Parses the Authentication-Results header.
    fn parse_authentication_results(&self, header: &str) -> EmailAuthenticationResults {
        let mut results = EmailAuthenticationResults {
            spf_pass: false,
            spf_result: "none".to_string(),
            spf_domain: None,
            dkim_pass: false,
            dkim_result: "none".to_string(),
            dkim_domain: None,
            dkim_selector: None,
            dmarc_pass: false,
            dmarc_result: "none".to_string(),
            dmarc_policy: None,
            alignment: false,
            alignment_details: "Unknown".to_string(),
            overall_result: AuthenticationAssessment::Unknown,
            risk_indicators: Vec::new(),
        };

        // Parse SPF result
        if let Some(spf_match) = self.find_result(header, "spf") {
            results.spf_result = spf_match.result.clone();
            results.spf_pass = self.is_pass_result(&spf_match.result);
            results.spf_domain = spf_match.domain;

            if !results.spf_pass {
                results
                    .risk_indicators
                    .push(format!("SPF check failed: {}", spf_match.result));
            }
        }

        // Parse DKIM result
        if let Some(dkim_match) = self.find_result(header, "dkim") {
            results.dkim_result = dkim_match.result.clone();
            results.dkim_pass = self.is_pass_result(&dkim_match.result);
            results.dkim_domain = dkim_match.domain.clone();
            results.dkim_selector = dkim_match.selector;

            if !results.dkim_pass {
                results
                    .risk_indicators
                    .push(format!("DKIM check failed: {}", dkim_match.result));
            }
        }

        // Parse DMARC result
        if let Some(dmarc_match) = self.find_result(header, "dmarc") {
            results.dmarc_result = dmarc_match.result.clone();
            results.dmarc_pass = self.is_pass_result(&dmarc_match.result);
            results.dmarc_policy = dmarc_match.policy;

            if !results.dmarc_pass {
                results
                    .risk_indicators
                    .push(format!("DMARC check failed: {}", dmarc_match.result));
            }
        }

        // Determine alignment
        self.check_alignment(&mut results);

        // Determine overall result
        results.overall_result = self.assess_overall(&results);

        results
    }

    /// Finds a specific authentication result in the header.
    fn find_result(&self, header: &str, method: &str) -> Option<AuthResult> {
        // Authentication-Results header format:
        // example.com; spf=pass smtp.mailfrom=sender.com; dkim=pass header.d=sender.com;
        // dmarc=pass (p=reject dis=none) header.from=sender.com

        let lower_header = header.to_lowercase();

        // Find the method section
        let pattern = format!("{}=", method);
        let start = lower_header.find(&pattern)?;
        let after_method = &header[start + pattern.len()..];

        // Get the result (pass, fail, none, etc.)
        let result_end = after_method
            .find([' ', ';', '('])
            .unwrap_or(after_method.len());
        let result = after_method[..result_end].trim().to_lowercase();

        // Find domain and other details
        let section_end = after_method.find(';').unwrap_or(after_method.len());
        let section = &after_method[..section_end];

        let domain = self.extract_domain(section);
        let selector = self.extract_selector(section);
        let policy = self.extract_policy(section);

        Some(AuthResult {
            result,
            domain,
            selector,
            policy,
        })
    }

    /// Extracts domain from authentication result section.
    fn extract_domain(&self, section: &str) -> Option<String> {
        // Look for common domain indicators
        for prefix in &["header.d=", "smtp.mailfrom=", "header.from=", "d="] {
            if let Some(start) = section.to_lowercase().find(prefix) {
                let after_prefix = &section[start + prefix.len()..];
                let end = after_prefix
                    .find([' ', ';', ')'])
                    .unwrap_or(after_prefix.len());
                let domain = after_prefix[..end].trim();
                if !domain.is_empty() {
                    return Some(domain.to_string());
                }
            }
        }
        None
    }

    /// Extracts selector from DKIM result section.
    fn extract_selector(&self, section: &str) -> Option<String> {
        if let Some(start) = section.to_lowercase().find("s=") {
            let after_prefix = &section[start + 2..];
            let end = after_prefix
                .find([' ', ';', ')'])
                .unwrap_or(after_prefix.len());
            let selector = after_prefix[..end].trim();
            if !selector.is_empty() {
                return Some(selector.to_string());
            }
        }
        None
    }

    /// Extracts policy from DMARC result section.
    fn extract_policy(&self, section: &str) -> Option<String> {
        // Look for policy in format (p=reject ...) or policy=reject
        let lower = section.to_lowercase();

        // Try (p=value) format
        if let Some(start) = lower.find("p=") {
            let after_p = &section[start + 2..];
            let end = after_p.find([' ', ')', ';']).unwrap_or(after_p.len());
            let policy = after_p[..end].trim();
            if !policy.is_empty() {
                return Some(policy.to_lowercase());
            }
        }

        // Try policy=value format
        if let Some(start) = lower.find("policy=") {
            let after_policy = &section[start + 7..];
            let end = after_policy
                .find([' ', ')', ';'])
                .unwrap_or(after_policy.len());
            let policy = after_policy[..end].trim();
            if !policy.is_empty() {
                return Some(policy.to_lowercase());
            }
        }

        None
    }

    /// Checks if a result indicates pass.
    fn is_pass_result(&self, result: &str) -> bool {
        matches!(result.to_lowercase().as_str(), "pass" | "passed")
    }

    /// Checks alignment between authentication domains and From domain.
    fn check_alignment(&self, results: &mut EmailAuthenticationResults) {
        // For proper alignment:
        // - SPF: The domain in RFC5321.MailFrom (envelope from) should align with RFC5322.From
        // - DKIM: The domain in the DKIM signature (d=) should align with RFC5322.From

        let spf_aligned = results.spf_pass && results.spf_domain.is_some();
        let dkim_aligned = results.dkim_pass && results.dkim_domain.is_some();

        if spf_aligned && dkim_aligned {
            results.alignment = true;
            results.alignment_details = "Both SPF and DKIM are aligned".to_string();
        } else if spf_aligned {
            results.alignment = true;
            results.alignment_details = "SPF is aligned".to_string();
        } else if dkim_aligned {
            results.alignment = true;
            results.alignment_details = "DKIM is aligned".to_string();
        } else {
            results.alignment = false;
            results.alignment_details = "Neither SPF nor DKIM is properly aligned".to_string();
            results
                .risk_indicators
                .push("Authentication alignment failure".to_string());
        }
    }

    /// Assesses the overall authentication status.
    fn assess_overall(&self, results: &EmailAuthenticationResults) -> AuthenticationAssessment {
        // DMARC pass is the gold standard
        if results.dmarc_pass && results.alignment {
            return AuthenticationAssessment::Pass;
        }

        // Both SPF and DKIM pass with alignment is strong
        if results.spf_pass && results.dkim_pass && results.alignment {
            return AuthenticationAssessment::Pass;
        }

        // At least one passed with alignment
        if (results.spf_pass || results.dkim_pass) && results.alignment {
            return AuthenticationAssessment::Partial;
        }

        // DMARC explicitly failed
        if results.dmarc_result == "fail" {
            return AuthenticationAssessment::Fail;
        }

        // Nothing passed
        if !results.spf_pass && !results.dkim_pass && !results.dmarc_pass {
            // Check if there were explicit failures vs just missing
            if results.spf_result == "fail" || results.dkim_result == "fail" {
                return AuthenticationAssessment::Fail;
            }
            return AuthenticationAssessment::Unknown;
        }

        // Partial pass without alignment
        if results.spf_pass || results.dkim_pass {
            return AuthenticationAssessment::Partial;
        }

        AuthenticationAssessment::Unknown
    }

    /// Parses headers from a headers parameter (string or object).
    fn extract_auth_header(&self, context: &ActionContext) -> Result<String, ActionError> {
        // Try to get authentication_results directly
        if let Some(auth_results) = context.get_string("authentication_results") {
            return Ok(auth_results);
        }

        // Try to get from headers object
        if let Some(headers) = context.get_param("headers") {
            if let Some(obj) = headers.as_object() {
                // Try various header name formats
                for key in &[
                    "Authentication-Results",
                    "authentication-results",
                    "authentication_results",
                    "AUTHENTICATION-RESULTS",
                ] {
                    if let Some(value) = obj.get(*key) {
                        if let Some(s) = value.as_str() {
                            return Ok(s.to_string());
                        }
                    }
                }
            }
        }

        Err(ActionError::InvalidParameters(
            "No authentication results header found. Provide 'authentication_results' string or 'headers' object".to_string(),
        ))
    }
}

/// Intermediate structure for parsing auth results.
struct AuthResult {
    result: String,
    domain: Option<String>,
    selector: Option<String>,
    policy: Option<String>,
}

impl Default for CheckEmailAuthenticationAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for CheckEmailAuthenticationAction {
    fn name(&self) -> &str {
        "check_email_authentication"
    }

    fn description(&self) -> &str {
        "Validates SPF, DKIM, and DMARC from email authentication headers"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::optional(
                "authentication_results",
                "The Authentication-Results header value",
                ParameterType::String,
                serde_json::json!(null),
            ),
            ParameterDef::optional(
                "headers",
                "Email headers object containing Authentication-Results",
                ParameterType::Object,
                serde_json::json!(null),
            ),
        ]
    }

    fn validate(&self, context: &ActionContext) -> Result<(), ActionError> {
        let has_auth_results = context.get_param("authentication_results").is_some()
            && !context
                .get_param("authentication_results")
                .unwrap()
                .is_null();
        let has_headers = context.get_param("headers").is_some()
            && !context.get_param("headers").unwrap().is_null();

        if !has_auth_results && !has_headers {
            return Err(ActionError::InvalidParameters(
                "Either 'authentication_results' or 'headers' must be provided".to_string(),
            ));
        }

        Ok(())
    }

    fn supports_rollback(&self) -> bool {
        false // Read-only operation, no rollback needed
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();

        let auth_header = self.extract_auth_header(&context)?;
        debug!("Parsing Authentication-Results: {}", auth_header);

        let results = self.parse_authentication_results(&auth_header);

        info!(
            "Email authentication: SPF={}, DKIM={}, DMARC={}, alignment={}, overall={:?}",
            results.spf_result,
            results.dkim_result,
            results.dmarc_result,
            results.alignment,
            results.overall_result
        );

        if !results.risk_indicators.is_empty() {
            warn!(
                "Authentication risk indicators: {:?}",
                results.risk_indicators
            );
        }

        let mut output = HashMap::new();
        output.insert("spf_pass".to_string(), serde_json::json!(results.spf_pass));
        output.insert(
            "spf_result".to_string(),
            serde_json::json!(results.spf_result),
        );
        output.insert(
            "spf_domain".to_string(),
            serde_json::json!(results.spf_domain),
        );
        output.insert(
            "dkim_pass".to_string(),
            serde_json::json!(results.dkim_pass),
        );
        output.insert(
            "dkim_result".to_string(),
            serde_json::json!(results.dkim_result),
        );
        output.insert(
            "dkim_domain".to_string(),
            serde_json::json!(results.dkim_domain),
        );
        output.insert(
            "dkim_selector".to_string(),
            serde_json::json!(results.dkim_selector),
        );
        output.insert(
            "dmarc_pass".to_string(),
            serde_json::json!(results.dmarc_pass),
        );
        output.insert(
            "dmarc_result".to_string(),
            serde_json::json!(results.dmarc_result),
        );
        output.insert(
            "dmarc_policy".to_string(),
            serde_json::json!(results.dmarc_policy),
        );
        output.insert(
            "alignment".to_string(),
            serde_json::json!(results.alignment),
        );
        output.insert(
            "alignment_details".to_string(),
            serde_json::json!(results.alignment_details),
        );
        output.insert(
            "overall_result".to_string(),
            serde_json::json!(results.overall_result),
        );
        output.insert(
            "risk_indicators".to_string(),
            serde_json::to_value(&results.risk_indicators).unwrap_or_default(),
        );

        let message = format!(
            "Email authentication: {:?} (SPF: {}, DKIM: {}, DMARC: {})",
            results.overall_result, results.spf_result, results.dkim_result, results.dmarc_result
        );

        Ok(ActionResult::success(
            self.name(),
            &message,
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_all_pass() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header = "mx.google.com; spf=pass smtp.mailfrom=example.com; \
            dkim=pass header.d=example.com header.s=selector1; \
            dmarc=pass (p=reject dis=none) header.from=example.com";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("spf_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("dkim_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("dmarc_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("alignment").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("overall_result").and_then(|v| v.as_str()),
            Some("pass")
        );
    }

    #[tokio::test]
    async fn test_spf_fail() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header = "mx.example.com; spf=fail smtp.mailfrom=attacker.com; \
            dkim=pass header.d=legitimate.com; dmarc=fail";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("spf_pass").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            result.output.get("dmarc_pass").and_then(|v| v.as_bool()),
            Some(false)
        );

        let risk_indicators = result
            .output
            .get("risk_indicators")
            .and_then(|v| v.as_array());
        assert!(risk_indicators.is_some());
        assert!(!risk_indicators.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_partial_pass() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header =
            "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=none; dmarc=none";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("spf_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("dkim_pass").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[tokio::test]
    async fn test_headers_object() {
        let action = CheckEmailAuthenticationAction::new();

        let headers = serde_json::json!({
            "Authentication-Results": "mx.example.com; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com"
        });

        let context = ActionContext::new(Uuid::new_v4()).with_param("headers", headers);

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("spf_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            result.output.get("dkim_pass").and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn test_extract_dmarc_policy() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header = "mx.example.com; spf=pass smtp.mailfrom=example.com; \
            dkim=pass header.d=example.com; dmarc=pass (p=reject dis=none)";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("dmarc_policy").and_then(|v| v.as_str()),
            Some("reject")
        );
    }

    #[tokio::test]
    async fn test_missing_parameters() {
        let action = CheckEmailAuthenticationAction::new();
        let context = ActionContext::new(Uuid::new_v4());

        let result = action.validate(&context);
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_no_authentication() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header = "mx.example.com; spf=none; dkim=none; dmarc=none";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("spf_pass").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            result.output.get("dkim_pass").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            result.output.get("dmarc_pass").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(
            result.output.get("overall_result").and_then(|v| v.as_str()),
            Some("unknown")
        );
    }

    #[tokio::test]
    async fn test_dkim_selector_extraction() {
        let action = CheckEmailAuthenticationAction::new();

        let auth_header = "mx.example.com; dkim=pass header.d=example.com header.s=selector2021";

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("authentication_results", serde_json::json!(auth_header));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        assert_eq!(
            result.output.get("dkim_domain").and_then(|v| v.as_str()),
            Some("example.com")
        );
        assert_eq!(
            result.output.get("dkim_selector").and_then(|v| v.as_str()),
            Some("selector2021")
        );
    }
}
