//! Lookup sender reputation action.
//!
//! This action queries sender domain/IP reputation via the ThreatIntel connector.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, instrument};
use tw_connectors::ThreatIntelConnector;

/// Action to look up sender reputation from threat intelligence.
pub struct LookupSenderReputationAction {
    threat_intel: Arc<dyn ThreatIntelConnector>,
}

impl LookupSenderReputationAction {
    /// Creates a new lookup sender reputation action.
    pub fn new(threat_intel: Arc<dyn ThreatIntelConnector>) -> Self {
        Self { threat_intel }
    }

    /// Extracts the domain from an email address.
    fn extract_domain(email_or_domain: &str) -> String {
        if let Some(at_pos) = email_or_domain.find('@') {
            email_or_domain[at_pos + 1..].to_string()
        } else {
            email_or_domain.to_string()
        }
    }

    /// Checks if a string is an IP address.
    fn parse_ip(value: &str) -> Option<IpAddr> {
        value.parse().ok()
    }
}

#[async_trait]
impl Action for LookupSenderReputationAction {
    fn name(&self) -> &str {
        "lookup_sender_reputation"
    }

    fn description(&self) -> &str {
        "Queries sender domain/IP reputation via threat intelligence"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "sender",
                "The sender email address, domain, or IP address to look up",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "include_historical",
                "Whether to include historical data in the response",
                ParameterType::Boolean,
                serde_json::json!(true),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        false // Lookup actions are read-only
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let sender = context.require_string("sender")?;
        let include_historical = context
            .get_param("include_historical")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        info!(
            "Looking up sender reputation: {} (include_historical: {})",
            sender, include_historical
        );

        let mut output = HashMap::new();
        output.insert("sender".to_string(), serde_json::json!(sender));

        // Determine if this is an IP address or domain/email
        if let Some(ip) = Self::parse_ip(&sender) {
            // Lookup IP reputation
            let result = self
                .threat_intel
                .lookup_ip(&ip)
                .await
                .map_err(|e| ActionError::ConnectorError(e.to_string()))?;

            output.insert("lookup_type".to_string(), serde_json::json!("ip"));
            output.insert("ip_address".to_string(), serde_json::json!(sender));
            output.insert(
                "verdict".to_string(),
                serde_json::json!(format!("{:?}", result.verdict)),
            );
            output.insert(
                "reputation_score".to_string(),
                serde_json::json!(100 - result.malicious_score as i32),
            );
            output.insert(
                "malicious_score".to_string(),
                serde_json::json!(result.malicious_score),
            );
            output.insert(
                "malicious_count".to_string(),
                serde_json::json!(result.malicious_count),
            );
            output.insert(
                "total_engines".to_string(),
                serde_json::json!(result.total_engines),
            );
            output.insert(
                "categories".to_string(),
                serde_json::json!(result.categories),
            );
            output.insert(
                "malware_families".to_string(),
                serde_json::json!(result.malware_families),
            );
            output.insert("source".to_string(), serde_json::json!(result.source));

            // Add malicious indicators
            let is_malicious = matches!(
                result.verdict,
                tw_connectors::ThreatVerdict::Malicious | tw_connectors::ThreatVerdict::Suspicious
            );
            output.insert("is_malicious".to_string(), serde_json::json!(is_malicious));

            if include_historical {
                if let Some(first_seen) = result.first_seen {
                    output.insert(
                        "first_seen".to_string(),
                        serde_json::json!(first_seen.to_rfc3339()),
                    );
                }
                if let Some(last_seen) = result.last_seen {
                    output.insert(
                        "last_seen".to_string(),
                        serde_json::json!(last_seen.to_rfc3339()),
                    );
                }
                output.insert("details".to_string(), serde_json::json!(result.details));
            }

            let verdict_msg = format!("{:?}", result.verdict).to_lowercase();
            info!(
                "Sender IP {} reputation lookup complete: {}",
                sender, verdict_msg
            );

            Ok(ActionResult::success(
                self.name(),
                &format!(
                    "Sender IP {} reputation: {} (score: {})",
                    sender, verdict_msg, result.malicious_score
                ),
                started_at,
                output,
            ))
        } else {
            // Extract domain and lookup domain reputation
            let domain = Self::extract_domain(&sender);
            output.insert("lookup_type".to_string(), serde_json::json!("domain"));
            output.insert("domain".to_string(), serde_json::json!(&domain));

            if sender.contains('@') {
                output.insert("email".to_string(), serde_json::json!(&sender));
            }

            let result = self
                .threat_intel
                .lookup_domain(&domain)
                .await
                .map_err(|e| ActionError::ConnectorError(e.to_string()))?;

            output.insert(
                "verdict".to_string(),
                serde_json::json!(format!("{:?}", result.verdict)),
            );
            output.insert(
                "reputation_score".to_string(),
                serde_json::json!(100 - result.malicious_score as i32),
            );
            output.insert(
                "malicious_score".to_string(),
                serde_json::json!(result.malicious_score),
            );
            output.insert(
                "malicious_count".to_string(),
                serde_json::json!(result.malicious_count),
            );
            output.insert(
                "total_engines".to_string(),
                serde_json::json!(result.total_engines),
            );
            output.insert(
                "categories".to_string(),
                serde_json::json!(result.categories),
            );
            output.insert(
                "malware_families".to_string(),
                serde_json::json!(result.malware_families),
            );
            output.insert("source".to_string(), serde_json::json!(result.source));

            // Add malicious indicators
            let is_malicious = matches!(
                result.verdict,
                tw_connectors::ThreatVerdict::Malicious | tw_connectors::ThreatVerdict::Suspicious
            );
            output.insert("is_malicious".to_string(), serde_json::json!(is_malicious));

            if include_historical {
                if let Some(first_seen) = result.first_seen {
                    output.insert(
                        "first_seen".to_string(),
                        serde_json::json!(first_seen.to_rfc3339()),
                    );
                }
                if let Some(last_seen) = result.last_seen {
                    output.insert(
                        "last_seen".to_string(),
                        serde_json::json!(last_seen.to_rfc3339()),
                    );
                }
                output.insert("details".to_string(), serde_json::json!(result.details));
            }

            let verdict_msg = format!("{:?}", result.verdict).to_lowercase();
            info!(
                "Sender domain {} reputation lookup complete: {}",
                domain, verdict_msg
            );

            Ok(ActionResult::success(
                self.name(),
                &format!(
                    "Sender domain {} reputation: {} (score: {})",
                    domain, verdict_msg, result.malicious_score
                ),
                started_at,
                output,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::MockThreatIntelConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_lookup_domain_from_email() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender", serde_json::json!("attacker@evil.example.com"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("domain").and_then(|v| v.as_str()),
            Some("evil.example.com")
        );
        assert_eq!(
            result.output.get("verdict").and_then(|v| v.as_str()),
            Some("Malicious")
        );
        assert!(result
            .output
            .get("is_malicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));
    }

    #[tokio::test]
    async fn test_lookup_clean_domain() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender", serde_json::json!("user@google.com"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("verdict").and_then(|v| v.as_str()),
            Some("Clean")
        );
        assert!(!result
            .output
            .get("is_malicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(true));
    }

    #[tokio::test]
    async fn test_lookup_ip_address() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender", serde_json::json!("203.0.113.100"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("lookup_type").and_then(|v| v.as_str()),
            Some("ip")
        );
        assert_eq!(
            result.output.get("verdict").and_then(|v| v.as_str()),
            Some("Malicious")
        );
    }

    #[tokio::test]
    async fn test_lookup_bare_domain() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender", serde_json::json!("phishing-site.example.org"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("lookup_type").and_then(|v| v.as_str()),
            Some("domain")
        );
        assert!(result
            .output
            .get("is_malicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));
    }

    #[tokio::test]
    async fn test_extract_domain() {
        assert_eq!(
            LookupSenderReputationAction::extract_domain("user@example.com"),
            "example.com"
        );
        assert_eq!(
            LookupSenderReputationAction::extract_domain("example.com"),
            "example.com"
        );
        assert_eq!(
            LookupSenderReputationAction::extract_domain("test@sub.domain.org"),
            "sub.domain.org"
        );
    }

    #[tokio::test]
    async fn test_lookup_without_historical() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender", serde_json::json!("user@google.com"))
            .with_param("include_historical", serde_json::json!(false));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        // Historical data should not be present
        assert!(!result.output.contains_key("details"));
    }

    #[test]
    fn test_action_metadata() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupSenderReputationAction::new(threat_intel);

        assert_eq!(action.name(), "lookup_sender_reputation");
        assert!(!action.supports_rollback());
        assert_eq!(action.required_parameters().len(), 2);
    }
}
