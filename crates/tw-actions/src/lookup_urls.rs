//! Lookup URLs action.
//!
//! This action checks URLs against threat intelligence for malicious indicators.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::{ThreatIntelConnector, ThreatVerdict};

/// Result of a single URL lookup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UrlLookupResult {
    /// The URL that was looked up.
    pub url: String,
    /// The verdict (malicious, suspicious, clean, unknown).
    pub verdict: String,
    /// Whether the URL is considered a threat.
    pub is_threat: bool,
    /// Malicious score (0-100).
    pub malicious_score: u8,
    /// Number of engines flagging as malicious.
    pub malicious_count: u32,
    /// Total engines that analyzed.
    pub total_engines: u32,
    /// Threat categories.
    pub categories: Vec<String>,
    /// Associated malware families.
    pub malware_families: Vec<String>,
    /// Additional threat details.
    pub details: HashMap<String, serde_json::Value>,
}

/// Action to look up URLs against threat intelligence.
pub struct LookupUrlsAction {
    threat_intel: Arc<dyn ThreatIntelConnector>,
}

impl LookupUrlsAction {
    /// Creates a new lookup URLs action.
    pub fn new(threat_intel: Arc<dyn ThreatIntelConnector>) -> Self {
        Self { threat_intel }
    }

    /// Determines if a verdict indicates a threat.
    fn is_threat(verdict: &ThreatVerdict) -> bool {
        matches!(
            verdict,
            ThreatVerdict::Malicious | ThreatVerdict::Suspicious
        )
    }
}

#[async_trait]
impl Action for LookupUrlsAction {
    fn name(&self) -> &str {
        "lookup_urls"
    }

    fn description(&self) -> &str {
        "Checks URLs against threat intelligence for malicious indicators"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "urls",
                "List of URLs to check against threat intelligence",
                ParameterType::List,
            ),
            ParameterDef::optional(
                "fail_on_error",
                "Whether to fail the entire action if any URL lookup fails",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        false // Lookup actions are read-only
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();

        // Get URLs from parameters
        let urls: Vec<String> = context
            .get_param("urls")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            })
            .ok_or_else(|| {
                ActionError::InvalidParameters(
                    "urls parameter must be an array of strings".to_string(),
                )
            })?;

        if urls.is_empty() {
            return Err(ActionError::InvalidParameters(
                "urls array cannot be empty".to_string(),
            ));
        }

        let fail_on_error = context
            .get_param("fail_on_error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        info!("Looking up {} URLs against threat intelligence", urls.len());

        let mut results: Vec<UrlLookupResult> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut malicious_count = 0;
        let mut suspicious_count = 0;
        let mut clean_count = 0;
        let mut unknown_count = 0;

        for url in &urls {
            match self.threat_intel.lookup_url(url).await {
                Ok(result) => {
                    let is_threat = Self::is_threat(&result.verdict);

                    match result.verdict {
                        ThreatVerdict::Malicious => malicious_count += 1,
                        ThreatVerdict::Suspicious => suspicious_count += 1,
                        ThreatVerdict::Clean => clean_count += 1,
                        ThreatVerdict::Unknown => unknown_count += 1,
                    }

                    results.push(UrlLookupResult {
                        url: url.clone(),
                        verdict: format!("{:?}", result.verdict),
                        is_threat,
                        malicious_score: result.malicious_score,
                        malicious_count: result.malicious_count,
                        total_engines: result.total_engines,
                        categories: result.categories,
                        malware_families: result.malware_families,
                        details: result.details,
                    });

                    info!(
                        "URL {} verdict: {:?} (score: {})",
                        url, result.verdict, result.malicious_score
                    );
                }
                Err(e) => {
                    let error_msg = format!("Failed to lookup URL {}: {}", url, e);
                    warn!("{}", error_msg);
                    errors.push(error_msg.clone());

                    if fail_on_error {
                        return Err(ActionError::ConnectorError(error_msg));
                    }

                    // Add a failed result entry
                    results.push(UrlLookupResult {
                        url: url.clone(),
                        verdict: "Error".to_string(),
                        is_threat: false,
                        malicious_score: 0,
                        malicious_count: 0,
                        total_engines: 0,
                        categories: vec![],
                        malware_families: vec![],
                        details: {
                            let mut d = HashMap::new();
                            d.insert("error".to_string(), serde_json::json!(e.to_string()));
                            d
                        },
                    });
                }
            }
        }

        let mut output = HashMap::new();
        output.insert("total_urls".to_string(), serde_json::json!(urls.len()));
        output.insert("results".to_string(), serde_json::json!(results));
        output.insert(
            "malicious_count".to_string(),
            serde_json::json!(malicious_count),
        );
        output.insert(
            "suspicious_count".to_string(),
            serde_json::json!(suspicious_count),
        );
        output.insert("clean_count".to_string(), serde_json::json!(clean_count));
        output.insert(
            "unknown_count".to_string(),
            serde_json::json!(unknown_count),
        );
        output.insert("error_count".to_string(), serde_json::json!(errors.len()));

        if !errors.is_empty() {
            output.insert("errors".to_string(), serde_json::json!(errors));
        }

        // Summary of threats
        let threat_count = malicious_count + suspicious_count;
        output.insert("threat_count".to_string(), serde_json::json!(threat_count));
        output.insert(
            "has_threats".to_string(),
            serde_json::json!(threat_count > 0),
        );

        // List of malicious URLs for easy access
        let malicious_urls: Vec<&str> = results
            .iter()
            .filter(|r| r.verdict == "Malicious" || r.verdict == "Suspicious")
            .map(|r| r.url.as_str())
            .collect();
        output.insert("threat_urls".to_string(), serde_json::json!(malicious_urls));

        let message = format!(
            "URL lookup complete: {} total, {} threats ({} malicious, {} suspicious), {} clean, {} unknown",
            urls.len(),
            threat_count,
            malicious_count,
            suspicious_count,
            clean_count,
            unknown_count
        );

        info!("{}", message);

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
    use tw_connectors::{IndicatorType, MockThreatIntelConnector, ThreatIntelResult};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_lookup_single_url() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupUrlsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("urls", serde_json::json!(["https://google.com"]));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("total_urls").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_lookup_multiple_urls() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));

        // Add a malicious URL
        threat_intel
            .add_result(
                "https://malware.example.com/payload",
                ThreatIntelResult {
                    indicator_type: IndicatorType::Url,
                    indicator: "https://malware.example.com/payload".to_string(),
                    verdict: ThreatVerdict::Malicious,
                    malicious_score: 95,
                    malicious_count: 60,
                    total_engines: 65,
                    categories: vec!["malware".to_string(), "dropper".to_string()],
                    malware_families: vec!["TrickBot".to_string()],
                    first_seen: Some(Utc::now()),
                    last_seen: Some(Utc::now()),
                    details: HashMap::new(),
                    source: "Mock".to_string(),
                    cache_ttl: 3600,
                },
            )
            .await;

        let action = LookupUrlsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "urls",
            serde_json::json!(["https://google.com", "https://malware.example.com/payload"]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("total_urls").and_then(|v| v.as_u64()),
            Some(2)
        );
        assert_eq!(
            result
                .output
                .get("malicious_count")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        assert!(result
            .output
            .get("has_threats")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));

        // Check threat_urls
        let threat_urls = result
            .output
            .get("threat_urls")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(threat_urls.len(), 1);
        assert_eq!(
            threat_urls[0].as_str(),
            Some("https://malware.example.com/payload")
        );
    }

    #[tokio::test]
    async fn test_lookup_empty_urls_fails() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupUrlsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param("urls", serde_json::json!([]));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_lookup_invalid_param_type() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupUrlsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("urls", serde_json::json!("not-an-array"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_lookup_with_suspicious_url() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));

        // Add a suspicious URL
        threat_intel
            .add_result(
                "https://suspicious.example.com",
                ThreatIntelResult {
                    indicator_type: IndicatorType::Url,
                    indicator: "https://suspicious.example.com".to_string(),
                    verdict: ThreatVerdict::Suspicious,
                    malicious_score: 45,
                    malicious_count: 10,
                    total_engines: 50,
                    categories: vec!["potentially-unwanted".to_string()],
                    malware_families: vec![],
                    first_seen: None,
                    last_seen: Some(Utc::now()),
                    details: HashMap::new(),
                    source: "Mock".to_string(),
                    cache_ttl: 3600,
                },
            )
            .await;

        let action = LookupUrlsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "urls",
            serde_json::json!(["https://suspicious.example.com"]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result
                .output
                .get("suspicious_count")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            result.output.get("threat_count").and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[test]
    fn test_action_metadata() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupUrlsAction::new(threat_intel);

        assert_eq!(action.name(), "lookup_urls");
        assert!(!action.supports_rollback());
        assert_eq!(action.required_parameters().len(), 2);
    }

    #[test]
    fn test_is_threat() {
        assert!(LookupUrlsAction::is_threat(&ThreatVerdict::Malicious));
        assert!(LookupUrlsAction::is_threat(&ThreatVerdict::Suspicious));
        assert!(!LookupUrlsAction::is_threat(&ThreatVerdict::Clean));
        assert!(!LookupUrlsAction::is_threat(&ThreatVerdict::Unknown));
    }
}
