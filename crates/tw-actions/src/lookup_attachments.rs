//! Lookup attachments action.
//!
//! This action hashes attachments and checks them against threat intelligence.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::{ThreatIntelConnector, ThreatVerdict};

/// Input data for an attachment to check.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentInput {
    /// Filename of the attachment.
    pub filename: String,
    /// Hash of the attachment (MD5, SHA1, or SHA256).
    pub hash: String,
    /// Hash type (md5, sha1, sha256).
    #[serde(default = "default_hash_type")]
    pub hash_type: String,
    /// Size of the attachment in bytes.
    #[serde(default)]
    pub size: Option<u64>,
}

fn default_hash_type() -> String {
    "sha256".to_string()
}

/// Result of a single attachment lookup.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AttachmentLookupResult {
    /// Filename of the attachment.
    pub filename: String,
    /// Hash that was looked up.
    pub hash: String,
    /// Hash type used.
    pub hash_type: String,
    /// Size in bytes.
    pub size: Option<u64>,
    /// The verdict (malicious, suspicious, clean, unknown).
    pub verdict: String,
    /// Whether the attachment is considered malware.
    pub is_malware: bool,
    /// Malicious score (0-100).
    pub malicious_score: u8,
    /// Number of engines flagging as malicious.
    pub malicious_count: u32,
    /// Total engines that analyzed.
    pub total_engines: u32,
    /// Malware families if detected.
    pub malware_families: Vec<String>,
    /// Threat categories.
    pub categories: Vec<String>,
    /// First seen timestamp.
    pub first_seen: Option<String>,
    /// Last seen timestamp.
    pub last_seen: Option<String>,
    /// Additional details.
    pub details: HashMap<String, serde_json::Value>,
}

/// Action to look up attachments against threat intelligence.
pub struct LookupAttachmentsAction {
    threat_intel: Arc<dyn ThreatIntelConnector>,
}

impl LookupAttachmentsAction {
    /// Creates a new lookup attachments action.
    pub fn new(threat_intel: Arc<dyn ThreatIntelConnector>) -> Self {
        Self { threat_intel }
    }

    /// Determines if a verdict indicates malware.
    fn is_malware(verdict: &ThreatVerdict) -> bool {
        matches!(verdict, ThreatVerdict::Malicious)
    }

    /// Determines if a verdict indicates a potential threat (includes suspicious).
    #[allow(dead_code)]
    fn is_threat(verdict: &ThreatVerdict) -> bool {
        matches!(
            verdict,
            ThreatVerdict::Malicious | ThreatVerdict::Suspicious
        )
    }

    /// Parses attachment input from JSON value.
    fn parse_attachment(value: &serde_json::Value) -> Result<AttachmentInput, String> {
        serde_json::from_value(value.clone())
            .map_err(|e| format!("Invalid attachment format: {}", e))
    }
}

#[async_trait]
impl Action for LookupAttachmentsAction {
    fn name(&self) -> &str {
        "lookup_attachments"
    }

    fn description(&self) -> &str {
        "Hashes attachments and checks them against threat intelligence for malware matches"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "attachments",
                "List of attachment objects with filename, hash, hash_type, and optional size",
                ParameterType::List,
            ),
            ParameterDef::optional(
                "fail_on_error",
                "Whether to fail the entire action if any lookup fails",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
            ParameterDef::optional(
                "include_suspicious",
                "Whether to include suspicious (not just malicious) in threat count",
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

        // Get attachments from parameters
        let attachments_raw = context
            .get_param("attachments")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ActionError::InvalidParameters("attachments parameter must be an array".to_string())
            })?;

        if attachments_raw.is_empty() {
            return Err(ActionError::InvalidParameters(
                "attachments array cannot be empty".to_string(),
            ));
        }

        // Parse attachments
        let mut attachments: Vec<AttachmentInput> = Vec::new();
        for (idx, raw) in attachments_raw.iter().enumerate() {
            match Self::parse_attachment(raw) {
                Ok(att) => attachments.push(att),
                Err(e) => {
                    return Err(ActionError::InvalidParameters(format!(
                        "Invalid attachment at index {}: {}",
                        idx, e
                    )));
                }
            }
        }

        let fail_on_error = context
            .get_param("fail_on_error")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let include_suspicious = context
            .get_param("include_suspicious")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        info!(
            "Looking up {} attachments against threat intelligence",
            attachments.len()
        );

        let mut results: Vec<AttachmentLookupResult> = Vec::new();
        let mut errors: Vec<String> = Vec::new();
        let mut malware_count = 0;
        let mut suspicious_count = 0;
        let mut clean_count = 0;
        let mut unknown_count = 0;
        let mut all_malware_families: Vec<String> = Vec::new();

        for attachment in &attachments {
            match self.threat_intel.lookup_hash(&attachment.hash).await {
                Ok(result) => {
                    let is_malware = Self::is_malware(&result.verdict);

                    match result.verdict {
                        ThreatVerdict::Malicious => malware_count += 1,
                        ThreatVerdict::Suspicious => suspicious_count += 1,
                        ThreatVerdict::Clean => clean_count += 1,
                        ThreatVerdict::Unknown => unknown_count += 1,
                    }

                    // Collect malware families
                    for family in &result.malware_families {
                        if !all_malware_families.contains(family) {
                            all_malware_families.push(family.clone());
                        }
                    }

                    results.push(AttachmentLookupResult {
                        filename: attachment.filename.clone(),
                        hash: attachment.hash.clone(),
                        hash_type: attachment.hash_type.clone(),
                        size: attachment.size,
                        verdict: format!("{:?}", result.verdict),
                        is_malware,
                        malicious_score: result.malicious_score,
                        malicious_count: result.malicious_count,
                        total_engines: result.total_engines,
                        malware_families: result.malware_families,
                        categories: result.categories,
                        first_seen: result.first_seen.map(|t| t.to_rfc3339()),
                        last_seen: result.last_seen.map(|t| t.to_rfc3339()),
                        details: result.details,
                    });

                    info!(
                        "Attachment {} ({}) verdict: {:?} (score: {})",
                        attachment.filename,
                        attachment.hash,
                        result.verdict,
                        result.malicious_score
                    );
                }
                Err(e) => {
                    let error_msg = format!(
                        "Failed to lookup attachment {} ({}): {}",
                        attachment.filename, attachment.hash, e
                    );
                    warn!("{}", error_msg);
                    errors.push(error_msg.clone());

                    if fail_on_error {
                        return Err(ActionError::ConnectorError(error_msg));
                    }

                    // Add a failed result entry
                    results.push(AttachmentLookupResult {
                        filename: attachment.filename.clone(),
                        hash: attachment.hash.clone(),
                        hash_type: attachment.hash_type.clone(),
                        size: attachment.size,
                        verdict: "Error".to_string(),
                        is_malware: false,
                        malicious_score: 0,
                        malicious_count: 0,
                        total_engines: 0,
                        malware_families: vec![],
                        categories: vec![],
                        first_seen: None,
                        last_seen: None,
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
        output.insert(
            "total_attachments".to_string(),
            serde_json::json!(attachments.len()),
        );
        output.insert("results".to_string(), serde_json::json!(results));
        output.insert(
            "malware_count".to_string(),
            serde_json::json!(malware_count),
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
        output.insert(
            "malware_families".to_string(),
            serde_json::json!(all_malware_families),
        );

        if !errors.is_empty() {
            output.insert("errors".to_string(), serde_json::json!(errors));
        }

        // Summary of threats
        let threat_count = if include_suspicious {
            malware_count + suspicious_count
        } else {
            malware_count
        };
        output.insert("threat_count".to_string(), serde_json::json!(threat_count));
        output.insert(
            "has_malware".to_string(),
            serde_json::json!(malware_count > 0),
        );
        output.insert(
            "has_threats".to_string(),
            serde_json::json!(threat_count > 0),
        );

        // List of malware files for easy access
        let malware_files: Vec<&str> = results
            .iter()
            .filter(|r| {
                if include_suspicious {
                    r.verdict == "Malicious" || r.verdict == "Suspicious"
                } else {
                    r.verdict == "Malicious"
                }
            })
            .map(|r| r.filename.as_str())
            .collect();
        output.insert("threat_files".to_string(), serde_json::json!(malware_files));

        // Malware hashes for blocking
        let malware_hashes: Vec<&str> = results
            .iter()
            .filter(|r| r.verdict == "Malicious")
            .map(|r| r.hash.as_str())
            .collect();
        output.insert(
            "malware_hashes".to_string(),
            serde_json::json!(malware_hashes),
        );

        let message = format!(
            "Attachment lookup complete: {} total, {} malware, {} suspicious, {} clean, {} unknown",
            attachments.len(),
            malware_count,
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
    async fn test_lookup_single_attachment() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "attachments",
            serde_json::json!([
                {
                    "filename": "document.pdf",
                    "hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                    "hash_type": "sha256",
                    "size": 12345
                }
            ]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result
                .output
                .get("total_attachments")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_lookup_malware_attachment() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        // Use the EICAR test hash which is preconfigured as malicious
        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "attachments",
            serde_json::json!([
                {
                    "filename": "malware.exe",
                    "hash": "44d88612fea8a8f36de82e1278abb02f",
                    "hash_type": "md5",
                    "size": 68
                }
            ]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result.output.get("malware_count").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert!(result
            .output
            .get("has_malware")
            .and_then(|v| v.as_bool())
            .unwrap_or(false));

        // Check malware hashes
        let malware_hashes = result
            .output
            .get("malware_hashes")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(malware_hashes.len(), 1);
        assert_eq!(
            malware_hashes[0].as_str(),
            Some("44d88612fea8a8f36de82e1278abb02f")
        );

        // Check malware families
        let families = result
            .output
            .get("malware_families")
            .and_then(|v| v.as_array())
            .unwrap();
        assert!(families
            .iter()
            .any(|f| f.as_str() == Some("EICAR-Test-File")));
    }

    #[tokio::test]
    async fn test_lookup_multiple_attachments() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));

        // Add a suspicious file
        threat_intel
            .add_result(
                "suspicious123456789012345678901234567890123456789012345678901234",
                ThreatIntelResult {
                    indicator_type: IndicatorType::Sha256,
                    indicator: "suspicious123456789012345678901234567890123456789012345678901234"
                        .to_string(),
                    verdict: ThreatVerdict::Suspicious,
                    malicious_score: 40,
                    malicious_count: 8,
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

        let action = LookupAttachmentsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "attachments",
            serde_json::json!([
                {
                    "filename": "malware.exe",
                    "hash": "44d88612fea8a8f36de82e1278abb02f",
                    "hash_type": "md5"
                },
                {
                    "filename": "suspicious.zip",
                    "hash": "suspicious123456789012345678901234567890123456789012345678901234",
                    "hash_type": "sha256"
                },
                {
                    "filename": "clean.docx",
                    "hash": "clean12345678901234567890123456789012345678901234567890123456",
                    "hash_type": "sha256"
                }
            ]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(
            result
                .output
                .get("total_attachments")
                .and_then(|v| v.as_u64()),
            Some(3)
        );
        assert_eq!(
            result.output.get("malware_count").and_then(|v| v.as_u64()),
            Some(1)
        );
        assert_eq!(
            result
                .output
                .get("suspicious_count")
                .and_then(|v| v.as_u64()),
            Some(1)
        );
        // With include_suspicious=true (default), threat count should be 2
        assert_eq!(
            result.output.get("threat_count").and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    #[tokio::test]
    async fn test_lookup_without_suspicious_in_threats() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));

        // Add a suspicious file
        threat_intel
            .add_result(
                "suspicious123456789012345678901234567890123456789012345678901234",
                ThreatIntelResult {
                    indicator_type: IndicatorType::Sha256,
                    indicator: "suspicious123456789012345678901234567890123456789012345678901234"
                        .to_string(),
                    verdict: ThreatVerdict::Suspicious,
                    malicious_score: 40,
                    malicious_count: 8,
                    total_engines: 50,
                    categories: vec![],
                    malware_families: vec![],
                    first_seen: None,
                    last_seen: None,
                    details: HashMap::new(),
                    source: "Mock".to_string(),
                    cache_ttl: 3600,
                },
            )
            .await;

        let action = LookupAttachmentsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param(
                "attachments",
                serde_json::json!([
                    {
                        "filename": "suspicious.zip",
                        "hash": "suspicious123456789012345678901234567890123456789012345678901234",
                        "hash_type": "sha256"
                    }
                ]),
            )
            .with_param("include_suspicious", serde_json::json!(false));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        // With include_suspicious=false, threat count should be 0
        assert_eq!(
            result.output.get("threat_count").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert!(!result
            .output
            .get("has_threats")
            .and_then(|v| v.as_bool())
            .unwrap_or(true));
    }

    #[tokio::test]
    async fn test_lookup_empty_attachments_fails() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        let context =
            ActionContext::new(Uuid::new_v4()).with_param("attachments", serde_json::json!([]));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_lookup_invalid_attachment_format() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "attachments",
            serde_json::json!([
                {
                    "invalid_field": "missing filename and hash"
                }
            ]),
        );

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_default_hash_type() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        // Attachment without hash_type should default to sha256
        let context = ActionContext::new(Uuid::new_v4()).with_param(
            "attachments",
            serde_json::json!([
                {
                    "filename": "test.pdf",
                    "hash": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                }
            ]),
        );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let results = result
            .output
            .get("results")
            .and_then(|v| v.as_array())
            .unwrap();
        assert_eq!(
            results[0].get("hash_type").and_then(|v| v.as_str()),
            Some("sha256")
        );
    }

    #[test]
    fn test_action_metadata() {
        let threat_intel = Arc::new(MockThreatIntelConnector::new("test"));
        let action = LookupAttachmentsAction::new(threat_intel);

        assert_eq!(action.name(), "lookup_attachments");
        assert!(!action.supports_rollback());
        assert_eq!(action.required_parameters().len(), 3);
    }

    #[test]
    fn test_is_malware() {
        assert!(LookupAttachmentsAction::is_malware(
            &ThreatVerdict::Malicious
        ));
        assert!(!LookupAttachmentsAction::is_malware(
            &ThreatVerdict::Suspicious
        ));
        assert!(!LookupAttachmentsAction::is_malware(&ThreatVerdict::Clean));
        assert!(!LookupAttachmentsAction::is_malware(
            &ThreatVerdict::Unknown
        ));
    }

    #[test]
    fn test_is_threat() {
        assert!(LookupAttachmentsAction::is_threat(
            &ThreatVerdict::Malicious
        ));
        assert!(LookupAttachmentsAction::is_threat(
            &ThreatVerdict::Suspicious
        ));
        assert!(!LookupAttachmentsAction::is_threat(&ThreatVerdict::Clean));
        assert!(!LookupAttachmentsAction::is_threat(&ThreatVerdict::Unknown));
    }
}
