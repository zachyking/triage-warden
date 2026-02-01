//! Run triage agent action.
//!
//! This action triggers the AI triage workflow for an incident.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Result of AI triage analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageResult {
    /// The verdict from the AI triage (e.g., "malicious", "benign", "suspicious").
    pub verdict: String,
    /// Confidence level (0.0 - 1.0).
    pub confidence: f64,
    /// Detailed analysis explanation.
    pub analysis: String,
    /// Recommended actions based on the analysis.
    pub recommended_actions: Vec<String>,
    /// Risk score (0-100).
    pub risk_score: u32,
    /// Indicators of compromise found.
    pub iocs: Vec<String>,
    /// MITRE ATT&CK techniques identified.
    pub mitre_techniques: Vec<String>,
}

/// Configuration for the triage agent.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// Model to use for triage (e.g., "gpt-4", "claude-3").
    pub model: Option<String>,
    /// Maximum tokens for response.
    pub max_tokens: Option<u32>,
    /// Temperature for response generation.
    pub temperature: Option<f64>,
    /// Whether to include IOC extraction.
    pub extract_iocs: bool,
    /// Whether to include MITRE ATT&CK mapping.
    pub map_mitre: bool,
}

/// Action to trigger the AI triage workflow for an incident.
pub struct RunTriageAgentAction;

impl RunTriageAgentAction {
    /// Creates a new run triage agent action.
    pub fn new() -> Self {
        Self
    }

    /// Generates mock triage data for testing/placeholder purposes.
    fn generate_mock_triage(incident_id: &str) -> TriageResult {
        TriageResult {
            verdict: "suspicious".to_string(),
            confidence: 0.85,
            analysis: format!(
                "AI triage analysis for incident {}. The incident exhibits characteristics \
                consistent with a potential phishing attempt. Multiple indicators suggest \
                this warrants further investigation by a human analyst.",
                incident_id
            ),
            recommended_actions: vec![
                "quarantine_email".to_string(),
                "notify_user".to_string(),
                "block_sender".to_string(),
            ],
            risk_score: 72,
            iocs: vec![
                "malicious-domain.com".to_string(),
                "192.168.100.50".to_string(),
            ],
            mitre_techniques: vec![
                "T1566.001 - Spearphishing Attachment".to_string(),
                "T1204.002 - Malicious File".to_string(),
            ],
        }
    }
}

impl Default for RunTriageAgentAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for RunTriageAgentAction {
    fn name(&self) -> &str {
        "run_triage_agent"
    }

    fn description(&self) -> &str {
        "Triggers the AI triage workflow for an incident to analyze and classify threats"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "incident_id",
                "The ID of the incident to triage",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "agent_config",
                "Optional configuration for the triage agent (model, max_tokens, temperature, extract_iocs, map_mitre)",
                ParameterType::Object,
                serde_json::json!({}),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        // Triage analysis cannot be rolled back - it's a read operation
        false
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let incident_id = context.require_string("incident_id")?;

        // Parse agent config if provided
        let _agent_config: AgentConfig = context
            .get_param("agent_config")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        info!("Running AI triage agent for incident: {}", incident_id);

        // Generate mock triage result
        // In a real implementation, this would:
        // 1. Fetch incident data from the incident repository
        // 2. Prepare context for the AI model
        // 3. Call the AI service (e.g., OpenAI, Anthropic)
        // 4. Parse and validate the response
        // 5. Store the triage result
        let triage_result = Self::generate_mock_triage(&incident_id);

        let triage_id = format!("triage-{}", uuid::Uuid::new_v4());

        let mut output = HashMap::new();
        output.insert("triage_id".to_string(), serde_json::json!(triage_id));
        output.insert("incident_id".to_string(), serde_json::json!(incident_id));
        output.insert(
            "verdict".to_string(),
            serde_json::json!(triage_result.verdict),
        );
        output.insert(
            "confidence".to_string(),
            serde_json::json!(triage_result.confidence),
        );
        output.insert(
            "analysis".to_string(),
            serde_json::json!(triage_result.analysis),
        );
        output.insert(
            "recommended_actions".to_string(),
            serde_json::json!(triage_result.recommended_actions),
        );
        output.insert(
            "risk_score".to_string(),
            serde_json::json!(triage_result.risk_score),
        );
        output.insert("iocs".to_string(), serde_json::json!(triage_result.iocs));
        output.insert(
            "mitre_techniques".to_string(),
            serde_json::json!(triage_result.mitre_techniques),
        );

        info!(
            "Triage {} completed for incident {} with verdict: {} (confidence: {:.2})",
            triage_id, incident_id, triage_result.verdict, triage_result.confidence
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Triage completed: verdict={}, confidence={:.2}, risk_score={}",
                triage_result.verdict, triage_result.confidence, triage_result.risk_score
            ),
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
    async fn test_run_triage_agent() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-001"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("triage_id"));
        assert!(result.output.contains_key("verdict"));
        assert!(result.output.contains_key("confidence"));
        assert!(result.output.contains_key("analysis"));
        assert!(result.output.contains_key("recommended_actions"));
        assert!(result.output.contains_key("risk_score"));
    }

    #[tokio::test]
    async fn test_run_triage_agent_with_config() {
        let action = RunTriageAgentAction::new();

        let config = serde_json::json!({
            "model": "claude-3",
            "max_tokens": 2000,
            "temperature": 0.7,
            "extract_iocs": true,
            "map_mitre": true
        });

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-002"))
            .with_param("agent_config", config);

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Verify triage result contains expected fields
        let verdict = result.output["verdict"].as_str().unwrap();
        assert_eq!(verdict, "suspicious");

        let confidence = result.output["confidence"].as_f64().unwrap();
        assert!(confidence > 0.0 && confidence <= 1.0);

        let risk_score = result.output["risk_score"].as_u64().unwrap();
        assert!(risk_score <= 100);
    }

    #[tokio::test]
    async fn test_run_triage_agent_no_rollback() {
        let action = RunTriageAgentAction::new();
        assert!(!action.supports_rollback());
    }

    #[tokio::test]
    async fn test_run_triage_agent_missing_incident_id() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_triage_result_contains_iocs() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"));

        let result = action.execute(context).await.unwrap();

        let iocs = result.output["iocs"].as_array().unwrap();
        assert!(!iocs.is_empty());
    }

    #[tokio::test]
    async fn test_triage_result_contains_mitre_techniques() {
        let action = RunTriageAgentAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-004"));

        let result = action.execute(context).await.unwrap();

        let techniques = result.output["mitre_techniques"].as_array().unwrap();
        assert!(!techniques.is_empty());
    }

    #[test]
    fn test_default_agent_config() {
        let config = AgentConfig::default();
        assert!(config.model.is_none());
        assert!(config.max_tokens.is_none());
        assert!(config.temperature.is_none());
        assert!(!config.extract_iocs);
        assert!(!config.map_mitre);
    }
}
