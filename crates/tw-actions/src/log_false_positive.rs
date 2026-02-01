//! Log false positive action.
//!
//! This action records a false positive for tuning and learning purposes.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// A false positive record for tracking and tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalsePositiveRecord {
    /// Unique identifier for the FP record.
    pub fp_record_id: String,
    /// The incident ID this FP relates to.
    pub incident_id: String,
    /// Reason for marking as false positive.
    pub reason: String,
    /// The original verdict from the system.
    pub original_verdict: String,
    /// The correct verdict as determined by analyst.
    pub correct_verdict: String,
    /// When the FP was recorded.
    pub timestamp: chrono::DateTime<Utc>,
    /// Who recorded the false positive (if available).
    pub recorded_by: Option<String>,
    /// Additional context or notes.
    pub notes: Option<String>,
}

/// Action to log a false positive for tuning/learning purposes.
pub struct LogFalsePositiveAction;

impl LogFalsePositiveAction {
    /// Creates a new log false positive action.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LogFalsePositiveAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for LogFalsePositiveAction {
    fn name(&self) -> &str {
        "log_false_positive"
    }

    fn description(&self) -> &str {
        "Records a false positive for tuning and machine learning purposes"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "incident_id",
                "The ID of the incident marked as false positive",
                ParameterType::String,
            ),
            ParameterDef::required(
                "reason",
                "Explanation for why this is a false positive",
                ParameterType::String,
            ),
            ParameterDef::required(
                "original_verdict",
                "The original verdict from the system (e.g., malicious, suspicious)",
                ParameterType::String,
            ),
            ParameterDef::required(
                "correct_verdict",
                "The correct verdict as determined by analyst (e.g., benign, legitimate)",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "recorded_by",
                "The analyst who recorded this false positive",
                ParameterType::String,
                serde_json::json!(null),
            ),
            ParameterDef::optional(
                "notes",
                "Additional context or notes about the false positive",
                ParameterType::String,
                serde_json::json!(null),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        // FP records should not be automatically rolled back - they are learning data
        false
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let incident_id = context.require_string("incident_id")?;
        let reason = context.require_string("reason")?;
        let original_verdict = context.require_string("original_verdict")?;
        let correct_verdict = context.require_string("correct_verdict")?;
        let recorded_by = context.get_string("recorded_by");
        let notes = context.get_string("notes");

        // Generate unique FP record ID
        let fp_record_id = format!("fp-{}", uuid::Uuid::new_v4());
        let timestamp = Utc::now();

        info!(
            "Recording false positive {} for incident {}: original={}, correct={}",
            fp_record_id, incident_id, original_verdict, correct_verdict
        );

        // Create the FP record
        let fp_record = FalsePositiveRecord {
            fp_record_id: fp_record_id.clone(),
            incident_id: incident_id.clone(),
            reason: reason.clone(),
            original_verdict: original_verdict.clone(),
            correct_verdict: correct_verdict.clone(),
            timestamp,
            recorded_by: recorded_by.clone(),
            notes: notes.clone(),
        };

        // In a real implementation, this would:
        // 1. Store the FP record in the database
        // 2. Update incident status to "false_positive"
        // 3. Potentially trigger ML model retraining or feedback loop
        // 4. Update detection rule statistics
        // 5. Notify relevant parties

        let mut output = HashMap::new();
        output.insert(
            "fp_record_id".to_string(),
            serde_json::json!(fp_record.fp_record_id),
        );
        output.insert(
            "incident_id".to_string(),
            serde_json::json!(fp_record.incident_id),
        );
        output.insert("reason".to_string(), serde_json::json!(fp_record.reason));
        output.insert(
            "original_verdict".to_string(),
            serde_json::json!(fp_record.original_verdict),
        );
        output.insert(
            "correct_verdict".to_string(),
            serde_json::json!(fp_record.correct_verdict),
        );
        output.insert(
            "timestamp".to_string(),
            serde_json::json!(fp_record.timestamp.to_rfc3339()),
        );

        if let Some(ref analyst) = recorded_by {
            output.insert("recorded_by".to_string(), serde_json::json!(analyst));
        }

        if let Some(ref note) = notes {
            output.insert("notes".to_string(), serde_json::json!(note));
        }

        info!(
            "False positive {} recorded successfully for incident {}",
            fp_record_id, incident_id
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "False positive recorded: {} (incident: {}, original: {}, correct: {})",
                fp_record_id, incident_id, original_verdict, correct_verdict
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
    async fn test_log_false_positive() {
        let action = LogFalsePositiveAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-001"))
            .with_param(
                "reason",
                serde_json::json!("Legitimate internal email miscategorized"),
            )
            .with_param("original_verdict", serde_json::json!("malicious"))
            .with_param("correct_verdict", serde_json::json!("benign"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("fp_record_id"));
        assert!(result.output.contains_key("timestamp"));

        let fp_id = result.output["fp_record_id"].as_str().unwrap();
        assert!(fp_id.starts_with("fp-"));
    }

    #[tokio::test]
    async fn test_log_false_positive_with_optional_fields() {
        let action = LogFalsePositiveAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-002"))
            .with_param(
                "reason",
                serde_json::json!("Known safe sender flagged by overly strict rule"),
            )
            .with_param("original_verdict", serde_json::json!("suspicious"))
            .with_param("correct_verdict", serde_json::json!("legitimate"))
            .with_param("recorded_by", serde_json::json!("analyst@company.com"))
            .with_param(
                "notes",
                serde_json::json!("Sender is on the approved list, rule needs adjustment"),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        // Verify optional fields are present
        assert!(result.output.contains_key("recorded_by"));
        assert!(result.output.contains_key("notes"));

        let recorded_by = result.output["recorded_by"].as_str().unwrap();
        assert_eq!(recorded_by, "analyst@company.com");
    }

    #[tokio::test]
    async fn test_log_false_positive_no_rollback() {
        let action = LogFalsePositiveAction::new();
        assert!(!action.supports_rollback());
    }

    #[tokio::test]
    async fn test_log_false_positive_missing_required_params() {
        let action = LogFalsePositiveAction::new();

        // Missing all required params
        let context = ActionContext::new(Uuid::new_v4());
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing reason
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing original_verdict
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"))
            .with_param("reason", serde_json::json!("Test reason"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing correct_verdict
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"))
            .with_param("reason", serde_json::json!("Test reason"))
            .with_param("original_verdict", serde_json::json!("malicious"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_log_false_positive_output_contains_all_fields() {
        let action = LogFalsePositiveAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-004"))
            .with_param("reason", serde_json::json!("Test FP"))
            .with_param("original_verdict", serde_json::json!("malicious"))
            .with_param("correct_verdict", serde_json::json!("benign"));

        let result = action.execute(context).await.unwrap();

        assert_eq!(
            result.output["incident_id"].as_str().unwrap(),
            "INC-2024-004"
        );
        assert_eq!(result.output["reason"].as_str().unwrap(), "Test FP");
        assert_eq!(
            result.output["original_verdict"].as_str().unwrap(),
            "malicious"
        );
        assert_eq!(result.output["correct_verdict"].as_str().unwrap(), "benign");
    }

    #[tokio::test]
    async fn test_false_positive_record_struct() {
        let record = FalsePositiveRecord {
            fp_record_id: "fp-123".to_string(),
            incident_id: "INC-001".to_string(),
            reason: "Test reason".to_string(),
            original_verdict: "malicious".to_string(),
            correct_verdict: "benign".to_string(),
            timestamp: Utc::now(),
            recorded_by: Some("analyst".to_string()),
            notes: Some("Test notes".to_string()),
        };

        // Test serialization
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("fp-123"));
        assert!(json.contains("INC-001"));

        // Test deserialization
        let deserialized: FalsePositiveRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.fp_record_id, "fp-123");
        assert_eq!(deserialized.incident_id, "INC-001");
    }
}
