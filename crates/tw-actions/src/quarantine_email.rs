//! Quarantine email action.
//!
//! This action moves an email to quarantine via the EmailGateway connector.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument};
use tw_connectors::EmailGatewayConnector;

/// Action to quarantine an email message.
pub struct QuarantineEmailAction {
    email_gateway: Arc<dyn EmailGatewayConnector>,
}

impl QuarantineEmailAction {
    /// Creates a new quarantine email action.
    pub fn new(email_gateway: Arc<dyn EmailGatewayConnector>) -> Self {
        Self { email_gateway }
    }
}

#[async_trait]
impl Action for QuarantineEmailAction {
    fn name(&self) -> &str {
        "quarantine_email"
    }

    fn description(&self) -> &str {
        "Moves an email to quarantine via the email gateway"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "message_id",
                "The message ID of the email to quarantine",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "reason",
                "Reason for quarantining the email",
                ParameterType::String,
                serde_json::json!("Automated quarantine by Triage Warden"),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let message_id = context.require_string("message_id")?;
        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated quarantine by Triage Warden".to_string());

        info!("Quarantining email: {} (reason: {})", message_id, reason);

        // Verify email exists first
        let email = self
            .email_gateway
            .get_email(&message_id)
            .await
            .map_err(|e| ActionError::ConnectorError(e.to_string()))?;

        // Execute quarantine
        let gateway_result = self
            .email_gateway
            .quarantine_email(&message_id)
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        if !gateway_result.success {
            return Err(ActionError::ExecutionFailed(gateway_result.message));
        }

        let quarantine_location = format!("quarantine/{}", message_id);

        let mut output = HashMap::new();
        output.insert("message_id".to_string(), serde_json::json!(message_id));
        output.insert("sender".to_string(), serde_json::json!(email.sender));
        output.insert("subject".to_string(), serde_json::json!(email.subject));
        output.insert(
            "quarantine_location".to_string(),
            serde_json::json!(quarantine_location),
        );
        output.insert(
            "action_id".to_string(),
            serde_json::json!(gateway_result.action_id),
        );
        output.insert("success".to_string(), serde_json::json!(true));

        let rollback_data = serde_json::json!({
            "message_id": message_id,
            "original_sender": email.sender,
            "original_subject": email.subject,
        });

        info!(
            "Email {} quarantined successfully to {}",
            message_id, quarantine_location
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Email {} quarantined successfully to {}",
                message_id, quarantine_location
            ),
            started_at,
            output,
        )
        .with_rollback(rollback_data))
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(
        &self,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let message_id = rollback_data["message_id"].as_str().ok_or_else(|| {
            ActionError::InvalidParameters("Missing message_id in rollback data".to_string())
        })?;

        info!("Rolling back quarantine for email: {}", message_id);

        let gateway_result = self
            .email_gateway
            .release_email(message_id)
            .await
            .map_err(|e| ActionError::RollbackFailed(e.to_string()))?;

        if !gateway_result.success {
            return Err(ActionError::RollbackFailed(gateway_result.message));
        }

        let mut output = HashMap::new();
        output.insert("message_id".to_string(), serde_json::json!(message_id));
        output.insert(
            "action_id".to_string(),
            serde_json::json!(gateway_result.action_id),
        );

        info!("Quarantine rolled back for email: {}", message_id);

        Ok(ActionResult::success(
            "rollback_quarantine_email",
            &format!("Email {} released from quarantine", message_id),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::email::MockEmailGatewayConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_quarantine_email() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = QuarantineEmailAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("message_id", serde_json::json!("msg-001"))
            .with_param("reason", serde_json::json!("Phishing detected"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.rollback_available);
        assert!(result.output.contains_key("quarantine_location"));
        assert!(result.output.contains_key("success"));
    }

    #[tokio::test]
    async fn test_quarantine_nonexistent_email() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = QuarantineEmailAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("message_id", serde_json::json!("nonexistent"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::ConnectorError(_))));
    }

    #[tokio::test]
    async fn test_quarantine_already_quarantined() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));

        // First quarantine the email
        email_gateway.quarantine_email("msg-001").await.unwrap();

        let action = QuarantineEmailAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("message_id", serde_json::json!("msg-001"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::ExecutionFailed(_))));
    }

    #[tokio::test]
    async fn test_rollback_quarantine() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = QuarantineEmailAction::new(email_gateway.clone());

        // First quarantine
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("message_id", serde_json::json!("msg-001"));

        let result = action.execute(context).await.unwrap();
        let rollback_data = result.rollback_data.unwrap();

        // Verify email is quarantined
        assert!(email_gateway.is_quarantined("msg-001").await);

        // Then rollback
        let rollback_result = action.rollback(rollback_data).await.unwrap();
        assert!(rollback_result.success);

        // Verify email is no longer quarantined
        assert!(!email_gateway.is_quarantined("msg-001").await);
    }

    #[tokio::test]
    async fn test_missing_message_id() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = QuarantineEmailAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }
}
