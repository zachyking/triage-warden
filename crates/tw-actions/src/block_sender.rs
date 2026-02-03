//! Block sender action.
//!
//! This action adds a sender to the blocklist via the EmailGateway connector.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument};
use tw_connectors::EmailGatewayConnector;
use tw_core::validation::ValidatedEmail;

/// Action to block an email sender.
pub struct BlockSenderAction {
    email_gateway: Arc<dyn EmailGatewayConnector>,
}

impl BlockSenderAction {
    /// Creates a new block sender action.
    pub fn new(email_gateway: Arc<dyn EmailGatewayConnector>) -> Self {
        Self { email_gateway }
    }
}

#[async_trait]
impl Action for BlockSenderAction {
    fn name(&self) -> &str {
        "block_sender"
    }

    fn description(&self) -> &str {
        "Adds a sender to the blocklist via the email gateway"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "sender_address",
                "The sender email address to block",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "reason",
                "Reason for blocking the sender",
                ParameterType::String,
                serde_json::json!("Automated block by Triage Warden"),
            ),
            ParameterDef::optional(
                "duration",
                "Duration of the block in hours (null for permanent)",
                ParameterType::Integer,
                serde_json::json!(null),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let sender_address_raw = context.require_string("sender_address")?;
        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated block by Triage Warden".to_string());
        let duration = context.get_param("duration").and_then(|v| v.as_i64());

        // Validate sender email address using RFC 5321-compliant validation
        let validated_email = ValidatedEmail::new(&sender_address_raw).map_err(|e| {
            ActionError::InvalidParameters(format!(
                "Invalid sender address '{}': {}",
                sender_address_raw, e
            ))
        })?;
        let sender_address = validated_email.as_str().to_string();

        let duration_str = match duration {
            Some(hours) => format!("{} hours", hours),
            None => "permanent".to_string(),
        };

        info!(
            "Blocking sender: {} (reason: {}, duration: {})",
            sender_address, reason, duration_str
        );

        // Execute block
        let gateway_result = self
            .email_gateway
            .block_sender(&sender_address)
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        if !gateway_result.success {
            return Err(ActionError::ExecutionFailed(gateway_result.message));
        }

        let block_entry_id = gateway_result.action_id.clone();

        let mut output = HashMap::new();
        output.insert(
            "sender_address".to_string(),
            serde_json::json!(sender_address),
        );
        output.insert(
            "block_entry_id".to_string(),
            serde_json::json!(block_entry_id),
        );
        output.insert("duration".to_string(), serde_json::json!(duration));
        output.insert("reason".to_string(), serde_json::json!(reason));
        output.insert("success".to_string(), serde_json::json!(true));

        let rollback_data = serde_json::json!({
            "sender_address": sender_address,
            "block_entry_id": block_entry_id,
        });

        info!(
            "Sender {} blocked successfully (entry ID: {})",
            sender_address, block_entry_id
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Sender {} blocked successfully (entry ID: {})",
                sender_address, block_entry_id
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
        let sender_address = rollback_data["sender_address"].as_str().ok_or_else(|| {
            ActionError::InvalidParameters("Missing sender_address in rollback data".to_string())
        })?;

        info!("Rolling back block for sender: {}", sender_address);

        let gateway_result = self
            .email_gateway
            .unblock_sender(sender_address)
            .await
            .map_err(|e| ActionError::RollbackFailed(e.to_string()))?;

        if !gateway_result.success {
            return Err(ActionError::RollbackFailed(gateway_result.message));
        }

        let mut output = HashMap::new();
        output.insert(
            "sender_address".to_string(),
            serde_json::json!(sender_address),
        );
        output.insert(
            "action_id".to_string(),
            serde_json::json!(gateway_result.action_id),
        );

        info!("Block removed for sender: {}", sender_address);

        Ok(ActionResult::success(
            "rollback_block_sender",
            &format!("Sender {} unblocked", sender_address),
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
    async fn test_block_sender() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker@evil.com"))
            .with_param("reason", serde_json::json!("Phishing campaign"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.rollback_available);
        assert!(result.output.contains_key("block_entry_id"));
        assert!(result.output.contains_key("success"));
    }

    #[tokio::test]
    async fn test_block_sender_with_duration() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("spammer@bulk.com"))
            .with_param("reason", serde_json::json!("Spam"))
            .with_param("duration", serde_json::json!(24));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output["duration"], serde_json::json!(24));
    }

    #[tokio::test]
    async fn test_block_already_blocked_sender() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));

        // First block the sender
        email_gateway
            .block_sender("attacker@evil.com")
            .await
            .unwrap();

        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker@evil.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::ExecutionFailed(_))));
    }

    #[tokio::test]
    async fn test_rollback_block() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway.clone());

        // First block
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker@evil.com"));

        let result = action.execute(context).await.unwrap();
        let rollback_data = result.rollback_data.unwrap();

        // Verify sender is blocked
        assert!(email_gateway.is_sender_blocked("attacker@evil.com").await);

        // Then rollback
        let rollback_result = action.rollback(rollback_data).await.unwrap();
        assert!(rollback_result.success);

        // Verify sender is no longer blocked
        assert!(!email_gateway.is_sender_blocked("attacker@evil.com").await);
    }

    #[tokio::test]
    async fn test_missing_sender_address() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    // ==================== Email Validation Tests ====================

    #[tokio::test]
    async fn test_block_sender_invalid_email_no_at() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("invalid-email"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
        if let Err(ActionError::InvalidParameters(msg)) = result {
            assert!(msg.contains("Invalid sender address"));
        }
    }

    #[tokio::test]
    async fn test_block_sender_invalid_email_empty_local() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("@evil.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_block_sender_invalid_email_empty_domain() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker@"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_block_sender_invalid_email_no_tld() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker@localhost"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_block_sender_invalid_email_multiple_at() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("user@domain@evil.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_block_sender_invalid_email_space() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker @evil.com"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_block_sender_valid_email_with_subdomain() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param(
                "sender_address",
                serde_json::json!("attacker@mail.evil.com"),
            )
            .with_param("reason", serde_json::json!("Phishing"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_block_sender_valid_email_with_plus() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("attacker+tag@evil.com"))
            .with_param("reason", serde_json::json!("Phishing"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_block_sender_email_normalized_to_lowercase() {
        let email_gateway = Arc::new(MockEmailGatewayConnector::with_sample_data("test"));
        let action = BlockSenderAction::new(email_gateway);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("sender_address", serde_json::json!("ATTACKER@EVIL.COM"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        // The email should be normalized to lowercase
        assert_eq!(
            result.output["sender_address"].as_str().unwrap(),
            "attacker@evil.com"
        );
    }
}
