//! Disable user action.
//!
//! This action disables a user account (placeholder - requires identity provider connector).

use crate::registry::{Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{info, instrument, warn};

/// Action to disable a user account.
pub struct DisableUserAction {
    // In a real implementation, this would hold an identity provider connector
}

impl DisableUserAction {
    /// Creates a new disable user action.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for DisableUserAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for DisableUserAction {
    fn name(&self) -> &str {
        "disable_user"
    }

    fn description(&self) -> &str {
        "Disables a user account in the identity provider"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "username",
                "The username or email of the user to disable",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "reason",
                "Reason for disabling the account",
                ParameterType::String,
                serde_json::json!("Automated disable by Triage Warden"),
            ),
            ParameterDef::optional(
                "revoke_sessions",
                "Whether to revoke active sessions",
                ParameterType::Boolean,
                serde_json::json!(true),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let username = context.require_string("username")?;
        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated disable by Triage Warden".to_string());
        let revoke_sessions = context
            .get_param("revoke_sessions")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        info!(
            "Disabling user: {} (reason: {}, revoke_sessions: {})",
            username, reason, revoke_sessions
        );

        // This is a placeholder implementation
        // In a real implementation, this would:
        // 1. Connect to the identity provider (Okta, Azure AD, etc.)
        // 2. Disable the user account
        // 3. Optionally revoke active sessions
        // 4. Return the result

        warn!("DisableUserAction is a placeholder - no identity provider configured");

        let mut output = HashMap::new();
        output.insert("username".to_string(), serde_json::json!(username));
        output.insert("revoke_sessions".to_string(), serde_json::json!(revoke_sessions));
        output.insert("status".to_string(), serde_json::json!("simulated"));

        let rollback_data = serde_json::json!({
            "username": username,
            "previous_state": "enabled",
        });

        Ok(ActionResult::success(
            self.name(),
            &format!("User {} would be disabled (placeholder)", username),
            started_at,
            output,
        )
        .with_rollback(rollback_data))
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(&self, rollback_data: serde_json::Value) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let username = rollback_data["username"]
            .as_str()
            .ok_or_else(|| ActionError::InvalidParameters("Missing username in rollback data".to_string()))?;

        info!("Rolling back user disable for: {}", username);

        // Placeholder - would re-enable the user
        warn!("DisableUserAction rollback is a placeholder");

        let mut output = HashMap::new();
        output.insert("username".to_string(), serde_json::json!(username));
        output.insert("status".to_string(), serde_json::json!("simulated"));

        Ok(ActionResult::success(
            "rollback_disable_user",
            &format!("User {} would be re-enabled (placeholder)", username),
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
    async fn test_disable_user() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jsmith@company.com"))
            .with_param("reason", serde_json::json!("Compromised credentials"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.rollback_available);
    }

    #[tokio::test]
    async fn test_disable_user_with_session_revoke() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jsmith@company.com"))
            .with_param("revoke_sessions", serde_json::json!(true));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }
}
