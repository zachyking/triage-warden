//! Disable user action.
//!
//! This action disables a user account (placeholder - requires identity provider connector).

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
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
        let username = context.require_string("username")?;
        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated disable by Triage Warden".to_string());
        let revoke_sessions = context
            .get_param("revoke_sessions")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        info!(
            "Attempting to disable user: {} (reason: {}, revoke_sessions: {})",
            username, reason, revoke_sessions
        );

        // Return an error indicating this action is not implemented
        // rather than returning a fake success which could mislead operators
        // into thinking the user was actually disabled.
        warn!(
            "DisableUserAction cannot execute - no identity provider connector configured. \
             User '{}' was NOT disabled.",
            username
        );

        Err(ActionError::NotSupported(
            format!(
                "disable_user action requires an identity provider integration (Okta, Azure AD, Google Workspace, etc.). \
                 No IdP connector is currently configured. User '{}' was NOT disabled. \
                 To enable this action:\n\
                 1. Configure an identity provider connector in the system settings\n\
                 2. Ensure the connector has permissions to manage user accounts\n\
                 3. Restart the service to apply the configuration\n\n\
                 For immediate user disablement, please use your identity provider's admin console directly.",
                username
            )
        ))
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(
        &self,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        let username = rollback_data["username"].as_str().ok_or_else(|| {
            ActionError::InvalidParameters("Missing username in rollback data".to_string())
        })?;

        warn!(
            "DisableUserAction rollback cannot execute - no identity provider connector configured. \
             User '{}' status unchanged.",
            username
        );

        Err(ActionError::NotSupported(
            format!(
                "disable_user rollback requires an identity provider integration. \
                 No IdP connector is currently configured. User '{}' status was NOT changed. \
                 Please use your identity provider's admin console to re-enable the user if needed.",
                username
            )
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_disable_user_returns_not_supported() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jsmith@company.com"))
            .with_param("reason", serde_json::json!("Compromised credentials"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::NotSupported(_))));

        if let Err(ActionError::NotSupported(msg)) = result {
            assert!(msg.contains("identity provider integration"));
            assert!(msg.contains("jsmith@company.com"));
            assert!(msg.contains("NOT disabled"));
        }
    }

    #[tokio::test]
    async fn test_disable_user_error_message_includes_username() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("admin@company.com"))
            .with_param("revoke_sessions", serde_json::json!(true));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::NotSupported(_))));

        if let Err(ActionError::NotSupported(msg)) = result {
            assert!(msg.contains("admin@company.com"));
        }
    }

    #[tokio::test]
    async fn test_disable_user_missing_username() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_rollback_returns_not_supported() {
        let action = DisableUserAction::new();

        let rollback_data = serde_json::json!({
            "username": "jsmith@company.com",
            "previous_state": "enabled",
        });

        let result = action.rollback(rollback_data).await;
        assert!(matches!(result, Err(ActionError::NotSupported(_))));
    }

    #[test]
    fn test_supports_rollback_true() {
        let action = DisableUserAction::new();
        // Even though rollback returns NotSupported, the action claims to support it
        // because if an IdP connector were configured, it would support rollback
        assert!(action.supports_rollback());
    }
}
