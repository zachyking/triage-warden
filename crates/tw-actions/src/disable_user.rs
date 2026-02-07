//! Disable user action.
//!
//! This action disables a user account in a configured identity provider.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument, warn};
use tw_connectors::IdentityConnector;

/// Action to disable a user account.
pub struct DisableUserAction {
    identity_connector: Option<Arc<dyn IdentityConnector>>,
}

impl DisableUserAction {
    /// Creates a new disable user action without a configured identity connector.
    ///
    /// Use [`Self::with_identity_connector`] for a fully functional action.
    pub fn new() -> Self {
        Self {
            identity_connector: None,
        }
    }

    /// Creates a new disable user action backed by an identity connector.
    pub fn with_identity_connector(identity_connector: Arc<dyn IdentityConnector>) -> Self {
        Self {
            identity_connector: Some(identity_connector),
        }
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
            "Attempting to disable user: {} (reason: {}, revoke_sessions: {})",
            username, reason, revoke_sessions
        );

        if context.dry_run {
            let mut output = HashMap::new();
            output.insert("username".to_string(), serde_json::json!(username));
            output.insert("reason".to_string(), serde_json::json!(reason));
            output.insert(
                "revoke_sessions_requested".to_string(),
                serde_json::json!(revoke_sessions),
            );
            output.insert("dry_run".to_string(), serde_json::json!(true));

            return Ok(ActionResult::success(
                self.name(),
                &format!("Dry run: user '{}' would be disabled", username),
                started_at,
                output,
            ));
        }

        let connector = self.identity_connector.as_ref().ok_or_else(|| {
            ActionError::NotSupported(
                "disable_user requires a configured identity connector".to_string(),
            )
        })?;

        let user = connector.get_user(&username).await.map_err(|e| {
            ActionError::ConnectorError(format!("Failed to resolve user '{}': {}", username, e))
        })?;

        if !user.active {
            let mut output = HashMap::new();
            output.insert("username".to_string(), serde_json::json!(user.username));
            output.insert("user_id".to_string(), serde_json::json!(user.id));
            output.insert("already_disabled".to_string(), serde_json::json!(true));
            output.insert(
                "revoke_sessions_requested".to_string(),
                serde_json::json!(false),
            );

            return Ok(ActionResult::success(
                self.name(),
                &format!("User '{}' is already disabled", user.username),
                started_at,
                output,
            ));
        }

        let suspend_result = connector
            .suspend_user(&user.id)
            .await
            .map_err(|e| ActionError::ConnectorError(format!("Failed to disable user: {}", e)))?;

        if !suspend_result.success {
            return Err(ActionError::ExecutionFailed(suspend_result.message));
        }

        let mut revoke_sessions_success = false;
        let mut message = format!("User '{}' disabled successfully", user.username);
        if revoke_sessions {
            match connector.revoke_sessions(&user.id).await {
                Ok(result) if result.success => {
                    revoke_sessions_success = true;
                    message.push_str(" and active sessions revoked");
                }
                Ok(result) => {
                    warn!(
                        "User '{}' disabled but session revocation reported failure: {}",
                        user.username, result.message
                    );
                    message.push_str(&format!("; session revocation failed: {}", result.message));
                }
                Err(e) => {
                    warn!(
                        "User '{}' disabled but session revocation failed: {}",
                        user.username, e
                    );
                    message.push_str("; session revocation failed");
                }
            }
        }

        let mut output = HashMap::new();
        output.insert("username".to_string(), serde_json::json!(user.username));
        output.insert("user_id".to_string(), serde_json::json!(user.id));
        output.insert(
            "idp_action_id".to_string(),
            serde_json::json!(suspend_result.action_id),
        );
        output.insert("was_active_before".to_string(), serde_json::json!(true));
        output.insert(
            "previous_status".to_string(),
            serde_json::json!(user.status.clone()),
        );
        output.insert("reason".to_string(), serde_json::json!(reason));
        output.insert(
            "revoke_sessions_requested".to_string(),
            serde_json::json!(revoke_sessions),
        );
        output.insert(
            "revoke_sessions_success".to_string(),
            serde_json::json!(revoke_sessions_success),
        );

        let rollback_data = serde_json::json!({
            "username": user.username,
            "user_id": user.id,
            "was_active_before": true,
            "previous_status": user.status,
        });

        Ok(
            ActionResult::success(self.name(), &message, started_at, output)
                .with_rollback(rollback_data),
        )
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(
        &self,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let username = rollback_data["username"].as_str().ok_or_else(|| {
            ActionError::InvalidParameters("Missing username in rollback data".to_string())
        })?;
        let user_id = rollback_data["user_id"].as_str().unwrap_or(username);
        let was_active_before = rollback_data["was_active_before"].as_bool().unwrap_or(true);

        if !was_active_before {
            let mut output = HashMap::new();
            output.insert("username".to_string(), serde_json::json!(username));
            output.insert("user_id".to_string(), serde_json::json!(user_id));
            output.insert("noop".to_string(), serde_json::json!(true));
            output.insert(
                "reason".to_string(),
                serde_json::json!("User was already disabled before execution"),
            );
            return Ok(ActionResult::success(
                "rollback_disable_user",
                &format!(
                    "Rollback skipped for '{}': account was already disabled before action execution",
                    username
                ),
                started_at,
                output,
            ));
        }

        let connector = self.identity_connector.as_ref().ok_or_else(|| {
            ActionError::NotSupported(
                "disable_user rollback requires a configured identity connector".to_string(),
            )
        })?;

        info!(
            "Attempting to rollback disable_user for '{}' (id: {})",
            username, user_id
        );

        let unsuspend_result = connector.unsuspend_user(user_id).await.map_err(|e| {
            ActionError::RollbackFailed(format!("Failed to re-enable user '{}': {}", username, e))
        })?;

        if !unsuspend_result.success {
            return Err(ActionError::RollbackFailed(unsuspend_result.message));
        }

        let mut output = HashMap::new();
        output.insert("username".to_string(), serde_json::json!(username));
        output.insert("user_id".to_string(), serde_json::json!(user_id));
        output.insert(
            "idp_action_id".to_string(),
            serde_json::json!(unsuspend_result.action_id),
        );

        Ok(ActionResult::success(
            "rollback_disable_user",
            &format!("User '{}' re-enabled successfully", username),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tw_connectors::{IdentityConnector, MockIdentityConnector};
    use uuid::Uuid;

    #[tokio::test]
    async fn test_disable_user_returns_not_supported_without_connector() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jsmith@company.com"))
            .with_param("reason", serde_json::json!("Compromised credentials"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::NotSupported(_))));

        if let Err(ActionError::NotSupported(msg)) = result {
            assert!(msg.contains("configured identity connector"));
        }
    }

    #[tokio::test]
    async fn test_disable_user_success_with_identity_connector() {
        let connector: Arc<dyn IdentityConnector> =
            Arc::new(MockIdentityConnector::with_sample_data("mock-idp"));
        let action = DisableUserAction::with_identity_connector(connector.clone());

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jdoe"))
            .with_param("revoke_sessions", serde_json::json!(false));

        let result = action
            .execute(context)
            .await
            .expect("action should succeed");
        assert!(result.success);
        assert!(result.message.contains("disabled successfully"));

        let updated_user = connector
            .get_user("jdoe")
            .await
            .expect("user should still be queryable");
        assert!(!updated_user.active);
        assert_eq!(updated_user.status, "suspended");
    }

    #[tokio::test]
    async fn test_disable_user_missing_username() {
        let action = DisableUserAction::new();

        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_rollback_returns_not_supported_without_connector() {
        let action = DisableUserAction::new();

        let rollback_data = serde_json::json!({
            "username": "jsmith@company.com",
            "user_id": "user-001",
            "previous_state": "enabled",
        });

        let result = action.rollback(rollback_data).await;
        assert!(matches!(result, Err(ActionError::NotSupported(_))));
    }

    #[tokio::test]
    async fn test_disable_user_dry_run() {
        let connector: Arc<dyn IdentityConnector> =
            Arc::new(MockIdentityConnector::with_sample_data("mock-idp"));
        let action = DisableUserAction::with_identity_connector(connector.clone());

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("admin"))
            .with_dry_run(true);

        let result = action
            .execute(context)
            .await
            .expect("dry run should succeed");
        assert!(result.success);
        assert!(result.message.contains("Dry run"));

        let unchanged_user = connector
            .get_user("admin")
            .await
            .expect("user should exist");
        assert!(unchanged_user.active);
    }

    #[tokio::test]
    async fn test_rollback_success_with_identity_connector() {
        let connector: Arc<dyn IdentityConnector> =
            Arc::new(MockIdentityConnector::with_sample_data("mock-idp"));
        let action = DisableUserAction::with_identity_connector(connector.clone());

        // Disable first so rollback has work to do
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("username", serde_json::json!("jdoe"))
            .with_param("revoke_sessions", serde_json::json!(false));
        action.execute(context).await.unwrap();

        let rollback_data = serde_json::json!({
            "username": "jdoe",
            "user_id": "user-001",
            "was_active_before": true,
        });

        let result = action.rollback(rollback_data).await.unwrap();
        assert!(result.success);
        assert!(result.message.contains("re-enabled successfully"));

        let updated_user = connector.get_user("jdoe").await.unwrap();
        assert!(updated_user.active);
        assert_eq!(updated_user.status, "active");
    }

    #[test]
    fn test_supports_rollback_true() {
        let action = DisableUserAction::new();
        assert!(action.supports_rollback());
    }
}
