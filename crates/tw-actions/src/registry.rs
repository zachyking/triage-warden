//! Action registry for Triage Warden.
//!
//! This module provides the action trait definition and registry for
//! managing and executing automated response actions.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, instrument, warn};
use uuid::Uuid;

/// Errors that can occur during action execution.
#[derive(Error, Debug)]
pub enum ActionError {
    #[error("Action not found: {0}")]
    NotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),

    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Connector error: {0}")]
    ConnectorError(String),

    #[error("Timeout: action did not complete within {0} seconds")]
    Timeout(u64),

    #[error("Rollback failed: {0}")]
    RollbackFailed(String),

    #[error("Action not supported: {0}")]
    NotSupported(String),
}

/// Result of an action execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionResult {
    /// Unique execution ID.
    pub execution_id: Uuid,
    /// Action name.
    pub action_name: String,
    /// Whether the action succeeded.
    pub success: bool,
    /// Result message.
    pub message: String,
    /// Execution start time.
    pub started_at: DateTime<Utc>,
    /// Execution end time.
    pub completed_at: DateTime<Utc>,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// Additional output data.
    pub output: HashMap<String, serde_json::Value>,
    /// Whether the action can be rolled back.
    pub rollback_available: bool,
    /// Rollback data (if rollback is available).
    pub rollback_data: Option<serde_json::Value>,
}

impl ActionResult {
    /// Creates a successful result.
    pub fn success(
        action_name: &str,
        message: &str,
        started_at: DateTime<Utc>,
        output: HashMap<String, serde_json::Value>,
    ) -> Self {
        let completed_at = Utc::now();
        Self {
            execution_id: Uuid::new_v4(),
            action_name: action_name.to_string(),
            success: true,
            message: message.to_string(),
            started_at,
            completed_at,
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            output,
            rollback_available: false,
            rollback_data: None,
        }
    }

    /// Creates a failed result.
    pub fn failure(action_name: &str, error: &str, started_at: DateTime<Utc>) -> Self {
        let completed_at = Utc::now();
        Self {
            execution_id: Uuid::new_v4(),
            action_name: action_name.to_string(),
            success: false,
            message: error.to_string(),
            started_at,
            completed_at,
            duration_ms: (completed_at - started_at).num_milliseconds() as u64,
            output: HashMap::new(),
            rollback_available: false,
            rollback_data: None,
        }
    }

    /// Marks the result as having rollback available.
    pub fn with_rollback(mut self, rollback_data: serde_json::Value) -> Self {
        self.rollback_available = true;
        self.rollback_data = Some(rollback_data);
        self
    }
}

/// Context provided to actions during execution.
#[derive(Debug, Clone)]
pub struct ActionContext {
    /// Incident ID this action is for.
    pub incident_id: Uuid,
    /// Action parameters.
    pub parameters: HashMap<String, serde_json::Value>,
    /// Timeout in seconds.
    pub timeout_secs: u64,
    /// Whether this is a dry run.
    pub dry_run: bool,
    /// Additional context data.
    pub metadata: HashMap<String, serde_json::Value>,
}

impl ActionContext {
    /// Creates a new action context.
    pub fn new(incident_id: Uuid) -> Self {
        Self {
            incident_id,
            parameters: HashMap::new(),
            timeout_secs: 60,
            dry_run: false,
            metadata: HashMap::new(),
        }
    }

    /// Sets a parameter.
    pub fn with_param(mut self, key: &str, value: serde_json::Value) -> Self {
        self.parameters.insert(key.to_string(), value);
        self
    }

    /// Sets the timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Sets dry run mode.
    pub fn with_dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    /// Gets a parameter value.
    pub fn get_param(&self, key: &str) -> Option<&serde_json::Value> {
        self.parameters.get(key)
    }

    /// Gets a parameter as a string.
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.parameters
            .get(key)
            .and_then(|v| v.as_str())
            .map(String::from)
    }

    /// Gets a required parameter as a string.
    pub fn require_string(&self, key: &str) -> Result<String, ActionError> {
        self.get_string(key).ok_or_else(|| {
            ActionError::InvalidParameters(format!("Missing required parameter: {}", key))
        })
    }
}

/// Trait for action implementations.
#[async_trait]
pub trait Action: Send + Sync {
    /// Returns the action name.
    fn name(&self) -> &str;

    /// Returns the action description.
    fn description(&self) -> &str;

    /// Returns the required parameters for this action.
    fn required_parameters(&self) -> Vec<ParameterDef>;

    /// Validates the action parameters.
    fn validate(&self, context: &ActionContext) -> Result<(), ActionError> {
        for param in self.required_parameters() {
            if param.required && !context.parameters.contains_key(&param.name) {
                return Err(ActionError::InvalidParameters(format!(
                    "Missing required parameter: {}",
                    param.name
                )));
            }
        }
        Ok(())
    }

    /// Executes the action.
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError>;

    /// Rolls back the action (if supported).
    async fn rollback(
        &self,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        Err(ActionError::NotSupported(format!(
            "Rollback not supported for action: {}",
            self.name()
        )))
    }

    /// Returns whether this action supports rollback.
    fn supports_rollback(&self) -> bool {
        false
    }
}

/// Definition of an action parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParameterDef {
    /// Parameter name.
    pub name: String,
    /// Parameter description.
    pub description: String,
    /// Parameter type.
    pub param_type: ParameterType,
    /// Whether the parameter is required.
    pub required: bool,
    /// Default value (if any).
    pub default: Option<serde_json::Value>,
}

impl ParameterDef {
    /// Creates a new required parameter definition.
    pub fn required(name: &str, description: &str, param_type: ParameterType) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            param_type,
            required: true,
            default: None,
        }
    }

    /// Creates a new optional parameter definition.
    pub fn optional(
        name: &str,
        description: &str,
        param_type: ParameterType,
        default: serde_json::Value,
    ) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            param_type,
            required: false,
            default: Some(default),
        }
    }
}

/// Types of action parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterType {
    String,
    Integer,
    Boolean,
    List,
    Object,
}

/// Registry for managing available actions.
pub struct ActionRegistry {
    actions: HashMap<String, Arc<dyn Action>>,
}

impl ActionRegistry {
    /// Creates a new empty action registry.
    pub fn new() -> Self {
        Self {
            actions: HashMap::new(),
        }
    }

    /// Registers an action.
    pub fn register(&mut self, action: Arc<dyn Action>) {
        let name = action.name().to_string();
        info!("Registering action: {}", name);
        self.actions.insert(name, action);
    }

    /// Gets an action by name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Action>> {
        self.actions.get(name).cloned()
    }

    /// Lists all registered actions.
    pub fn list(&self) -> Vec<&str> {
        self.actions.keys().map(|s| s.as_str()).collect()
    }

    /// Executes an action by name.
    #[instrument(skip(self, context), fields(action = %name))]
    pub async fn execute(
        &self,
        name: &str,
        context: ActionContext,
    ) -> Result<ActionResult, ActionError> {
        let action = self
            .get(name)
            .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

        // Validate parameters
        action.validate(&context)?;

        if context.dry_run {
            debug!("Dry run mode - skipping actual execution");
            return Ok(ActionResult::success(
                name,
                "Dry run - action would be executed",
                Utc::now(),
                HashMap::new(),
            ));
        }

        // Execute with timeout
        let timeout = tokio::time::Duration::from_secs(context.timeout_secs);
        match tokio::time::timeout(timeout, action.execute(context)).await {
            Ok(result) => result,
            Err(_) => Err(ActionError::Timeout(timeout.as_secs())),
        }
    }

    /// Rolls back an action by name.
    #[instrument(skip(self, rollback_data), fields(action = %name))]
    pub async fn rollback(
        &self,
        name: &str,
        rollback_data: serde_json::Value,
    ) -> Result<ActionResult, ActionError> {
        let action = self
            .get(name)
            .ok_or_else(|| ActionError::NotFound(name.to_string()))?;

        if !action.supports_rollback() {
            return Err(ActionError::NotSupported(format!(
                "Rollback not supported for action: {}",
                name
            )));
        }

        action.rollback(rollback_data).await
    }

    /// Gets action metadata.
    pub fn get_action_info(&self, name: &str) -> Option<ActionInfo> {
        self.actions.get(name).map(|a| ActionInfo {
            name: a.name().to_string(),
            description: a.description().to_string(),
            parameters: a.required_parameters(),
            supports_rollback: a.supports_rollback(),
        })
    }

    /// Gets all action metadata.
    pub fn get_all_action_info(&self) -> Vec<ActionInfo> {
        self.actions
            .values()
            .map(|a| ActionInfo {
                name: a.name().to_string(),
                description: a.description().to_string(),
                parameters: a.required_parameters(),
                supports_rollback: a.supports_rollback(),
            })
            .collect()
    }
}

impl Default for ActionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a registered action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionInfo {
    pub name: String,
    pub description: String,
    pub parameters: Vec<ParameterDef>,
    pub supports_rollback: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestAction;

    #[async_trait]
    impl Action for TestAction {
        fn name(&self) -> &str {
            "test_action"
        }

        fn description(&self) -> &str {
            "A test action"
        }

        fn required_parameters(&self) -> Vec<ParameterDef> {
            vec![ParameterDef::required(
                "target",
                "The target",
                ParameterType::String,
            )]
        }

        async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
            let target = context.require_string("target")?;
            Ok(ActionResult::success(
                self.name(),
                &format!("Executed on {}", target),
                Utc::now(),
                HashMap::new(),
            ))
        }
    }

    #[tokio::test]
    async fn test_registry_execute() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context =
            ActionContext::new(Uuid::new_v4()).with_param("target", serde_json::json!("test-host"));

        let result = registry.execute("test_action", context).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_missing_parameter() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4());

        let result = registry.execute("test_action", context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_dry_run() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-host"))
            .with_dry_run(true);

        let result = registry.execute("test_action", context).await.unwrap();
        assert!(result.success);
        assert!(result.message.contains("Dry run"));
    }

    #[test]
    fn test_action_info() {
        let mut registry = ActionRegistry::new();
        registry.register(Arc::new(TestAction));

        let info = registry.get_action_info("test_action").unwrap();
        assert_eq!(info.name, "test_action");
        assert_eq!(info.parameters.len(), 1);
    }
}
