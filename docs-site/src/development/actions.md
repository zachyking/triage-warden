# Adding Actions

Guide to implementing new action handlers.

## Action Architecture

Actions implement the `Action` trait:

```rust
#[async_trait]
pub trait Action: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn required_parameters(&self) -> Vec<ParameterDef>;
    fn supports_rollback(&self) -> bool;

    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError>;

    async fn rollback(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        Err(ActionError::RollbackNotSupported)
    }
}
```

## Implementing an Action

### 1. Create the File

```bash
touch crates/tw-actions/src/my_action.rs
```

### 2. Define the Action

```rust
use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use tracing::{info, instrument};

/// My custom action handler.
pub struct MyAction;

impl MyAction {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MyAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for MyAction {
    fn name(&self) -> &str {
        "my_action"
    }

    fn description(&self) -> &str {
        "Description of what this action does"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "target",
                "The target of the action",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "force",
                "Force the action even if conditions aren't met",
                ParameterType::Boolean,
                serde_json::json!(false),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();

        // Get required parameter
        let target = context.require_string("target")?;

        // Get optional parameter with default
        let force = context
            .get_param("force")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        info!("Executing my_action on target: {}", target);

        // Perform the action
        // ...

        // Build output
        let mut output = HashMap::new();
        output.insert("target".to_string(), serde_json::json!(target));
        output.insert("success".to_string(), serde_json::json!(true));

        Ok(ActionResult::success(
            self.name(),
            &format!("Action completed on {}", target),
            started_at,
            output,
        ))
    }

    async fn rollback(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let target = context.require_string("target")?;

        info!("Rolling back my_action on target: {}", target);

        // Perform rollback
        // ...

        let mut output = HashMap::new();
        output.insert("target".to_string(), serde_json::json!(target));

        Ok(ActionResult::success(
            &format!("{}_rollback", self.name()),
            &format!("Rollback completed on {}", target),
            started_at,
            output,
        ))
    }
}
```

### 3. Add to Module

```rust
// crates/tw-actions/src/lib.rs
mod my_action;
pub use my_action::MyAction;
```

### 4. Register in Registry

```rust
// crates/tw-actions/src/registry.rs
impl ActionRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            actions: HashMap::new(),
        };

        // Register built-in actions
        registry.register(Box::new(QuarantineEmailAction::new()));
        registry.register(Box::new(BlockSenderAction::new()));
        registry.register(Box::new(MyAction::new())); // Add here

        registry
    }
}
```

## Parameter Types

Available parameter types:

```rust
pub enum ParameterType {
    String,
    Integer,
    Float,
    Boolean,
    List,
    Object,
}
```

Define parameters:

```rust
fn required_parameters(&self) -> Vec<ParameterDef> {
    vec![
        ParameterDef::required("name", "Description", ParameterType::String),
        ParameterDef::optional("count", "Description", ParameterType::Integer, json!(10)),
        ParameterDef::optional("tags", "Description", ParameterType::List, json!([])),
    ]
}
```

## Using Connectors

Actions can use connectors via dependency injection:

```rust
pub struct MyAction {
    connector: Arc<dyn MyConnector + Send + Sync>,
}

impl MyAction {
    pub fn new(connector: Arc<dyn MyConnector + Send + Sync>) -> Self {
        Self { connector }
    }
}

#[async_trait]
impl Action for MyAction {
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        // Use connector
        let result = self.connector.do_something().await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        // ...
    }
}
```

## Error Handling

Use appropriate error types:

```rust
pub enum ActionError {
    /// Missing or invalid parameters
    InvalidParameters(String),

    /// Execution failed
    ExecutionFailed(String),

    /// Action timed out
    Timeout,

    /// Rollback not supported
    RollbackNotSupported,

    /// Policy denied the action
    PolicyDenied(String),
}
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_my_action_success() {
        let action = MyAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-target"));

        let result = action.execute(context).await.unwrap();

        assert!(result.success);
        assert_eq!(result.output["target"], "test-target");
    }

    #[tokio::test]
    async fn test_my_action_missing_param() {
        let action = MyAction::new();
        let context = ActionContext::new(Uuid::new_v4());

        let result = action.execute(context).await;

        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_my_action_rollback() {
        let action = MyAction::new();
        assert!(action.supports_rollback());

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("target", serde_json::json!("test-target"));

        let result = action.rollback(context).await.unwrap();
        assert!(result.success);
    }
}
```

## Policy Integration

Actions are automatically evaluated by the policy engine. Configure default approval:

```toml
# Default policy for new action
[[policy.rules]]
name = "my_action_default"
action = "my_action"
approval_level = "analyst"
```

## Documentation

Document your action:

```rust
//! My custom action.
//!
//! This action performs X on target Y.
//!
//! # Parameters
//!
//! - `target` (required): The target to act on
//! - `force` (optional): Force execution (default: false)
//!
//! # Example
//!
//! ```yaml
//! - action: my_action
//!   parameters:
//!     target: "example"
//!     force: true
//! ```
//!
//! # Rollback
//!
//! This action supports rollback via `my_action_rollback`.
```
