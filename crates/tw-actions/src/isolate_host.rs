//! Host isolation action.
//!
//! This action isolates a host from the network using the configured EDR connector.

use crate::registry::{Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument};
use tw_connectors::EDRConnector;

/// Action to isolate a host from the network.
pub struct IsolateHostAction {
    edr: Arc<dyn EDRConnector>,
}

impl IsolateHostAction {
    /// Creates a new isolate host action.
    pub fn new(edr: Arc<dyn EDRConnector>) -> Self {
        Self { edr }
    }
}

#[async_trait]
impl Action for IsolateHostAction {
    fn name(&self) -> &str {
        "isolate_host"
    }

    fn description(&self) -> &str {
        "Isolates a host from the network using the EDR agent"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required("hostname", "The hostname to isolate", ParameterType::String),
            ParameterDef::optional(
                "reason",
                "Reason for isolation",
                ParameterType::String,
                serde_json::json!("Automated isolation by Triage Warden"),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        true
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let hostname = context.require_string("hostname")?;
        let reason = context
            .get_string("reason")
            .unwrap_or_else(|| "Automated isolation by Triage Warden".to_string());

        info!("Isolating host: {} (reason: {})", hostname, reason);

        // Get current host info to verify it exists and capture state for rollback
        let host_info = self
            .edr
            .get_host_info(&hostname)
            .await
            .map_err(|e| ActionError::ConnectorError(e.to_string()))?;

        if host_info.isolated {
            return Ok(ActionResult::success(
                self.name(),
                &format!("Host {} is already isolated", hostname),
                started_at,
                HashMap::new(),
            ));
        }

        // Execute isolation
        let edr_result = self
            .edr
            .isolate_host(&hostname)
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        if !edr_result.success {
            return Err(ActionError::ExecutionFailed(edr_result.message));
        }

        let mut output = HashMap::new();
        output.insert("hostname".to_string(), serde_json::json!(hostname));
        output.insert("host_id".to_string(), serde_json::json!(host_info.host_id));
        output.insert("action_id".to_string(), serde_json::json!(edr_result.action_id));

        let rollback_data = serde_json::json!({
            "hostname": hostname,
            "host_id": host_info.host_id,
        });

        info!("Host {} isolated successfully", hostname);

        Ok(ActionResult::success(
            self.name(),
            &format!("Host {} isolated successfully", hostname),
            started_at,
            output,
        )
        .with_rollback(rollback_data))
    }

    #[instrument(skip(self, rollback_data))]
    async fn rollback(&self, rollback_data: serde_json::Value) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let hostname = rollback_data["hostname"]
            .as_str()
            .ok_or_else(|| ActionError::InvalidParameters("Missing hostname in rollback data".to_string()))?;

        info!("Rolling back isolation for host: {}", hostname);

        let edr_result = self
            .edr
            .unisolate_host(hostname)
            .await
            .map_err(|e| ActionError::RollbackFailed(e.to_string()))?;

        if !edr_result.success {
            return Err(ActionError::RollbackFailed(edr_result.message));
        }

        let mut output = HashMap::new();
        output.insert("hostname".to_string(), serde_json::json!(hostname));
        output.insert("action_id".to_string(), serde_json::json!(edr_result.action_id));

        info!("Isolation rolled back for host: {}", hostname);

        Ok(ActionResult::success(
            "rollback_isolate_host",
            &format!("Isolation removed from host {}", hostname),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::edr::MockEDRConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_isolate_host() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"))
            .with_param("reason", serde_json::json!("Malware detected"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.rollback_available);
    }

    #[tokio::test]
    async fn test_isolate_already_isolated() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));

        // First isolate
        edr.isolate_host("workstation-001").await.unwrap();

        let action = IsolateHostAction::new(edr);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.message.contains("already isolated"));
    }

    #[tokio::test]
    async fn test_rollback() {
        let edr = Arc::new(MockEDRConnector::with_sample_data("test"));
        let action = IsolateHostAction::new(edr.clone());

        // First isolate
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("hostname", serde_json::json!("workstation-001"));

        let result = action.execute(context).await.unwrap();
        let rollback_data = result.rollback_data.unwrap();

        // Then rollback
        let rollback_result = action.rollback(rollback_data).await.unwrap();
        assert!(rollback_result.success);

        // Verify host is no longer isolated
        let host = edr.get_host_info("workstation-001").await.unwrap();
        assert!(!host.isolated);
    }
}
