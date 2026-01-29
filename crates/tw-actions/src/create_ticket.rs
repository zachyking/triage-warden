//! Create ticket action.
//!
//! This action creates a ticket in the configured ticketing system.

use crate::registry::{Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, instrument};
use tw_connectors::{CreateTicketRequest, TicketPriority, TicketingConnector};

/// Action to create a ticket in the ticketing system.
pub struct CreateTicketAction {
    ticketing: Arc<dyn TicketingConnector>,
}

impl CreateTicketAction {
    /// Creates a new create ticket action.
    pub fn new(ticketing: Arc<dyn TicketingConnector>) -> Self {
        Self { ticketing }
    }

    /// Maps string priority to TicketPriority.
    fn map_priority(priority: &str) -> TicketPriority {
        match priority.to_lowercase().as_str() {
            "lowest" => TicketPriority::Lowest,
            "low" => TicketPriority::Low,
            "high" => TicketPriority::High,
            "highest" | "critical" => TicketPriority::Highest,
            _ => TicketPriority::Medium,
        }
    }
}

#[async_trait]
impl Action for CreateTicketAction {
    fn name(&self) -> &str {
        "create_ticket"
    }

    fn description(&self) -> &str {
        "Creates a ticket in the ticketing system for the incident"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required("title", "The ticket title/summary", ParameterType::String),
            ParameterDef::required(
                "description",
                "The ticket description",
                ParameterType::String,
            ),
            ParameterDef::optional(
                "priority",
                "The ticket priority (lowest, low, medium, high, highest)",
                ParameterType::String,
                serde_json::json!("medium"),
            ),
            ParameterDef::optional(
                "ticket_type",
                "The ticket type (e.g., incident, task)",
                ParameterType::String,
                serde_json::json!("incident"),
            ),
            ParameterDef::optional(
                "labels",
                "Labels to apply to the ticket",
                ParameterType::List,
                serde_json::json!(["security", "triage-warden"]),
            ),
            ParameterDef::optional(
                "assignee",
                "The user to assign the ticket to",
                ParameterType::String,
                serde_json::json!(null),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        false // Tickets should not be auto-deleted
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let title = context.require_string("title")?;
        let description = context.require_string("description")?;

        let priority = context
            .get_string("priority")
            .map(|s| Self::map_priority(&s))
            .unwrap_or(TicketPriority::Medium);

        let ticket_type = context
            .get_string("ticket_type")
            .unwrap_or_else(|| "incident".to_string());

        let labels: Vec<String> = context
            .get_param("labels")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_else(|| vec!["security".to_string(), "triage-warden".to_string()]);

        let assignee = context.get_string("assignee");

        info!("Creating ticket: {} (priority: {:?})", title, priority);

        let request = CreateTicketRequest {
            title,
            description,
            ticket_type,
            priority,
            labels,
            assignee,
            custom_fields: {
                let mut fields = HashMap::new();
                fields.insert(
                    "incident_id".to_string(),
                    serde_json::json!(context.incident_id.to_string()),
                );
                fields
            },
        };

        let ticket = self
            .ticketing
            .create_ticket(request)
            .await
            .map_err(|e| ActionError::ExecutionFailed(e.to_string()))?;

        let mut output = HashMap::new();
        output.insert("ticket_id".to_string(), serde_json::json!(ticket.id));
        output.insert("ticket_key".to_string(), serde_json::json!(ticket.key));
        output.insert("ticket_url".to_string(), serde_json::json!(ticket.url));

        info!("Created ticket: {} ({})", ticket.key, ticket.url);

        Ok(ActionResult::success(
            self.name(),
            &format!("Created ticket {} ({})", ticket.key, ticket.url),
            started_at,
            output,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tw_connectors::ticketing::MockTicketingConnector;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_create_ticket() {
        let ticketing = Arc::new(MockTicketingConnector::new("test"));
        let action = CreateTicketAction::new(ticketing);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("title", serde_json::json!("Security Incident - Malware Detected"))
            .with_param(
                "description",
                serde_json::json!("Malware was detected on workstation-001"),
            )
            .with_param("priority", serde_json::json!("high"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(result.output.contains_key("ticket_id"));
        assert!(result.output.contains_key("ticket_key"));
    }

    #[tokio::test]
    async fn test_create_ticket_with_labels() {
        let ticketing = Arc::new(MockTicketingConnector::new("test"));
        let action = CreateTicketAction::new(ticketing);

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("title", serde_json::json!("Phishing Alert"))
            .with_param("description", serde_json::json!("User reported phishing email"))
            .with_param(
                "labels",
                serde_json::json!(["phishing", "email", "user-reported"]),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
    }
}
