//! Escalate action.
//!
//! This action routes an incident to the appropriate approval level.

use crate::registry::{
    Action, ActionContext, ActionError, ActionResult, ParameterDef, ParameterType,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{info, instrument};

/// Escalation levels that map to policy engine approval levels.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EscalationLevel {
    /// Route to security analyst.
    Analyst,
    /// Route to senior analyst.
    Senior,
    /// Route to SOC manager.
    Manager,
}

impl std::fmt::Display for EscalationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EscalationLevel::Analyst => write!(f, "Analyst"),
            EscalationLevel::Senior => write!(f, "Senior Analyst"),
            EscalationLevel::Manager => write!(f, "SOC Manager"),
        }
    }
}

impl FromStr for EscalationLevel {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "analyst" => Ok(EscalationLevel::Analyst),
            "senior" | "senior_analyst" => Ok(EscalationLevel::Senior),
            "manager" | "soc_manager" => Ok(EscalationLevel::Manager),
            _ => Err(()),
        }
    }
}

impl EscalationLevel {
    /// Returns the default SLA (time to respond) in hours for this level.
    pub fn default_sla_hours(&self) -> i64 {
        match self {
            EscalationLevel::Analyst => 4,
            EscalationLevel::Senior => 2,
            EscalationLevel::Manager => 1,
        }
    }

    /// Returns mock assignees for testing purposes.
    fn mock_assignees(&self) -> Vec<&'static str> {
        match self {
            EscalationLevel::Analyst => vec!["analyst1@company.com", "analyst2@company.com"],
            EscalationLevel::Senior => vec!["senior.analyst@company.com"],
            EscalationLevel::Manager => vec!["soc.manager@company.com"],
        }
    }
}

/// An escalation record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationRecord {
    /// Unique escalation ID.
    pub escalation_id: String,
    /// The incident being escalated.
    pub incident_id: String,
    /// The escalation level.
    pub level: EscalationLevel,
    /// Reason for escalation.
    pub reason: String,
    /// Who the incident is assigned to.
    pub assigned_to: String,
    /// When the escalation was created.
    pub created_at: chrono::DateTime<Utc>,
    /// Due date based on SLA.
    pub due_date: chrono::DateTime<Utc>,
    /// Priority derived from escalation level.
    pub priority: String,
}

/// Action to escalate an incident to the appropriate approval level.
pub struct EscalateAction;

impl EscalateAction {
    /// Creates a new escalate action.
    pub fn new() -> Self {
        Self
    }

    /// Determines priority based on escalation level.
    fn determine_priority(level: EscalationLevel) -> &'static str {
        match level {
            EscalationLevel::Analyst => "medium",
            EscalationLevel::Senior => "high",
            EscalationLevel::Manager => "critical",
        }
    }

    /// Selects an assignee for the escalation (mock implementation).
    fn select_assignee(level: EscalationLevel) -> String {
        // In a real implementation, this would:
        // 1. Query the on-call schedule
        // 2. Check workload/availability
        // 3. Use round-robin or least-loaded algorithm
        let assignees = level.mock_assignees();
        assignees[0].to_string()
    }
}

impl Default for EscalateAction {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Action for EscalateAction {
    fn name(&self) -> &str {
        "escalate"
    }

    fn description(&self) -> &str {
        "Routes an incident to the appropriate approval level based on escalation policy"
    }

    fn required_parameters(&self) -> Vec<ParameterDef> {
        vec![
            ParameterDef::required(
                "incident_id",
                "The ID of the incident to escalate",
                ParameterType::String,
            ),
            ParameterDef::required(
                "escalation_level",
                "The escalation level (analyst, senior, manager)",
                ParameterType::String,
            ),
            ParameterDef::required("reason", "Reason for the escalation", ParameterType::String),
            ParameterDef::optional(
                "override_assignee",
                "Specific assignee to route to (overrides automatic assignment)",
                ParameterType::String,
                serde_json::json!(null),
            ),
            ParameterDef::optional(
                "custom_sla_hours",
                "Custom SLA in hours (overrides default for level)",
                ParameterType::Integer,
                serde_json::json!(null),
            ),
            ParameterDef::optional(
                "notify_channels",
                "Additional notification channels (e.g., slack, pagerduty)",
                ParameterType::List,
                serde_json::json!([]),
            ),
        ]
    }

    fn supports_rollback(&self) -> bool {
        // Escalations could potentially be rolled back by reassigning,
        // but we keep this simple for now
        false
    }

    #[instrument(skip(self, context))]
    async fn execute(&self, context: ActionContext) -> Result<ActionResult, ActionError> {
        let started_at = Utc::now();
        let incident_id = context.require_string("incident_id")?;
        let escalation_level_str = context.require_string("escalation_level")?;
        let reason = context.require_string("reason")?;
        let override_assignee = context.get_string("override_assignee");
        let custom_sla_hours = context
            .get_param("custom_sla_hours")
            .and_then(|v| v.as_i64());

        // Parse escalation level
        let escalation_level = escalation_level_str
            .parse::<EscalationLevel>()
            .map_err(|_| {
                ActionError::InvalidParameters(format!(
                    "Invalid escalation level: {}. Valid values: analyst, senior, manager",
                    escalation_level_str
                ))
            })?;

        // Determine assignee
        let assigned_to =
            override_assignee.unwrap_or_else(|| Self::select_assignee(escalation_level));

        // Calculate due date based on SLA
        let sla_hours = custom_sla_hours.unwrap_or_else(|| escalation_level.default_sla_hours());
        let due_date = Utc::now() + Duration::hours(sla_hours);

        // Generate escalation ID
        let escalation_id = format!("esc-{}", uuid::Uuid::new_v4());

        // Determine priority
        let priority = Self::determine_priority(escalation_level);

        info!(
            "Escalating incident {} to {} level (assigned to: {}, due: {})",
            incident_id, escalation_level, assigned_to, due_date
        );

        // Create escalation record
        let escalation = EscalationRecord {
            escalation_id: escalation_id.clone(),
            incident_id: incident_id.clone(),
            level: escalation_level,
            reason: reason.clone(),
            assigned_to: assigned_to.clone(),
            created_at: Utc::now(),
            due_date,
            priority: priority.to_string(),
        };

        // In a real implementation, this would:
        // 1. Create an approval request in the policy engine
        // 2. Update incident status and assignment
        // 3. Send notifications to the assignee
        // 4. Trigger any escalation webhooks
        // 5. Update SLA tracking
        // 6. Log the escalation for audit

        // Handle notification channels
        let notify_channels: Vec<String> = context
            .get_param("notify_channels")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        if !notify_channels.is_empty() {
            info!(
                "Triggering notifications for escalation {} on channels: {:?}",
                escalation_id, notify_channels
            );
            // In a real implementation, trigger notifications
        }

        let mut output = HashMap::new();
        output.insert(
            "escalation_id".to_string(),
            serde_json::json!(escalation.escalation_id),
        );
        output.insert(
            "incident_id".to_string(),
            serde_json::json!(escalation.incident_id),
        );
        output.insert(
            "escalation_level".to_string(),
            serde_json::json!(escalation_level_str),
        );
        output.insert(
            "assigned_to".to_string(),
            serde_json::json!(escalation.assigned_to),
        );
        output.insert(
            "due_date".to_string(),
            serde_json::json!(escalation.due_date.to_rfc3339()),
        );
        output.insert(
            "priority".to_string(),
            serde_json::json!(escalation.priority),
        );
        output.insert("reason".to_string(), serde_json::json!(escalation.reason));
        output.insert("sla_hours".to_string(), serde_json::json!(sla_hours));

        if !notify_channels.is_empty() {
            output.insert(
                "notify_channels".to_string(),
                serde_json::json!(notify_channels),
            );
        }

        info!(
            "Escalation {} created successfully for incident {}",
            escalation_id, incident_id
        );

        Ok(ActionResult::success(
            self.name(),
            &format!(
                "Incident {} escalated to {} (assigned to: {}, due: {}, priority: {})",
                incident_id,
                escalation_level,
                assigned_to,
                due_date.format("%Y-%m-%d %H:%M UTC"),
                priority
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
    async fn test_escalate_to_analyst() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-001"))
            .with_param("escalation_level", serde_json::json!("analyst"))
            .with_param("reason", serde_json::json!("Requires human verification"));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);
        assert!(!result.rollback_available);
        assert!(result.output.contains_key("escalation_id"));
        assert!(result.output.contains_key("assigned_to"));
        assert!(result.output.contains_key("due_date"));

        let esc_id = result.output["escalation_id"].as_str().unwrap();
        assert!(esc_id.starts_with("esc-"));

        let priority = result.output["priority"].as_str().unwrap();
        assert_eq!(priority, "medium");
    }

    #[tokio::test]
    async fn test_escalate_to_senior() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-002"))
            .with_param("escalation_level", serde_json::json!("senior"))
            .with_param(
                "reason",
                serde_json::json!("Complex threat requiring senior expertise"),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let priority = result.output["priority"].as_str().unwrap();
        assert_eq!(priority, "high");

        let assigned_to = result.output["assigned_to"].as_str().unwrap();
        assert!(assigned_to.contains("senior"));
    }

    #[tokio::test]
    async fn test_escalate_to_manager() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-003"))
            .with_param("escalation_level", serde_json::json!("manager"))
            .with_param(
                "reason",
                serde_json::json!("Critical incident requiring manager approval"),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let priority = result.output["priority"].as_str().unwrap();
        assert_eq!(priority, "critical");

        let assigned_to = result.output["assigned_to"].as_str().unwrap();
        assert!(assigned_to.contains("manager"));
    }

    #[tokio::test]
    async fn test_escalate_with_override_assignee() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-004"))
            .with_param("escalation_level", serde_json::json!("analyst"))
            .with_param("reason", serde_json::json!("Test escalation"))
            .with_param(
                "override_assignee",
                serde_json::json!("specific.analyst@company.com"),
            );

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let assigned_to = result.output["assigned_to"].as_str().unwrap();
        assert_eq!(assigned_to, "specific.analyst@company.com");
    }

    #[tokio::test]
    async fn test_escalate_with_custom_sla() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-005"))
            .with_param("escalation_level", serde_json::json!("analyst"))
            .with_param("reason", serde_json::json!("Urgent escalation"))
            .with_param("custom_sla_hours", serde_json::json!(1));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let sla_hours = result.output["sla_hours"].as_i64().unwrap();
        assert_eq!(sla_hours, 1);
    }

    #[tokio::test]
    async fn test_escalate_with_notify_channels() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-006"))
            .with_param("escalation_level", serde_json::json!("manager"))
            .with_param("reason", serde_json::json!("Critical escalation"))
            .with_param("notify_channels", serde_json::json!(["slack", "pagerduty"]));

        let result = action.execute(context).await.unwrap();
        assert!(result.success);

        let channels = result.output["notify_channels"].as_array().unwrap();
        assert_eq!(channels.len(), 2);
    }

    #[tokio::test]
    async fn test_escalate_invalid_level() {
        let action = EscalateAction::new();

        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-007"))
            .with_param("escalation_level", serde_json::json!("invalid_level"))
            .with_param("reason", serde_json::json!("Test"));

        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_escalate_missing_required_params() {
        let action = EscalateAction::new();

        // Missing all required params
        let context = ActionContext::new(Uuid::new_v4());
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing escalation_level
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-008"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));

        // Missing reason
        let context = ActionContext::new(Uuid::new_v4())
            .with_param("incident_id", serde_json::json!("INC-2024-008"))
            .with_param("escalation_level", serde_json::json!("analyst"));
        let result = action.execute(context).await;
        assert!(matches!(result, Err(ActionError::InvalidParameters(_))));
    }

    #[tokio::test]
    async fn test_escalate_no_rollback() {
        let action = EscalateAction::new();
        assert!(!action.supports_rollback());
    }

    #[test]
    fn test_escalation_level_display() {
        assert_eq!(format!("{}", EscalationLevel::Analyst), "Analyst");
        assert_eq!(format!("{}", EscalationLevel::Senior), "Senior Analyst");
        assert_eq!(format!("{}", EscalationLevel::Manager), "SOC Manager");
    }

    #[test]
    fn test_escalation_level_from_str() {
        assert_eq!(
            "analyst".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Analyst)
        );
        assert_eq!(
            "ANALYST".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Analyst)
        );
        assert_eq!(
            "senior".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Senior)
        );
        assert_eq!(
            "senior_analyst".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Senior)
        );
        assert_eq!(
            "manager".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Manager)
        );
        assert_eq!(
            "soc_manager".parse::<EscalationLevel>(),
            Ok(EscalationLevel::Manager)
        );
        assert!("invalid".parse::<EscalationLevel>().is_err());
    }

    #[test]
    fn test_escalation_level_default_sla() {
        assert_eq!(EscalationLevel::Analyst.default_sla_hours(), 4);
        assert_eq!(EscalationLevel::Senior.default_sla_hours(), 2);
        assert_eq!(EscalationLevel::Manager.default_sla_hours(), 1);
    }

    #[test]
    fn test_escalation_level_ordering() {
        assert!(EscalationLevel::Manager > EscalationLevel::Senior);
        assert!(EscalationLevel::Senior > EscalationLevel::Analyst);
    }

    #[test]
    fn test_escalation_level_serialization() {
        let level = EscalationLevel::Senior;
        let json = serde_json::to_string(&level).unwrap();
        assert_eq!(json, "\"senior\"");

        let deserialized: EscalationLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, EscalationLevel::Senior);
    }

    #[test]
    fn test_determine_priority() {
        assert_eq!(
            EscalateAction::determine_priority(EscalationLevel::Analyst),
            "medium"
        );
        assert_eq!(
            EscalateAction::determine_priority(EscalationLevel::Senior),
            "high"
        );
        assert_eq!(
            EscalateAction::determine_priority(EscalationLevel::Manager),
            "critical"
        );
    }
}
