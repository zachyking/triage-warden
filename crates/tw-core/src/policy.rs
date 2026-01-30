//! Policy data models for Triage Warden.
//!
//! This module defines the data structures used for approval policies
//! that determine how incidents and actions are handled.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Action to take when a policy matches.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    /// Automatically approve the action without manual review.
    AutoApprove,
    /// Require manual approval before proceeding.
    RequireApproval,
    /// Deny the action.
    Deny,
}

impl PolicyAction {
    /// Returns the database-compatible string representation.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            PolicyAction::AutoApprove => "auto_approve",
            PolicyAction::RequireApproval => "require_approval",
            PolicyAction::Deny => "deny",
        }
    }

    /// Parses a PolicyAction from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "auto_approve" => Some(PolicyAction::AutoApprove),
            "require_approval" => Some(PolicyAction::RequireApproval),
            "deny" => Some(PolicyAction::Deny),
            _ => None,
        }
    }
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::AutoApprove => write!(f, "Auto Approve"),
            PolicyAction::RequireApproval => write!(f, "Require Approval"),
            PolicyAction::Deny => write!(f, "Deny"),
        }
    }
}

/// Level of approval required for an action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    /// Level 1: Security analyst.
    Analyst,
    /// Level 2: Senior analyst.
    Senior,
    /// Level 3: Security manager.
    Manager,
    /// Level 4: Executive/CISO level.
    Executive,
}

impl ApprovalLevel {
    /// Returns the database-compatible string representation.
    pub fn as_db_str(&self) -> &'static str {
        match self {
            ApprovalLevel::Analyst => "analyst",
            ApprovalLevel::Senior => "senior",
            ApprovalLevel::Manager => "manager",
            ApprovalLevel::Executive => "executive",
        }
    }

    /// Parses an ApprovalLevel from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "analyst" => Some(ApprovalLevel::Analyst),
            "senior" => Some(ApprovalLevel::Senior),
            "manager" => Some(ApprovalLevel::Manager),
            "executive" => Some(ApprovalLevel::Executive),
            _ => None,
        }
    }
}

impl std::fmt::Display for ApprovalLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalLevel::Analyst => write!(f, "Analyst"),
            ApprovalLevel::Senior => write!(f, "Senior"),
            ApprovalLevel::Manager => write!(f, "Manager"),
            ApprovalLevel::Executive => write!(f, "Executive"),
        }
    }
}

/// An approval policy that determines how actions are handled.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Unique identifier for this policy.
    pub id: Uuid,
    /// Human-readable name for the policy.
    pub name: String,
    /// Optional description of what the policy does.
    pub description: Option<String>,
    /// Condition expression (e.g., "severity == 'critical'").
    pub condition: String,
    /// Action to take when the condition matches.
    pub action: PolicyAction,
    /// Required approval level (if action is RequireApproval).
    pub approval_level: Option<ApprovalLevel>,
    /// Priority for policy evaluation (lower = higher priority).
    pub priority: i32,
    /// Whether the policy is currently active.
    pub enabled: bool,
    /// Timestamp when the policy was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update.
    pub updated_at: DateTime<Utc>,
}

impl Policy {
    /// Creates a new policy with default values.
    pub fn new(name: String, condition: String, action: PolicyAction) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            condition,
            action,
            approval_level: None,
            priority: 100,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Sets the description for the policy.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Sets the approval level for the policy.
    pub fn with_approval_level(mut self, level: ApprovalLevel) -> Self {
        self.approval_level = Some(level);
        self
    }

    /// Sets the priority for the policy.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }

    /// Sets whether the policy is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_creation() {
        let policy = Policy::new(
            "Critical Severity Policy".to_string(),
            "severity == 'critical'".to_string(),
            PolicyAction::RequireApproval,
        )
        .with_description("Require approval for critical severity incidents")
        .with_approval_level(ApprovalLevel::Senior)
        .with_priority(10);

        assert_eq!(policy.name, "Critical Severity Policy");
        assert_eq!(policy.condition, "severity == 'critical'");
        assert_eq!(policy.action, PolicyAction::RequireApproval);
        assert_eq!(policy.approval_level, Some(ApprovalLevel::Senior));
        assert_eq!(policy.priority, 10);
        assert!(policy.enabled);
    }

    #[test]
    fn test_policy_action_db_roundtrip() {
        let actions = [
            PolicyAction::AutoApprove,
            PolicyAction::RequireApproval,
            PolicyAction::Deny,
        ];

        for action in &actions {
            let db_str = action.as_db_str();
            let parsed = PolicyAction::from_db_str(db_str).unwrap();
            assert_eq!(&parsed, action);
        }
    }

    #[test]
    fn test_approval_level_ordering() {
        assert!(ApprovalLevel::Executive > ApprovalLevel::Manager);
        assert!(ApprovalLevel::Manager > ApprovalLevel::Senior);
        assert!(ApprovalLevel::Senior > ApprovalLevel::Analyst);
    }

    #[test]
    fn test_approval_level_db_roundtrip() {
        let levels = [
            ApprovalLevel::Analyst,
            ApprovalLevel::Senior,
            ApprovalLevel::Manager,
            ApprovalLevel::Executive,
        ];

        for level in &levels {
            let db_str = level.as_db_str();
            let parsed = ApprovalLevel::from_db_str(db_str).unwrap();
            assert_eq!(&parsed, level);
        }
    }
}
