//! Permission model for granular authorization.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Resource domain protected by RBAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Incident,
    Playbook,
    Connector,
    User,
    ApiKey,
    Policy,
    AuditLog,
    Hunt,
    KnowledgeBase,
    Settings,
    Compliance,
    Role,
    Privacy,
    Guardrail,
}

impl Resource {
    /// Stable string identifier for persistence and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Resource::Incident => "incident",
            Resource::Playbook => "playbook",
            Resource::Connector => "connector",
            Resource::User => "user",
            Resource::ApiKey => "api_key",
            Resource::Policy => "policy",
            Resource::AuditLog => "audit_log",
            Resource::Hunt => "hunt",
            Resource::KnowledgeBase => "knowledge_base",
            Resource::Settings => "settings",
            Resource::Compliance => "compliance",
            Resource::Role => "role",
            Resource::Privacy => "privacy",
            Resource::Guardrail => "guardrail",
        }
    }
}

/// Action that can be performed on a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Create,
    Read,
    Update,
    Delete,
    Execute,
    Approve,
    Export,
    Manage,
}

impl Action {
    /// Stable string identifier for persistence and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::Update => "update",
            Action::Delete => "delete",
            Action::Execute => "execute",
            Action::Approve => "approve",
            Action::Export => "export",
            Action::Manage => "manage",
        }
    }
}

/// Constraint operator for contextual permission checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConstraintOp {
    Eq,
    NotEq,
    In,
    NotIn,
    Contains,
    Lt,
    Lte,
    Gt,
    Gte,
}

/// Optional constraint to narrow a permission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Constraint {
    pub field: String,
    pub operator: ConstraintOp,
    pub value: serde_json::Value,
}

/// Concrete permission grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Permission {
    pub resource: Resource,
    pub action: Action,
    #[serde(default)]
    pub constraints: Vec<Constraint>,
}

impl Permission {
    /// Creates an unconstrained permission.
    pub fn new(resource: Resource, action: Action) -> Self {
        Self {
            resource,
            action,
            constraints: Vec::new(),
        }
    }

    /// Creates a constrained permission.
    pub fn constrained(resource: Resource, action: Action, constraints: Vec<Constraint>) -> Self {
        Self {
            resource,
            action,
            constraints,
        }
    }

    /// Stable key format used in APIs and logs.
    pub fn key(&self) -> String {
        format!("{}:{}", self.resource.as_str(), self.action.as_str())
    }

    /// Returns true if this permission applies to the given request.
    pub fn matches(&self, resource: Resource, action: Action) -> bool {
        self.resource == resource && (self.action == action || self.action == Action::Manage)
    }

    /// Evaluates contextual constraints for this permission.
    pub fn constraints_match(&self, context: &HashMap<String, serde_json::Value>) -> bool {
        if self.constraints.is_empty() {
            return true;
        }
        self.constraints
            .iter()
            .all(|c| evaluate_constraint(c, context))
    }
}

fn evaluate_constraint(
    constraint: &Constraint,
    context: &HashMap<String, serde_json::Value>,
) -> bool {
    let Some(actual) = context.get(&constraint.field) else {
        return false;
    };
    let expected = &constraint.value;

    match constraint.operator {
        ConstraintOp::Eq => actual == expected,
        ConstraintOp::NotEq => actual != expected,
        ConstraintOp::Contains => value_contains(actual, expected),
        ConstraintOp::In => expected
            .as_array()
            .map(|arr| arr.iter().any(|v| v == actual))
            .unwrap_or(false),
        ConstraintOp::NotIn => expected
            .as_array()
            .map(|arr| arr.iter().all(|v| v != actual))
            .unwrap_or(false),
        ConstraintOp::Lt => compare_numbers(actual, expected, |a, b| a < b),
        ConstraintOp::Lte => compare_numbers(actual, expected, |a, b| a <= b),
        ConstraintOp::Gt => compare_numbers(actual, expected, |a, b| a > b),
        ConstraintOp::Gte => compare_numbers(actual, expected, |a, b| a >= b),
    }
}

fn value_contains(actual: &serde_json::Value, expected: &serde_json::Value) -> bool {
    match actual {
        serde_json::Value::Array(values) => values.iter().any(|v| v == expected),
        serde_json::Value::String(s) => expected
            .as_str()
            .map(|needle| s.contains(needle))
            .unwrap_or(false),
        _ => false,
    }
}

fn compare_numbers<F>(actual: &serde_json::Value, expected: &serde_json::Value, op: F) -> bool
where
    F: Fn(f64, f64) -> bool,
{
    match (actual.as_f64(), expected.as_f64()) {
        (Some(a), Some(b)) => op(a, b),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_permission_key() {
        let p = Permission::new(Resource::Incident, Action::Read);
        assert_eq!(p.key(), "incident:read");
    }

    #[test]
    fn test_permission_matches_manage_action() {
        let p = Permission::new(Resource::Incident, Action::Manage);
        assert!(p.matches(Resource::Incident, Action::Read));
        assert!(p.matches(Resource::Incident, Action::Delete));
    }

    #[test]
    fn test_constraint_evaluation() {
        let p = Permission::constrained(
            Resource::Incident,
            Action::Read,
            vec![Constraint {
                field: "severity".to_string(),
                operator: ConstraintOp::In,
                value: serde_json::json!(["high", "critical"]),
            }],
        );
        let mut ctx = HashMap::new();
        ctx.insert("severity".to_string(), serde_json::json!("high"));
        assert!(p.constraints_match(&ctx));

        ctx.insert("severity".to_string(), serde_json::json!("low"));
        assert!(!p.constraints_match(&ctx));
    }
}
