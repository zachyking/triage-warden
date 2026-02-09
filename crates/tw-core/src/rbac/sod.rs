//! Separation of duties validation for role assignments.

use crate::rbac::permission::Permission;
use serde::{Deserialize, Serialize};

/// How a SoD rule is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SodEnforcement {
    Prevent,
    Warn,
    Audit,
}

/// SoD rule describing conflicting permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeparationOfDutiesRule {
    pub name: String,
    pub conflicting_permissions: Vec<(Permission, Permission)>,
    pub enforcement: SodEnforcement,
}

/// SoD validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SodViolation {
    pub rule_name: String,
    pub enforcement: SodEnforcement,
}

/// SoD validator engine.
#[derive(Debug, Clone)]
pub struct SodValidator {
    rules: Vec<SeparationOfDutiesRule>,
}

impl SodValidator {
    /// Creates a validator from a rule set.
    pub fn new(rules: Vec<SeparationOfDutiesRule>) -> Self {
        Self { rules }
    }

    /// Validates permission grants against SoD rules.
    pub fn validate(&self, permissions: &[Permission]) -> Vec<SodViolation> {
        let mut violations = Vec::new();
        for rule in &self.rules {
            for (a, b) in &rule.conflicting_permissions {
                let has_a = permissions.iter().any(|p| p == a);
                let has_b = permissions.iter().any(|p| p == b);
                if has_a && has_b {
                    violations.push(SodViolation {
                        rule_name: rule.name.clone(),
                        enforcement: rule.enforcement,
                    });
                    break;
                }
            }
        }
        violations
    }
}

/// Default SoD rules.
pub fn default_sod_rules() -> Vec<SeparationOfDutiesRule> {
    use crate::rbac::permission::{Action, Resource};

    vec![
        SeparationOfDutiesRule {
            name: "action_creator_cannot_approve".to_string(),
            conflicting_permissions: vec![(
                Permission::new(Resource::Incident, Action::Create),
                Permission::new(Resource::Incident, Action::Approve),
            )],
            enforcement: SodEnforcement::Prevent,
        },
        SeparationOfDutiesRule {
            name: "user_admin_plus_action_approver".to_string(),
            conflicting_permissions: vec![(
                Permission::new(Resource::User, Action::Manage),
                Permission::new(Resource::Incident, Action::Approve),
            )],
            enforcement: SodEnforcement::Warn,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rbac::permission::{Action, Resource};

    #[test]
    fn test_sod_detects_violation() {
        let validator = SodValidator::new(default_sod_rules());
        let permissions = vec![
            Permission::new(Resource::Incident, Action::Create),
            Permission::new(Resource::Incident, Action::Approve),
        ];

        let violations = validator.validate(&permissions);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].enforcement, SodEnforcement::Prevent);
    }
}
