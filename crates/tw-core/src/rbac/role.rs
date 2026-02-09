//! Role definitions and assignment models.

use crate::rbac::permission::{Action, Permission, Resource};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Role definition with attached permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacRole {
    pub id: Uuid,
    pub tenant_id: Option<Uuid>,
    pub name: String,
    pub description: String,
    pub permissions: Vec<Permission>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl RbacRole {
    /// Creates a new role.
    pub fn new(
        tenant_id: Option<Uuid>,
        name: impl Into<String>,
        description: impl Into<String>,
        permissions: Vec<Permission>,
        is_system: bool,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            name: name.into(),
            description: description.into(),
            permissions,
            is_system,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Assignment linking a role to a user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub role_id: Uuid,
    pub assigned_by: Option<Uuid>,
    pub assigned_at: DateTime<Utc>,
}

impl RoleAssignment {
    /// Creates a new role assignment.
    pub fn new(tenant_id: Uuid, user_id: Uuid, role_id: Uuid, assigned_by: Option<Uuid>) -> Self {
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            user_id,
            role_id,
            assigned_by,
            assigned_at: Utc::now(),
        }
    }
}

/// Built-in system roles for enterprise deployments.
pub fn builtin_roles(tenant_id: Option<Uuid>) -> Vec<RbacRole> {
    vec![
        RbacRole::new(
            tenant_id,
            "super_admin",
            "Full global administrative access",
            vec![
                Permission::new(Resource::Incident, Action::Manage),
                Permission::new(Resource::Playbook, Action::Manage),
                Permission::new(Resource::Connector, Action::Manage),
                Permission::new(Resource::User, Action::Manage),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Policy, Action::Manage),
                Permission::new(Resource::AuditLog, Action::Manage),
                Permission::new(Resource::Hunt, Action::Manage),
                Permission::new(Resource::KnowledgeBase, Action::Manage),
                Permission::new(Resource::Settings, Action::Manage),
                Permission::new(Resource::Compliance, Action::Manage),
                Permission::new(Resource::Role, Action::Manage),
                Permission::new(Resource::Privacy, Action::Manage),
                Permission::new(Resource::Guardrail, Action::Manage),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "tenant_admin",
            "Full tenant administrative access",
            vec![
                Permission::new(Resource::Incident, Action::Manage),
                Permission::new(Resource::Playbook, Action::Manage),
                Permission::new(Resource::Connector, Action::Manage),
                Permission::new(Resource::User, Action::Manage),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Policy, Action::Manage),
                Permission::new(Resource::AuditLog, Action::Read),
                Permission::new(Resource::AuditLog, Action::Export),
                Permission::new(Resource::Role, Action::Manage),
                Permission::new(Resource::Settings, Action::Manage),
                Permission::new(Resource::Compliance, Action::Manage),
                Permission::new(Resource::Privacy, Action::Manage),
                Permission::new(Resource::Guardrail, Action::Manage),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "soc_manager",
            "Operational manager with approval rights",
            vec![
                Permission::new(Resource::Incident, Action::Read),
                Permission::new(Resource::Incident, Action::Update),
                Permission::new(Resource::Incident, Action::Approve),
                Permission::new(Resource::Incident, Action::Execute),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Playbook, Action::Read),
                Permission::new(Resource::Playbook, Action::Update),
                Permission::new(Resource::Connector, Action::Read),
                Permission::new(Resource::Policy, Action::Read),
                Permission::new(Resource::Hunt, Action::Manage),
                Permission::new(Resource::AuditLog, Action::Read),
                Permission::new(Resource::Compliance, Action::Read),
                Permission::new(Resource::Privacy, Action::Read),
                Permission::new(Resource::Guardrail, Action::Read),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "senior_analyst",
            "Senior analyst with execution and approval rights",
            vec![
                Permission::new(Resource::Incident, Action::Read),
                Permission::new(Resource::Incident, Action::Update),
                Permission::new(Resource::Incident, Action::Approve),
                Permission::new(Resource::Incident, Action::Execute),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Playbook, Action::Read),
                Permission::new(Resource::Connector, Action::Read),
                Permission::new(Resource::Policy, Action::Read),
                Permission::new(Resource::Hunt, Action::Read),
                Permission::new(Resource::KnowledgeBase, Action::Read),
                Permission::new(Resource::AuditLog, Action::Read),
                Permission::new(Resource::Compliance, Action::Read),
                Permission::new(Resource::Privacy, Action::Read),
                Permission::new(Resource::Guardrail, Action::Read),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "analyst",
            "Standard analyst role",
            vec![
                Permission::new(Resource::Incident, Action::Read),
                Permission::new(Resource::Incident, Action::Update),
                Permission::new(Resource::Incident, Action::Execute),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Playbook, Action::Read),
                Permission::new(Resource::Connector, Action::Read),
                Permission::new(Resource::Policy, Action::Read),
                Permission::new(Resource::Hunt, Action::Read),
                Permission::new(Resource::KnowledgeBase, Action::Read),
                Permission::new(Resource::AuditLog, Action::Read),
                Permission::new(Resource::Compliance, Action::Read),
                Permission::new(Resource::Privacy, Action::Read),
                Permission::new(Resource::Guardrail, Action::Read),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "viewer",
            "Read-only analyst visibility",
            vec![
                Permission::new(Resource::Incident, Action::Read),
                Permission::new(Resource::ApiKey, Action::Manage),
                Permission::new(Resource::Playbook, Action::Read),
                Permission::new(Resource::AuditLog, Action::Read),
                Permission::new(Resource::KnowledgeBase, Action::Read),
            ],
            true,
        ),
        RbacRole::new(
            tenant_id,
            "api_only",
            "Programmatic automation access only",
            vec![
                Permission::new(Resource::Incident, Action::Read),
                Permission::new(Resource::Incident, Action::Execute),
                Permission::new(Resource::ApiKey, Action::Manage),
            ],
            true,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builtin_roles_exist() {
        let roles = builtin_roles(None);
        assert!(roles.iter().any(|r| r.name == "super_admin"));
        assert!(roles.iter().any(|r| r.name == "soc_manager"));
        assert!(roles.iter().all(|r| r.is_system));
    }
}
