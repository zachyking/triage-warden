//! Permission evaluation engine.

use crate::rbac::permission::{Action, Permission, Resource};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Authorization request context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub user_id: Uuid,
    pub tenant_id: Uuid,
    pub resource: Resource,
    pub action: Action,
    #[serde(default)]
    pub context: HashMap<String, serde_json::Value>,
}

/// Authorization decision with optional denial reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub reason: Option<String>,
}

impl AuthorizationDecision {
    /// Allowed decision.
    pub fn allow() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    /// Denied decision.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.into()),
        }
    }
}

/// Evaluator for matching request context against permissions.
#[derive(Debug, Clone, Default)]
pub struct PermissionEvaluator;

impl PermissionEvaluator {
    /// Evaluates whether any permission authorizes the request.
    pub fn evaluate(
        &self,
        permissions: &[Permission],
        request: &AuthorizationRequest,
    ) -> AuthorizationDecision {
        for permission in permissions {
            if permission.matches(request.resource, request.action)
                && permission.constraints_match(&request.context)
            {
                return AuthorizationDecision::allow();
            }
        }

        AuthorizationDecision::deny(format!(
            "missing permission {}:{}",
            request.resource.as_str(),
            request.action.as_str()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluator_allows_matching_permission() {
        let evaluator = PermissionEvaluator;
        let request = AuthorizationRequest {
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            resource: Resource::Incident,
            action: Action::Read,
            context: HashMap::new(),
        };
        let permissions = vec![Permission::new(Resource::Incident, Action::Read)];
        let decision = evaluator.evaluate(&permissions, &request);
        assert!(decision.allowed);
    }

    #[test]
    fn test_evaluator_denies_missing_permission() {
        let evaluator = PermissionEvaluator;
        let request = AuthorizationRequest {
            user_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            resource: Resource::Incident,
            action: Action::Delete,
            context: HashMap::new(),
        };
        let permissions = vec![Permission::new(Resource::Incident, Action::Read)];
        let decision = evaluator.evaluate(&permissions, &request);
        assert!(!decision.allowed);
    }
}
