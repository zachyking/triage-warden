//! Authorization middleware for fine-grained RBAC enforcement.

use crate::auth::extractors::{scopes, AuthenticatedUser};
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{FromRequestParts, State};
use axum::http::{Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use tracing::warn;
use tw_core::auth::{ApiKey, Role};
use tw_core::db::create_rbac_repository;
use tw_core::rbac::{
    builtin_roles, Action as RbacAction, AuthorizationRequest, Permission as RbacPermission,
    PermissionEvaluator, Resource as RbacResource,
};

/// Required permission for a protected route.
#[derive(Debug, Clone)]
pub struct PermissionRequirement {
    pub resource: RbacResource,
    pub action: RbacAction,
}

impl PermissionRequirement {
    /// Creates a new permission requirement.
    pub fn new(resource: RbacResource, action: RbacAction) -> Self {
        Self { resource, action }
    }
}

/// Middleware state wrapper for permission checks.
#[derive(Clone)]
pub struct AuthorizationState {
    pub app_state: AppState,
    pub requirement: PermissionRequirement,
}

/// Route middleware enforcing a specific permission.
pub async fn require_permission_middleware(
    State(state): State<AuthorizationState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let (mut parts, body) = request.into_parts();
    let required_action =
        resolve_required_action(&state.requirement, &parts.method, parts.uri.path());
    let AuthenticatedUser(user) =
        AuthenticatedUser::from_request_parts(&mut parts, &state.app_state).await?;
    if let Some(api_key) = parts.extensions.get::<ApiKey>() {
        enforce_api_key_scopes(api_key, &state.requirement, required_action)?;
    }
    let request = Request::from_parts(parts, body);

    let mut effective_permissions = builtin_permissions_for_role(user.role, user.tenant_id);
    let rbac_repo = create_rbac_repository(&state.app_state.db);
    let custom_permissions = rbac_repo
        .get_user_permissions(user.tenant_id, user.id)
        .await
        .map_err(ApiError::from)?;
    effective_permissions.extend(custom_permissions);

    let auth_request = AuthorizationRequest {
        user_id: user.id,
        tenant_id: user.tenant_id,
        resource: state.requirement.resource,
        action: required_action,
        context: HashMap::new(),
    };
    let decision = PermissionEvaluator.evaluate(&effective_permissions, &auth_request);
    if !decision.allowed {
        warn!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            role = %user.role,
            resource = %state.requirement.resource.as_str(),
            action = %required_action.as_str(),
            reason = ?decision.reason,
            "Permission denied by authorization middleware"
        );
        return Err(ApiError::Forbidden(format!(
            "Missing permission {}:{}",
            state.requirement.resource.as_str(),
            required_action.as_str()
        )));
    }

    Ok(next.run(request).await)
}

fn enforce_api_key_scopes(
    api_key: &ApiKey,
    requirement: &PermissionRequirement,
    required_action: RbacAction,
) -> Result<(), ApiError> {
    let access_scope = if matches!(required_action, RbacAction::Read) {
        scopes::READ
    } else {
        scopes::WRITE
    };
    if !api_key.has_scope(access_scope) {
        return Err(ApiError::Forbidden(format!(
            "API key does not have required scope: {}",
            access_scope
        )));
    }

    let resource_scopes = resource_scopes_for_requirement(requirement);
    if !resource_scopes.is_empty() && !resource_scopes.iter().any(|scope| api_key.has_scope(scope))
    {
        return Err(ApiError::Forbidden(format!(
            "API key does not have required scope: one of {}",
            resource_scopes.join(", ")
        )));
    }

    Ok(())
}

fn is_read_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn resolve_required_action(
    requirement: &PermissionRequirement,
    method: &Method,
    path: &str,
) -> RbacAction {
    if !matches!(requirement.action, RbacAction::Read) {
        return requirement.action;
    }

    if let Some(overridden) = endpoint_action_override(requirement.resource, method, path) {
        return overridden;
    }

    if is_read_method(method) {
        RbacAction::Read
    } else {
        RbacAction::Update
    }
}

fn endpoint_action_override(
    resource: RbacResource,
    method: &Method,
    path: &str,
) -> Option<RbacAction> {
    let path = normalize_path(path);

    match resource {
        RbacResource::Incident => {
            if path_contains(path, "/incidents/") && path_has_suffix(path, "/approve") {
                return Some(RbacAction::Approve);
            }
            if (path_contains(path, "/incidents/") && path_has_suffix(path, "/actions"))
                || (path_contains(path, "/incidents/") && path_has_suffix(path, "/enrich"))
            {
                return Some(RbacAction::Execute);
            }
            if path_has_suffix(path, "/nl/query") {
                return Some(RbacAction::Read);
            }
        }
        RbacResource::Hunt => {
            if path_has_suffix(path, "/execute") {
                return Some(RbacAction::Execute);
            }
        }
        RbacResource::AuditLog => {
            if path_has_suffix(path, "/audit/immutable/export")
                || path_has_suffix(path, "/audit/immutable/anchor")
                || path_has_suffix(path, "/audit/immutable/verify/job")
                || path_has_suffix(path, "/audit/immutable/archive")
            {
                return Some(RbacAction::Export);
            }
        }
        RbacResource::Compliance => {
            if path_has_suffix(path, "/risk/score") {
                return Some(RbacAction::Read);
            }
            if path_has_suffix(path, "/compliance/reports/generate")
                || path_has_suffix(path, "/compliance/evidence/package")
                || path_has_suffix(path, "/custody")
            {
                return Some(RbacAction::Export);
            }
        }
        RbacResource::Privacy => {
            if path_has_suffix(path, "/privacy/classify")
                || path_has_suffix(path, "/privacy/mask")
                || path_has_suffix(path, "/privacy/retention/evaluate")
                || path_has_suffix(path, "/privacy/retention/cleanup/plan")
                || path_has_suffix(path, "/privacy/route-llm")
            {
                return Some(RbacAction::Read);
            }
            if path_has_suffix(path, "/privacy/subject-access/export")
                || path_has_suffix(path, "/privacy/subject-access/delete")
                || (!is_read_method(method) && path_has_suffix(path, "/privacy/retention/policies"))
            {
                return Some(RbacAction::Manage);
            }
        }
        RbacResource::Guardrail => {
            if path_has_suffix(path, "/guardrails/simulate") {
                return Some(RbacAction::Read);
            }
            if path_has_suffix(path, "/autonomy/resolve")
                || path_has_suffix(path, "/guardrails/rollback/register")
                || path_has_suffix(path, "/guardrails/rollback/derive")
                || path_has_suffix(path, "/status")
                || path_has_suffix(path, "/guardrails/anomaly/check")
                || path_has_suffix(path, "/guardrails/automation/pause/resume")
                || (!is_read_method(method) && path_has_suffix(path, "/autonomy/config"))
            {
                return Some(RbacAction::Manage);
            }
        }
        RbacResource::Playbook => {
            if path_has_suffix(path, "/packages/validate") {
                return Some(RbacAction::Read);
            }
            if path_contains(path, "/packages/export/") {
                return Some(RbacAction::Export);
            }
        }
        _ => {}
    }

    None
}

fn normalize_path(path: &str) -> &str {
    if path == "/" {
        path
    } else {
        path.trim_end_matches('/')
    }
}

fn path_has_suffix(path: &str, suffix: &str) -> bool {
    let normalized_suffix = normalize_path(suffix);
    path.ends_with(normalized_suffix)
}

fn path_contains(path: &str, fragment: &str) -> bool {
    path.contains(fragment)
}

fn resource_scopes_for_requirement(requirement: &PermissionRequirement) -> &'static [&'static str] {
    match requirement.resource {
        RbacResource::Incident => &[scopes::INCIDENTS],
        RbacResource::Connector => &[scopes::CONNECTORS],
        RbacResource::Playbook => &[scopes::PLAYBOOKS],
        RbacResource::Settings => &[scopes::SETTINGS, scopes::ADMIN],
        RbacResource::User | RbacResource::Role => &[scopes::ADMIN],
        _ => &[],
    }
}

fn builtin_permissions_for_role(role: Role, tenant_id: uuid::Uuid) -> Vec<RbacPermission> {
    let roles = builtin_roles(Some(tenant_id));
    let role_name = match role {
        Role::Admin => "tenant_admin",
        Role::Analyst => "analyst",
        Role::Viewer => "viewer",
    };
    roles
        .into_iter()
        .find(|r| r.name == role_name)
        .map(|r| r.permissions)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_enforce_api_key_scopes_requires_write_for_mutating_methods() {
        let (api_key, _) = ApiKey::new(Uuid::new_v4(), "read-only", vec![scopes::READ.to_string()]);
        let requirement = PermissionRequirement::new(RbacResource::Compliance, RbacAction::Read);

        assert!(enforce_api_key_scopes(&api_key, &requirement, RbacAction::Read).is_ok());
        assert!(enforce_api_key_scopes(&api_key, &requirement, RbacAction::Update).is_err());
    }

    #[test]
    fn test_enforce_api_key_scopes_requires_incidents_scope_for_incident_routes() {
        let (insufficient, _) =
            ApiKey::new(Uuid::new_v4(), "read-only", vec![scopes::READ.to_string()]);
        let requirement = PermissionRequirement::new(RbacResource::Incident, RbacAction::Read);
        assert!(enforce_api_key_scopes(&insufficient, &requirement, RbacAction::Read).is_err());

        let (sufficient, _) = ApiKey::new(
            Uuid::new_v4(),
            "incident-reader",
            vec![scopes::READ.to_string(), scopes::INCIDENTS.to_string()],
        );
        assert!(enforce_api_key_scopes(&sufficient, &requirement, RbacAction::Read).is_ok());
    }

    #[test]
    fn test_enforce_api_key_scopes_requires_admin_scope_for_settings_routes() {
        let requirement = PermissionRequirement::new(RbacResource::Settings, RbacAction::Read);
        let (no_admin, _) =
            ApiKey::new(Uuid::new_v4(), "read-write", vec![scopes::READ.to_string()]);
        assert!(enforce_api_key_scopes(&no_admin, &requirement, RbacAction::Read).is_err());

        let (with_admin, _) = ApiKey::new(
            Uuid::new_v4(),
            "admin-reader",
            vec![scopes::READ.to_string(), scopes::ADMIN.to_string()],
        );
        assert!(enforce_api_key_scopes(&with_admin, &requirement, RbacAction::Read).is_ok());

        let (with_settings, _) = ApiKey::new(
            Uuid::new_v4(),
            "settings-reader",
            vec![scopes::READ.to_string(), scopes::SETTINGS.to_string()],
        );
        assert!(enforce_api_key_scopes(&with_settings, &requirement, RbacAction::Read).is_ok());
    }

    #[test]
    fn test_enforce_api_key_scopes_requires_playbooks_scope_for_playbook_routes() {
        let requirement = PermissionRequirement::new(RbacResource::Playbook, RbacAction::Read);
        let (insufficient, _) =
            ApiKey::new(Uuid::new_v4(), "reader", vec![scopes::READ.to_string()]);
        assert!(enforce_api_key_scopes(&insufficient, &requirement, RbacAction::Read).is_err());

        let (sufficient, _) = ApiKey::new(
            Uuid::new_v4(),
            "playbook-reader",
            vec![scopes::READ.to_string(), scopes::PLAYBOOKS.to_string()],
        );
        assert!(enforce_api_key_scopes(&sufficient, &requirement, RbacAction::Read).is_ok());
    }

    #[test]
    fn test_resolve_required_action_incident_execute_and_approve() {
        let requirement = PermissionRequirement::new(RbacResource::Incident, RbacAction::Read);

        assert_eq!(
            resolve_required_action(&requirement, &Method::POST, "/api/v1/incidents/123/actions",),
            RbacAction::Execute
        );
        assert_eq!(
            resolve_required_action(&requirement, &Method::POST, "/api/v1/incidents/123/approve",),
            RbacAction::Approve
        );
        assert_eq!(
            resolve_required_action(&requirement, &Method::POST, "/api/v1/incidents/123/dismiss",),
            RbacAction::Update
        );
    }

    #[test]
    fn test_resolve_required_action_handles_read_like_posts() {
        let incident_requirement =
            PermissionRequirement::new(RbacResource::Incident, RbacAction::Read);
        let compliance_requirement =
            PermissionRequirement::new(RbacResource::Compliance, RbacAction::Read);
        let guardrail_requirement =
            PermissionRequirement::new(RbacResource::Guardrail, RbacAction::Read);

        assert_eq!(
            resolve_required_action(&incident_requirement, &Method::POST, "/api/v1/nl/query",),
            RbacAction::Read
        );
        assert_eq!(
            resolve_required_action(&compliance_requirement, &Method::POST, "/api/v1/risk/score",),
            RbacAction::Read
        );
        assert_eq!(
            resolve_required_action(
                &guardrail_requirement,
                &Method::POST,
                "/api/v1/guardrails/simulate",
            ),
            RbacAction::Read
        );
    }

    #[test]
    fn test_resolve_required_action_handles_export_and_manage_overrides() {
        let audit_requirement =
            PermissionRequirement::new(RbacResource::AuditLog, RbacAction::Read);
        let privacy_requirement =
            PermissionRequirement::new(RbacResource::Privacy, RbacAction::Read);

        assert_eq!(
            resolve_required_action(
                &audit_requirement,
                &Method::GET,
                "/api/v1/audit/immutable/export",
            ),
            RbacAction::Export
        );
        assert_eq!(
            resolve_required_action(
                &audit_requirement,
                &Method::POST,
                "/api/v1/audit/immutable/anchor",
            ),
            RbacAction::Export
        );
        assert_eq!(
            resolve_required_action(
                &privacy_requirement,
                &Method::POST,
                "/api/v1/privacy/subject-access/export",
            ),
            RbacAction::Manage
        );
    }
}
