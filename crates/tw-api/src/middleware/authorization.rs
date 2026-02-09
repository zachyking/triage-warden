//! Authorization middleware for fine-grained RBAC enforcement.

use crate::auth::extractors::AuthenticatedUser;
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{FromRequestParts, State};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::collections::HashMap;
use tracing::warn;
use tw_core::auth::Role;
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
    let AuthenticatedUser(user) =
        AuthenticatedUser::from_request_parts(&mut parts, &state.app_state).await?;
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
        action: state.requirement.action,
        context: HashMap::new(),
    };
    let decision = PermissionEvaluator.evaluate(&effective_permissions, &auth_request);
    if !decision.allowed {
        warn!(
            user_id = %user.id,
            tenant_id = %user.tenant_id,
            role = %user.role,
            resource = %state.requirement.resource.as_str(),
            action = %state.requirement.action.as_str(),
            reason = ?decision.reason,
            "Permission denied by authorization middleware"
        );
        return Err(ApiError::Forbidden(format!(
            "Missing permission {}:{}",
            state.requirement.resource.as_str(),
            state.requirement.action.as_str()
        )));
    }

    Ok(next.run(request).await)
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
