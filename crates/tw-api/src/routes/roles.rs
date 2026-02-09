//! RBAC role management routes.

use crate::auth::RequireAdmin;
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::warn;
use tw_core::db::create_rbac_repository;
use tw_core::rbac::{default_sod_rules, RbacRole, RoleAssignment, SodEnforcement, SodValidator};
use uuid::Uuid;

/// Creates the role-management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_roles).post(create_role))
        .route(
            "/:role_id",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route("/assignments/:user_id", get(list_assignments))
        .route("/assignments", post(assign_role))
        .route("/assignments/:user_id/:role_id", delete(unassign_role))
}

#[derive(Debug, Deserialize)]
struct ListRolesQuery {
    include_system: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CreateRoleRequest {
    name: String,
    description: String,
    permissions: Vec<tw_core::rbac::Permission>,
}

#[derive(Debug, Deserialize)]
struct UpdateRoleRequest {
    description: Option<String>,
    permissions: Option<Vec<tw_core::rbac::Permission>>,
}

#[derive(Debug, Deserialize)]
struct AssignRoleRequest {
    user_id: Uuid,
    role_id: Uuid,
}

#[derive(Debug, Serialize)]
struct RoleAssignmentResponse {
    assignment: RoleAssignment,
    warnings: Vec<String>,
}

async fn list_roles(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Query(query): Query<ListRolesQuery>,
) -> Result<Json<Vec<RbacRole>>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    repo.ensure_builtin_roles(admin.tenant_id)
        .await
        .map_err(ApiError::from)?;
    let roles = repo
        .list_roles(admin.tenant_id, query.include_system.unwrap_or(true))
        .await
        .map_err(ApiError::from)?;
    Ok(Json(roles))
}

async fn get_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(role_id): Path<Uuid>,
) -> Result<Json<RbacRole>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    repo.ensure_builtin_roles(admin.tenant_id)
        .await
        .map_err(ApiError::from)?;
    let role = repo.get_role(role_id).await.map_err(ApiError::from)?;
    match role {
        Some(role) if role.tenant_id == Some(admin.tenant_id) => Ok(Json(role)),
        Some(_) => Err(ApiError::Forbidden(
            "Role does not belong to this tenant".to_string(),
        )),
        None => Err(ApiError::NotFound(format!("Role {} not found", role_id))),
    }
}

async fn create_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Json(request): Json<CreateRoleRequest>,
) -> Result<Json<RbacRole>, ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::validation_field(
            "name",
            "required",
            "Role name is required",
        ));
    }
    if request.permissions.is_empty() {
        return Err(ApiError::validation_field(
            "permissions",
            "required",
            "At least one permission is required",
        ));
    }

    let repo = create_rbac_repository(&state.db);
    repo.ensure_builtin_roles(admin.tenant_id)
        .await
        .map_err(ApiError::from)?;

    let role = RbacRole::new(
        Some(admin.tenant_id),
        request.name.trim().to_ascii_lowercase(),
        request.description.trim().to_string(),
        request.permissions,
        false,
    );

    let created = repo.create_role(&role).await.map_err(ApiError::from)?;
    Ok(Json(created))
}

async fn update_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(role_id): Path<Uuid>,
    Json(request): Json<UpdateRoleRequest>,
) -> Result<Json<RbacRole>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    let mut role = repo
        .get_role(role_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Role {} not found", role_id)))?;
    if role.tenant_id != Some(admin.tenant_id) {
        return Err(ApiError::Forbidden(
            "Role does not belong to this tenant".to_string(),
        ));
    }
    if role.is_system {
        return Err(ApiError::Forbidden(
            "System roles cannot be modified".to_string(),
        ));
    }

    if let Some(description) = request.description {
        role.description = description;
    }
    if let Some(permissions) = request.permissions {
        role.permissions = permissions;
    }

    let updated = repo
        .update_role(role_id, &role)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(updated))
}

async fn delete_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(role_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    let role = repo
        .get_role(role_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Role {} not found", role_id)))?;
    if role.tenant_id != Some(admin.tenant_id) {
        return Err(ApiError::Forbidden(
            "Role does not belong to this tenant".to_string(),
        ));
    }
    if role.is_system {
        return Err(ApiError::Forbidden(
            "System roles cannot be deleted".to_string(),
        ));
    }

    let deleted = repo.delete_role(role_id).await.map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

async fn list_assignments(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(user_id): Path<Uuid>,
) -> Result<Json<Vec<RoleAssignment>>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    let assignments = repo
        .list_user_assignments(admin.tenant_id, user_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(assignments))
}

async fn assign_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Json(request): Json<AssignRoleRequest>,
) -> Result<Json<RoleAssignmentResponse>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    repo.ensure_builtin_roles(admin.tenant_id)
        .await
        .map_err(ApiError::from)?;

    let role = repo
        .get_role(request.role_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Role {} not found", request.role_id)))?;
    if role.tenant_id != Some(admin.tenant_id) {
        return Err(ApiError::Forbidden(
            "Role does not belong to this tenant".to_string(),
        ));
    }

    let mut effective_permissions = repo
        .get_user_permissions(admin.tenant_id, request.user_id)
        .await
        .map_err(ApiError::from)?;
    effective_permissions.extend(role.permissions.clone());

    let validator = SodValidator::new(default_sod_rules());
    let violations = validator.validate(&effective_permissions);
    let mut warnings = Vec::new();
    for violation in violations {
        match violation.enforcement {
            SodEnforcement::Prevent => {
                return Err(ApiError::Conflict(format!(
                    "Role assignment violates separation-of-duties rule '{}'",
                    violation.rule_name
                )));
            }
            SodEnforcement::Warn => {
                warnings.push(format!(
                    "Potential SoD conflict detected by rule '{}'",
                    violation.rule_name
                ));
                warn!(
                    user_id = %request.user_id,
                    role_id = %request.role_id,
                    rule = %violation.rule_name,
                    "SoD warning during role assignment"
                );
            }
            SodEnforcement::Audit => {
                warn!(
                    user_id = %request.user_id,
                    role_id = %request.role_id,
                    rule = %violation.rule_name,
                    "SoD audit-only rule matched during role assignment"
                );
            }
        }
    }

    let assignment = RoleAssignment::new(
        admin.tenant_id,
        request.user_id,
        request.role_id,
        Some(admin.id),
    );
    let saved = repo
        .assign_role(&assignment)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(RoleAssignmentResponse {
        assignment: saved,
        warnings,
    }))
}

async fn unassign_role(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path((user_id, role_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let repo = create_rbac_repository(&state.db);
    let removed = repo
        .unassign_role(admin.tenant_id, user_id, role_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(serde_json::json!({ "removed": removed })))
}
