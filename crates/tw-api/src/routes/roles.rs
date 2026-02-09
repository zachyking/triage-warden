//! RBAC role management routes.

use crate::auth::RequireAdmin;
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use tw_core::db::{create_rbac_repository, create_settings_repository, SettingsRepository};
use tw_core::rbac::{
    default_sod_rules, AccessDecision, AccessDecisionOutcome, AccessReview, RbacRole, ReviewScope,
    ReviewStatus, RoleAssignment, SodEnforcement, SodValidator,
};
use uuid::Uuid;

const ACCESS_REVIEWS_SETTINGS_KEY: &str = "rbac_access_reviews";

/// Creates the role-management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_roles).post(create_role))
        .route(
            "/access-reviews",
            get(list_access_reviews).post(create_access_review),
        )
        .route(
            "/access-reviews/reminders/due",
            get(list_due_review_reminders),
        )
        .route("/access-reviews/:review_id", get(get_access_review))
        .route(
            "/access-reviews/:review_id/status",
            post(update_access_review_status),
        )
        .route(
            "/access-reviews/:review_id/decisions",
            post(record_access_review_decision),
        )
        .route(
            "/access-reviews/:review_id/reminders/mark-sent",
            post(mark_access_review_reminder_sent),
        )
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

#[derive(Debug, Deserialize)]
struct ListAccessReviewsQuery {
    status: Option<ReviewStatus>,
}

#[derive(Debug, Deserialize)]
struct CreateAccessReviewRequest {
    name: String,
    scope: ReviewScope,
    reviewers: Vec<Uuid>,
    deadline: DateTime<Utc>,
    status: Option<ReviewStatus>,
}

#[derive(Debug, Deserialize)]
struct UpdateAccessReviewStatusRequest {
    status: ReviewStatus,
}

#[derive(Debug, Deserialize)]
struct RecordAccessDecisionRequest {
    target_user_id: Uuid,
    role_id: Option<Uuid>,
    decision: AccessDecisionOutcome,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReminderQuery {
    within_days: Option<i64>,
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

async fn list_access_reviews(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Query(query): Query<ListAccessReviewsQuery>,
) -> Result<Json<Vec<AccessReview>>, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let changed = refresh_review_statuses(&mut reviews);
    if changed {
        save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;
    }

    if let Some(status) = query.status {
        reviews.retain(|r| r.status == status);
    }

    Ok(Json(reviews))
}

async fn create_access_review(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Json(request): Json<CreateAccessReviewRequest>,
) -> Result<Json<AccessReview>, ApiError> {
    if request.name.trim().is_empty() {
        return Err(ApiError::validation_field(
            "name",
            "required",
            "Review campaign name is required",
        ));
    }
    if request.reviewers.is_empty() {
        return Err(ApiError::validation_field(
            "reviewers",
            "required",
            "At least one reviewer is required",
        ));
    }
    if request.deadline <= Utc::now() {
        return Err(ApiError::validation_field(
            "deadline",
            "invalid",
            "Deadline must be in the future",
        ));
    }

    let mut review = AccessReview::new(
        admin.tenant_id,
        request.name.trim(),
        request.scope,
        request.reviewers,
        request.deadline,
    );
    if let Some(status) = request.status {
        if matches!(status, ReviewStatus::Completed | ReviewStatus::Cancelled) {
            return Err(ApiError::validation_field(
                "status",
                "invalid",
                "New campaigns cannot start as completed or cancelled",
            ));
        }
        review.set_status(status);
    }
    review.refresh_deadline_status(Utc::now());

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    reviews.push(review.clone());
    save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;

    Ok(Json(review))
}

async fn get_access_review(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(review_id): Path<Uuid>,
) -> Result<Json<AccessReview>, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let changed = refresh_review_statuses(&mut reviews);
    let review = reviews
        .iter()
        .find(|r| r.id == review_id)
        .cloned()
        .ok_or_else(|| ApiError::NotFound(format!("Access review {} not found", review_id)))?;
    if changed {
        save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;
    }
    Ok(Json(review))
}

async fn update_access_review_status(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(review_id): Path<Uuid>,
    Json(request): Json<UpdateAccessReviewStatusRequest>,
) -> Result<Json<AccessReview>, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let review = reviews
        .iter_mut()
        .find(|r| r.id == review_id)
        .ok_or_else(|| ApiError::NotFound(format!("Access review {} not found", review_id)))?;
    review.set_status(request.status);
    review.refresh_deadline_status(Utc::now());
    let out = review.clone();
    save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;
    Ok(Json(out))
}

async fn record_access_review_decision(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(review_id): Path<Uuid>,
    Json(request): Json<RecordAccessDecisionRequest>,
) -> Result<Json<AccessDecision>, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let review = reviews
        .iter_mut()
        .find(|r| r.id == review_id)
        .ok_or_else(|| ApiError::NotFound(format!("Access review {} not found", review_id)))?;

    if !matches!(review.status, ReviewStatus::Active | ReviewStatus::Overdue) {
        return Err(ApiError::Conflict(
            "Access review campaign is not in an attestable state".to_string(),
        ));
    }

    if !review.reviewers.contains(&admin.id) {
        return Err(ApiError::Forbidden(
            "Current user is not assigned as a reviewer for this campaign".to_string(),
        ));
    }

    let mut access_change_applied = false;
    if matches!(request.decision, AccessDecisionOutcome::Revoked) {
        if let Some(role_id) = request.role_id {
            let rbac_repo = create_rbac_repository(&state.db);
            access_change_applied = rbac_repo
                .unassign_role(admin.tenant_id, request.target_user_id, role_id)
                .await
                .map_err(ApiError::from)?;
        }
    }

    let decision = AccessDecision::new(
        review.id,
        request.target_user_id,
        request.role_id,
        request.decision,
        admin.id,
        request.reason,
        access_change_applied,
    );
    review.add_decision(decision.clone());
    save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;

    Ok(Json(decision))
}

async fn list_due_review_reminders(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Query(query): Query<ReminderQuery>,
) -> Result<Json<Vec<AccessReview>>, ApiError> {
    let within_days = query.within_days.unwrap_or(3).clamp(0, 30);

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let changed = refresh_review_statuses(&mut reviews);
    let now = Utc::now();
    let due: Vec<AccessReview> = reviews
        .iter()
        .filter(|review| review.is_due_for_reminder(now, within_days))
        .cloned()
        .collect();
    if changed {
        save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;
    }

    Ok(Json(due))
}

async fn mark_access_review_reminder_sent(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(review_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut reviews = load_access_reviews(settings_repo.as_ref(), admin.tenant_id).await?;
    let review = reviews
        .iter_mut()
        .find(|r| r.id == review_id)
        .ok_or_else(|| ApiError::NotFound(format!("Access review {} not found", review_id)))?;
    let now = Utc::now();
    review.mark_reminder_sent(now);
    save_access_reviews(settings_repo.as_ref(), admin.tenant_id, &reviews).await?;

    Ok(Json(serde_json::json!({
        "marked": true,
        "review_id": review_id,
        "reminder_sent_at": now,
    })))
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

async fn load_access_reviews(
    repo: &dyn SettingsRepository,
    tenant_id: Uuid,
) -> Result<Vec<AccessReview>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, ACCESS_REVIEWS_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let reviews = serde_json::from_str::<Vec<AccessReview>>(&raw).map_err(|e| {
            ApiError::BadRequest(format!("invalid stored access review payload: {e}"))
        })?;
        return Ok(reviews);
    }
    Ok(Vec::new())
}

async fn save_access_reviews(
    repo: &dyn SettingsRepository,
    tenant_id: Uuid,
    reviews: &[AccessReview],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(reviews)
        .map_err(|e| ApiError::Internal(format!("failed to serialize access reviews: {e}")))?;
    repo.save_raw(tenant_id, ACCESS_REVIEWS_SETTINGS_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

fn refresh_review_statuses(reviews: &mut [AccessReview]) -> bool {
    let now = Utc::now();
    let mut changed = false;
    for review in reviews {
        let previous = review.status;
        review.refresh_deadline_status(now);
        if review.status != previous {
            changed = true;
        }
    }
    changed
}
