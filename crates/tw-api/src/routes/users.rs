//! User management routes (admin only).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use tw_core::{
    auth::{Role, UserFilter, UserUpdate},
    db::create_user_repository,
    hash_password, validate_password_strength, User,
};

use crate::auth::RequireAdmin;
use crate::error::ApiError;
use crate::state::AppState;

/// Creates the user management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_users))
        .route("/", post(create_user))
        .route("/:id", get(get_user))
        .route("/:id", put(update_user))
        .route("/:id", delete(delete_user))
        .route("/:id/password", post(reset_password))
}

/// Query parameters for listing users.
#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub role: Option<String>,
    pub enabled: Option<bool>,
    pub search: Option<String>,
}

/// Response for a user (excludes sensitive fields).
#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub role: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub last_login_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            username: user.username,
            role: user.role.as_str().to_string(),
            display_name: user.display_name,
            enabled: user.enabled,
            last_login_at: user.last_login_at.map(|t| t.to_rfc3339()),
            created_at: user.created_at.to_rfc3339(),
            updated_at: user.updated_at.to_rfc3339(),
        }
    }
}

/// Request to create a new user.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: String,
    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: String,
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
    pub role: String,
    pub display_name: Option<String>,
}

/// Request to update a user.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateUserRequest {
    #[validate(email(message = "Invalid email address"))]
    pub email: Option<String>,
    #[validate(length(min = 3, max = 50, message = "Username must be 3-50 characters"))]
    pub username: Option<String>,
    pub role: Option<String>,
    pub display_name: Option<String>,
    pub enabled: Option<bool>,
}

/// Request to reset a user's password.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ResetPasswordRequest {
    #[validate(length(min = 8, message = "Password must be at least 8 characters"))]
    pub password: String,
}

/// Lists all users.
async fn list_users(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let filter = UserFilter {
        role: query.role.as_deref().and_then(|r| r.parse().ok()),
        enabled: query.enabled,
        search: query.search,
    };

    let user_repo = create_user_repository(&state.db);
    let users = user_repo.list(&filter).await?;

    let responses: Vec<UserResponse> = users.into_iter().map(Into::into).collect();
    Ok(Json(responses))
}

/// Creates a new user.
async fn create_user(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Json(request): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    request.validate()?;

    // Validate password strength
    let password_errors = validate_password_strength(&request.password);
    if !password_errors.is_empty() {
        return Err(ApiError::validation_field(
            "password",
            "weak_password",
            &password_errors.join("; "),
        ));
    }

    // Parse role
    let role = request.role.parse::<Role>().map_err(|_| {
        ApiError::validation_field(
            "role",
            "invalid_role",
            &format!(
                "Invalid role: '{}'. Valid roles are: admin, analyst, viewer",
                request.role
            ),
        )
    })?;

    // Hash password
    let password_hash = hash_password(&request.password)
        .map_err(|e| ApiError::Internal(format!("Failed to hash password: {}", e)))?;

    // Create user
    let mut user = User::new(&request.email, &request.username, password_hash, role);
    user.display_name = request.display_name;

    let user_repo = create_user_repository(&state.db);

    // Check for existing email/username
    if user_repo.get_by_email(&request.email).await?.is_some() {
        return Err(ApiError::validation_field(
            "email",
            "already_exists",
            "This email address is already in use by another account",
        ));
    }
    if user_repo
        .get_by_username(&request.username)
        .await?
        .is_some()
    {
        return Err(ApiError::validation_field(
            "username",
            "already_exists",
            "This username is already taken by another account",
        ));
    }

    let created_user = user_repo.create(&user).await?;

    info!(
        "User created by {}: {} ({})",
        admin.username, created_user.username, created_user.role
    );

    Ok((StatusCode::CREATED, Json(created_user.into())))
}

/// Gets a user by ID.
async fn get_user(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<Json<UserResponse>, ApiError> {
    let user_repo = create_user_repository(&state.db);
    let user = user_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

    Ok(Json(user.into()))
}

/// Updates a user.
async fn update_user(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    request.validate()?;

    let user_repo = create_user_repository(&state.db);

    // Check user exists
    let existing = user_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

    // Prevent admin from disabling themselves
    if admin.id == id && request.enabled == Some(false) {
        return Err(ApiError::BadRequest(
            "Cannot disable your own account".to_string(),
        ));
    }

    // Prevent admin from demoting themselves
    if admin.id == id {
        if let Some(role_str) = &request.role {
            let new_role = role_str
                .parse::<Role>()
                .map_err(|_| ApiError::BadRequest(format!("Invalid role: {}", role_str)))?;
            if new_role != Role::Admin {
                return Err(ApiError::BadRequest(
                    "Cannot demote your own account".to_string(),
                ));
            }
        }
    }

    // Check for email/username conflicts
    if let Some(email) = &request.email {
        if email != &existing.email && user_repo.get_by_email(email).await?.is_some() {
            return Err(ApiError::Conflict("Email already in use".to_string()));
        }
    }
    if let Some(username) = &request.username {
        if username != &existing.username && user_repo.get_by_username(username).await?.is_some() {
            return Err(ApiError::Conflict("Username already in use".to_string()));
        }
    }

    let update = UserUpdate {
        email: request.email,
        username: request.username,
        role: request.role.as_deref().and_then(|r| r.parse().ok()),
        display_name: request.display_name.map(Some),
        enabled: request.enabled,
    };

    let updated_user = user_repo.update(id, &update).await?;

    info!(
        "User updated by {}: {} ({})",
        admin.username, updated_user.username, updated_user.role
    );

    Ok(Json(updated_user.into()))
}

/// Deletes a user.
async fn delete_user(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    // Prevent admin from deleting themselves
    if admin.id == id {
        return Err(ApiError::BadRequest(
            "Cannot delete your own account".to_string(),
        ));
    }

    let user_repo = create_user_repository(&state.db);

    // Get user for logging
    let user = user_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

    let deleted = user_repo.delete(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("User {} not found", id)));
    }

    info!("User deleted by {}: {}", admin.username, user.username);

    Ok(StatusCode::NO_CONTENT)
}

/// Resets a user's password.
async fn reset_password(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(id): Path<Uuid>,
    Json(request): Json<ResetPasswordRequest>,
) -> Result<StatusCode, ApiError> {
    request.validate()?;

    // Validate password strength
    let password_errors = validate_password_strength(&request.password);
    if !password_errors.is_empty() {
        return Err(ApiError::BadRequest(password_errors.join(", ")));
    }

    let user_repo = create_user_repository(&state.db);

    // Get user for logging
    let user = user_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("User {} not found", id)))?;

    // Hash new password
    let password_hash = hash_password(&request.password)
        .map_err(|e| ApiError::Internal(format!("Failed to hash password: {}", e)))?;

    user_repo.update_password(id, &password_hash).await?;

    info!(
        "Password reset by {} for user: {}",
        admin.username, user.username
    );

    Ok(StatusCode::NO_CONTENT)
}
