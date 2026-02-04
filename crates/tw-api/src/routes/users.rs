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
    /// Page number (1-indexed). Defaults to 1.
    #[serde(default = "default_page")]
    pub page: u32,
    /// Number of items per page. Defaults to 50, max 100.
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}

fn default_per_page() -> u32 {
    50
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

/// Paginated response for users list.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedUsersResponse {
    /// List of users on this page.
    pub users: Vec<UserResponse>,
    /// Current page number (1-indexed).
    pub page: u32,
    /// Number of items per page.
    pub per_page: u32,
    /// Total number of users matching the filter.
    pub total: u64,
    /// Total number of pages.
    pub total_pages: u32,
}

/// Maximum allowed items per page.
const MAX_PER_PAGE: u32 = 100;

/// Lists all users with pagination.
async fn list_users(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<PaginatedUsersResponse>, ApiError> {
    // Validate and clamp pagination parameters
    let page = query.page.max(1);
    let per_page = query.per_page.clamp(1, MAX_PER_PAGE);

    // TODO: Task 1.4.1 - Get tenant_id from TenantContext middleware
    let filter = UserFilter {
        tenant_id: None, // Will be set by tenant middleware
        role: query.role.as_deref().and_then(|r| r.parse().ok()),
        enabled: query.enabled,
        search: query.search,
    };

    let user_repo = create_user_repository(&state.db);

    // Get total count for pagination metadata
    let total = user_repo.count(&filter).await?;
    let total_pages = ((total as f64) / (per_page as f64)).ceil() as u32;

    // Get all users and apply pagination in-memory
    // TODO: For better performance, add pagination support to UserRepository
    let all_users = user_repo.list(&filter).await?;
    let start = ((page - 1) * per_page) as usize;
    let users: Vec<UserResponse> = all_users
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .map(Into::into)
        .collect();

    Ok(Json(PaginatedUsersResponse {
        users,
        page,
        per_page,
        total,
        total_pages,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_response_from_user() {
        use chrono::Utc;

        let user = User {
            id: Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT_ID,
            email: "test@example.com".to_string(),
            username: "testuser".to_string(),
            password_hash: "hashed".to_string(),
            role: Role::Analyst,
            display_name: Some("Test User".to_string()),
            enabled: true,
            last_login_at: Some(Utc::now()),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response: UserResponse = user.clone().into();

        assert_eq!(response.id, user.id);
        assert_eq!(response.email, "test@example.com");
        assert_eq!(response.username, "testuser");
        assert_eq!(response.role, "analyst");
        assert_eq!(response.display_name, Some("Test User".to_string()));
        assert!(response.enabled);
        assert!(response.last_login_at.is_some());
    }

    #[test]
    fn test_user_response_without_optional_fields() {
        use chrono::Utc;

        let user = User {
            id: Uuid::new_v4(),
            tenant_id: DEFAULT_TENANT_ID,
            email: "minimal@example.com".to_string(),
            username: "minimal".to_string(),
            password_hash: "hashed".to_string(),
            role: Role::Viewer,
            display_name: None,
            enabled: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let response: UserResponse = user.into();

        assert_eq!(response.role, "viewer");
        assert!(response.display_name.is_none());
        assert!(response.last_login_at.is_none());
    }

    #[test]
    fn test_create_user_request_validation() {
        // Valid request
        let valid = CreateUserRequest {
            email: "valid@example.com".to_string(),
            username: "validuser".to_string(),
            password: "StrongP@ss123".to_string(),
            role: "analyst".to_string(),
            display_name: None,
        };
        assert!(valid.validate().is_ok());

        // Invalid email
        let invalid_email = CreateUserRequest {
            email: "not-an-email".to_string(),
            username: "user".to_string(),
            password: "StrongP@ss123".to_string(),
            role: "analyst".to_string(),
            display_name: None,
        };
        assert!(invalid_email.validate().is_err());

        // Username too short
        let short_username = CreateUserRequest {
            email: "test@example.com".to_string(),
            username: "ab".to_string(),
            password: "StrongP@ss123".to_string(),
            role: "analyst".to_string(),
            display_name: None,
        };
        assert!(short_username.validate().is_err());

        // Password too short
        let short_password = CreateUserRequest {
            email: "test@example.com".to_string(),
            username: "validuser".to_string(),
            password: "short".to_string(),
            role: "analyst".to_string(),
            display_name: None,
        };
        assert!(short_password.validate().is_err());
    }

    #[test]
    fn test_update_user_request_validation() {
        // Valid update
        let valid = UpdateUserRequest {
            email: Some("new@example.com".to_string()),
            username: Some("newuser".to_string()),
            role: Some("admin".to_string()),
            display_name: Some("New Name".to_string()),
            enabled: Some(true),
        };
        assert!(valid.validate().is_ok());

        // Empty update is valid
        let empty = UpdateUserRequest {
            email: None,
            username: None,
            role: None,
            display_name: None,
            enabled: None,
        };
        assert!(empty.validate().is_ok());

        // Invalid email in update
        let invalid_email = UpdateUserRequest {
            email: Some("not-an-email".to_string()),
            username: None,
            role: None,
            display_name: None,
            enabled: None,
        };
        assert!(invalid_email.validate().is_err());

        // Username too short in update
        let short_username = UpdateUserRequest {
            email: None,
            username: Some("ab".to_string()),
            role: None,
            display_name: None,
            enabled: None,
        };
        assert!(short_username.validate().is_err());
    }

    #[test]
    fn test_reset_password_request_validation() {
        // Valid password
        let valid = ResetPasswordRequest {
            password: "NewStrongP@ss123".to_string(),
        };
        assert!(valid.validate().is_ok());

        // Password too short
        let short = ResetPasswordRequest {
            password: "short".to_string(),
        };
        assert!(short.validate().is_err());
    }

    #[test]
    fn test_list_users_query_parsing() {
        // Test that query parameters can be deserialized
        let query_str = "role=admin&enabled=true&search=john";
        let query: ListUsersQuery = serde_urlencoded::from_str(query_str).unwrap();

        assert_eq!(query.role, Some("admin".to_string()));
        assert_eq!(query.enabled, Some(true));
        assert_eq!(query.search, Some("john".to_string()));
    }

    #[test]
    fn test_role_parsing() {
        // Valid roles
        assert!("admin".parse::<Role>().is_ok());
        assert!("analyst".parse::<Role>().is_ok());
        assert!("viewer".parse::<Role>().is_ok());

        // Invalid role
        assert!("invalid_role".parse::<Role>().is_err());
    }
}
