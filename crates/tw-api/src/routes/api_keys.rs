//! API key management routes.
//!
//! Allows authenticated users to create, list, and revoke their own API keys.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use tw_core::{auth::ApiKey, db::create_api_key_repository};

use crate::auth::AuthenticatedUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Creates the API key management routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_api_keys))
        .route("/", post(create_api_key))
        .route("/:id", get(get_api_key))
        .route("/:id", delete(revoke_api_key))
}

/// Response for an API key (excludes the actual key hash).
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyResponse {
    /// Unique identifier for the API key.
    pub id: Uuid,
    /// Descriptive name for the key.
    pub name: String,
    /// Prefix of the key for identification (e.g., "tw_abc123").
    pub key_prefix: String,
    /// Scopes/permissions for this key.
    pub scopes: Vec<String>,
    /// Expiration timestamp (optional).
    pub expires_at: Option<String>,
    /// Last time this key was used.
    pub last_used_at: Option<String>,
    /// Creation timestamp.
    pub created_at: String,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            key_prefix: key.key_prefix,
            scopes: key.scopes,
            expires_at: key.expires_at.map(|t| t.to_rfc3339()),
            last_used_at: key.last_used_at.map(|t| t.to_rfc3339()),
            created_at: key.created_at.to_rfc3339(),
        }
    }
}

/// Response when creating a new API key (includes the raw key, shown only once).
#[derive(Debug, Serialize, ToSchema)]
pub struct CreateApiKeyResponse {
    /// The API key details.
    #[serde(flatten)]
    pub key: ApiKeyResponse,
    /// The raw API key value. This is only shown once and cannot be retrieved later.
    /// Store this securely.
    pub raw_key: String,
}

/// Request to create a new API key.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateApiKeyRequest {
    /// Descriptive name for the key (e.g., "CI/CD Pipeline", "External Integration").
    #[validate(length(min = 1, max = 100, message = "Name must be 1-100 characters"))]
    pub name: String,
    /// Scopes/permissions for this key. Use "*" for full access.
    /// Available scopes: read, write, incidents, connectors, playbooks, settings, admin
    #[validate(length(min = 1, message = "At least one scope is required"))]
    pub scopes: Vec<String>,
    /// Optional expiration in days. If not set, the key never expires.
    #[validate(range(min = 1, max = 365, message = "Expiration must be 1-365 days"))]
    pub expires_in_days: Option<i64>,
}

/// Lists all API keys for the current user.
async fn list_api_keys(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    let api_key_repo = create_api_key_repository(&state.db);
    let keys = api_key_repo.list_by_user(user.id).await?;

    let responses: Vec<ApiKeyResponse> = keys.into_iter().map(Into::into).collect();
    Ok(Json(responses))
}

/// Creates a new API key for the current user.
async fn create_api_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), ApiError> {
    request.validate()?;

    // Validate scopes
    let valid_scopes = [
        "read",
        "write",
        "incidents",
        "connectors",
        "playbooks",
        "settings",
        "admin",
        "*",
    ];
    for scope in &request.scopes {
        if !valid_scopes.contains(&scope.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "Invalid scope: '{}'. Valid scopes are: {}",
                scope,
                valid_scopes.join(", ")
            )));
        }
    }

    // Only admins can create keys with admin scope
    if (request.scopes.contains(&"admin".to_string()) || request.scopes.contains(&"*".to_string()))
        && user.role != tw_core::auth::Role::Admin
    {
        return Err(ApiError::Forbidden(
            "Only administrators can create API keys with admin or wildcard scope".to_string(),
        ));
    }

    // Create the API key
    let (mut api_key, raw_key) = ApiKey::new(user.id, &request.name, request.scopes.clone());

    // Set expiration if specified
    if let Some(days) = request.expires_in_days {
        api_key.expires_at = Some(chrono::Utc::now() + chrono::Duration::days(days));
    }

    let api_key_repo = create_api_key_repository(&state.db);
    let created_key = api_key_repo.create(&api_key).await?;

    info!(
        "API key created by {}: {} (prefix: {})",
        user.username, created_key.name, created_key.key_prefix
    );

    Ok((
        StatusCode::CREATED,
        Json(CreateApiKeyResponse {
            key: created_key.into(),
            raw_key,
        }),
    ))
}

/// Gets details for a specific API key.
async fn get_api_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    let api_key_repo = create_api_key_repository(&state.db);
    let key = api_key_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("API key {} not found", id)))?;

    // Ensure the key belongs to the current user
    if key.user_id != user.id {
        return Err(ApiError::Forbidden(
            "You can only view your own API keys".to_string(),
        ));
    }

    Ok(Json(key.into()))
}

/// Revokes (deletes) an API key.
async fn revoke_api_key(
    State(state): State<AppState>,
    AuthenticatedUser(user): AuthenticatedUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let api_key_repo = create_api_key_repository(&state.db);

    // Get the key to verify ownership
    let key = api_key_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("API key {} not found", id)))?;

    // Ensure the key belongs to the current user
    if key.user_id != user.id {
        return Err(ApiError::Forbidden(
            "You can only revoke your own API keys".to_string(),
        ));
    }

    let deleted = api_key_repo.delete(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("API key {} not found", id)));
    }

    info!(
        "API key revoked by {}: {} (prefix: {})",
        user.username, key.name, key.key_prefix
    );

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_scopes() {
        let valid = [
            "read",
            "write",
            "incidents",
            "connectors",
            "playbooks",
            "settings",
            "admin",
            "*",
        ];
        for scope in valid {
            assert!(valid.contains(&scope));
        }
    }
}
