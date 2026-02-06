//! Feature flag admin endpoints.
//!
//! This module provides admin API endpoints for managing feature flags at runtime.
//! All endpoints require Admin role.

use axum::{
    extract::{Path, State},
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use tw_core::features::{FeatureFlag, FeatureFlagError, FeatureFlagStore, FeatureFlags};

use crate::auth::RequireAdmin;
use crate::error::ApiError;
use crate::state::AppState;

/// Creates the feature flag admin routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_feature_flags))
        .route("/:name", get(get_feature_flag))
        .route("/:name", put(update_feature_flag))
        .route("/:name/override/:tenant_id", post(set_tenant_override))
        .route("/:name/override/:tenant_id", delete(remove_tenant_override))
}

// ============================================================================
// Request/Response Types
// ============================================================================

/// Response for a feature flag.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FeatureFlagResponse {
    /// Unique name identifier for the flag.
    pub name: String,
    /// Human-readable description of what this flag controls.
    pub description: Option<String>,
    /// Whether the flag is enabled by default.
    pub enabled: bool,
    /// Per-tenant overrides (tenant_id as string -> enabled).
    pub tenant_overrides: HashMap<String, bool>,
    /// Optional percentage rollout (0-100).
    pub percentage_rollout: Option<u8>,
    /// Timestamp when the flag was created.
    pub created_at: String,
    /// Timestamp of the last update.
    pub updated_at: String,
}

impl From<FeatureFlag> for FeatureFlagResponse {
    fn from(flag: FeatureFlag) -> Self {
        Self {
            name: flag.name,
            description: if flag.description.is_empty() {
                None
            } else {
                Some(flag.description)
            },
            enabled: flag.default_enabled,
            tenant_overrides: flag
                .tenant_overrides
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            percentage_rollout: flag.percentage_rollout,
            created_at: flag.created_at.to_rfc3339(),
            updated_at: flag.updated_at.to_rfc3339(),
        }
    }
}

/// Request to update a feature flag.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateFeatureFlagRequest {
    /// Whether the flag is enabled by default.
    pub enabled: Option<bool>,
    /// Human-readable description of what this flag controls.
    pub description: Option<String>,
    /// Optional percentage rollout (0-100). Set to null to disable.
    #[validate(range(max = 100, message = "Percentage must be between 0 and 100"))]
    pub percentage_rollout: Option<u8>,
}

/// Request to set a tenant override.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct TenantOverrideRequest {
    /// Whether the flag should be enabled for this tenant.
    pub enabled: bool,
}

/// Response for listing all feature flags.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FeatureFlagsListResponse {
    /// List of all feature flags.
    pub flags: Vec<FeatureFlagResponse>,
    /// Total number of flags.
    pub total: usize,
}

// ============================================================================
// Handlers
// ============================================================================

/// List all feature flags.
#[utoipa::path(
    get,
    path = "/api/v1/admin/features",
    responses(
        (status = 200, description = "List of all feature flags", body = FeatureFlagsListResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - Admin role required"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Feature Flags"
)]
async fn list_feature_flags(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
) -> Result<Json<FeatureFlagsListResponse>, ApiError> {
    let feature_flags = get_feature_flags_service(&state).await?;
    let flags = feature_flags.list().await;

    let response_flags: Vec<FeatureFlagResponse> = flags.into_iter().map(Into::into).collect();
    let total = response_flags.len();

    Ok(Json(FeatureFlagsListResponse {
        flags: response_flags,
        total,
    }))
}

/// Get a single feature flag by name.
#[utoipa::path(
    get,
    path = "/api/v1/admin/features/{name}",
    params(
        ("name" = String, Path, description = "Feature flag name")
    ),
    responses(
        (status = 200, description = "Feature flag details", body = FeatureFlagResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - Admin role required"),
        (status = 404, description = "Feature flag not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Feature Flags"
)]
async fn get_feature_flag(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Path(name): Path<String>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    let feature_flags = get_feature_flags_service(&state).await?;
    let flag = feature_flags
        .get(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Feature flag '{}' not found", name)))?;

    Ok(Json(flag.into()))
}

/// Update a feature flag.
#[utoipa::path(
    put,
    path = "/api/v1/admin/features/{name}",
    params(
        ("name" = String, Path, description = "Feature flag name")
    ),
    request_body = UpdateFeatureFlagRequest,
    responses(
        (status = 200, description = "Feature flag updated", body = FeatureFlagResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - Admin role required"),
        (status = 404, description = "Feature flag not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Feature Flags"
)]
async fn update_feature_flag(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path(name): Path<String>,
    Json(request): Json<UpdateFeatureFlagRequest>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    request.validate()?;

    let feature_flags = get_feature_flags_service(&state).await?;

    // Get existing flag
    let mut flag = feature_flags
        .get(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Feature flag '{}' not found", name)))?;

    // Track what was changed for audit log
    let mut changes = Vec::new();

    // Apply updates
    if let Some(enabled) = request.enabled {
        if flag.default_enabled != enabled {
            changes.push(format!("enabled: {} -> {}", flag.default_enabled, enabled));
            flag.default_enabled = enabled;
        }
    }

    if let Some(description) = request.description {
        if flag.description != description {
            changes.push(format!(
                "description: '{}' -> '{}'",
                flag.description, description
            ));
            flag.description = description;
        }
    }

    if let Some(percentage) = request.percentage_rollout {
        if flag.percentage_rollout != Some(percentage) {
            changes.push(format!(
                "percentage_rollout: {:?} -> {}",
                flag.percentage_rollout, percentage
            ));
            flag.set_percentage_rollout(Some(percentage))
                .map_err(|e| ApiError::BadRequest(format!("Invalid percentage rollout: {}", e)))?;
        }
    }

    // Update timestamp
    flag.updated_at = chrono::Utc::now();

    // Save to store
    feature_flags
        .upsert(&flag)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to update feature flag: {}", e)))?;

    // Audit log
    if !changes.is_empty() {
        info!(
            "Feature flag '{}' updated by {}: {}",
            name,
            admin.username,
            changes.join(", ")
        );
    }

    Ok(Json(flag.into()))
}

/// Set a tenant-specific override for a feature flag.
#[utoipa::path(
    post,
    path = "/api/v1/admin/features/{name}/override/{tenant_id}",
    params(
        ("name" = String, Path, description = "Feature flag name"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    request_body = TenantOverrideRequest,
    responses(
        (status = 200, description = "Tenant override set", body = FeatureFlagResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - Admin role required"),
        (status = 404, description = "Feature flag not found"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Feature Flags"
)]
async fn set_tenant_override(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path((name, tenant_id)): Path<(String, Uuid)>,
    Json(request): Json<TenantOverrideRequest>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    request.validate()?;

    let feature_flags = get_feature_flags_service(&state).await?;

    // Get existing flag
    let mut flag = feature_flags
        .get(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Feature flag '{}' not found", name)))?;

    // Set tenant override
    let old_value = flag.tenant_overrides.get(&tenant_id).copied();
    flag.set_tenant_override(tenant_id, request.enabled);

    // Save to store
    feature_flags
        .upsert(&flag)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to update feature flag: {}", e)))?;

    // Audit log
    info!(
        "Feature flag '{}' tenant override set by {}: tenant {} = {} (was {:?})",
        name, admin.username, tenant_id, request.enabled, old_value
    );

    Ok(Json(flag.into()))
}

/// Remove a tenant-specific override for a feature flag.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/features/{name}/override/{tenant_id}",
    params(
        ("name" = String, Path, description = "Feature flag name"),
        ("tenant_id" = Uuid, Path, description = "Tenant ID")
    ),
    responses(
        (status = 200, description = "Tenant override removed", body = FeatureFlagResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - Admin role required"),
        (status = 404, description = "Feature flag not found or tenant override does not exist"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Feature Flags"
)]
async fn remove_tenant_override(
    State(state): State<AppState>,
    RequireAdmin(admin): RequireAdmin,
    Path((name, tenant_id)): Path<(String, Uuid)>,
) -> Result<Json<FeatureFlagResponse>, ApiError> {
    let feature_flags = get_feature_flags_service(&state).await?;

    // Get existing flag
    let mut flag = feature_flags
        .get(&name)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Feature flag '{}' not found", name)))?;

    // Check if override exists
    if !flag.tenant_overrides.contains_key(&tenant_id) {
        return Err(ApiError::NotFound(format!(
            "Tenant override for tenant '{}' not found on flag '{}'",
            tenant_id, name
        )));
    }

    // Get old value for audit log
    let old_value = flag.tenant_overrides.get(&tenant_id).copied();

    // Remove tenant override
    flag.remove_tenant_override(&tenant_id);

    // Save to store
    feature_flags
        .upsert(&flag)
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to update feature flag: {}", e)))?;

    // Audit log
    info!(
        "Feature flag '{}' tenant override removed by {}: tenant {} (was {:?})",
        name, admin.username, tenant_id, old_value
    );

    Ok(Json(flag.into()))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Gets or creates the FeatureFlags service from app state.
///
/// This function creates a new FeatureFlags service using the database-backed store.
/// In a production environment, this service should be cached in AppState.
async fn get_feature_flags_service(state: &AppState) -> Result<FeatureFlags, ApiError> {
    use tw_core::db::create_feature_flag_store;

    let store: Arc<dyn FeatureFlagStore> = Arc::from(create_feature_flag_store(&state.db));
    let service = FeatureFlags::new(store);

    // Refresh cache from store
    service
        .refresh()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to load feature flags: {}", e)))?;

    Ok(service)
}

impl From<FeatureFlagError> for ApiError {
    fn from(err: FeatureFlagError) -> Self {
        match err {
            FeatureFlagError::NotFound(name) => {
                ApiError::NotFound(format!("Feature flag '{}' not found", name))
            }
            FeatureFlagError::Storage(msg) => {
                ApiError::Internal(format!("Feature flag storage error: {}", msg))
            }
            FeatureFlagError::InvalidPercentage(pct) => ApiError::BadRequest(format!(
                "Invalid percentage: {}. Must be between 0 and 100.",
                pct
            )),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        Extension, Router,
    };
    use tower::ServiceExt;

    use crate::auth::test_helpers::TestUser;
    use crate::test_helpers::create_test_state;

    /// Creates a test router with the feature flag routes and admin authentication.
    async fn create_admin_test_router() -> (Router, AppState) {
        let state = create_test_state().await;
        let router = Router::new()
            .nest("/api/v1/admin/features", routes())
            .layer(Extension(TestUser::admin()))
            .with_state(state.clone());
        (router, state)
    }

    /// Creates a test router with analyst authentication (should fail).
    async fn create_analyst_test_router() -> (Router, AppState) {
        let state = create_test_state().await;
        let router = Router::new()
            .nest("/api/v1/admin/features", routes())
            .layer(Extension(TestUser::analyst()))
            .with_state(state.clone());
        (router, state)
    }

    /// Helper to create a test feature flag directly in the database.
    async fn create_test_flag(state: &AppState, name: &str, enabled: bool) -> FeatureFlag {
        let feature_flags = get_feature_flags_service(state).await.unwrap();
        let flag = FeatureFlag::new(name, &format!("Test flag: {}", name), enabled, None).unwrap();
        feature_flags.upsert(&flag).await.unwrap();
        flag
    }

    // ==============================================
    // Authentication Tests
    // ==============================================

    #[tokio::test]
    async fn test_list_flags_requires_admin() {
        let (app, _state) = create_analyst_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/features")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    // ==============================================
    // List Feature Flags Tests
    // ==============================================

    #[tokio::test]
    async fn test_list_feature_flags_returns_defaults() {
        let (app, _state) = create_admin_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/features")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagsListResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        // Default flags are seeded by the migration: multi_tenancy, distributed_queue,
        // enrichment_cache, rag_analysis, nl_query
        assert_eq!(result.flags.len(), 5);
        assert_eq!(result.total, 5);

        // Verify expected default flags exist
        let names: Vec<&str> = result.flags.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"multi_tenancy"));
        assert!(names.contains(&"distributed_queue"));
        assert!(names.contains(&"enrichment_cache"));
    }

    #[tokio::test]
    async fn test_list_feature_flags_with_additional_data() {
        let (app, state) = create_admin_test_router().await;

        // Create additional test flags on top of the 5 default flags
        create_test_flag(&state, "flag_a", true).await;
        create_test_flag(&state, "flag_b", false).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/features")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagsListResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        // 5 default flags + 2 test flags = 7
        assert_eq!(result.flags.len(), 7);
        assert_eq!(result.total, 7);

        // Verify our test flags exist
        let names: Vec<&str> = result.flags.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"flag_a"));
        assert!(names.contains(&"flag_b"));
    }

    // ==============================================
    // Get Feature Flag Tests
    // ==============================================

    #[tokio::test]
    async fn test_get_feature_flag_success() {
        let (app, state) = create_admin_test_router().await;

        create_test_flag(&state, "test_flag", true).await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/features/test_flag")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.name, "test_flag");
        assert!(result.enabled);
    }

    #[tokio::test]
    async fn test_get_feature_flag_not_found() {
        let (app, _state) = create_admin_test_router().await;

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/admin/features/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Update Feature Flag Tests
    // ==============================================

    #[tokio::test]
    async fn test_update_feature_flag_success() {
        let (app, state) = create_admin_test_router().await;

        create_test_flag(&state, "update_flag", false).await;

        let request_body = serde_json::json!({
            "enabled": true,
            "description": "Updated description"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/features/update_flag")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.name, "update_flag");
        assert!(result.enabled);
        assert_eq!(result.description, Some("Updated description".to_string()));
    }

    #[tokio::test]
    async fn test_update_feature_flag_not_found() {
        let (app, _state) = create_admin_test_router().await;

        let request_body = serde_json::json!({
            "enabled": true
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/features/nonexistent")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_feature_flag_percentage_rollout() {
        let (app, state) = create_admin_test_router().await;

        create_test_flag(&state, "rollout_flag", false).await;

        let request_body = serde_json::json!({
            "percentage_rollout": 50
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/v1/admin/features/rollout_flag")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(result.percentage_rollout, Some(50));
    }

    // ==============================================
    // Tenant Override Tests
    // ==============================================

    #[tokio::test]
    async fn test_set_tenant_override_success() {
        let (app, state) = create_admin_test_router().await;

        create_test_flag(&state, "override_flag", false).await;

        let tenant_id = Uuid::new_v4();
        let request_body = serde_json::json!({
            "enabled": true
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/api/v1/admin/features/override_flag/override/{}",
                        tenant_id
                    ))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert_eq!(
            result.tenant_overrides.get(&tenant_id.to_string()),
            Some(&true)
        );
    }

    #[tokio::test]
    async fn test_set_tenant_override_flag_not_found() {
        let (app, _state) = create_admin_test_router().await;

        let tenant_id = Uuid::new_v4();
        let request_body = serde_json::json!({
            "enabled": true
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!(
                        "/api/v1/admin/features/nonexistent/override/{}",
                        tenant_id
                    ))
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_string(&request_body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_remove_tenant_override_success() {
        let (app, state) = create_admin_test_router().await;

        // Create flag with a tenant override
        let feature_flags = get_feature_flags_service(&state).await.unwrap();
        let mut flag = FeatureFlag::new("remove_override_flag", "Test", false, None).unwrap();
        let tenant_id = Uuid::new_v4();
        flag.set_tenant_override(tenant_id, true);
        feature_flags.upsert(&flag).await.unwrap();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v1/admin/features/remove_override_flag/override/{}",
                        tenant_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: FeatureFlagResponse =
            serde_json::from_slice(&body).expect("Failed to parse response");

        assert!(result.tenant_overrides.is_empty());
    }

    #[tokio::test]
    async fn test_remove_tenant_override_not_found() {
        let (app, state) = create_admin_test_router().await;

        create_test_flag(&state, "no_override_flag", false).await;

        let tenant_id = Uuid::new_v4();

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!(
                        "/api/v1/admin/features/no_override_flag/override/{}",
                        tenant_id
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // ==============================================
    // Response Type Tests
    // ==============================================

    #[test]
    fn test_feature_flag_response_from_flag() {
        let mut flag = FeatureFlag::new("test", "Description", true, Some(50)).unwrap();
        let tenant_id = Uuid::new_v4();
        flag.set_tenant_override(tenant_id, false);

        let response: FeatureFlagResponse = flag.into();

        assert_eq!(response.name, "test");
        assert_eq!(response.description, Some("Description".to_string()));
        assert!(response.enabled);
        assert_eq!(response.percentage_rollout, Some(50));
        assert_eq!(
            response.tenant_overrides.get(&tenant_id.to_string()),
            Some(&false)
        );
    }

    #[test]
    fn test_feature_flag_response_empty_description() {
        let flag = FeatureFlag::new("test", "", true, None).unwrap();
        let response: FeatureFlagResponse = flag.into();

        assert_eq!(response.description, None);
    }

    #[test]
    fn test_update_request_validation() {
        // Valid request
        let valid = UpdateFeatureFlagRequest {
            enabled: Some(true),
            description: Some("Test".to_string()),
            percentage_rollout: Some(50),
        };
        assert!(valid.validate().is_ok());

        // Empty request is also valid
        let empty = UpdateFeatureFlagRequest {
            enabled: None,
            description: None,
            percentage_rollout: None,
        };
        assert!(empty.validate().is_ok());
    }
}
