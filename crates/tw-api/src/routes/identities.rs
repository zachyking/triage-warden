//! Identity management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;

/// Creates identity routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_identities).post(create_identity))
        .route("/:id", get(get_identity).put(update_identity))
        .route("/:id/assets", get(get_identity_assets))
}

// ============================================================================
// DTOs
// ============================================================================

/// Query parameters for listing identities.
#[derive(Debug, Deserialize, Validate)]
pub struct ListIdentitiesQuery {
    /// Search by display name.
    pub display_name: Option<String>,
    /// Filter by identity type.
    pub identity_type: Option<String>,
    /// Filter by status.
    pub status: Option<String>,
    /// Filter by department.
    pub department: Option<String>,
    /// Filter by minimum risk score.
    pub min_risk_score: Option<f32>,
    /// Page number (1-indexed).
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page.
    #[validate(range(min = 1, max = 200))]
    pub per_page: Option<u32>,
}

/// Request body for creating an identity.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateIdentityRequest {
    /// Identity type (user, service_account, shared_account, admin, external).
    pub identity_type: String,
    /// Primary identifier (email or username).
    #[validate(length(min = 1, max = 255))]
    pub primary_identifier: String,
    /// Display name.
    #[validate(length(min = 1, max = 255))]
    pub display_name: String,
    /// Department.
    pub department: Option<String>,
    /// Security groups.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Permissions.
    #[serde(default)]
    pub permissions: Vec<String>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Request body for updating an identity.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateIdentityRequest {
    /// Display name.
    #[validate(length(min = 1, max = 255))]
    pub display_name: Option<String>,
    /// Department.
    pub department: Option<String>,
    /// Status.
    pub status: Option<String>,
    /// Risk score.
    pub risk_score: Option<f32>,
    /// Security groups (replaces all).
    pub groups: Option<Vec<String>>,
    /// Permissions (replaces all).
    pub permissions: Option<Vec<String>>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Identity response DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentityResponse {
    pub id: Uuid,
    pub identity_type: String,
    pub primary_identifier: String,
    pub display_name: String,
    pub department: Option<String>,
    pub manager: Option<Uuid>,
    pub risk_score: f32,
    pub status: String,
    pub groups: Vec<String>,
    pub permissions: Vec<String>,
    pub associated_assets: Vec<Uuid>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub source_connectors: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Paginated identity response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedIdentityResponse {
    pub data: Vec<IdentityResponse>,
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

/// Associated asset summary.
#[derive(Debug, Serialize, ToSchema)]
pub struct AssociatedAssetResponse {
    pub asset_id: Uuid,
    pub asset_name: String,
    pub asset_type: String,
    pub criticality: String,
    pub relationship_type: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// List identities with pagination and filters.
async fn list_identities(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<ListIdentitiesQuery>,
) -> Result<Json<PaginatedIdentityResponse>, ApiError> {
    query.validate()?;

    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);

    Ok(Json(PaginatedIdentityResponse {
        data: vec![],
        page,
        per_page,
        total_items: 0,
        total_pages: 0,
    }))
}

/// Create a new identity.
async fn create_identity(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<CreateIdentityRequest>,
) -> Result<(StatusCode, Json<IdentityResponse>), ApiError> {
    request.validate()?;

    let identity_type = parse_identity_type(&request.identity_type)?;
    let tenant_id = tw_core::auth::DEFAULT_TENANT_ID;

    let mut identity = tw_core::models::Identity::new(
        tenant_id,
        identity_type,
        request.primary_identifier,
        request.display_name,
    );
    identity.department = request.department;
    identity.groups = request.groups;
    identity.permissions = request.permissions;
    if let Some(metadata) = request.metadata {
        identity.metadata = metadata;
    }

    let response = identity_to_response(&identity);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get identity by ID.
async fn get_identity(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<IdentityResponse>, ApiError> {
    Err(ApiError::NotFound(format!("Identity {} not found", id)))
}

/// Update an identity.
async fn update_identity(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateIdentityRequest>,
) -> Result<Json<IdentityResponse>, ApiError> {
    request.validate()?;

    // Validate status if provided
    if let Some(ref status) = request.status {
        let _status = parse_identity_status(status)?;
    }

    Err(ApiError::NotFound(format!("Identity {} not found", id)))
}

/// Get associated assets for an identity.
async fn get_identity_assets(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AssociatedAssetResponse>>, ApiError> {
    // Return empty for now - will be connected to RelationshipStore
    let _ = id;
    Ok(Json(vec![]))
}

// ============================================================================
// Helpers
// ============================================================================

fn identity_to_response(identity: &tw_core::models::Identity) -> IdentityResponse {
    IdentityResponse {
        id: identity.id,
        identity_type: format!("{}", identity.identity_type),
        primary_identifier: identity.primary_identifier.clone(),
        display_name: identity.display_name.clone(),
        department: identity.department.clone(),
        manager: identity.manager,
        risk_score: identity.risk_score,
        status: format!("{}", identity.status),
        groups: identity.groups.clone(),
        permissions: identity.permissions.clone(),
        associated_assets: identity.associated_assets.clone(),
        last_activity: identity.last_activity,
        source_connectors: identity.source_connectors.clone(),
        created_at: identity.created_at,
        updated_at: identity.updated_at,
    }
}

fn parse_identity_type(s: &str) -> Result<tw_core::models::IdentityType, ApiError> {
    use tw_core::models::IdentityType;
    match s.to_lowercase().as_str() {
        "user" => Ok(IdentityType::User),
        "service_account" => Ok(IdentityType::ServiceAccount),
        "shared_account" => Ok(IdentityType::SharedAccount),
        "admin" => Ok(IdentityType::Admin),
        "external" => Ok(IdentityType::External),
        _ => Ok(IdentityType::Custom(s.to_string())),
    }
}

fn parse_identity_status(s: &str) -> Result<tw_core::models::IdentityStatus, ApiError> {
    use tw_core::models::IdentityStatus;
    match s.to_lowercase().as_str() {
        "active" => Ok(IdentityStatus::Active),
        "suspended" => Ok(IdentityStatus::Suspended),
        "disabled" => Ok(IdentityStatus::Disabled),
        "locked_out" => Ok(IdentityStatus::LockedOut),
        "deprovisioned" => Ok(IdentityStatus::Deprovisioned),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid identity status: {}. Must be one of: active, suspended, disabled, locked_out, deprovisioned",
            s
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_identity_type() {
        assert!(matches!(
            parse_identity_type("user"),
            Ok(tw_core::models::IdentityType::User)
        ));
        assert!(matches!(
            parse_identity_type("service_account"),
            Ok(tw_core::models::IdentityType::ServiceAccount)
        ));
        assert!(matches!(
            parse_identity_type("admin"),
            Ok(tw_core::models::IdentityType::Admin)
        ));
        assert!(matches!(
            parse_identity_type("custom_type"),
            Ok(tw_core::models::IdentityType::Custom(_))
        ));
    }

    #[test]
    fn test_parse_identity_status() {
        assert!(matches!(
            parse_identity_status("active"),
            Ok(tw_core::models::IdentityStatus::Active)
        ));
        assert!(matches!(
            parse_identity_status("suspended"),
            Ok(tw_core::models::IdentityStatus::Suspended)
        ));
        assert!(matches!(
            parse_identity_status("disabled"),
            Ok(tw_core::models::IdentityStatus::Disabled)
        ));
        assert!(matches!(
            parse_identity_status("locked_out"),
            Ok(tw_core::models::IdentityStatus::LockedOut)
        ));
        assert!(parse_identity_status("invalid").is_err());
    }

    #[test]
    fn test_parse_identity_type_case_insensitive() {
        assert!(matches!(
            parse_identity_type("USER"),
            Ok(tw_core::models::IdentityType::User)
        ));
        assert!(matches!(
            parse_identity_type("Service_Account"),
            Ok(tw_core::models::IdentityType::ServiceAccount)
        ));
    }

    #[test]
    fn test_identity_to_response() {
        let mut identity = tw_core::models::Identity::new(
            Uuid::new_v4(),
            tw_core::models::IdentityType::User,
            "jdoe@example.com".to_string(),
            "John Doe".to_string(),
        );
        identity.department = Some("Engineering".to_string());
        identity.set_risk_score(45.0);

        let response = identity_to_response(&identity);
        assert_eq!(response.display_name, "John Doe");
        assert_eq!(response.primary_identifier, "jdoe@example.com");
        assert_eq!(response.identity_type, "User");
        assert_eq!(response.risk_score, 45.0);
        assert_eq!(response.department, Some("Engineering".to_string()));
    }
}
