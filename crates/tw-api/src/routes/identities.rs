//! Identity management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::{AssetStoreError, EntityRef, IdentitySearchParams};

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
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ListIdentitiesQuery>,
) -> Result<Json<PaginatedIdentityResponse>, ApiError> {
    query.validate()?;

    let tenant_id = tenant_id_or_default(tenant);
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);
    let offset = ((page - 1) * per_page) as usize;
    let parsed_identity_type = query
        .identity_type
        .as_deref()
        .map(parse_identity_type)
        .transpose()?;
    let parsed_status = query
        .status
        .as_deref()
        .map(parse_identity_status)
        .transpose()?;

    let filtered_total = state
        .identity_store
        .search(
            tenant_id,
            &IdentitySearchParams {
                display_name: query.display_name.clone(),
                identity_type: parsed_identity_type.clone(),
                status: parsed_status.clone(),
                department: query.department.clone(),
                min_risk_score: query.min_risk_score,
                limit: None,
                offset: None,
            },
        )
        .await
        .map_err(map_asset_store_error)?
        .len() as u64;

    let identities = state
        .identity_store
        .search(
            tenant_id,
            &IdentitySearchParams {
                display_name: query.display_name,
                identity_type: parsed_identity_type,
                status: parsed_status,
                department: query.department,
                min_risk_score: query.min_risk_score,
                limit: Some(per_page as usize),
                offset: Some(offset),
            },
        )
        .await
        .map_err(map_asset_store_error)?;

    let total_pages = if filtered_total == 0 {
        0
    } else {
        ((filtered_total as f64) / (per_page as f64)).ceil() as u32
    };

    Ok(Json(PaginatedIdentityResponse {
        data: identities.iter().map(identity_to_response).collect(),
        page,
        per_page,
        total_items: filtered_total,
        total_pages,
    }))
}

/// Create a new identity.
async fn create_identity(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<CreateIdentityRequest>,
) -> Result<(StatusCode, Json<IdentityResponse>), ApiError> {
    request.validate()?;

    let identity_type = parse_identity_type(&request.identity_type)?;
    let tenant_id = tenant_id_or_default(tenant);

    let existing = state
        .identity_store
        .find_by_identifier(tenant_id, &request.primary_identifier)
        .await
        .map_err(map_asset_store_error)?;
    if existing.is_some() {
        return Err(ApiError::Conflict(format!(
            "Identity with identifier '{}' already exists",
            request.primary_identifier
        )));
    }

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

    state
        .identity_store
        .create(&identity)
        .await
        .map_err(map_asset_store_error)?;

    let response = identity_to_response(&identity);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get identity by ID.
async fn get_identity(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<IdentityResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let identity = state
        .identity_store
        .find_by_id(tenant_id, id)
        .await
        .map_err(map_asset_store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("Identity {} not found", id)))?;

    Ok(Json(identity_to_response(&identity)))
}

/// Update an identity.
async fn update_identity(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateIdentityRequest>,
) -> Result<Json<IdentityResponse>, ApiError> {
    request.validate()?;

    let tenant_id = tenant_id_or_default(tenant);
    let mut identity = state
        .identity_store
        .find_by_id(tenant_id, id)
        .await
        .map_err(map_asset_store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("Identity {} not found", id)))?;

    if let Some(display_name) = request.display_name {
        identity.display_name = display_name;
    }
    if let Some(department) = request.department {
        identity.department = Some(department);
    }
    if let Some(status) = request.status {
        identity.status = parse_identity_status(&status)?;
    }
    if let Some(risk_score) = request.risk_score {
        identity.set_risk_score(risk_score);
    }
    if let Some(groups) = request.groups {
        identity.groups = groups;
    }
    if let Some(permissions) = request.permissions {
        identity.permissions = permissions;
    }
    if let Some(metadata) = request.metadata {
        identity.metadata = metadata;
    }
    identity.updated_at = Utc::now();

    state
        .identity_store
        .update(&identity)
        .await
        .map_err(map_asset_store_error)?;

    Ok(Json(identity_to_response(&identity)))
}

/// Get associated assets for an identity.
async fn get_identity_assets(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<AssociatedAssetResponse>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let identity = state
        .identity_store
        .find_by_id(tenant_id, id)
        .await
        .map_err(map_asset_store_error)?
        .ok_or_else(|| ApiError::NotFound(format!("Identity {} not found", id)))?;

    let relationships = state
        .relationship_store
        .find_relationships(tenant_id, &EntityRef::identity(id), None)
        .await
        .map_err(map_asset_store_error)?;

    let mut relationship_map: HashMap<Uuid, String> = HashMap::new();
    for relationship in relationships {
        if relationship.source_entity.id == id {
            relationship_map.insert(
                relationship.target_entity.id,
                format!("{}", relationship.relationship_type),
            );
        } else if relationship.target_entity.id == id {
            relationship_map.insert(
                relationship.source_entity.id,
                format!("{}", relationship.relationship_type),
            );
        }
    }

    let mut response = Vec::new();
    for asset_id in identity.associated_assets {
        if let Some(asset) = state
            .asset_store
            .find_by_id(tenant_id, asset_id)
            .await
            .map_err(map_asset_store_error)?
        {
            response.push(AssociatedAssetResponse {
                asset_id: asset.id,
                asset_name: asset.name,
                asset_type: format!("{}", asset.asset_type),
                criticality: format!("{}", asset.criticality),
                relationship_type: relationship_map
                    .get(&asset.id)
                    .cloned()
                    .unwrap_or_else(|| "Associated".to_string()),
            });
        }
    }

    Ok(Json(response))
}

// ============================================================================
// Helpers
// ============================================================================

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

fn map_asset_store_error(error: AssetStoreError) -> ApiError {
    match error {
        AssetStoreError::NotFound(msg) => ApiError::NotFound(msg),
        AssetStoreError::Duplicate(msg) => ApiError::Conflict(msg),
        AssetStoreError::Internal(msg) => ApiError::Internal(msg),
    }
}

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
