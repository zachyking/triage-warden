//! Asset management endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;

/// Creates asset routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_assets).post(create_asset))
        .route(
            "/:id",
            get(get_asset).put(update_asset).delete(delete_asset),
        )
        .route("/:id/relationships", get(get_relationships))
        .route("/import", post(bulk_import))
}

// ============================================================================
// DTOs
// ============================================================================

/// Query parameters for listing assets.
#[derive(Debug, Deserialize, Validate)]
pub struct ListAssetsQuery {
    /// Search by name.
    pub name: Option<String>,
    /// Filter by asset type.
    pub asset_type: Option<String>,
    /// Filter by criticality.
    pub criticality: Option<String>,
    /// Filter by environment.
    pub environment: Option<String>,
    /// Page number (1-indexed).
    #[validate(range(min = 1))]
    pub page: Option<u32>,
    /// Items per page.
    #[validate(range(min = 1, max = 200))]
    pub per_page: Option<u32>,
}

/// Request body for creating an asset.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateAssetRequest {
    /// Asset name.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// Asset type.
    pub asset_type: String,
    /// Business criticality.
    pub criticality: String,
    /// Environment.
    pub environment: String,
    /// Identifiers.
    #[serde(default)]
    pub identifiers: Vec<IdentifierInput>,
    /// Team responsible.
    pub team: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: HashMap<String, String>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Request body for updating an asset.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateAssetRequest {
    /// Asset name.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    /// Business criticality.
    pub criticality: Option<String>,
    /// Environment.
    pub environment: Option<String>,
    /// Team responsible.
    pub team: Option<String>,
    /// Tags (replaces all).
    pub tags: Option<HashMap<String, String>>,
    /// Additional metadata.
    pub metadata: Option<serde_json::Value>,
}

/// Identifier input for creating/updating assets.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct IdentifierInput {
    /// Type of identifier (hostname, ipv4, ipv6, mac_address, fqdn, etc.).
    pub identifier_type: String,
    /// Identifier value.
    pub value: String,
    /// Source of the identifier.
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "api".to_string()
}

/// Request body for bulk asset import.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct BulkImportRequest {
    /// Assets to import.
    pub assets: Vec<CreateAssetRequest>,
}

/// Asset response DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct AssetResponse {
    pub id: Uuid,
    pub name: String,
    pub asset_type: String,
    pub criticality: String,
    pub environment: String,
    pub team: Option<String>,
    pub identifiers: Vec<IdentifierResponse>,
    pub tags: HashMap<String, String>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub source_connectors: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Identifier response DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct IdentifierResponse {
    pub identifier_type: String,
    pub value: String,
    pub confidence: f64,
    pub source: String,
}

/// Relationship response DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct RelationshipResponse {
    pub id: Uuid,
    pub source_entity_type: String,
    pub source_entity_id: Uuid,
    pub target_entity_type: String,
    pub target_entity_id: Uuid,
    pub relationship_type: String,
    pub strength: f32,
    pub evidence: Vec<String>,
    pub first_seen: chrono::DateTime<chrono::Utc>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
}

/// Bulk import result DTO.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkImportResponse {
    pub created: u32,
    pub errors: u32,
    pub error_details: Vec<String>,
}

/// Paginated response wrapper.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaginatedAssetResponse {
    pub data: Vec<AssetResponse>,
    pub page: u32,
    pub per_page: u32,
    pub total_items: u64,
    pub total_pages: u32,
}

// ============================================================================
// Handlers
// ============================================================================

/// List assets with pagination and filters.
async fn list_assets(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<ListAssetsQuery>,
) -> Result<Json<PaginatedAssetResponse>, ApiError> {
    query.validate()?;

    // In a full implementation, this would use AssetStore from AppState.
    // For now, return an empty paginated response.
    let page = query.page.unwrap_or(1);
    let per_page = query.per_page.unwrap_or(20);

    Ok(Json(PaginatedAssetResponse {
        data: vec![],
        page,
        per_page,
        total_items: 0,
        total_pages: 0,
    }))
}

/// Create a new asset.
async fn create_asset(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<CreateAssetRequest>,
) -> Result<(StatusCode, Json<AssetResponse>), ApiError> {
    request.validate()?;

    let asset_type = parse_asset_type(&request.asset_type)?;
    let criticality = parse_criticality(&request.criticality)?;
    let environment = parse_environment(&request.environment)?;

    let tenant_id = tw_core::auth::DEFAULT_TENANT_ID;
    let mut asset = tw_core::models::Asset::new(
        tenant_id,
        request.name,
        asset_type,
        criticality,
        environment,
    );
    asset.team = request.team;
    asset.tags = request.tags;
    if let Some(metadata) = request.metadata {
        asset.metadata = metadata;
    }

    for id_input in &request.identifiers {
        let id_type = parse_identifier_type(&id_input.identifier_type)?;
        asset.add_identifier(tw_core::models::AssetIdentifier::new(
            id_type,
            id_input.value.clone(),
            id_input.source.clone(),
        ));
    }

    let response = asset_to_response(&asset);
    Ok((StatusCode::CREATED, Json(response)))
}

/// Get asset by ID.
async fn get_asset(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<AssetResponse>, ApiError> {
    Err(ApiError::NotFound(format!("Asset {} not found", id)))
}

/// Update an asset.
async fn update_asset(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateAssetRequest>,
) -> Result<Json<AssetResponse>, ApiError> {
    request.validate()?;
    Err(ApiError::NotFound(format!("Asset {} not found", id)))
}

/// Delete an asset.
async fn delete_asset(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    Err(ApiError::NotFound(format!("Asset {} not found", id)))
}

/// Get relationships for an asset.
async fn get_relationships(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<RelationshipResponse>>, ApiError> {
    // Return empty for now - will be connected to RelationshipStore
    let _ = id;
    Ok(Json(vec![]))
}

/// Bulk import assets.
async fn bulk_import(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<BulkImportRequest>,
) -> Result<(StatusCode, Json<BulkImportResponse>), ApiError> {
    request.validate()?;

    let mut created = 0u32;
    let mut errors = 0u32;
    let mut error_details = Vec::new();

    for (i, asset_req) in request.assets.iter().enumerate() {
        if let Err(e) = asset_req.validate() {
            errors += 1;
            error_details.push(format!("Asset [{}]: {}", i, e));
            continue;
        }
        if parse_asset_type(&asset_req.asset_type).is_err()
            || parse_criticality(&asset_req.criticality).is_err()
            || parse_environment(&asset_req.environment).is_err()
        {
            errors += 1;
            error_details.push(format!(
                "Asset [{}]: invalid type/criticality/environment",
                i
            ));
            continue;
        }
        created += 1;
    }

    Ok((
        StatusCode::OK,
        Json(BulkImportResponse {
            created,
            errors,
            error_details,
        }),
    ))
}

// ============================================================================
// Helpers
// ============================================================================

fn asset_to_response(asset: &tw_core::models::Asset) -> AssetResponse {
    AssetResponse {
        id: asset.id,
        name: asset.name.clone(),
        asset_type: format!("{}", asset.asset_type),
        criticality: format!("{}", asset.criticality),
        environment: format!("{}", asset.environment),
        team: asset.team.clone(),
        identifiers: asset
            .identifiers
            .iter()
            .map(|id| IdentifierResponse {
                identifier_type: format!("{}", id.identifier_type),
                value: id.value.clone(),
                confidence: id.confidence,
                source: id.source.clone(),
            })
            .collect(),
        tags: asset.tags.clone(),
        last_seen: asset.last_seen,
        source_connectors: asset.source_connectors.clone(),
        created_at: asset.created_at,
        updated_at: asset.updated_at,
    }
}

fn parse_asset_type(s: &str) -> Result<tw_core::models::AssetType, ApiError> {
    use tw_core::models::AssetType;
    match s.to_lowercase().as_str() {
        "server" => Ok(AssetType::Server),
        "workstation" => Ok(AssetType::Workstation),
        "mobile_device" => Ok(AssetType::MobileDevice),
        "network_device" => Ok(AssetType::NetworkDevice),
        "cloud_instance" => Ok(AssetType::CloudInstance),
        "container" => Ok(AssetType::Container),
        "database" => Ok(AssetType::Database),
        "application" => Ok(AssetType::Application),
        "iot_device" => Ok(AssetType::IotDevice),
        _ => Ok(AssetType::Custom(s.to_string())),
    }
}

fn parse_criticality(s: &str) -> Result<tw_core::models::Criticality, ApiError> {
    use tw_core::models::Criticality;
    match s.to_lowercase().as_str() {
        "low" => Ok(Criticality::Low),
        "medium" => Ok(Criticality::Medium),
        "high" => Ok(Criticality::High),
        "critical" => Ok(Criticality::Critical),
        _ => Err(ApiError::BadRequest(format!(
            "Invalid criticality: {}. Must be one of: low, medium, high, critical",
            s
        ))),
    }
}

fn parse_environment(s: &str) -> Result<tw_core::models::Environment, ApiError> {
    use tw_core::models::Environment;
    match s.to_lowercase().as_str() {
        "production" => Ok(Environment::Production),
        "staging" => Ok(Environment::Staging),
        "development" => Ok(Environment::Development),
        "testing" => Ok(Environment::Testing),
        _ => Ok(Environment::Custom(s.to_string())),
    }
}

fn parse_identifier_type(s: &str) -> Result<tw_core::models::IdentifierType, ApiError> {
    use tw_core::models::IdentifierType;
    match s.to_lowercase().as_str() {
        "hostname" => Ok(IdentifierType::Hostname),
        "ipv4" => Ok(IdentifierType::Ipv4),
        "ipv6" => Ok(IdentifierType::Ipv6),
        "mac_address" => Ok(IdentifierType::MacAddress),
        "fqdn" => Ok(IdentifierType::Fqdn),
        "cloud_instance_id" => Ok(IdentifierType::CloudInstanceId),
        "cloud_arn" => Ok(IdentifierType::CloudArn),
        "serial_number" => Ok(IdentifierType::SerialNumber),
        _ => Ok(IdentifierType::Custom(s.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_asset_type() {
        assert!(matches!(
            parse_asset_type("server"),
            Ok(tw_core::models::AssetType::Server)
        ));
        assert!(matches!(
            parse_asset_type("workstation"),
            Ok(tw_core::models::AssetType::Workstation)
        ));
        assert!(matches!(
            parse_asset_type("database"),
            Ok(tw_core::models::AssetType::Database)
        ));
        assert!(matches!(
            parse_asset_type("custom_thing"),
            Ok(tw_core::models::AssetType::Custom(_))
        ));
    }

    #[test]
    fn test_parse_criticality() {
        assert!(matches!(
            parse_criticality("low"),
            Ok(tw_core::models::Criticality::Low)
        ));
        assert!(matches!(
            parse_criticality("medium"),
            Ok(tw_core::models::Criticality::Medium)
        ));
        assert!(matches!(
            parse_criticality("high"),
            Ok(tw_core::models::Criticality::High)
        ));
        assert!(matches!(
            parse_criticality("critical"),
            Ok(tw_core::models::Criticality::Critical)
        ));
        assert!(parse_criticality("invalid").is_err());
    }

    #[test]
    fn test_parse_environment() {
        assert!(matches!(
            parse_environment("production"),
            Ok(tw_core::models::Environment::Production)
        ));
        assert!(matches!(
            parse_environment("staging"),
            Ok(tw_core::models::Environment::Staging)
        ));
        assert!(matches!(
            parse_environment("development"),
            Ok(tw_core::models::Environment::Development)
        ));
        assert!(matches!(
            parse_environment("custom_env"),
            Ok(tw_core::models::Environment::Custom(_))
        ));
    }

    #[test]
    fn test_parse_identifier_type() {
        assert!(matches!(
            parse_identifier_type("hostname"),
            Ok(tw_core::models::IdentifierType::Hostname)
        ));
        assert!(matches!(
            parse_identifier_type("ipv4"),
            Ok(tw_core::models::IdentifierType::Ipv4)
        ));
        assert!(matches!(
            parse_identifier_type("cloud_arn"),
            Ok(tw_core::models::IdentifierType::CloudArn)
        ));
        assert!(matches!(
            parse_identifier_type("custom_id"),
            Ok(tw_core::models::IdentifierType::Custom(_))
        ));
    }

    #[test]
    fn test_parse_criticality_case_insensitive() {
        assert!(matches!(
            parse_criticality("HIGH"),
            Ok(tw_core::models::Criticality::High)
        ));
        assert!(matches!(
            parse_criticality("Critical"),
            Ok(tw_core::models::Criticality::Critical)
        ));
    }

    #[test]
    fn test_asset_to_response() {
        let mut asset = tw_core::models::Asset::new(
            Uuid::new_v4(),
            "test-server".to_string(),
            tw_core::models::AssetType::Server,
            tw_core::models::Criticality::High,
            tw_core::models::Environment::Production,
        );
        asset.team = Some("Platform Team".to_string());
        asset.add_identifier(tw_core::models::AssetIdentifier::new(
            tw_core::models::IdentifierType::Hostname,
            "test-server.corp".to_string(),
            "cmdb".to_string(),
        ));

        let response = asset_to_response(&asset);
        assert_eq!(response.name, "test-server");
        assert_eq!(response.asset_type, "Server");
        assert_eq!(response.criticality, "High");
        assert_eq!(response.environment, "Production");
        assert_eq!(response.team, Some("Platform Team".to_string()));
        assert_eq!(response.identifiers.len(), 1);
        assert_eq!(response.identifiers[0].value, "test-server.corp");
    }
}
