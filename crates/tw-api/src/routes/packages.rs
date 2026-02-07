//! Content package API endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::db::{
    create_playbook_repository, create_settings_repository, PlaybookRepository, PlaybookUpdate,
};
use tw_core::hunting::{HuntType, HuntingHunt, HuntingQuery, QueryType};
use tw_core::playbook::{Playbook, PlaybookStage};

const PACKAGES_SETTINGS_KEY: &str = "content_packages_v1";
const HUNTS_SETTINGS_KEY: &str = "hunting_hunts_v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImportedPackageRecord {
    id: Uuid,
    imported_at: DateTime<Utc>,
    manifest: ManifestDto,
    contents: Vec<ContentDto>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConflictMode {
    Skip,
    Overwrite,
    Rename,
}

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

/// Creates package routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/import", post(import_package))
        .route("/validate", post(validate_package))
        .route("/export/playbook/:id", post(export_playbook))
        .route("/export/hunt/:id", post(export_hunt))
}

// ============================================================================
// DTOs
// ============================================================================

/// Request to import a content package.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportPackageRequest {
    /// The package to import.
    pub package: PackageDto,
    /// How to resolve name conflicts.
    #[serde(default = "default_conflict_resolution")]
    pub conflict_resolution: String,
}

fn default_conflict_resolution() -> String {
    "skip".to_string()
}

/// A content package for API transport.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PackageDto {
    /// Package manifest.
    pub manifest: ManifestDto,
    /// Package contents.
    pub contents: Vec<ContentDto>,
}

/// Package manifest DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ManifestDto {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Description.
    pub description: String,
    /// Author.
    pub author: String,
    /// License (optional).
    pub license: Option<String>,
    /// Tags.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Compatibility version.
    pub compatibility: Option<String>,
}

/// A content item in a package DTO.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentDto {
    Playbook {
        name: String,
        data: serde_json::Value,
    },
    Hunt {
        name: String,
        data: serde_json::Value,
    },
    Knowledge {
        title: String,
        content: String,
    },
    Query {
        name: String,
        query_type: String,
        query: String,
    },
}

/// Response from importing a package.
#[derive(Debug, Serialize, ToSchema)]
pub struct ImportResultResponse {
    /// Number of items imported.
    pub imported: usize,
    /// Number of items skipped.
    pub skipped: usize,
    /// Errors encountered.
    pub errors: Vec<String>,
}

/// Response from validating a package.
#[derive(Debug, Serialize, ToSchema)]
pub struct ValidationResultResponse {
    /// Whether the package is valid.
    pub valid: bool,
    /// Warning messages.
    pub warnings: Vec<String>,
    /// Error messages.
    pub errors: Vec<String>,
    /// Number of content items.
    pub content_count: usize,
}

/// Response containing an exported package.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExportResponse {
    /// The exported package.
    pub package: PackageDto,
}

/// Request body for export operations.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ExportRequest {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// Package description.
    pub description: String,
    /// Author name.
    pub author: String,
    /// License (optional).
    pub license: Option<String>,
    /// Tags (optional).
    #[serde(default)]
    pub tags: Vec<String>,
}

// ============================================================================
// Handlers
// ============================================================================

/// Import a content package.
async fn import_package(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<ImportPackageRequest>,
) -> Result<(StatusCode, Json<ImportResultResponse>), ApiError> {
    let validation = validate_package_dto(&request.package);
    if !validation.valid {
        return Err(ApiError::BadRequest(format!(
            "Package validation failed: {}",
            validation.errors.join("; ")
        )));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let conflict_mode = parse_conflict_mode(&request.conflict_resolution)?;
    let playbook_repo = create_playbook_repository(&state.db);
    let mut hunts = load_hunts(&state, tenant_id).await?;

    let mut imported = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    for content in &request.package.contents {
        let result = match content {
            ContentDto::Playbook { name, data } => {
                import_playbook_content(
                    playbook_repo.as_ref(),
                    tenant_id,
                    conflict_mode,
                    name,
                    data,
                )
                .await
            }
            ContentDto::Hunt { name, data } => {
                import_hunt_content(&mut hunts, tenant_id, conflict_mode, name, data)
            }
            ContentDto::Knowledge { .. } | ContentDto::Query { .. } => Ok(true),
        };

        match result {
            Ok(true) => imported += 1,
            Ok(false) => skipped += 1,
            Err(err) => {
                skipped += 1;
                errors.push(err);
            }
        }
    }

    save_hunts(&state, tenant_id, &hunts).await?;
    append_import_record(&state, tenant_id, &request.package).await?;

    Ok((
        StatusCode::OK,
        Json(ImportResultResponse {
            imported,
            skipped,
            errors,
        }),
    ))
}

/// Validate a content package without importing.
async fn validate_package(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<PackageDto>,
) -> Result<Json<ValidationResultResponse>, ApiError> {
    let result = validate_package_dto(&request);
    Ok(Json(result))
}

/// Export a playbook as a content package.
async fn export_playbook(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo = create_playbook_repository(&state.db);
    let playbook = repo
        .get_for_tenant(id, tenant_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Playbook {} not found", id)))?;

    let package = PackageDto {
        manifest: manifest_from_export_request(request),
        contents: vec![ContentDto::Playbook {
            name: playbook.name.clone(),
            data: serde_json::to_value(&playbook)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize playbook: {}", e)))?,
        }],
    };

    Ok(Json(ExportResponse { package }))
}

/// Export a hunt as a content package.
async fn export_hunt(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
    Json(request): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let hunts = load_hunts(&state, tenant_id).await?;
    let hunt = hunts
        .into_iter()
        .find(|h| h.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("Hunt {} not found", id)))?;

    let package = PackageDto {
        manifest: manifest_from_export_request(request),
        contents: vec![ContentDto::Hunt {
            name: hunt.name.clone(),
            data: serde_json::to_value(&hunt)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize hunt: {}", e)))?,
        }],
    };

    Ok(Json(ExportResponse { package }))
}

// ============================================================================
// Helpers
// ============================================================================

fn validate_package_dto(package: &PackageDto) -> ValidationResultResponse {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if package.manifest.name.is_empty() {
        errors.push("Package name is required".to_string());
    }
    if package.manifest.version.is_empty() {
        errors.push("Package version is required".to_string());
    }
    if package.manifest.author.is_empty() {
        warnings.push("Package author is not specified".to_string());
    }
    if package.contents.is_empty() {
        warnings.push("Package has no content items".to_string());
    }

    for (i, content) in package.contents.iter().enumerate() {
        let name = match content {
            ContentDto::Playbook { name, .. } => name,
            ContentDto::Hunt { name, .. } => name,
            ContentDto::Knowledge { title, .. } => title,
            ContentDto::Query { name, .. } => name,
        };

        if name.is_empty() {
            errors.push(format!("Content item {} has an empty name", i));
        }
    }

    ValidationResultResponse {
        valid: errors.is_empty(),
        warnings,
        errors,
        content_count: package.contents.len(),
    }
}

fn parse_conflict_mode(raw: &str) -> Result<ConflictMode, ApiError> {
    match raw.trim().to_lowercase().as_str() {
        "skip" => Ok(ConflictMode::Skip),
        "overwrite" => Ok(ConflictMode::Overwrite),
        "rename" => Ok(ConflictMode::Rename),
        other => Err(ApiError::BadRequest(format!(
            "Invalid conflict_resolution '{}'. Expected skip, overwrite, or rename",
            other
        ))),
    }
}

fn manifest_from_export_request(request: ExportRequest) -> ManifestDto {
    ManifestDto {
        name: request.name,
        version: request.version,
        description: request.description,
        author: request.author,
        license: request.license,
        tags: request.tags,
        compatibility: None,
    }
}

async fn load_hunts(state: &AppState, tenant_id: Uuid) -> Result<Vec<HuntingHunt>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, HUNTS_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?;
    match raw {
        Some(raw) => serde_json::from_str(&raw)
            .map_err(|e| ApiError::Internal(format!("Failed to deserialize hunts: {}", e))),
        None => Ok(Vec::new()),
    }
}

async fn save_hunts(
    state: &AppState,
    tenant_id: Uuid,
    hunts: &[HuntingHunt],
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let serialized = serde_json::to_string(hunts)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize hunts: {}", e)))?;
    repo.save_raw(tenant_id, HUNTS_SETTINGS_KEY, &serialized)
        .await
        .map_err(ApiError::from)
}

async fn load_import_records(
    state: &AppState,
    tenant_id: Uuid,
) -> Result<Vec<ImportedPackageRecord>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, PACKAGES_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?;
    match raw {
        Some(raw) => serde_json::from_str(&raw).map_err(|e| {
            ApiError::Internal(format!(
                "Failed to deserialize imported package records: {}",
                e
            ))
        }),
        None => Ok(Vec::new()),
    }
}

async fn save_import_records(
    state: &AppState,
    tenant_id: Uuid,
    records: &[ImportedPackageRecord],
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let serialized = serde_json::to_string(records).map_err(|e| {
        ApiError::Internal(format!(
            "Failed to serialize imported package records: {}",
            e
        ))
    })?;
    repo.save_raw(tenant_id, PACKAGES_SETTINGS_KEY, &serialized)
        .await
        .map_err(ApiError::from)
}

async fn append_import_record(
    state: &AppState,
    tenant_id: Uuid,
    package: &PackageDto,
) -> Result<(), ApiError> {
    let mut records = load_import_records(state, tenant_id).await?;
    records.push(ImportedPackageRecord {
        id: Uuid::new_v4(),
        imported_at: Utc::now(),
        manifest: package.manifest.clone(),
        contents: package.contents.clone(),
    });
    if records.len() > 100 {
        let trim = records.len() - 100;
        records.drain(0..trim);
    }
    save_import_records(state, tenant_id, &records).await
}

fn parse_hunt_type(raw: &str) -> HuntType {
    match raw {
        "scheduled" => HuntType::Scheduled,
        "continuous" => HuntType::Continuous,
        "triggered" => HuntType::Triggered,
        _ => HuntType::OnDemand,
    }
}

fn parse_query_type(raw: &str) -> QueryType {
    match raw {
        "splunk" => QueryType::Splunk,
        "elasticsearch" => QueryType::Elasticsearch,
        "sql" => QueryType::Sql,
        "kusto" => QueryType::Kusto,
        custom if !custom.is_empty() => QueryType::Custom(custom.to_string()),
        _ => QueryType::Custom("unknown".to_string()),
    }
}

fn playbook_from_content(name: &str, data: &serde_json::Value) -> Result<Playbook, String> {
    if let Ok(mut parsed) = serde_json::from_value::<Playbook>(data.clone()) {
        if parsed.name.trim().is_empty() {
            parsed.name = default_playbook_name(name);
        }
        return Ok(parsed);
    }

    let mut playbook = Playbook::new(
        default_playbook_name(name),
        data.get("trigger_type")
            .and_then(|v| v.as_str())
            .unwrap_or("alert"),
    );

    playbook.description = data
        .get("description")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    playbook.trigger_condition = data
        .get("trigger_condition")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    playbook.enabled = data
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if let Some(stages_value) = data.get("stages") {
        playbook.stages = serde_json::from_value::<Vec<PlaybookStage>>(stages_value.clone())
            .map_err(|e| format!("Invalid playbook stages: {}", e))?;
    }

    Ok(playbook)
}

fn hunt_from_content(
    name: &str,
    data: &serde_json::Value,
    tenant_id: Uuid,
) -> Result<HuntingHunt, String> {
    if let Ok(mut parsed) = serde_json::from_value::<HuntingHunt>(data.clone()) {
        parsed.tenant_id = tenant_id;
        if parsed.name.trim().is_empty() {
            parsed.name = default_hunt_name(name);
        }
        return Ok(parsed);
    }

    let hypothesis = data
        .get("hypothesis")
        .and_then(|v| v.as_str())
        .unwrap_or("Imported hunt hypothesis");

    let mut hunt = HuntingHunt::new(default_hunt_name(name), hypothesis).with_tenant(tenant_id);
    hunt.description = data
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    hunt.hunt_type = parse_hunt_type(
        data.get("hunt_type")
            .and_then(|v| v.as_str())
            .unwrap_or("on_demand"),
    );
    hunt.created_by = data
        .get("created_by")
        .and_then(|v| v.as_str())
        .unwrap_or("package-import")
        .to_string();
    hunt.enabled = data
        .get("enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);

    if let Some(queries_value) = data.get("queries").and_then(|v| v.as_array()) {
        let mut parsed_queries = Vec::new();
        for (index, query_value) in queries_value.iter().enumerate() {
            if let Ok(query) = serde_json::from_value::<HuntingQuery>(query_value.clone()) {
                parsed_queries.push(query);
                continue;
            }

            parsed_queries.push(HuntingQuery {
                id: query_value
                    .get("id")
                    .and_then(|v| v.as_str())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| format!("q{}", index + 1)),
                query_type: parse_query_type(
                    query_value
                        .get("query_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("custom"),
                ),
                query: query_value
                    .get("query")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                description: query_value
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Imported query")
                    .to_string(),
                timeout_secs: query_value
                    .get("timeout_secs")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(300),
                expected_baseline: query_value
                    .get("expected_baseline")
                    .and_then(|v| v.as_u64()),
            });
        }
        hunt.queries = parsed_queries;
    }

    Ok(hunt)
}

fn default_playbook_name(name: &str) -> String {
    if name.trim().is_empty() {
        "imported-playbook".to_string()
    } else {
        name.trim().to_string()
    }
}

fn default_hunt_name(name: &str) -> String {
    if name.trim().is_empty() {
        "imported-hunt".to_string()
    } else {
        name.trim().to_string()
    }
}

async fn import_playbook_content(
    repo: &dyn PlaybookRepository,
    tenant_id: Uuid,
    conflict_mode: ConflictMode,
    name: &str,
    data: &serde_json::Value,
) -> Result<bool, String> {
    let mut playbook = playbook_from_content(name, data)?;
    playbook.updated_at = Utc::now();

    let existing = repo
        .get_by_name_for_tenant(&playbook.name, tenant_id)
        .await
        .map_err(|e| {
            format!(
                "Failed to check playbook conflict '{}': {}",
                playbook.name, e
            )
        })?;

    match (existing, conflict_mode) {
        (Some(_), ConflictMode::Skip) => Ok(false),
        (Some(existing), ConflictMode::Overwrite) => {
            let update = PlaybookUpdate {
                name: Some(playbook.name.clone()),
                description: Some(playbook.description.clone()),
                trigger_type: Some(playbook.trigger_type.clone()),
                trigger_condition: Some(playbook.trigger_condition.clone()),
                stages: Some(playbook.stages.clone()),
                enabled: Some(playbook.enabled),
            };
            repo.update_for_tenant(existing.id, tenant_id, &update)
                .await
                .map_err(|e| format!("Failed to overwrite playbook '{}': {}", playbook.name, e))?;
            Ok(true)
        }
        (Some(_), ConflictMode::Rename) => {
            let base_name = default_playbook_name(&playbook.name);
            let mut index = 1usize;
            loop {
                let candidate = format!("{}-imported-{}", base_name, index);
                let exists = repo
                    .get_by_name_for_tenant(&candidate, tenant_id)
                    .await
                    .map_err(|e| {
                        format!(
                            "Failed to check playbook rename candidate '{}': {}",
                            candidate, e
                        )
                    })?;
                if exists.is_none() {
                    playbook.name = candidate;
                    break;
                }
                index += 1;
            }

            let now = Utc::now();
            playbook.id = Uuid::new_v4();
            playbook.created_at = now;
            playbook.updated_at = now;
            repo.create(tenant_id, &playbook)
                .await
                .map_err(|e| format!("Failed to import playbook '{}': {}", playbook.name, e))?;
            Ok(true)
        }
        (None, _) => {
            let now = Utc::now();
            playbook.id = Uuid::new_v4();
            playbook.created_at = now;
            playbook.updated_at = now;
            repo.create(tenant_id, &playbook)
                .await
                .map_err(|e| format!("Failed to import playbook '{}': {}", playbook.name, e))?;
            Ok(true)
        }
    }
}

fn import_hunt_content(
    hunts: &mut Vec<HuntingHunt>,
    tenant_id: Uuid,
    conflict_mode: ConflictMode,
    name: &str,
    data: &serde_json::Value,
) -> Result<bool, String> {
    let mut hunt = hunt_from_content(name, data, tenant_id)?;
    hunt.updated_at = Utc::now();

    let existing_index = hunts.iter().position(|h| h.name == hunt.name);

    match (existing_index, conflict_mode) {
        (Some(_), ConflictMode::Skip) => Ok(false),
        (Some(index), ConflictMode::Overwrite) => {
            let existing_id = hunts[index].id;
            hunt.id = existing_id;
            hunts[index] = hunt;
            Ok(true)
        }
        (Some(_), ConflictMode::Rename) => {
            hunt.name = unique_hunt_name(hunts, &hunt.name);
            hunt.id = Uuid::new_v4();
            hunts.push(hunt);
            Ok(true)
        }
        (None, _) => {
            hunt.id = Uuid::new_v4();
            hunts.push(hunt);
            Ok(true)
        }
    }
}

fn unique_hunt_name(hunts: &[HuntingHunt], base: &str) -> String {
    let clean_base = if base.trim().is_empty() {
        "imported-hunt"
    } else {
        base.trim()
    };
    let mut index = 1usize;
    loop {
        let candidate = format!("{}-imported-{}", clean_base, index);
        if !hunts.iter().any(|h| h.name == candidate) {
            return candidate;
        }
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_package_dto() -> PackageDto {
        PackageDto {
            manifest: ManifestDto {
                name: "test-pack".to_string(),
                version: "1.0.0".to_string(),
                description: "Test".to_string(),
                author: "tester".to_string(),
                license: None,
                tags: vec![],
                compatibility: None,
            },
            contents: vec![ContentDto::Playbook {
                name: "pb-1".to_string(),
                data: serde_json::json!({"stages": []}),
            }],
        }
    }

    #[test]
    fn test_validate_valid_package() {
        let result = validate_package_dto(&valid_package_dto());
        assert!(result.valid);
        assert!(result.errors.is_empty());
        assert_eq!(result.content_count, 1);
    }

    #[test]
    fn test_validate_empty_name() {
        let mut pkg = valid_package_dto();
        pkg.manifest.name = "".to_string();
        let result = validate_package_dto(&pkg);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("name is required")));
    }

    #[test]
    fn test_validate_empty_version() {
        let mut pkg = valid_package_dto();
        pkg.manifest.version = "".to_string();
        let result = validate_package_dto(&pkg);
        assert!(!result.valid);
    }

    #[test]
    fn test_validate_empty_contents_warning() {
        let mut pkg = valid_package_dto();
        pkg.contents = vec![];
        let result = validate_package_dto(&pkg);
        assert!(result.valid); // Warning, not error
        assert!(result.warnings.iter().any(|w| w.contains("no content")));
    }

    #[test]
    fn test_validate_empty_content_name() {
        let pkg = PackageDto {
            manifest: ManifestDto {
                name: "test".to_string(),
                version: "1.0.0".to_string(),
                description: "Test".to_string(),
                author: "tester".to_string(),
                license: None,
                tags: vec![],
                compatibility: None,
            },
            contents: vec![ContentDto::Playbook {
                name: "".to_string(),
                data: serde_json::json!({}),
            }],
        };
        let result = validate_package_dto(&pkg);
        assert!(!result.valid);
        assert!(result.errors.iter().any(|e| e.contains("empty name")));
    }

    #[test]
    fn test_package_dto_serialization() {
        let pkg = valid_package_dto();
        let json = serde_json::to_string(&pkg).unwrap();
        let deserialized: PackageDto = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.manifest.name, "test-pack");
        assert_eq!(deserialized.contents.len(), 1);
    }

    #[test]
    fn test_content_dto_variants() {
        let contents = vec![
            ContentDto::Playbook {
                name: "pb".to_string(),
                data: serde_json::json!({}),
            },
            ContentDto::Hunt {
                name: "hunt".to_string(),
                data: serde_json::json!({}),
            },
            ContentDto::Knowledge {
                title: "kb".to_string(),
                content: "text".to_string(),
            },
            ContentDto::Query {
                name: "q".to_string(),
                query_type: "siem".to_string(),
                query: "SELECT *".to_string(),
            },
        ];

        for content in contents {
            let json = serde_json::to_string(&content).unwrap();
            let _: ContentDto = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_import_request_default_conflict_resolution() {
        let json = serde_json::json!({
            "package": {
                "manifest": {
                    "name": "test",
                    "version": "1.0.0",
                    "description": "test",
                    "author": "tester"
                },
                "contents": []
            }
        });

        let request: ImportPackageRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.conflict_resolution, "skip");
    }

    #[test]
    fn test_import_result_response_serialization() {
        let result = ImportResultResponse {
            imported: 5,
            skipped: 1,
            errors: vec!["Failed to import item 3".to_string()],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"imported\":5"));
        assert!(json.contains("\"skipped\":1"));
    }

    #[test]
    fn test_validation_result_response_serialization() {
        let result = ValidationResultResponse {
            valid: true,
            warnings: vec!["Warning 1".to_string()],
            errors: vec![],
            content_count: 3,
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"valid\":true"));
        assert!(json.contains("\"content_count\":3"));
    }

    #[test]
    fn test_export_request_serialization() {
        let json = serde_json::json!({
            "name": "my-package",
            "version": "1.0.0",
            "description": "A package",
            "author": "Me",
            "license": "MIT",
            "tags": ["security", "phishing"]
        });

        let request: ExportRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.name, "my-package");
        assert_eq!(request.license, Some("MIT".to_string()));
        assert_eq!(request.tags.len(), 2);
    }

    #[test]
    fn test_manifest_dto_optional_fields() {
        let json = serde_json::json!({
            "name": "test",
            "version": "1.0.0",
            "description": "test",
            "author": "tester"
        });

        let manifest: ManifestDto = serde_json::from_value(json).unwrap();
        assert!(manifest.license.is_none());
        assert!(manifest.tags.is_empty());
        assert!(manifest.compatibility.is_none());
    }
}
