//! Content package API endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

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
    State(_state): State<AppState>,
    Json(request): Json<ImportPackageRequest>,
) -> Result<(StatusCode, Json<ImportResultResponse>), ApiError> {
    // Validate the package first
    let validation = validate_package_dto(&request.package);
    if !validation.valid {
        return Err(ApiError::BadRequest(format!(
            "Package validation failed: {}",
            validation.errors.join("; ")
        )));
    }

    // TODO: Convert DTOs to domain types and perform actual import
    let result = ImportResultResponse {
        imported: request.package.contents.len(),
        skipped: 0,
        errors: vec![],
    };

    Ok((StatusCode::CREATED, Json(result)))
}

/// Validate a content package without importing.
async fn validate_package(
    State(_state): State<AppState>,
    Json(request): Json<PackageDto>,
) -> Result<Json<ValidationResultResponse>, ApiError> {
    let result = validate_package_dto(&request);
    Ok(Json(result))
}

/// Export a playbook as a content package.
async fn export_playbook(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    // TODO: Fetch playbook from database and export
    Err(ApiError::NotImplemented(format!(
        "Playbook export for {} not yet implemented",
        id
    )))
}

/// Export a hunt as a content package.
async fn export_hunt(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(_request): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, ApiError> {
    // TODO: Fetch hunt from database and export
    Err(ApiError::NotImplemented(format!(
        "Hunt export for {} not yet implemented",
        id
    )))
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
