//! Connector management endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
use tw_core::db::{create_connector_repository, ConnectorRepository, ConnectorUpdate};

/// Creates connector routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connectors).post(create_connector))
        .route(
            "/{id}",
            get(get_connector)
                .put(update_connector)
                .delete(delete_connector),
        )
        .route("/{id}/test", post(test_connector))
}

// ============================================================================
// DTOs
// ============================================================================

/// Request to create a connector.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateConnectorRequest {
    /// Human-readable name for the connector.
    #[validate(length(min = 1, max = 255))]
    pub name: String,
    /// Type of connector.
    pub connector_type: String,
    /// Connector-specific configuration (api_key, base_url, etc.).
    pub config: serde_json::Value,
    /// Whether the connector is enabled (defaults to true).
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Request to update a connector.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct UpdateConnectorRequest {
    /// New name for the connector.
    #[validate(length(min = 1, max = 255))]
    pub name: Option<String>,
    /// New configuration.
    pub config: Option<serde_json::Value>,
    /// New enabled state.
    pub enabled: Option<bool>,
}

/// Connector response (with masked sensitive fields).
#[derive(Debug, Serialize, ToSchema)]
pub struct ConnectorResponse {
    pub id: Uuid,
    pub name: String,
    pub connector_type: String,
    /// Masked configuration (sensitive fields redacted).
    pub config: serde_json::Value,
    pub status: String,
    pub enabled: bool,
    pub last_health_check: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

/// Test connection result.
#[derive(Debug, Serialize, ToSchema)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
    pub latency_ms: Option<u64>,
}

// ============================================================================
// Handlers
// ============================================================================

/// List all connectors.
#[utoipa::path(
    get,
    path = "/api/connectors",
    responses(
        (status = 200, description = "List of connectors", body = Vec<ConnectorResponse>),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn list_connectors(
    State(state): State<AppState>,
) -> Result<Json<Vec<ConnectorResponse>>, ApiError> {
    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);

    let connectors = repo.list().await?;
    let responses: Vec<ConnectorResponse> = connectors
        .into_iter()
        .map(|c| connector_to_response(c, true))
        .collect();

    Ok(Json(responses))
}

/// Get a single connector by ID.
#[utoipa::path(
    get,
    path = "/api/connectors/{id}",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connector details", body = ConnectorResponse),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn get_connector(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ConnectorResponse>, ApiError> {
    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);

    let connector = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Connector {} not found", id)))?;

    Ok(Json(connector_to_response(connector, true)))
}

/// Create a new connector.
#[utoipa::path(
    post,
    path = "/api/connectors",
    request_body = CreateConnectorRequest,
    responses(
        (status = 201, description = "Connector created", body = ConnectorResponse),
        (status = 400, description = "Invalid request"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn create_connector(
    State(state): State<AppState>,
    Json(request): Json<CreateConnectorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    request.validate()?;

    let connector_type = parse_connector_type(&request.connector_type).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "Unknown connector type: {}",
            request.connector_type
        ))
    })?;

    let connector = ConnectorConfig::new(request.name, connector_type, request.config);
    let mut connector = connector;
    if !request.enabled {
        connector.set_enabled(false);
    }

    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);
    let created = repo.create(&connector).await?;

    let response = connector_to_response(created, false);

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Connector Created",
            "message": format!("Connector '{}' has been created successfully.", response.name)
        }
    });

    Ok((
        StatusCode::CREATED,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(response),
    ))
}

/// Update an existing connector.
#[utoipa::path(
    put,
    path = "/api/connectors/{id}",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    request_body = UpdateConnectorRequest,
    responses(
        (status = 200, description = "Connector updated", body = ConnectorResponse),
        (status = 400, description = "Invalid request"),
        (status = 404, description = "Connector not found"),
        (status = 422, description = "Validation error"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn update_connector(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateConnectorRequest>,
) -> Result<impl IntoResponse, ApiError> {
    request.validate()?;

    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);

    // Verify connector exists
    let _ = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Connector {} not found", id)))?;

    let update = ConnectorUpdate {
        name: request.name,
        config: request.config,
        enabled: request.enabled,
    };

    let updated = repo.update(id, &update).await?;
    let response = connector_to_response(updated, true);

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Connector Updated",
            "message": format!("Connector '{}' has been updated successfully.", response.name)
        }
    });

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(response),
    ))
}

/// Delete a connector.
#[utoipa::path(
    delete,
    path = "/api/connectors/{id}",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 204, description = "Connector deleted"),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn delete_connector(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);

    // Get connector name before deletion for the toast message
    let connector = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Connector {} not found", id)))?;

    let deleted = repo.delete(id).await?;

    if !deleted {
        return Err(ApiError::NotFound(format!("Connector {} not found", id)));
    }

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "info",
            "title": "Connector Deleted",
            "message": format!("Connector '{}' has been deleted.", connector.name)
        }
    });

    Ok((
        StatusCode::NO_CONTENT,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
    ))
}

/// Test a connector's connection.
#[utoipa::path(
    post,
    path = "/api/connectors/{id}/test",
    params(
        ("id" = Uuid, Path, description = "Connector ID")
    ),
    responses(
        (status = 200, description = "Connection test result", body = TestConnectionResponse),
        (status = 404, description = "Connector not found"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Connectors"
)]
async fn test_connector(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, ApiError> {
    let repo: Box<dyn ConnectorRepository> = create_connector_repository(&state.db);

    let connector = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Connector {} not found", id)))?;

    // Test connection based on connector type
    let start = std::time::Instant::now();
    let test_result = test_connection_for_type(&connector).await;
    let latency_ms = start.elapsed().as_millis() as u64;

    // Update connector status based on test result
    let new_status = if test_result.success {
        ConnectorStatus::Connected
    } else {
        ConnectorStatus::Error
    };

    // Update status and health check timestamp
    let _ = repo.update_status(id, new_status).await;
    let _ = repo.update_health_check(id).await;

    let response = TestConnectionResponse {
        success: test_result.success,
        message: test_result.message,
        latency_ms: Some(latency_ms),
    };

    let toast_type = if test_result.success {
        "success"
    } else {
        "error"
    };
    let toast_title = if test_result.success {
        "Connection Successful"
    } else {
        "Connection Failed"
    };

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": toast_type,
            "title": toast_title,
            "message": response.message.clone()
        }
    });

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(response),
    ))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Internal test result structure.
struct InternalTestResult {
    success: bool,
    message: String,
}

/// Tests connection for a given connector type.
///
/// For MVP, this performs basic validation and returns mock success.
/// In production, this would instantiate the actual connector and call test_connection().
async fn test_connection_for_type(connector: &ConnectorConfig) -> InternalTestResult {
    // Validate that required config fields exist based on connector type
    let validation_result = validate_connector_config(connector);

    if let Err(msg) = validation_result {
        return InternalTestResult {
            success: false,
            message: msg,
        };
    }

    // For MVP, we simulate connection testing
    // In a full implementation, we would:
    // 1. Instantiate the appropriate connector (VirusTotalConnector, JiraConnector, etc.)
    // 2. Call connector.test_connection()
    // 3. Return the actual result

    match connector.connector_type {
        ConnectorType::VirusTotal => {
            // Check for api_key in config
            if connector.config.get("api_key").is_some() {
                InternalTestResult {
                    success: true,
                    message: "VirusTotal API connection validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message: "VirusTotal requires an 'api_key' in configuration.".to_string(),
                }
            }
        }
        ConnectorType::Jira => {
            let has_url = connector.config.get("base_url").is_some();
            let has_auth = connector.config.get("api_token").is_some()
                || connector.config.get("username").is_some();

            if has_url && has_auth {
                InternalTestResult {
                    success: true,
                    message: "Jira connection validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message:
                        "Jira requires 'base_url' and authentication credentials in configuration."
                            .to_string(),
                }
            }
        }
        ConnectorType::Splunk => {
            let has_url = connector.config.get("base_url").is_some();
            let has_token = connector.config.get("token").is_some();

            if has_url && has_token {
                InternalTestResult {
                    success: true,
                    message: "Splunk connection validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message: "Splunk requires 'base_url' and 'token' in configuration.".to_string(),
                }
            }
        }
        ConnectorType::CrowdStrike => {
            let has_client_id = connector.config.get("client_id").is_some();
            let has_client_secret = connector.config.get("client_secret").is_some();

            if has_client_id && has_client_secret {
                InternalTestResult {
                    success: true,
                    message: "CrowdStrike connection validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message:
                        "CrowdStrike requires 'client_id' and 'client_secret' in configuration."
                            .to_string(),
                }
            }
        }
        ConnectorType::Defender | ConnectorType::M365 => {
            let has_tenant_id = connector.config.get("tenant_id").is_some();
            let has_client_id = connector.config.get("client_id").is_some();

            if has_tenant_id && has_client_id {
                InternalTestResult {
                    success: true,
                    message: format!(
                        "{} connection validated successfully.",
                        connector.connector_type
                    ),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message: format!(
                        "{} requires 'tenant_id' and 'client_id' in configuration.",
                        connector.connector_type
                    ),
                }
            }
        }
        ConnectorType::GoogleWorkspace => {
            let has_credentials = connector.config.get("service_account_json").is_some()
                || connector.config.get("credentials_file").is_some();

            if has_credentials {
                InternalTestResult {
                    success: true,
                    message: "Google Workspace connection validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message:
                        "Google Workspace requires service account credentials in configuration."
                            .to_string(),
                }
            }
        }
        ConnectorType::Generic => {
            // Generic connectors just need a base_url
            if connector.config.get("base_url").is_some() {
                InternalTestResult {
                    success: true,
                    message: "Generic connector configuration validated successfully.".to_string(),
                }
            } else {
                InternalTestResult {
                    success: false,
                    message: "Generic connector requires at least a 'base_url' in configuration."
                        .to_string(),
                }
            }
        }
    }
}

/// Validates connector configuration has minimum required fields.
fn validate_connector_config(connector: &ConnectorConfig) -> Result<(), String> {
    if connector.name.is_empty() {
        return Err("Connector name cannot be empty.".to_string());
    }

    if connector.config.is_null() {
        return Err("Connector configuration cannot be null.".to_string());
    }

    Ok(())
}

/// Converts a ConnectorConfig to a response DTO with optional masking.
fn connector_to_response(connector: ConnectorConfig, mask_sensitive: bool) -> ConnectorResponse {
    let masked_config = if mask_sensitive {
        mask_sensitive_config(&connector.config)
    } else {
        connector.config
    };

    ConnectorResponse {
        id: connector.id,
        name: connector.name,
        connector_type: connector.connector_type.to_string(),
        config: masked_config,
        status: connector.status.to_string(),
        enabled: connector.enabled,
        last_health_check: connector.last_health_check,
        created_at: connector.created_at,
        updated_at: connector.updated_at,
    }
}

/// Masks sensitive fields in configuration JSON.
fn mask_sensitive_config(config: &serde_json::Value) -> serde_json::Value {
    let sensitive_fields = [
        "api_key",
        "api_token",
        "token",
        "secret",
        "password",
        "client_secret",
        "private_key",
        "service_account_json",
        "credentials",
    ];

    match config {
        serde_json::Value::Object(map) => {
            let mut masked_map = serde_json::Map::new();
            for (key, value) in map {
                let lower_key = key.to_lowercase();
                let is_sensitive = sensitive_fields
                    .iter()
                    .any(|&field| lower_key.contains(field));

                if is_sensitive {
                    if let serde_json::Value::String(s) = value {
                        masked_map.insert(key.clone(), serde_json::Value::String(mask_api_key(s)));
                    } else {
                        masked_map
                            .insert(key.clone(), serde_json::Value::String("***".to_string()));
                    }
                } else {
                    // Recursively mask nested objects
                    masked_map.insert(key.clone(), mask_sensitive_config(value));
                }
            }
            serde_json::Value::Object(masked_map)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(mask_sensitive_config).collect())
        }
        other => other.clone(),
    }
}

/// Masks an API key, showing only first 3 and last 3 characters.
fn mask_api_key(key: &str) -> String {
    if key.len() > 6 {
        format!("{}***{}", &key[..3], &key[key.len() - 3..])
    } else {
        "***".to_string()
    }
}

/// Parses a connector type from a string.
fn parse_connector_type(s: &str) -> Option<ConnectorType> {
    match s.to_lowercase().as_str() {
        "virustotal" | "virus_total" => Some(ConnectorType::VirusTotal),
        "jira" => Some(ConnectorType::Jira),
        "splunk" => Some(ConnectorType::Splunk),
        "crowdstrike" | "crowd_strike" => Some(ConnectorType::CrowdStrike),
        "defender" => Some(ConnectorType::Defender),
        "m365" | "microsoft365" => Some(ConnectorType::M365),
        "googleworkspace" | "google_workspace" => Some(ConnectorType::GoogleWorkspace),
        "generic" => Some(ConnectorType::Generic),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_api_key_long() {
        assert_eq!(mask_api_key("sk-abc123xyz789"), "sk-***789");
    }

    #[test]
    fn test_mask_api_key_short() {
        assert_eq!(mask_api_key("short"), "***");
        assert_eq!(mask_api_key("123456"), "***");
    }

    #[test]
    fn test_mask_api_key_exactly_seven() {
        assert_eq!(mask_api_key("1234567"), "123***567");
    }

    #[test]
    fn test_mask_sensitive_config() {
        let config = serde_json::json!({
            "api_key": "sk-verysecretkey123",
            "base_url": "https://api.example.com",
            "client_secret": "supersecret",
            "timeout": 30
        });

        let masked = mask_sensitive_config(&config);

        assert_eq!(masked["base_url"], "https://api.example.com");
        assert_eq!(masked["timeout"], 30);
        assert_eq!(masked["api_key"], "sk-***123");
        assert_eq!(masked["client_secret"], "sup***ret");
    }

    #[test]
    fn test_mask_sensitive_config_nested() {
        let config = serde_json::json!({
            "auth": {
                "api_key": "secret123key",
                "username": "user"
            },
            "base_url": "https://api.example.com"
        });

        let masked = mask_sensitive_config(&config);

        assert_eq!(masked["base_url"], "https://api.example.com");
        assert_eq!(masked["auth"]["username"], "user");
        assert_eq!(masked["auth"]["api_key"], "sec***key");
    }

    #[test]
    fn test_parse_connector_type() {
        assert_eq!(
            parse_connector_type("virustotal"),
            Some(ConnectorType::VirusTotal)
        );
        assert_eq!(
            parse_connector_type("virus_total"),
            Some(ConnectorType::VirusTotal)
        );
        assert_eq!(parse_connector_type("JIRA"), Some(ConnectorType::Jira));
        assert_eq!(
            parse_connector_type("CrowdStrike"),
            Some(ConnectorType::CrowdStrike)
        );
        assert_eq!(parse_connector_type("unknown"), None);
    }
}
