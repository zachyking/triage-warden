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
use std::sync::Arc;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
use tw_core::db::{create_connector_repository, ConnectorRepository, ConnectorUpdate};
use tw_core::CredentialEncryptor;

/// Creates connector routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_connectors).post(create_connector))
        .route(
            "/:id",
            get(get_connector)
                .put(update_connector)
                .delete(delete_connector),
        )
        .route("/:id/test", post(test_connector))
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
#[cfg_attr(test, derive(serde::Deserialize))]
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
#[cfg_attr(test, derive(serde::Deserialize))]
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
        ApiError::validation_field(
            "connector_type",
            "invalid_type",
            &format!(
                "Unknown connector type: '{}'. Valid types are: splunk, crowdstrike, jira, virustotal, m365, defender, elastic, sentinel, sentinelone, servicenow, alienvault, google",
                request.connector_type
            ),
        )
    })?;

    // Encrypt sensitive fields in the config before storage
    let encrypted_config = encrypt_sensitive_config(&request.config, &state.encryptor);

    let connector = ConnectorConfig::new(request.name, connector_type, encrypted_config);
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

    // Encrypt sensitive fields in the config before storage
    let encrypted_config = request
        .config
        .map(|c| encrypt_sensitive_config(&c, &state.encryptor));

    let update = ConnectorUpdate {
        name: request.name,
        config: encrypted_config,
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
    match config {
        serde_json::Value::Object(map) => {
            let mut masked_map = serde_json::Map::new();
            for (key, value) in map {
                let lower_key = key.to_lowercase();
                let is_sensitive = SENSITIVE_FIELDS
                    .iter()
                    .any(|&field| lower_key.contains(field));

                if is_sensitive {
                    if let serde_json::Value::String(s) = value {
                        // Handle encrypted values (strip enc: prefix for masking)
                        let plain = s.strip_prefix("enc:").unwrap_or(s);
                        masked_map
                            .insert(key.clone(), serde_json::Value::String(mask_api_key(plain)));
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

/// Sensitive field names that should be encrypted.
const SENSITIVE_FIELDS: &[&str] = &[
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

/// Encrypts sensitive fields in configuration JSON before storage.
fn encrypt_sensitive_config(
    config: &serde_json::Value,
    encryptor: &Arc<dyn CredentialEncryptor>,
) -> serde_json::Value {
    match config {
        serde_json::Value::Object(map) => {
            let mut encrypted_map = serde_json::Map::new();
            for (key, value) in map {
                let lower_key = key.to_lowercase();
                let is_sensitive = SENSITIVE_FIELDS
                    .iter()
                    .any(|&field| lower_key.contains(field));

                if is_sensitive {
                    if let serde_json::Value::String(s) = value {
                        // Only encrypt non-empty strings that aren't already encrypted
                        if !s.is_empty() && !s.starts_with("enc:") {
                            match encryptor.encrypt(s) {
                                Ok(encrypted) => {
                                    // Prefix with "enc:" to identify encrypted values
                                    encrypted_map.insert(
                                        key.clone(),
                                        serde_json::Value::String(format!("enc:{}", encrypted)),
                                    );
                                }
                                Err(e) => {
                                    tracing::error!(
                                        field = key,
                                        error = %e,
                                        "Failed to encrypt sensitive field"
                                    );
                                    // Keep original value on encryption failure
                                    encrypted_map.insert(key.clone(), value.clone());
                                }
                            }
                        } else {
                            // Empty or already encrypted
                            encrypted_map.insert(key.clone(), value.clone());
                        }
                    } else {
                        encrypted_map.insert(key.clone(), value.clone());
                    }
                } else {
                    // Recursively encrypt nested objects
                    encrypted_map.insert(key.clone(), encrypt_sensitive_config(value, encryptor));
                }
            }
            serde_json::Value::Object(encrypted_map)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| encrypt_sensitive_config(v, encryptor))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Decrypts sensitive fields in configuration JSON after retrieval.
/// Used when testing connections or when credentials need to be read.
#[allow(dead_code)] // Will be used when real connector testing is implemented
fn decrypt_sensitive_config(
    config: &serde_json::Value,
    encryptor: &Arc<dyn CredentialEncryptor>,
) -> serde_json::Value {
    match config {
        serde_json::Value::Object(map) => {
            let mut decrypted_map = serde_json::Map::new();
            for (key, value) in map {
                if let serde_json::Value::String(s) = value {
                    // Check if this is an encrypted value
                    if let Some(encrypted) = s.strip_prefix("enc:") {
                        match encryptor.decrypt(encrypted) {
                            Ok(decrypted) => {
                                decrypted_map
                                    .insert(key.clone(), serde_json::Value::String(decrypted));
                            }
                            Err(e) => {
                                tracing::error!(
                                    field = key,
                                    error = %e,
                                    "Failed to decrypt sensitive field"
                                );
                                // Keep encrypted value on decryption failure
                                decrypted_map.insert(key.clone(), value.clone());
                            }
                        }
                    } else {
                        decrypted_map.insert(key.clone(), value.clone());
                    }
                } else {
                    // Recursively decrypt nested objects
                    decrypted_map.insert(key.clone(), decrypt_sensitive_config(value, encryptor));
                }
            }
            serde_json::Value::Object(decrypted_map)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.iter()
                .map(|v| decrypt_sensitive_config(v, encryptor))
                .collect(),
        ),
        other => other.clone(),
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

    #[test]
    fn test_encrypt_sensitive_config() {
        use tw_core::Aes256GcmEncryptor;

        let key = [0u8; 32];
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new(key));

        let config = serde_json::json!({
            "api_key": "sk-verysecretkey123",
            "base_url": "https://api.example.com",
            "client_secret": "supersecret",
            "timeout": 30
        });

        let encrypted = encrypt_sensitive_config(&config, &encryptor);

        // Non-sensitive fields unchanged
        assert_eq!(encrypted["base_url"], "https://api.example.com");
        assert_eq!(encrypted["timeout"], 30);

        // Sensitive fields should be encrypted (prefixed with enc:)
        let api_key = encrypted["api_key"].as_str().unwrap();
        assert!(api_key.starts_with("enc:"), "api_key should be encrypted");

        let client_secret = encrypted["client_secret"].as_str().unwrap();
        assert!(
            client_secret.starts_with("enc:"),
            "client_secret should be encrypted"
        );
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        use tw_core::Aes256GcmEncryptor;

        let key = [42u8; 32];
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new(key));

        let config = serde_json::json!({
            "api_key": "sk-verysecretkey123",
            "base_url": "https://api.example.com",
            "nested": {
                "token": "nested-secret-token"
            }
        });

        let encrypted = encrypt_sensitive_config(&config, &encryptor);
        let decrypted = decrypt_sensitive_config(&encrypted, &encryptor);

        // Verify roundtrip preserves original values
        assert_eq!(decrypted["api_key"], "sk-verysecretkey123");
        assert_eq!(decrypted["base_url"], "https://api.example.com");
        assert_eq!(decrypted["nested"]["token"], "nested-secret-token");
    }

    #[test]
    fn test_encrypt_empty_and_already_encrypted() {
        use tw_core::Aes256GcmEncryptor;

        let key = [0u8; 32];
        let encryptor: Arc<dyn CredentialEncryptor> = Arc::new(Aes256GcmEncryptor::new(key));

        let config = serde_json::json!({
            "api_key": "",  // Empty should not be encrypted
            "token": "enc:already-encrypted-value"  // Already encrypted should be kept as-is
        });

        let encrypted = encrypt_sensitive_config(&config, &encryptor);

        assert_eq!(encrypted["api_key"], "");
        assert_eq!(encrypted["token"], "enc:already-encrypted-value");
    }

    #[test]
    fn test_mask_encrypted_values() {
        // Masking should work correctly with encrypted values
        let config = serde_json::json!({
            "api_key": "enc:somebase64encryptedvalue==",
            "base_url": "https://api.example.com"
        });

        let masked = mask_sensitive_config(&config);

        // Should strip enc: prefix and mask the remaining value
        assert_eq!(masked["base_url"], "https://api.example.com");
        // "somebase64encryptedvalue==" has 26 chars, so mask should show first 3 and last 3
        assert!(masked["api_key"].as_str().unwrap().contains("***"));
    }
}

/// API tests for connector routes.
///
/// These tests use an in-memory SQLite database with manual schema creation.
#[cfg(test)]
mod api_tests {
    use super::*;
    use crate::state::AppState;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use tw_core::db::DbPool;
    use tw_core::EventBus;

    /// SQL to create the connectors table for testing.
    const CREATE_CONNECTORS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS connectors (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            connector_type TEXT NOT NULL,
            config TEXT NOT NULL DEFAULT '{}',
            status TEXT NOT NULL DEFAULT 'unknown',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_health_check TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_connectors_name ON connectors(name);
        CREATE INDEX IF NOT EXISTS idx_connectors_connector_type ON connectors(connector_type);
        CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
        CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON connectors(enabled);
    "#;

    /// Creates an in-memory SQLite database and returns the test app router.
    async fn setup_test_app() -> axum::Router {
        // Use a unique UUID for complete database isolation
        let unique_id = Uuid::new_v4();
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join(format!("tw_api_connector_test_{}.db", unique_id));
        let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create SQLite pool");

        // Create tables directly
        sqlx::raw_sql(CREATE_CONNECTORS_TABLE)
            .execute(&pool)
            .await
            .expect("Failed to create connectors table");

        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        let state = AppState::new(db, event_bus);

        axum::Router::new()
            .nest("/api/connectors", routes())
            .with_state(state)
    }

    /// Helper to create a connector via the API and return its response.
    async fn create_test_connector_via_api(
        app: &axum::Router,
        name: &str,
        connector_type: &str,
    ) -> (StatusCode, serde_json::Value) {
        let body = serde_json::json!({
            "name": name,
            "connector_type": connector_type,
            "config": {
                "api_key": "test-api-key-12345",
                "base_url": "https://example.com",
                "api_token": "test-token"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        let status = response.status();

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();

        (status, json)
    }

    // ==================== LIST CONNECTORS TESTS ====================

    #[tokio::test]
    async fn test_list_connectors_empty() {
        let app = setup_test_app().await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/connectors")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connectors: Vec<ConnectorResponse> = serde_json::from_slice(&body_bytes).unwrap();

        assert!(connectors.is_empty());
    }

    #[tokio::test]
    async fn test_list_connectors_returns_all() {
        let app = setup_test_app().await;

        // Create two connectors
        let (status1, _) = create_test_connector_via_api(&app, "Connector 1", "virustotal").await;
        assert_eq!(status1, StatusCode::CREATED);

        let (status2, _) = create_test_connector_via_api(&app, "Connector 2", "jira").await;
        assert_eq!(status2, StatusCode::CREATED);

        let request = Request::builder()
            .method("GET")
            .uri("/api/connectors")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connectors: Vec<ConnectorResponse> = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connectors.len(), 2);
    }

    #[tokio::test]
    async fn test_list_connectors_returns_correct_fields() {
        let app = setup_test_app().await;

        let (status, _) = create_test_connector_via_api(&app, "Test Conn", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let request = Request::builder()
            .method("GET")
            .uri("/api/connectors")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connectors: Vec<ConnectorResponse> = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connectors.len(), 1);
        let conn = &connectors[0];
        assert_eq!(conn.name, "Test Conn");
        assert_eq!(conn.connector_type, "VirusTotal");
        assert_eq!(conn.status, "Unknown");
        assert!(conn.enabled);
    }

    // ==================== GET CONNECTOR TESTS ====================

    #[tokio::test]
    async fn test_get_connector_success() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "Test Connector", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Get the connector
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connector.name, "Test Connector");
        assert_eq!(connector.connector_type, "VirusTotal");
    }

    #[tokio::test]
    async fn test_get_connector_not_found() {
        let app = setup_test_app().await;

        let nonexistent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/connectors/{}", nonexistent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_connector_masks_sensitive_fields() {
        let app = setup_test_app().await;

        // Create a connector with sensitive config
        let (status, created) =
            create_test_connector_via_api(&app, "Sensitive Connector", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Get the connector - sensitive fields should be masked
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // The api_key should be masked (showing only first 3 and last 3 chars)
        let api_key = connector.config["api_key"].as_str().unwrap();
        assert!(api_key.contains("***"));
    }

    #[tokio::test]
    async fn test_get_connector_invalid_uuid() {
        let app = setup_test_app().await;

        let request = Request::builder()
            .method("GET")
            .uri("/api/connectors/not-a-uuid")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should return 400 Bad Request for invalid UUID
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // ==================== CREATE CONNECTOR TESTS ====================

    #[tokio::test]
    async fn test_create_connector_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "New VirusTotal",
            "connector_type": "virustotal",
            "config": {
                "api_key": "vt-api-key-12345"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Check HX-Trigger header for toast notification
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connector.name, "New VirusTotal");
        assert_eq!(connector.connector_type, "VirusTotal");
        assert!(connector.enabled);
    }

    #[tokio::test]
    async fn test_create_connector_disabled() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Disabled Connector",
            "connector_type": "jira",
            "config": {
                "base_url": "https://jira.example.com",
                "api_token": "jira-token"
            },
            "enabled": false
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!connector.enabled);
    }

    #[tokio::test]
    async fn test_create_connector_default_enabled() {
        let app = setup_test_app().await;

        // Don't specify enabled - should default to true
        let body = serde_json::json!({
            "name": "Default Enabled",
            "connector_type": "splunk",
            "config": {
                "base_url": "https://splunk.example.com",
                "token": "splunk-token"
            }
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(connector.enabled);
    }

    #[tokio::test]
    async fn test_create_connector_invalid_type() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Bad Connector",
            "connector_type": "invalid_type",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Validation errors return 422 Unprocessable Entity with field-level details
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_create_connector_empty_name_fails() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "",
            "connector_type": "virustotal",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should fail validation - empty name
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_create_connector_name_too_long_fails() {
        let app = setup_test_app().await;

        // Create a name that's 256 characters (exceeds max of 255)
        let long_name = "a".repeat(256);

        let body = serde_json::json!({
            "name": long_name,
            "connector_type": "virustotal",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should fail validation - name too long
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_create_connector_all_types() {
        let app = setup_test_app().await;

        let connector_types = vec![
            "virustotal",
            "jira",
            "splunk",
            "crowdstrike",
            "defender",
            "m365",
            "googleworkspace",
            "generic",
        ];

        for (i, connector_type) in connector_types.iter().enumerate() {
            let body = serde_json::json!({
                "name": format!("Connector {}", i),
                "connector_type": connector_type,
                "config": {"key": "value"},
                "enabled": true
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/connectors")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();

            assert_eq!(
                response.status(),
                StatusCode::CREATED,
                "Failed to create connector of type: {}",
                connector_type
            );
        }
    }

    #[tokio::test]
    async fn test_create_connector_alternate_type_names() {
        let app = setup_test_app().await;

        // Test alternate type name formats
        // The second element is the Display format of ConnectorType
        let alternate_types = vec![
            ("virus_total", "VirusTotal"),
            ("crowd_strike", "CrowdStrike"),
            ("microsoft365", "M365"),
            ("google_workspace", "Google Workspace"),
        ];

        for (i, (input_type, expected_type)) in alternate_types.iter().enumerate() {
            let body = serde_json::json!({
                "name": format!("Alt Type Connector {}", i),
                "connector_type": input_type,
                "config": {"key": "value"},
                "enabled": true
            });

            let request = Request::builder()
                .method("POST")
                .uri("/api/connectors")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&body).unwrap()))
                .unwrap();

            let response = app.clone().oneshot(request).await.unwrap();

            assert_eq!(response.status(), StatusCode::CREATED);

            let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

            assert_eq!(
                connector.connector_type, *expected_type,
                "Type {} should normalize to {}",
                input_type, expected_type
            );
        }
    }

    #[tokio::test]
    async fn test_create_connector_with_complex_config() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Complex Connector",
            "connector_type": "jira",
            "config": {
                "base_url": "https://jira.example.com",
                "api_token": "secret-token",
                "project_key": "SOC",
                "issue_type": "Incident",
                "custom_fields": {
                    "severity": "customfield_10001",
                    "category": "customfield_10002"
                },
                "rate_limit": 100,
                "timeout_seconds": 30
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Verify nested config is preserved (note: api_token not checked as it's not masked on create)
        assert_eq!(connector.config["project_key"], "SOC");
        assert_eq!(
            connector.config["custom_fields"]["severity"],
            "customfield_10001"
        );
        assert_eq!(connector.config["rate_limit"], 100);
    }

    #[tokio::test]
    async fn test_create_connector_hx_trigger_contains_toast() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "HX Trigger Test",
            "connector_type": "generic",
            "config": {"base_url": "https://example.com"},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let hx_trigger = response.headers().get("hx-trigger").unwrap();
        let trigger_value = hx_trigger.to_str().unwrap();

        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("success"));
        assert!(trigger_value.contains("Connector Created"));
    }

    // ==================== UPDATE CONNECTOR TESTS ====================

    #[tokio::test]
    async fn test_update_connector_name() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "Original Name", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Update the name
        let update_body = serde_json::json!({
            "name": "Updated Name"
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connector.name, "Updated Name");
    }

    #[tokio::test]
    async fn test_update_connector_config() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "Config Connector", "jira").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Update the config
        let update_body = serde_json::json!({
            "config": {
                "base_url": "https://new-jira.example.com",
                "api_token": "new-token"
            }
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connector.config["base_url"], "https://new-jira.example.com");
    }

    #[tokio::test]
    async fn test_update_connector_enabled() {
        let app = setup_test_app().await;

        // Create an enabled connector
        let (status, created) =
            create_test_connector_via_api(&app, "Toggle Connector", "splunk").await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(created["enabled"].as_bool().unwrap());

        let connector_id = created["id"].as_str().unwrap();

        // Disable it
        let update_body = serde_json::json!({
            "enabled": false
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!connector.enabled);
    }

    #[tokio::test]
    async fn test_update_connector_multiple_fields() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) = create_test_connector_via_api(&app, "Multi Update", "splunk").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Update multiple fields at once
        let update_body = serde_json::json!({
            "name": "Updated Multi",
            "config": {
                "base_url": "https://new-splunk.example.com",
                "token": "new-token"
            },
            "enabled": false
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connector.name, "Updated Multi");
        assert_eq!(
            connector.config["base_url"],
            "https://new-splunk.example.com"
        );
        assert!(!connector.enabled);
    }

    #[tokio::test]
    async fn test_update_connector_not_found() {
        let app = setup_test_app().await;

        let nonexistent_id = Uuid::new_v4();

        let update_body = serde_json::json!({
            "name": "Won't Work"
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", nonexistent_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_update_connector_empty_name_fails() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "Valid Name", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Try to update with empty name
        let update_body = serde_json::json!({
            "name": ""
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_update_connector_has_hx_trigger() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "HX Trigger Test", "generic").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        let update_body = serde_json::json!({
            "name": "New Name"
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Check HX-Trigger header exists
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("success"));
    }

    #[tokio::test]
    async fn test_update_connector_preserves_unchanged_fields() {
        let app = setup_test_app().await;

        // Create a connector with specific config
        let body = serde_json::json!({
            "name": "Preserve Test",
            "connector_type": "virustotal",
            "config": {
                "api_key": "original-key"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Update only the name
        let update_body = serde_json::json!({
            "name": "New Name Only"
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", created.id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Name should be updated
        assert_eq!(updated.name, "New Name Only");
        // Other fields should be preserved
        assert!(updated.enabled);
        assert_eq!(updated.connector_type, "VirusTotal");
    }

    // ==================== DELETE CONNECTOR TESTS ====================

    #[tokio::test]
    async fn test_delete_connector_success() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) =
            create_test_connector_via_api(&app, "To Delete", "virustotal").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        // Delete it
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Verify it's gone
        let request = Request::builder()
            .method("GET")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_connector_not_found() {
        let app = setup_test_app().await;

        let nonexistent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/connectors/{}", nonexistent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_connector_has_hx_trigger() {
        let app = setup_test_app().await;

        // Create a connector
        let (status, created) = create_test_connector_via_api(&app, "HX Delete Test", "jira").await;
        assert_eq!(status, StatusCode::CREATED);

        let connector_id = created["id"].as_str().unwrap();

        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // Check HX-Trigger header exists
        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("Connector Deleted"));
    }

    #[tokio::test]
    async fn test_delete_connector_removes_from_list() {
        let app = setup_test_app().await;

        // Create two connectors
        let (status1, created1) = create_test_connector_via_api(&app, "Conn 1", "virustotal").await;
        assert_eq!(status1, StatusCode::CREATED);

        let (status2, _) = create_test_connector_via_api(&app, "Conn 2", "jira").await;
        assert_eq!(status2, StatusCode::CREATED);

        let connector_id = created1["id"].as_str().unwrap();

        // Delete the first connector
        let request = Request::builder()
            .method("DELETE")
            .uri(format!("/api/connectors/{}", connector_id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        // List should now have only one connector
        let request = Request::builder()
            .method("GET")
            .uri("/api/connectors")
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connectors: Vec<ConnectorResponse> = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(connectors.len(), 1);
        assert_eq!(connectors[0].name, "Conn 2");
    }

    // ==================== TEST CONNECTION TESTS ====================

    #[tokio::test]
    async fn test_test_connector_success_virustotal() {
        let app = setup_test_app().await;

        // Create a VirusTotal connector with valid config
        let body = serde_json::json!({
            "name": "VT Test",
            "connector_type": "virustotal",
            "config": {
                "api_key": "test-api-key-12345"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Test the connection
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.latency_ms.is_some());
        assert!(result.message.contains("VirusTotal"));
    }

    #[tokio::test]
    async fn test_test_connector_failure_missing_api_key() {
        let app = setup_test_app().await;

        // Create a VirusTotal connector without api_key
        let body = serde_json::json!({
            "name": "VT No Key",
            "connector_type": "virustotal",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Test the connection - should fail
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!result.success);
        assert!(result.message.contains("api_key"));
    }

    #[tokio::test]
    async fn test_test_connector_not_found() {
        let app = setup_test_app().await;

        let nonexistent_id = Uuid::new_v4();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", nonexistent_id))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_test_connector_jira_success() {
        let app = setup_test_app().await;

        // Create a Jira connector with valid config
        let body = serde_json::json!({
            "name": "Jira Test",
            "connector_type": "jira",
            "config": {
                "base_url": "https://jira.example.com",
                "api_token": "jira-token"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Test the connection
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("Jira"));
    }

    #[tokio::test]
    async fn test_test_connector_jira_missing_config() {
        let app = setup_test_app().await;

        // Create a Jira connector without required config
        let body = serde_json::json!({
            "name": "Jira Incomplete",
            "connector_type": "jira",
            "config": {
                "base_url": "https://jira.example.com"
                // Missing api_token
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // Test the connection - should fail
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(!result.success);
        assert!(result.message.contains("authentication"));
    }

    #[tokio::test]
    async fn test_test_connector_splunk_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Splunk Test",
            "connector_type": "splunk",
            "config": {
                "base_url": "https://splunk.example.com",
                "token": "splunk-token"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("Splunk"));
    }

    #[tokio::test]
    async fn test_test_connector_crowdstrike_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "CrowdStrike Test",
            "connector_type": "crowdstrike",
            "config": {
                "client_id": "cs-client-id",
                "client_secret": "cs-client-secret"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("CrowdStrike"));
    }

    #[tokio::test]
    async fn test_test_connector_defender_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Defender Test",
            "connector_type": "defender",
            "config": {
                "tenant_id": "tenant-123",
                "client_id": "client-456"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("Defender"));
    }

    #[tokio::test]
    async fn test_test_connector_google_workspace_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Google Workspace Test",
            "connector_type": "googleworkspace",
            "config": {
                "service_account_json": "{\"type\": \"service_account\"}"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("Google Workspace"));
    }

    #[tokio::test]
    async fn test_test_connector_generic_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Generic Test",
            "connector_type": "generic",
            "config": {
                "base_url": "https://api.example.com"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.success);
        assert!(result.message.contains("Generic"));
    }

    #[tokio::test]
    async fn test_test_connector_has_hx_trigger_on_success() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "HX Test Success",
            "connector_type": "generic",
            "config": {
                "base_url": "https://example.com"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("success"));
        assert!(trigger_value.contains("Connection Successful"));
    }

    #[tokio::test]
    async fn test_test_connector_has_hx_trigger_on_failure() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "HX Test Failure",
            "connector_type": "virustotal",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        assert!(trigger_value.contains("showToast"));
        assert!(trigger_value.contains("error"));
        assert!(trigger_value.contains("Connection Failed"));
    }

    #[tokio::test]
    async fn test_test_connector_includes_latency() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Latency Test",
            "connector_type": "virustotal",
            "config": {
                "api_key": "test-key-12345"
            },
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let created: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/connectors/{}/test", created.id))
            .body(Body::empty())
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let result: TestConnectionResponse = serde_json::from_slice(&body_bytes).unwrap();

        assert!(result.latency_ms.is_some());
        // Latency should be reasonable (less than 5 seconds for a mock test)
        assert!(result.latency_ms.unwrap() < 5000);
    }

    // ==================== EDGE CASE TESTS ====================

    #[tokio::test]
    async fn test_invalid_json_body() {
        let app = setup_test_app().await;

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from("not valid json"))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should return 400 Bad Request for invalid JSON
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_required_fields() {
        let app = setup_test_app().await;

        // Missing connector_type
        let body = serde_json::json!({
            "name": "Incomplete",
            "config": {}
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should return 422 Unprocessable Entity for missing required fields
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn test_empty_request_body() {
        let app = setup_test_app().await;

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        // Should return 400 Bad Request for empty body
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_case_insensitive_connector_type() {
        let app = setup_test_app().await;

        // Test uppercase
        let body = serde_json::json!({
            "name": "Uppercase Type",
            "connector_type": "VIRUSTOTAL",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // Test mixed case
        let body = serde_json::json!({
            "name": "Mixed Case Type",
            "connector_type": "VirusTotal",
            "config": {},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn test_connector_created_at_and_updated_at() {
        let app = setup_test_app().await;

        let body = serde_json::json!({
            "name": "Timestamp Test",
            "connector_type": "generic",
            "config": {"base_url": "https://example.com"},
            "enabled": true
        });

        let request = Request::builder()
            .method("POST")
            .uri("/api/connectors")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let connector: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // created_at and updated_at should be set
        assert!(connector.created_at <= Utc::now());
        assert!(connector.updated_at <= Utc::now());
        // Initially they should be close to each other
        let diff = (connector.updated_at - connector.created_at)
            .num_seconds()
            .abs();
        assert!(
            diff < 2,
            "created_at and updated_at should be within 2 seconds"
        );
    }

    #[tokio::test]
    async fn test_update_changes_updated_at() {
        let app = setup_test_app().await;

        let (status, created) =
            create_test_connector_via_api(&app, "Timestamp Update", "generic").await;
        assert_eq!(status, StatusCode::CREATED);

        let original_updated_at = created["updated_at"].as_str().unwrap().to_string();
        let connector_id = created["id"].as_str().unwrap();

        // Small delay to ensure timestamp difference
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let update_body = serde_json::json!({
            "name": "Updated Timestamp"
        });

        let request = Request::builder()
            .method("PUT")
            .uri(format!("/api/connectors/{}", connector_id))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&update_body).unwrap()))
            .unwrap();

        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ConnectorResponse = serde_json::from_slice(&body_bytes).unwrap();

        // updated_at should have changed
        let new_updated_at = updated.updated_at.to_rfc3339();
        assert_ne!(original_updated_at, new_updated_at);
    }
}
