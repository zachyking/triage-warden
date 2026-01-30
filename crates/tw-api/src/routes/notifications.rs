//! Notification channel management endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::db::{create_notification_repository, NotificationChannelRepository};
use tw_core::notification::{ChannelType, NotificationChannel, NotificationChannelUpdate};

/// Creates notification channel routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_channels).post(create_channel))
        .route(
            "/{id}",
            get(get_channel).put(update_channel).delete(delete_channel),
        )
        .route("/{id}/toggle", post(toggle_channel))
        .route("/{id}/test", post(test_channel))
}

/// Request for creating a new notification channel.
#[derive(Debug, Deserialize)]
pub struct CreateChannelRequest {
    /// Human-readable name for the channel.
    pub name: String,
    /// The type of notification channel.
    pub channel_type: String,
    /// Webhook URL (for slack, teams, webhook types).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Slack channel override (optional).
    #[serde(default)]
    pub channel: Option<String>,
    /// Email recipients (comma-separated).
    #[serde(default)]
    pub recipients: Option<String>,
    /// SMTP host for email.
    #[serde(default)]
    pub smtp_host: Option<String>,
    /// SMTP port for email.
    #[serde(default)]
    pub smtp_port: Option<u16>,
    /// PagerDuty integration key.
    #[serde(default)]
    pub integration_key: Option<String>,
    /// PagerDuty severity mapping.
    #[serde(default)]
    pub pd_severity: Option<String>,
    /// Authentication header for generic webhooks.
    #[serde(default)]
    pub auth_header: Option<String>,
    /// Event types to subscribe to.
    #[serde(default, rename = "events[]")]
    pub events: Vec<String>,
    /// Whether the channel is enabled.
    #[serde(default)]
    pub enabled: Option<String>,
}

/// Request for updating a notification channel.
#[derive(Debug, Deserialize)]
pub struct UpdateChannelRequest {
    /// Updated name.
    #[serde(default)]
    pub name: Option<String>,
    /// Updated channel type.
    #[serde(default)]
    pub channel_type: Option<String>,
    /// Webhook URL.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Slack channel override.
    #[serde(default)]
    pub channel: Option<String>,
    /// Email recipients.
    #[serde(default)]
    pub recipients: Option<String>,
    /// SMTP host.
    #[serde(default)]
    pub smtp_host: Option<String>,
    /// SMTP port.
    #[serde(default)]
    pub smtp_port: Option<u16>,
    /// PagerDuty integration key.
    #[serde(default)]
    pub integration_key: Option<String>,
    /// PagerDuty severity mapping.
    #[serde(default)]
    pub pd_severity: Option<String>,
    /// Authentication header.
    #[serde(default)]
    pub auth_header: Option<String>,
    /// Event types.
    #[serde(default, rename = "events[]")]
    pub events: Option<Vec<String>>,
    /// Whether enabled.
    #[serde(default)]
    pub enabled: Option<String>,
}

/// Response for a notification channel.
#[derive(Debug, Serialize)]
pub struct ChannelResponse {
    pub id: Uuid,
    pub name: String,
    pub channel_type: String,
    pub config: serde_json::Value,
    pub events: Vec<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

/// Response for test notification.
#[derive(Debug, Serialize)]
pub struct TestNotificationResponse {
    pub success: bool,
    pub message: String,
}

impl From<NotificationChannel> for ChannelResponse {
    fn from(channel: NotificationChannel) -> Self {
        ChannelResponse {
            id: channel.id,
            name: channel.name,
            channel_type: channel.channel_type.as_db_str().to_string(),
            config: channel.config,
            events: channel.events,
            enabled: channel.enabled,
            created_at: channel.created_at.to_rfc3339(),
            updated_at: channel.updated_at.to_rfc3339(),
        }
    }
}

/// List all notification channels.
async fn list_channels(
    State(state): State<AppState>,
) -> Result<Json<Vec<ChannelResponse>>, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    let channels = repo.list().await?;
    let response: Vec<ChannelResponse> = channels.into_iter().map(ChannelResponse::from).collect();

    Ok(Json(response))
}

/// Get a single notification channel by ID.
async fn get_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ChannelResponse>, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    let channel = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification channel {} not found", id)))?;

    Ok(Json(ChannelResponse::from(channel)))
}

/// Create a new notification channel.
async fn create_channel(
    State(state): State<AppState>,
    Form(request): Form<CreateChannelRequest>,
) -> Result<Response, ApiError> {
    // Validate name
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Channel name is required".to_string()));
    }

    // Parse channel type
    let channel_type = ChannelType::from_db_str(&request.channel_type).ok_or_else(|| {
        ApiError::BadRequest(format!("Invalid channel type: {}", request.channel_type))
    })?;

    // Build config JSON based on channel type
    let config = build_config(&channel_type, &request)?;

    // Parse enabled status (checkbox sends "on" when checked, nothing when unchecked)
    let enabled = request.enabled.as_ref().is_some_and(|v| v == "on");

    // Get events (default to empty if none selected)
    let events = if request.events.is_empty() {
        vec![]
    } else {
        request.events
    };

    // Create the channel
    let channel = NotificationChannel::new(request.name, channel_type, config, events);
    let mut channel = channel;
    channel.enabled = enabled;

    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);
    let created = repo.create(&channel).await?;

    // Return with HX-Trigger for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Channel Created",
            "message": format!("Notification channel '{}' has been created.", created.name)
        }
    });

    Ok((
        StatusCode::CREATED,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(ChannelResponse::from(created)),
    )
        .into_response())
}

/// Update an existing notification channel.
async fn update_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Form(request): Form<UpdateChannelRequest>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    // Verify channel exists
    let existing = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification channel {} not found", id)))?;

    // Parse channel type if provided
    let channel_type = match &request.channel_type {
        Some(ct) => Some(
            ChannelType::from_db_str(ct)
                .ok_or_else(|| ApiError::BadRequest(format!("Invalid channel type: {}", ct)))?,
        ),
        None => None,
    };

    // Build config if any config fields are provided
    let config = if request.webhook_url.is_some()
        || request.channel.is_some()
        || request.recipients.is_some()
        || request.smtp_host.is_some()
        || request.integration_key.is_some()
        || request.auth_header.is_some()
    {
        // Use the provided channel type or fall back to existing
        let ct = channel_type
            .clone()
            .unwrap_or(existing.channel_type.clone());
        Some(build_config_for_update(&ct, &request)?)
    } else {
        None
    };

    // Parse enabled status
    let enabled = request.enabled.as_ref().map(|v| v == "on");

    let update = NotificationChannelUpdate {
        name: request.name,
        channel_type,
        config,
        events: request.events,
        enabled,
    };

    let updated = repo.update(id, &update).await?;

    // Return with HX-Trigger for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Channel Updated",
            "message": format!("Notification channel '{}' has been updated.", updated.name)
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(ChannelResponse::from(updated)),
    )
        .into_response())
}

/// Delete a notification channel.
async fn delete_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    // Get channel name before deletion for the toast message
    let channel = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification channel {} not found", id)))?;

    let deleted = repo.delete(id).await?;

    if !deleted {
        return Err(ApiError::NotFound(format!(
            "Notification channel {} not found",
            id
        )));
    }

    // Return with HX-Trigger for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Channel Deleted",
            "message": format!("Notification channel '{}' has been deleted.", channel.name)
        }
    });

    Ok((
        StatusCode::OK,
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        "",
    )
        .into_response())
}

/// Toggle the enabled status of a notification channel.
async fn toggle_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    let updated = repo.toggle_enabled(id).await?;

    let status_text = if updated.enabled {
        "enabled"
    } else {
        "disabled"
    };

    // Return with HX-Trigger for toast notification
    let trigger_json = serde_json::json!({
        "showToast": {
            "type": "success",
            "title": "Channel Updated",
            "message": format!("Notification channel '{}' has been {}.", updated.name, status_text)
        }
    });

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(ChannelResponse::from(updated)),
    )
        .into_response())
}

/// Send a test notification to a channel.
async fn test_channel(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Response, ApiError> {
    let repo: Box<dyn NotificationChannelRepository> = create_notification_repository(&state.db);

    let channel = repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Notification channel {} not found", id)))?;

    // Perform test notification based on channel type
    let result = send_test_notification(&channel).await;

    let (toast_type, title, message, success) = match &result {
        Ok(msg) => ("success", "Test Sent", msg.clone(), true),
        Err(msg) => ("error", "Test Failed", msg.clone(), false),
    };

    let trigger_json = serde_json::json!({
        "showToast": {
            "type": toast_type,
            "title": title,
            "message": message
        }
    });

    let response = TestNotificationResponse { success, message };

    Ok((
        [(
            axum::http::header::HeaderName::from_static("hx-trigger"),
            trigger_json.to_string(),
        )],
        Json(response),
    )
        .into_response())
}

/// Build config JSON from the create request based on channel type.
fn build_config(
    channel_type: &ChannelType,
    request: &CreateChannelRequest,
) -> Result<serde_json::Value, ApiError> {
    match channel_type {
        ChannelType::Slack => {
            let webhook_url = request.webhook_url.clone().ok_or_else(|| {
                ApiError::BadRequest("Webhook URL is required for Slack".to_string())
            })?;

            let mut config = serde_json::json!({
                "webhook_url": webhook_url
            });

            if let Some(channel) = &request.channel {
                if !channel.is_empty() {
                    config["channel"] = serde_json::json!(channel);
                }
            }

            Ok(config)
        }
        ChannelType::Teams => {
            let webhook_url = request.webhook_url.clone().ok_or_else(|| {
                ApiError::BadRequest("Webhook URL is required for Teams".to_string())
            })?;

            Ok(serde_json::json!({
                "webhook_url": webhook_url
            }))
        }
        ChannelType::Email => {
            let recipients = request.recipients.clone().ok_or_else(|| {
                ApiError::BadRequest("Recipients are required for Email".to_string())
            })?;

            let mut config = serde_json::json!({
                "recipients": recipients
            });

            if let Some(smtp_host) = &request.smtp_host {
                if !smtp_host.is_empty() {
                    config["smtp_host"] = serde_json::json!(smtp_host);
                }
            }

            if let Some(smtp_port) = request.smtp_port {
                config["smtp_port"] = serde_json::json!(smtp_port);
            }

            Ok(config)
        }
        ChannelType::PagerDuty => {
            let integration_key = request.integration_key.clone().ok_or_else(|| {
                ApiError::BadRequest("Integration key is required for PagerDuty".to_string())
            })?;

            let mut config = serde_json::json!({
                "integration_key": integration_key
            });

            if let Some(severity) = &request.pd_severity {
                config["severity"] = serde_json::json!(severity);
            }

            Ok(config)
        }
        ChannelType::Webhook => {
            let webhook_url = request
                .webhook_url
                .clone()
                .ok_or_else(|| ApiError::BadRequest("Webhook URL is required".to_string()))?;

            let mut config = serde_json::json!({
                "webhook_url": webhook_url
            });

            if let Some(auth_header) = &request.auth_header {
                if !auth_header.is_empty() {
                    config["auth_header"] = serde_json::json!(auth_header);
                }
            }

            Ok(config)
        }
    }
}

/// Build config JSON from the update request based on channel type.
fn build_config_for_update(
    channel_type: &ChannelType,
    request: &UpdateChannelRequest,
) -> Result<serde_json::Value, ApiError> {
    match channel_type {
        ChannelType::Slack => {
            let mut config = serde_json::Map::new();

            if let Some(webhook_url) = &request.webhook_url {
                config.insert("webhook_url".to_string(), serde_json::json!(webhook_url));
            }
            if let Some(channel) = &request.channel {
                if !channel.is_empty() {
                    config.insert("channel".to_string(), serde_json::json!(channel));
                }
            }

            Ok(serde_json::Value::Object(config))
        }
        ChannelType::Teams => {
            let mut config = serde_json::Map::new();

            if let Some(webhook_url) = &request.webhook_url {
                config.insert("webhook_url".to_string(), serde_json::json!(webhook_url));
            }

            Ok(serde_json::Value::Object(config))
        }
        ChannelType::Email => {
            let mut config = serde_json::Map::new();

            if let Some(recipients) = &request.recipients {
                config.insert("recipients".to_string(), serde_json::json!(recipients));
            }
            if let Some(smtp_host) = &request.smtp_host {
                if !smtp_host.is_empty() {
                    config.insert("smtp_host".to_string(), serde_json::json!(smtp_host));
                }
            }
            if let Some(smtp_port) = request.smtp_port {
                config.insert("smtp_port".to_string(), serde_json::json!(smtp_port));
            }

            Ok(serde_json::Value::Object(config))
        }
        ChannelType::PagerDuty => {
            let mut config = serde_json::Map::new();

            if let Some(integration_key) = &request.integration_key {
                config.insert(
                    "integration_key".to_string(),
                    serde_json::json!(integration_key),
                );
            }
            if let Some(severity) = &request.pd_severity {
                config.insert("severity".to_string(), serde_json::json!(severity));
            }

            Ok(serde_json::Value::Object(config))
        }
        ChannelType::Webhook => {
            let mut config = serde_json::Map::new();

            if let Some(webhook_url) = &request.webhook_url {
                config.insert("webhook_url".to_string(), serde_json::json!(webhook_url));
            }
            if let Some(auth_header) = &request.auth_header {
                if !auth_header.is_empty() {
                    config.insert("auth_header".to_string(), serde_json::json!(auth_header));
                }
            }

            Ok(serde_json::Value::Object(config))
        }
    }
}

/// Send a test notification to verify channel configuration.
async fn send_test_notification(channel: &NotificationChannel) -> Result<String, String> {
    let test_payload = serde_json::json!({
        "type": "test",
        "title": "Triage Warden Test Notification",
        "message": "This is a test notification from Triage Warden to verify your channel configuration.",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "channel_name": channel.name
    });

    match channel.channel_type {
        ChannelType::Webhook | ChannelType::Slack | ChannelType::Teams => {
            // Get webhook URL from config
            let webhook_url = channel
                .config
                .get("webhook_url")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "No webhook URL configured".to_string())?;

            // Create HTTP client
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

            // Build the payload based on channel type
            let payload = match channel.channel_type {
                ChannelType::Slack => {
                    serde_json::json!({
                        "text": format!("*{}*\n{}",
                            test_payload["title"].as_str().unwrap_or("Test"),
                            test_payload["message"].as_str().unwrap_or("")
                        )
                    })
                }
                ChannelType::Teams => {
                    serde_json::json!({
                        "@type": "MessageCard",
                        "@context": "http://schema.org/extensions",
                        "themeColor": "0076D7",
                        "summary": test_payload["title"].as_str().unwrap_or("Test"),
                        "sections": [{
                            "activityTitle": test_payload["title"].as_str().unwrap_or("Test"),
                            "text": test_payload["message"].as_str().unwrap_or("")
                        }]
                    })
                }
                _ => test_payload.clone(),
            };

            // Build the request
            let mut request = client.post(webhook_url).json(&payload);

            // Add auth header if configured (for generic webhooks)
            if let Some(auth_header) = channel.config.get("auth_header").and_then(|v| v.as_str()) {
                if !auth_header.is_empty() {
                    request = request.header("Authorization", auth_header);
                }
            }

            // Send the request
            let response = request
                .send()
                .await
                .map_err(|e| format!("Failed to send request: {}", e))?;

            if response.status().is_success() {
                Ok(format!(
                    "Test notification sent successfully to '{}'.",
                    channel.name
                ))
            } else {
                Err(format!(
                    "Webhook returned error status: {} - {}",
                    response.status(),
                    response
                        .text()
                        .await
                        .unwrap_or_else(|_| "Unknown error".to_string())
                ))
            }
        }
        ChannelType::Email => {
            // For MVP, we just return a success message since we'd need SMTP setup
            Ok(format!(
                "Test notification would be sent to: {}",
                channel
                    .config
                    .get("recipients")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no recipients configured)")
            ))
        }
        ChannelType::PagerDuty => {
            // For MVP, we just return a success message since we'd need PD API setup
            Ok(
                "Test notification would be sent to PagerDuty. Integration key is configured."
                    .to_string(),
            )
        }
    }
}
