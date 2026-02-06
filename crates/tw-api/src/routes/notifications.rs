//! Notification channel management and notification rules endpoints.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{create_notification_repository, NotificationChannelRepository};
use tw_core::notification::{ChannelType, NotificationChannel, NotificationChannelUpdate};
use tw_core::notifications::{
    ChannelConfig, NotificationCondition, NotificationEngine, NotificationHistory,
    NotificationRule, NotificationTrigger, ThrottleConfig,
};

/// Creates notification channel routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_channels).post(create_channel))
        .route(
            "/:id",
            get(get_channel).put(update_channel).delete(delete_channel),
        )
        .route("/:id/toggle", post(toggle_channel))
        .route("/:id/test", post(test_channel))
        // Notification rules sub-routes
        .nest("/rules", rules_routes())
        .route("/history", get(list_notification_history))
}

/// Creates notification rules routes.
fn rules_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list_rules).post(create_rule))
        .route("/:id", get(get_rule).put(update_rule).delete(delete_rule))
        .route("/:id/test", post(test_rule))
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
#[derive(Debug, Serialize, Deserialize)]
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
#[derive(Debug, Serialize, Deserialize)]
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
    let created = repo.create(DEFAULT_TENANT_ID, &channel).await?;

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

// =============================================================================
// Notification Rules DTOs
// =============================================================================

/// Request for creating a new notification rule.
#[derive(Debug, Deserialize)]
pub struct CreateNotificationRuleRequest {
    /// Human-readable name for the rule.
    pub name: String,
    /// Optional description.
    #[serde(default)]
    pub description: Option<String>,
    /// The trigger event type.
    pub trigger: NotificationTrigger,
    /// Additional conditions that must be met.
    #[serde(default)]
    pub conditions: Vec<NotificationCondition>,
    /// Channels to send notifications to.
    pub channels: Vec<ChannelConfig>,
    /// Optional throttle configuration.
    #[serde(default)]
    pub throttle: Option<ThrottleConfig>,
    /// Whether the rule is enabled (defaults to true).
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Request for updating an existing notification rule.
#[derive(Debug, Deserialize)]
pub struct UpdateNotificationRuleRequest {
    /// Updated name.
    #[serde(default)]
    pub name: Option<String>,
    /// Updated description.
    #[serde(default)]
    pub description: Option<Option<String>>,
    /// Updated trigger.
    #[serde(default)]
    pub trigger: Option<NotificationTrigger>,
    /// Updated conditions.
    #[serde(default)]
    pub conditions: Option<Vec<NotificationCondition>>,
    /// Updated channels.
    #[serde(default)]
    pub channels: Option<Vec<ChannelConfig>>,
    /// Updated throttle config.
    #[serde(default)]
    pub throttle: Option<Option<ThrottleConfig>>,
    /// Updated enabled status.
    #[serde(default)]
    pub enabled: Option<bool>,
}

/// Response for a notification rule.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationRuleResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub trigger: NotificationTrigger,
    pub conditions: Vec<NotificationCondition>,
    pub channels: Vec<ChannelConfig>,
    pub throttle: Option<ThrottleConfig>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<NotificationRule> for NotificationRuleResponse {
    fn from(rule: NotificationRule) -> Self {
        Self {
            id: rule.id,
            tenant_id: rule.tenant_id,
            name: rule.name,
            description: rule.description,
            trigger: rule.trigger,
            conditions: rule.conditions,
            channels: rule.channels,
            throttle: rule.throttle,
            enabled: rule.enabled,
            created_at: rule.created_at,
            updated_at: rule.updated_at,
        }
    }
}

/// Response for a notification delivery history entry.
#[derive(Debug, Serialize, Deserialize)]
pub struct NotificationHistoryResponse {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub trigger: String,
    pub channel_type: String,
    pub success: bool,
    pub error: Option<String>,
    pub sent_at: DateTime<Utc>,
}

impl From<NotificationHistory> for NotificationHistoryResponse {
    fn from(h: NotificationHistory) -> Self {
        Self {
            id: h.id,
            rule_id: h.rule_id,
            trigger: h.trigger,
            channel_type: h.channel_type,
            success: h.success,
            error: h.error,
            sent_at: h.sent_at,
        }
    }
}

/// Response for testing a notification rule.
#[derive(Debug, Serialize, Deserialize)]
pub struct TestRuleResponse {
    /// Whether the test event would trigger this rule.
    pub would_trigger: bool,
    /// The matching conditions that were evaluated.
    pub conditions_met: bool,
    /// Message describing the result.
    pub message: String,
}

/// Query parameters for notification history.
#[derive(Debug, Deserialize)]
pub struct NotificationHistoryQuery {
    /// Maximum number of history entries to return.
    #[serde(default = "default_history_limit")]
    pub limit: usize,
}

fn default_history_limit() -> usize {
    100
}

// =============================================================================
// Notification Rules Handlers
// =============================================================================

/// List all notification rules.
async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<Vec<NotificationRuleResponse>>, ApiError> {
    let engine = get_notification_engine(&state);
    let rules = engine.get_rules().await;
    let response: Vec<NotificationRuleResponse> = rules
        .into_iter()
        .map(NotificationRuleResponse::from)
        .collect();
    Ok(Json(response))
}

/// Get a single notification rule by ID.
async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<NotificationRuleResponse>, ApiError> {
    let engine = get_notification_engine(&state);
    let rule = engine
        .get_rule(id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Notification rule {} not found", id)))?;
    Ok(Json(NotificationRuleResponse::from(rule)))
}

/// Create a new notification rule.
async fn create_rule(
    State(state): State<AppState>,
    Json(request): Json<CreateNotificationRuleRequest>,
) -> Result<(StatusCode, Json<NotificationRuleResponse>), ApiError> {
    // Validate name
    if request.name.trim().is_empty() {
        return Err(ApiError::BadRequest("Rule name is required".to_string()));
    }

    // Validate channels
    if request.channels.is_empty() {
        return Err(ApiError::BadRequest(
            "At least one channel is required".to_string(),
        ));
    }

    let tenant_id = DEFAULT_TENANT_ID;

    let mut rule =
        NotificationRule::new(tenant_id, request.name, request.trigger, request.channels);
    rule.description = request.description;
    rule.conditions = request.conditions;
    rule.throttle = request.throttle;
    rule.enabled = request.enabled;

    let engine = get_notification_engine(&state);
    engine.add_rule(rule.clone()).await;

    Ok((
        StatusCode::CREATED,
        Json(NotificationRuleResponse::from(rule)),
    ))
}

/// Update an existing notification rule.
async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<UpdateNotificationRuleRequest>,
) -> Result<Json<NotificationRuleResponse>, ApiError> {
    let engine = get_notification_engine(&state);

    let mut rule = engine
        .get_rule(id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Notification rule {} not found", id)))?;

    // Apply updates
    if let Some(name) = request.name {
        if name.trim().is_empty() {
            return Err(ApiError::BadRequest(
                "Rule name cannot be empty".to_string(),
            ));
        }
        rule.name = name;
    }
    if let Some(description) = request.description {
        rule.description = description;
    }
    if let Some(trigger) = request.trigger {
        rule.trigger = trigger;
    }
    if let Some(conditions) = request.conditions {
        rule.conditions = conditions;
    }
    if let Some(channels) = request.channels {
        if channels.is_empty() {
            return Err(ApiError::BadRequest(
                "At least one channel is required".to_string(),
            ));
        }
        rule.channels = channels;
    }
    if let Some(throttle) = request.throttle {
        rule.throttle = throttle;
    }
    if let Some(enabled) = request.enabled {
        rule.enabled = enabled;
    }

    rule.updated_at = Utc::now();

    let updated = engine.update_rule(rule.clone()).await;
    if !updated {
        return Err(ApiError::Internal(
            "Failed to update notification rule".to_string(),
        ));
    }

    Ok(Json(NotificationRuleResponse::from(rule)))
}

/// Delete a notification rule.
async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let engine = get_notification_engine(&state);
    let removed = engine.remove_rule(id).await;
    if !removed {
        return Err(ApiError::NotFound(format!(
            "Notification rule {} not found",
            id
        )));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Test a notification rule with a simulated event.
async fn test_rule(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<TestRuleResponse>, ApiError> {
    let engine = get_notification_engine(&state);
    let rule = engine
        .get_rule(id)
        .await
        .ok_or_else(|| ApiError::NotFound(format!("Notification rule {} not found", id)))?;

    // Build a test event based on the rule's trigger
    let test_event = build_test_event(&rule.trigger);
    let event_json = serde_json::to_value(&test_event).unwrap_or_default();

    // Evaluate conditions against the test event
    let conditions_met =
        tw_core::notifications::rules::evaluate_conditions(&rule.conditions, &event_json);

    let would_trigger = rule.enabled && conditions_met;

    let message = if !rule.enabled {
        "Rule is disabled and would not trigger.".to_string()
    } else if conditions_met {
        format!(
            "Rule would trigger and send to {} channel(s).",
            rule.channels.len()
        )
    } else {
        "Rule conditions were not met for the test event.".to_string()
    };

    Ok(Json(TestRuleResponse {
        would_trigger,
        conditions_met,
        message,
    }))
}

/// List notification delivery history.
async fn list_notification_history(
    State(state): State<AppState>,
    Query(query): Query<NotificationHistoryQuery>,
) -> Result<Json<Vec<NotificationHistoryResponse>>, ApiError> {
    let engine = get_notification_engine(&state);
    let limit = query.limit.min(1000);
    let history = engine.get_history(Some(limit)).await;
    let response: Vec<NotificationHistoryResponse> = history
        .into_iter()
        .map(NotificationHistoryResponse::from)
        .collect();
    Ok(Json(response))
}

// =============================================================================
// Helper Functions for Rules
// =============================================================================

/// Gets or creates the notification engine from app state.
///
/// The notification engine is stored as a shared resource.
/// For now we use a lazily initialized global engine per app instance.
fn get_notification_engine(_state: &AppState) -> &'static NotificationEngine {
    use std::sync::OnceLock;
    static ENGINE: OnceLock<NotificationEngine> = OnceLock::new();
    ENGINE.get_or_init(NotificationEngine::new)
}

/// Builds a test event for rule testing purposes.
fn build_test_event(trigger: &NotificationTrigger) -> tw_core::TriageEvent {
    let test_id = Uuid::new_v4();
    match trigger {
        NotificationTrigger::IncidentCreated => tw_core::TriageEvent::IncidentCreated {
            incident_id: test_id,
            alert_id: "test-alert-001".to_string(),
        },
        NotificationTrigger::IncidentResolved => tw_core::TriageEvent::IncidentResolved {
            incident_id: test_id,
            resolution: tw_core::events::Resolution {
                resolution_type: tw_core::events::ResolutionType::Remediated,
                summary: "Test resolution".to_string(),
                actions_taken: vec![],
                lessons_learned: None,
            },
        },
        NotificationTrigger::IncidentEscalated => tw_core::TriageEvent::IncidentEscalated {
            incident_id: test_id,
            escalation_level: 2,
            reason: "Test escalation".to_string(),
        },
        NotificationTrigger::AnalysisCompleted => {
            // Build a minimal TriageAnalysis for testing
            let analysis = tw_core::incident::TriageAnalysis {
                verdict: tw_core::incident::TriageVerdict::TruePositive,
                confidence: 0.85,
                calibrated_confidence: None,
                summary: "Test analysis".to_string(),
                reasoning: "Test reasoning".to_string(),
                mitre_techniques: vec![],
                iocs: vec![],
                recommendations: vec!["Test recommendation".to_string()],
                risk_score: 75,
                analyzed_by: "test".to_string(),
                timestamp: Utc::now(),
                evidence: vec![],
                investigation_steps: vec![],
            };
            tw_core::TriageEvent::AnalysisComplete {
                incident_id: test_id,
                analysis,
            }
        }
        NotificationTrigger::ActionPendingApproval => tw_core::TriageEvent::ActionsProposed {
            incident_id: test_id,
            actions: vec![],
        },
        NotificationTrigger::ActionExecuted => tw_core::TriageEvent::ActionExecuted {
            incident_id: test_id,
            action_id: Uuid::new_v4(),
            action_type: tw_core::incident::ActionType::IsolateHost,
            result: tw_core::events::ActionResult {
                success: true,
                message: "Test action executed".to_string(),
                data: None,
                error: None,
            },
        },
        NotificationTrigger::KillSwitchActivated => tw_core::TriageEvent::KillSwitchActivated {
            reason: "Test kill switch activation".to_string(),
            activated_by: "test-user".to_string(),
        },
        NotificationTrigger::SystemError => tw_core::TriageEvent::SystemError {
            incident_id: None,
            error: "Test system error".to_string(),
            recoverable: true,
        },
        NotificationTrigger::FeedbackReceived => tw_core::TriageEvent::FeedbackReceived {
            incident_id: test_id,
            feedback_id: Uuid::new_v4(),
            feedback_type: "correction".to_string(),
            is_correction: true,
        },
        NotificationTrigger::SeverityChanged => tw_core::TriageEvent::StatusChanged {
            incident_id: test_id,
            old_status: tw_core::incident::IncidentStatus::New,
            new_status: tw_core::incident::IncidentStatus::Enriching,
        },
        NotificationTrigger::PlaybookCompleted | NotificationTrigger::Custom(_) => {
            // Use a generic incident created event for unsupported triggers
            tw_core::TriageEvent::IncidentCreated {
                incident_id: test_id,
                alert_id: "test-alert-playbook".to_string(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sqlx::Executor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tower::ServiceExt;
    use tw_core::db::DbPool;
    use tw_core::{EventBus, FeatureFlagStore, FeatureFlags, InMemoryFeatureFlagStore};

    // Counter to ensure unique database names across tests
    static DB_COUNTER: AtomicU64 = AtomicU64::new(5_000_000);

    /// Creates an in-memory SQLite database pool with all required migrations.
    async fn setup_test_pool() -> sqlx::SqlitePool {
        let db_id = DB_COUNTER.fetch_add(1, Ordering::SeqCst);
        let unique_id = uuid::Uuid::new_v4();
        let db_url = format!(
            "sqlite:file:notification_test_{}_{}?mode=memory&cache=shared",
            db_id, unique_id
        );

        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&db_url)
            .await
            .expect("Failed to create pool");

        // Run migrations using Executor::execute for multi-statement SQL
        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240101_000001_initial_schema.sql"
        ))
        .await
        .expect("Failed to create initial schema");

        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240102_000001_create_playbooks.sql"
        ))
        .await
        .expect("Failed to create playbooks table");

        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240103_000001_create_connectors.sql"
        ))
        .await
        .expect("Failed to create connectors table");

        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240104_000001_create_policies.sql"
        ))
        .await
        .expect("Failed to create policies table");

        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240105_000001_create_notification_channels.sql"
        ))
        .await
        .expect("Failed to create notification_channels table");

        pool.execute(include_str!(
            "../../../tw-core/src/db/migrations/sqlite/20240106_000001_create_settings.sql"
        ))
        .await
        .expect("Failed to create settings table");

        // Create tenants table for multi-tenancy
        pool.execute(
            r#"
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                slug TEXT NOT NULL UNIQUE,
                settings TEXT NOT NULL DEFAULT '{}',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO tenants (id, name, slug, settings, enabled, created_at, updated_at)
            VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', '{}', 1, datetime('now'), datetime('now'));
            "#,
        )
        .await
        .expect("Failed to create tenants table");

        // Add tenant_id to tables that need it
        pool.execute(
            r#"
            ALTER TABLE notification_channels ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            ALTER TABLE settings ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
            ALTER TABLE incidents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            ALTER TABLE playbooks ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            ALTER TABLE connectors ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            ALTER TABLE policies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id);
            "#,
        )
        .await
        .expect("Failed to add tenant_id to tables");

        pool
    }

    /// Creates a test app router with the notification routes.
    async fn setup_test_app() -> axum::Router {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);
        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);

        axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state)
    }

    // =========================================================================
    // GET /api/notifications - List channels
    // =========================================================================

    #[tokio::test]
    async fn test_list_channels_empty() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channels: Vec<ChannelResponse> = serde_json::from_slice(&body).unwrap();

        assert!(channels.is_empty());
    }

    #[tokio::test]
    async fn test_list_channels_with_data() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Insert a channel directly
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Test Slack".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/test"}),
            vec!["incident.created".to_string()],
        );
        repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channels: Vec<ChannelResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0].name, "Test Slack");
        assert_eq!(channels[0].channel_type, "slack");
    }

    // =========================================================================
    // GET /api/notifications/{id} - Get single channel
    // =========================================================================

    #[tokio::test]
    async fn test_get_channel_success() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Insert a channel
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Teams Channel".to_string(),
            ChannelType::Teams,
            serde_json::json!({"webhook_url": "https://outlook.office.com/webhook/test"}),
            vec!["action.approved".to_string()],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.id, created.id);
        assert_eq!(resp.name, "Teams Channel");
        assert_eq!(resp.channel_type, "teams");
    }

    #[tokio::test]
    async fn test_get_channel_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/api/notifications/{}", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // =========================================================================
    // POST /api/notifications - Create channel
    // =========================================================================

    #[tokio::test]
    async fn test_create_channel_slack() {
        let app = setup_test_app().await;

        // Note: Not including events[] in form as serde_urlencoded Vec handling is tricky
        let form_body = "name=Alerts+Slack&channel_type=slack&webhook_url=https%3A%2F%2Fhooks.slack.com%2Fservices%2FT00%2FB00%2Fxxxx&enabled=on";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(channel.name, "Alerts Slack");
        assert_eq!(channel.channel_type, "slack");
        assert!(channel.enabled);
    }

    #[tokio::test]
    async fn test_create_channel_webhook() {
        let app = setup_test_app().await;

        let form_body = "name=Custom+Webhook&channel_type=webhook&webhook_url=https%3A%2F%2Fexample.com%2Fwebhook";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(channel.name, "Custom Webhook");
        assert_eq!(channel.channel_type, "webhook");
        assert!(!channel.enabled); // Not enabled by default
    }

    #[tokio::test]
    async fn test_create_channel_teams() {
        let app = setup_test_app().await;

        let form_body = "name=Security+Teams&channel_type=teams&webhook_url=https%3A%2F%2Foutlook.office.com%2Fwebhook%2Fabc123&enabled=on";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(channel.name, "Security Teams");
        assert_eq!(channel.channel_type, "teams");
    }

    #[tokio::test]
    async fn test_create_channel_missing_name() {
        let app = setup_test_app().await;

        let form_body = "name=&channel_type=slack&webhook_url=https://hooks.slack.com/test";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_channel_invalid_type() {
        let app = setup_test_app().await;

        let form_body =
            "name=Test&channel_type=invalid_type&webhook_url=https://example.com/webhook";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_channel_slack_missing_webhook() {
        let app = setup_test_app().await;

        let form_body = "name=Missing+Webhook&channel_type=slack";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_channel_email() {
        let app = setup_test_app().await;

        let form_body = "name=Email+Alerts&channel_type=email&recipients=admin%40example.com%2Csecurity%40example.com&smtp_host=smtp.example.com&smtp_port=587&enabled=on";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(channel.name, "Email Alerts");
        assert_eq!(channel.channel_type, "email");
        assert!(channel.config.get("recipients").is_some());
    }

    #[tokio::test]
    async fn test_create_channel_email_missing_recipients() {
        let app = setup_test_app().await;

        let form_body = "name=Email+No+Recipients&channel_type=email";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_channel_pagerduty() {
        let app = setup_test_app().await;

        let form_body = "name=PagerDuty+Critical&channel_type=pagerduty&integration_key=abc123def456&pd_severity=critical&enabled=on";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(channel.name, "PagerDuty Critical");
        assert_eq!(channel.channel_type, "pagerduty");
        assert!(channel.config.get("integration_key").is_some());
    }

    #[tokio::test]
    async fn test_create_channel_pagerduty_missing_key() {
        let app = setup_test_app().await;

        let form_body = "name=PagerDuty+No+Key&channel_type=pagerduty";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // =========================================================================
    // PUT /api/notifications/{id} - Update channel
    // =========================================================================

    #[tokio::test]
    async fn test_update_channel_name() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create a channel
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Original Name".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/test"}),
            vec!["incident.created".to_string()],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let form_body = "name=Updated+Name";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(updated.name, "Updated Name");
    }

    #[tokio::test]
    async fn test_update_channel_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let form_body = "name=New+Name";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", non_existent_id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // =========================================================================
    // DELETE /api/notifications/{id} - Delete channel
    // =========================================================================

    #[tokio::test]
    async fn test_delete_channel_success() {
        let pool = setup_test_pool().await;
        let pool_clone = pool.clone();
        let db = DbPool::Sqlite(pool);

        // Create a channel
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "To Delete".to_string(),
            ChannelType::Webhook,
            serde_json::json!({"webhook_url": "https://example.com/delete"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify channel is deleted using the cloned pool
        let db_verify = DbPool::Sqlite(pool_clone);
        let verify_repo = tw_core::db::create_notification_repository(&db_verify);
        let deleted = verify_repo.get(created.id).await.unwrap();
        assert!(deleted.is_none());
    }

    #[tokio::test]
    async fn test_delete_channel_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/notifications/{}", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // =========================================================================
    // POST /api/notifications/{id}/toggle - Toggle enabled status
    // =========================================================================

    #[tokio::test]
    async fn test_toggle_channel_enable() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create a disabled channel
        let repo = tw_core::db::create_notification_repository(&db);
        let mut channel = NotificationChannel::new(
            "Toggle Test".to_string(),
            ChannelType::Teams,
            serde_json::json!({"webhook_url": "https://outlook.office.com/webhook/toggle"}),
            vec!["incident.resolved".to_string()],
        );
        channel.enabled = false;
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        assert!(!created.enabled);

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/toggle", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let toggled: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert!(toggled.enabled);
    }

    #[tokio::test]
    async fn test_toggle_channel_disable() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create an enabled channel
        let repo = tw_core::db::create_notification_repository(&db);
        let mut channel = NotificationChannel::new(
            "Toggle Test".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/toggle"}),
            vec![],
        );
        channel.enabled = true;
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        assert!(created.enabled);

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/toggle", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let toggled: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert!(!toggled.enabled);
    }

    #[tokio::test]
    async fn test_toggle_channel_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/toggle", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // toggle_enabled returns a DbError for not found, which may map to 500 or 404
        assert!(
            response.status() == StatusCode::NOT_FOUND
                || response.status() == StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    // =========================================================================
    // POST /api/notifications/{id}/test - Test notification channel
    // =========================================================================

    #[tokio::test]
    async fn test_test_channel_email_success() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create an email channel (does not require network)
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Test Email Channel".to_string(),
            ChannelType::Email,
            serde_json::json!({"recipients": "test@example.com"}),
            vec!["incident.created".to_string()],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/test", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let test_response: TestNotificationResponse = serde_json::from_slice(&body).unwrap();

        assert!(test_response.success);
        assert!(test_response.message.contains("test@example.com"));
    }

    #[tokio::test]
    async fn test_test_channel_pagerduty_success() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create a PagerDuty channel (does not require network)
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Test PD Channel".to_string(),
            ChannelType::PagerDuty,
            serde_json::json!({"integration_key": "test123"}),
            vec!["incident.created".to_string()],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/test", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let test_response: TestNotificationResponse = serde_json::from_slice(&body).unwrap();

        assert!(test_response.success);
        assert!(test_response.message.contains("PagerDuty"));
    }

    #[tokio::test]
    async fn test_test_channel_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/test", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_test_channel_webhook_missing_url() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Create a webhook channel without webhook_url in config
        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Broken Webhook".to_string(),
            ChannelType::Webhook,
            serde_json::json!({}), // Missing webhook_url
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/test", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let test_response: TestNotificationResponse = serde_json::from_slice(&body).unwrap();

        assert!(!test_response.success);
        assert!(test_response.message.contains("No webhook URL configured"));
    }

    // =========================================================================
    // HX-Trigger header tests
    // =========================================================================

    #[tokio::test]
    async fn test_create_channel_returns_hx_trigger() {
        let app = setup_test_app().await;

        let form_body = "name=HX+Trigger+Test&channel_type=slack&webhook_url=https%3A%2F%2Fhooks.slack.com%2Ftest";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(trigger_value).unwrap();

        assert_eq!(parsed["showToast"]["type"], "success");
        assert_eq!(parsed["showToast"]["title"], "Channel Created");
    }

    #[tokio::test]
    async fn test_delete_channel_returns_hx_trigger() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Delete HX Test".to_string(),
            ChannelType::Webhook,
            serde_json::json!({"webhook_url": "https://example.com/hx"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(trigger_value).unwrap();

        assert_eq!(parsed["showToast"]["type"], "success");
        assert_eq!(parsed["showToast"]["title"], "Channel Deleted");
    }

    #[tokio::test]
    async fn test_toggle_channel_returns_hx_trigger() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Toggle HX Test".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/hx"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/notifications/{}/toggle", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let hx_trigger = response.headers().get("hx-trigger");
        assert!(hx_trigger.is_some());

        let trigger_value = hx_trigger.unwrap().to_str().unwrap();
        let parsed: serde_json::Value = serde_json::from_str(trigger_value).unwrap();

        assert_eq!(parsed["showToast"]["type"], "success");
        assert_eq!(parsed["showToast"]["title"], "Channel Updated");
    }

    // =========================================================================
    // Additional update tests
    // =========================================================================

    #[tokio::test]
    async fn test_update_channel_webhook_url() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Update Config Test".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/old"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let form_body = "webhook_url=https%3A%2F%2Fhooks.slack.com%2Fnew";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            updated.config.get("webhook_url").unwrap().as_str(),
            Some("https://hooks.slack.com/new")
        );
    }

    #[tokio::test]
    async fn test_update_channel_enabled_status() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let mut channel = NotificationChannel::new(
            "Enabled Status Test".to_string(),
            ChannelType::Teams,
            serde_json::json!({"webhook_url": "https://outlook.office.com/webhook/test"}),
            vec![],
        );
        channel.enabled = false;
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        assert!(!created.enabled);

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        // Update with enabled=on
        let form_body = "enabled=on";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert!(updated.enabled);
    }

    #[tokio::test]
    async fn test_update_channel_change_type() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Type Change Test".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/test"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        // Change from slack to teams with new webhook URL
        let form_body =
            "channel_type=teams&webhook_url=https%3A%2F%2Foutlook.office.com%2Fwebhook%2Fnew";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let updated: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(updated.channel_type, "teams");
    }

    #[tokio::test]
    async fn test_update_channel_invalid_type() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Invalid Type Update".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/test"}),
            vec![],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let form_body = "channel_type=invalid_type";

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    // =========================================================================
    // Edge case tests
    // =========================================================================

    #[tokio::test]
    async fn test_create_channel_whitespace_name() {
        let app = setup_test_app().await;

        let form_body =
            "name=+++&channel_type=slack&webhook_url=https%3A%2F%2Fhooks.slack.com%2Ftest";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_channel_slack_with_channel_override() {
        let app = setup_test_app().await;

        let form_body = "name=Slack+With+Channel&channel_type=slack&webhook_url=https%3A%2F%2Fhooks.slack.com%2Ftest&channel=%23alerts";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            channel.config.get("channel").unwrap().as_str(),
            Some("#alerts")
        );
    }

    #[tokio::test]
    async fn test_create_channel_webhook_with_auth_header() {
        let app = setup_test_app().await;

        let form_body = "name=Auth+Webhook&channel_type=webhook&webhook_url=https%3A%2F%2Fexample.com%2Fhook&auth_header=Bearer+token123";

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(form_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channel: ChannelResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            channel.config.get("auth_header").unwrap().as_str(),
            Some("Bearer token123")
        );
    }

    #[tokio::test]
    async fn test_get_channel_invalid_uuid() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications/not-a-valid-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Axum returns 400 for invalid path parameters
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_list_channels_multiple() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        // Insert multiple channels
        let repo = tw_core::db::create_notification_repository(&db);

        let channel1 = NotificationChannel::new(
            "Slack Channel".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/test1"}),
            vec!["incident.created".to_string()],
        );
        repo.create(DEFAULT_TENANT_ID, &channel1).await.unwrap();

        let channel2 = NotificationChannel::new(
            "Teams Channel".to_string(),
            ChannelType::Teams,
            serde_json::json!({"webhook_url": "https://outlook.office.com/webhook/test2"}),
            vec!["action.approved".to_string()],
        );
        repo.create(DEFAULT_TENANT_ID, &channel2).await.unwrap();

        let channel3 = NotificationChannel::new(
            "Email Channel".to_string(),
            ChannelType::Email,
            serde_json::json!({"recipients": "admin@test.com"}),
            vec![],
        );
        repo.create(DEFAULT_TENANT_ID, &channel3).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let channels: Vec<ChannelResponse> = serde_json::from_slice(&body).unwrap();

        assert_eq!(channels.len(), 3);
    }

    #[tokio::test]
    async fn test_channel_response_fields() {
        let pool = setup_test_pool().await;
        let db = DbPool::Sqlite(pool);

        let repo = tw_core::db::create_notification_repository(&db);
        let channel = NotificationChannel::new(
            "Full Response Test".to_string(),
            ChannelType::Slack,
            serde_json::json!({"webhook_url": "https://hooks.slack.com/full"}),
            vec![
                "incident.created".to_string(),
                "action.approved".to_string(),
            ],
        );
        let created = repo.create(DEFAULT_TENANT_ID, &channel).await.unwrap();

        let event_bus = EventBus::new(100);
        let store: Arc<dyn FeatureFlagStore> = Arc::new(InMemoryFeatureFlagStore::new());
        let feature_flags = FeatureFlags::new(store);
        let state = AppState::new(db, event_bus, feature_flags);
        let app = axum::Router::new()
            .nest("/api/notifications", routes())
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/api/notifications/{}", created.id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let resp: ChannelResponse = serde_json::from_slice(&body).unwrap();

        // Verify all fields are present and correct
        assert_eq!(resp.id, created.id);
        assert_eq!(resp.name, "Full Response Test");
        assert_eq!(resp.channel_type, "slack");
        assert!(!resp.config.is_null());
        assert_eq!(resp.events.len(), 2);
        assert!(resp.events.contains(&"incident.created".to_string()));
        assert!(resp.events.contains(&"action.approved".to_string()));
        assert!(resp.enabled); // Default is true
        assert!(!resp.created_at.is_empty());
        assert!(!resp.updated_at.is_empty());
    }

    // =========================================================================
    // Notification Rules API Tests
    // =========================================================================

    #[tokio::test]
    async fn test_list_rules_empty() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rules: Vec<NotificationRuleResponse> = serde_json::from_slice(&body).unwrap();
        // May or may not be empty depending on the global engine state from other tests
        let _ = rules;
    }

    #[tokio::test]
    async fn test_create_rule_success() {
        let app = setup_test_app().await;

        let payload = serde_json::json!({
            "name": "Critical Incident Alert",
            "description": "Notify on critical incidents",
            "trigger": "incident_created",
            "conditions": [{
                "field": "severity",
                "operator": "equals",
                "value": "critical"
            }],
            "channels": [{
                "type": "slack",
                "channel_id": "#security-alerts",
                "mention_users": ["@oncall"]
            }],
            "throttle": {
                "max_per_hour": 10,
                "cooldown_secs": 60
            },
            "enabled": true
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let rule: NotificationRuleResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(rule.name, "Critical Incident Alert");
        assert!(rule.enabled);
        assert_eq!(rule.conditions.len(), 1);
        assert_eq!(rule.channels.len(), 1);
        assert!(rule.throttle.is_some());
    }

    #[tokio::test]
    async fn test_create_rule_missing_name() {
        let app = setup_test_app().await;

        let payload = serde_json::json!({
            "name": "",
            "trigger": "incident_created",
            "channels": [{
                "type": "slack",
                "channel_id": "#alerts"
            }]
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_create_rule_missing_channels() {
        let app = setup_test_app().await;

        let payload = serde_json::json!({
            "name": "No Channels Rule",
            "trigger": "incident_created",
            "channels": []
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/notifications/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_rule_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(&format!("/api/notifications/rules/{}", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_delete_rule_not_found() {
        let app = setup_test_app().await;

        let non_existent_id = Uuid::new_v4();
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/notifications/rules/{}", non_existent_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_notification_history_empty() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications/history")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let history: Vec<NotificationHistoryResponse> = serde_json::from_slice(&body).unwrap();
        let _ = history;
    }

    #[tokio::test]
    async fn test_notification_history_with_limit() {
        let app = setup_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/notifications/history?limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn test_notification_rule_response_serialization() {
        let rule = NotificationRule::new(
            Uuid::new_v4(),
            "Test Rule".to_string(),
            NotificationTrigger::IncidentCreated,
            vec![ChannelConfig::Slack {
                channel_id: "#test".to_string(),
                mention_users: vec![],
            }],
        );

        let response = NotificationRuleResponse::from(rule.clone());
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("Test Rule"));
        assert!(json.contains("incident_created"));
    }

    #[test]
    fn test_create_rule_request_deserialization() {
        let json = r#"{
            "name": "Test",
            "trigger": "kill_switch_activated",
            "channels": [{"type": "teams", "webhook_url": "https://example.com/webhook"}],
            "enabled": false
        }"#;

        let request: CreateNotificationRuleRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.name, "Test");
        assert!(!request.enabled);
        assert!(request.conditions.is_empty());
    }

    #[test]
    fn test_create_rule_request_defaults() {
        let json = r#"{
            "name": "Defaults Test",
            "trigger": "system_error",
            "channels": [{"type": "email", "recipients": ["admin@test.com"]}]
        }"#;

        let request: CreateNotificationRuleRequest = serde_json::from_str(json).unwrap();
        assert!(request.enabled); // Default true
        assert!(request.conditions.is_empty()); // Default empty
        assert!(request.throttle.is_none()); // Default none
        assert!(request.description.is_none()); // Default none
    }

    #[test]
    fn test_build_test_event_incident_created() {
        let event = build_test_event(&NotificationTrigger::IncidentCreated);
        match event {
            tw_core::TriageEvent::IncidentCreated { alert_id, .. } => {
                assert_eq!(alert_id, "test-alert-001");
            }
            _ => panic!("Expected IncidentCreated event"),
        }
    }

    #[test]
    fn test_build_test_event_kill_switch() {
        let event = build_test_event(&NotificationTrigger::KillSwitchActivated);
        match event {
            tw_core::TriageEvent::KillSwitchActivated { reason, .. } => {
                assert!(reason.contains("Test"));
            }
            _ => panic!("Expected KillSwitchActivated event"),
        }
    }

    #[test]
    fn test_build_test_event_all_triggers() {
        // Verify all triggers produce valid events without panicking
        let triggers = vec![
            NotificationTrigger::IncidentCreated,
            NotificationTrigger::SeverityChanged,
            NotificationTrigger::ActionPendingApproval,
            NotificationTrigger::AnalysisCompleted,
            NotificationTrigger::IncidentResolved,
            NotificationTrigger::ActionExecuted,
            NotificationTrigger::IncidentEscalated,
            NotificationTrigger::KillSwitchActivated,
            NotificationTrigger::SystemError,
            NotificationTrigger::FeedbackReceived,
            NotificationTrigger::PlaybookCompleted,
            NotificationTrigger::Custom("test".to_string()),
        ];

        for trigger in triggers {
            let _ = build_test_event(&trigger);
        }
    }
}
