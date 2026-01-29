//! Webhook ingestion endpoints.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use uuid::Uuid;
use validator::Validate;

use crate::dto::{WebhookAcceptedResponse, WebhookAlertPayload};
use crate::error::ApiError;
use crate::state::AppState;
use crate::webhooks::{validate_signature, normalize_alert};

/// Creates webhook routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/alerts", post(receive_alert))
        .route("/alerts/:source", post(receive_alert_from_source))
}

/// Receive a generic alert via webhook.
#[utoipa::path(
    post,
    path = "/api/webhooks/alerts",
    request_body = WebhookAlertPayload,
    responses(
        (status = 202, description = "Alert accepted", body = WebhookAcceptedResponse),
        (status = 400, description = "Invalid payload"),
        (status = 401, description = "Invalid signature"),
        (status = 429, description = "Rate limit exceeded"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Webhooks"
)]
async fn receive_alert(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<WebhookAcceptedResponse>), ApiError> {
    // Validate signature if configured
    if let Some(secret) = state.webhook_secrets.get("default") {
        validate_webhook_signature(&headers, &body, secret)?;
    }

    // Parse payload
    let payload: WebhookAlertPayload = serde_json::from_slice(&body)?;
    payload.validate()?;

    // Normalize and process alert
    let alert = normalize_alert(&payload);
    let alert_id = alert.id.clone();

    // Create incident from alert
    let incident = tw_core::Incident::from_alert(alert.clone());
    let incident_id = incident.id;

    // Publish event (async processing)
    let _ = state.event_bus.publish(tw_core::TriageEvent::AlertReceived(alert)).await;
    let _ = state.event_bus.publish(tw_core::TriageEvent::IncidentCreated {
        incident_id,
        alert_id: alert_id.clone(),
    }).await;

    // TODO: Persist incident to database
    // let repo = tw_core::db::create_incident_repository(&state.db);
    // repo.create(&incident).await?;

    Ok((
        StatusCode::ACCEPTED,
        Json(WebhookAcceptedResponse {
            accepted: true,
            message: "Alert received and queued for processing".to_string(),
            alert_id: Some(alert_id),
            incident_id: Some(incident_id),
        }),
    ))
}

/// Receive an alert from a specific source.
#[utoipa::path(
    post,
    path = "/api/webhooks/alerts/{source}",
    params(
        ("source" = String, Path, description = "Source system identifier")
    ),
    request_body = WebhookAlertPayload,
    responses(
        (status = 202, description = "Alert accepted", body = WebhookAcceptedResponse),
        (status = 400, description = "Invalid payload"),
        (status = 401, description = "Invalid signature"),
        (status = 429, description = "Rate limit exceeded"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Webhooks"
)]
async fn receive_alert_from_source(
    State(state): State<AppState>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<WebhookAcceptedResponse>), ApiError> {
    // Validate source-specific signature
    if let Some(secret) = state.webhook_secrets.get(&source) {
        validate_webhook_signature(&headers, &body, secret)?;
    }

    // Parse payload
    let mut payload: WebhookAlertPayload = serde_json::from_slice(&body)?;

    // Override source with path parameter
    payload.source = source;

    payload.validate()?;

    // Normalize and process alert
    let alert = normalize_alert(&payload);
    let alert_id = alert.id.clone();

    // Create incident from alert
    let incident = tw_core::Incident::from_alert(alert.clone());
    let incident_id = incident.id;

    // Publish event (async processing)
    let _ = state.event_bus.publish(tw_core::TriageEvent::AlertReceived(alert)).await;
    let _ = state.event_bus.publish(tw_core::TriageEvent::IncidentCreated {
        incident_id,
        alert_id: alert_id.clone(),
    }).await;

    Ok((
        StatusCode::ACCEPTED,
        Json(WebhookAcceptedResponse {
            accepted: true,
            message: "Alert received and queued for processing".to_string(),
            alert_id: Some(alert_id),
            incident_id: Some(incident_id),
        }),
    ))
}

/// Validates the webhook signature from headers.
fn validate_webhook_signature(
    headers: &HeaderMap,
    body: &[u8],
    secret: &str,
) -> Result<(), ApiError> {
    // Look for common signature headers
    let signature = headers
        .get("X-Signature-256")
        .or_else(|| headers.get("X-Hub-Signature-256"))
        .or_else(|| headers.get("X-Webhook-Signature"))
        .and_then(|v| v.to_str().ok());

    match signature {
        Some(sig) => {
            if validate_signature(body, sig, secret) {
                Ok(())
            } else {
                Err(ApiError::InvalidSignature)
            }
        }
        None => {
            // If no signature header but secret is configured, that's an error
            Err(ApiError::InvalidSignature)
        }
    }
}
