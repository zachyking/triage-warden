//! Webhook ingestion endpoints.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use tracing::warn;
use tw_core::is_production_environment;
use validator::Validate;

use crate::dto::{WebhookAcceptedResponse, WebhookAlertPayload};
use crate::error::ApiError;
use crate::state::AppState;
use crate::webhooks::{normalize_alert, validate_signature};

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
    // Validate webhook signature
    validate_webhook_with_config(&state, "default", &headers, &body)?;

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
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::AlertReceived(alert))
        .await;
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::IncidentCreated {
            incident_id,
            alert_id: alert_id.clone(),
        })
        .await;

    // Persist incident to database
    let repo = tw_core::db::create_incident_repository(&state.db);
    repo.create(&incident).await?;

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
    // Validate source-specific webhook signature
    validate_webhook_with_config(&state, &source, &headers, &body)?;

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
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::AlertReceived(alert))
        .await;
    let _ = state
        .event_bus
        .publish(tw_core::TriageEvent::IncidentCreated {
            incident_id,
            alert_id: alert_id.clone(),
        })
        .await;

    // Persist incident to database
    let repo = tw_core::db::create_incident_repository(&state.db);
    repo.create(&incident).await?;

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

/// Validates webhook signature based on environment and configuration.
///
/// # Behavior
///
/// - **Production**: Signatures are REQUIRED. If no webhook secret is configured,
///   the request is rejected with a 403 Forbidden error.
/// - **Development**: Signatures are optional. If no secret is configured,
///   a warning is logged but the request is allowed to proceed.
///
/// This can be overridden with the `TW_WEBHOOK_REQUIRE_SIGNATURE` env var:
/// - `true` or `1`: Always require signatures
/// - `false` or `0`: Never require signatures (NOT RECOMMENDED)
fn validate_webhook_with_config(
    state: &AppState,
    source: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(), ApiError> {
    let secret = state.webhook_secrets.get(source);
    let is_production = is_production_environment();

    // Check for explicit override
    let require_signature = std::env::var("TW_WEBHOOK_REQUIRE_SIGNATURE")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(is_production);

    match secret {
        Some(secret) => {
            // Secret is configured - validate signature
            validate_webhook_signature(headers, body, secret)
        }
        None => {
            if require_signature {
                // Production (or explicit requirement): reject unsigned webhooks
                warn!(
                    source = %source,
                    "Webhook rejected: no secret configured for source in production"
                );
                Err(ApiError::Forbidden(
                    "Webhook signature validation is required but no secret is configured. \
                     Configure a webhook secret for this source."
                        .to_string(),
                ))
            } else {
                // Development: allow but warn
                warn!(
                    source = %source,
                    "Accepting webhook without signature validation (development mode). \
                     Configure a webhook secret for production use."
                );
                Ok(())
            }
        }
    }
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
                warn!("Webhook signature verification failed");
                Err(ApiError::InvalidSignature)
            }
        }
        None => {
            // If no signature header but secret is configured, that's an error
            warn!("Webhook missing signature header");
            Err(ApiError::InvalidSignature)
        }
    }
}
