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

    // Publish events (async processing) with fallback logging
    state
        .event_bus
        .publish_with_fallback(tw_core::TriageEvent::AlertReceived(alert))
        .await;
    state
        .event_bus
        .publish_with_fallback(tw_core::TriageEvent::IncidentCreated {
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

    // Publish events (async processing) with fallback logging
    state
        .event_bus
        .publish_with_fallback(tw_core::TriageEvent::AlertReceived(alert))
        .await;
    state
        .event_bus
        .publish_with_fallback(tw_core::TriageEvent::IncidentCreated {
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

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// Compute HMAC-SHA256 signature for testing.
    fn compute_test_signature(body: &[u8], secret: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn test_validate_signature_x_signature_256() {
        let body = b"test payload";
        let secret = "test-secret";
        let signature = compute_test_signature(body, secret);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Signature-256",
            format!("sha256={}", signature).parse().unwrap(),
        );

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_x_hub_signature_256() {
        let body = b"test payload";
        let secret = "test-secret";
        let signature = compute_test_signature(body, secret);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Hub-Signature-256",
            format!("sha256={}", signature).parse().unwrap(),
        );

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_x_webhook_signature() {
        let body = b"test payload";
        let secret = "test-secret";
        let signature = compute_test_signature(body, secret);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Webhook-Signature",
            format!("sha256={}", signature).parse().unwrap(),
        );

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_signature_invalid() {
        let body = b"test payload";
        let secret = "test-secret";

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Signature-256",
            "sha256=invalid_signature".parse().unwrap(),
        );

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_err());
        match result {
            Err(ApiError::InvalidSignature) => {}
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_validate_signature_missing_header() {
        let body = b"test payload";
        let secret = "test-secret";
        let headers = HeaderMap::new();

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_err());
        match result {
            Err(ApiError::InvalidSignature) => {}
            _ => panic!("Expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_validate_signature_wrong_secret() {
        let body = b"test payload";
        let secret = "test-secret";
        let wrong_secret = "wrong-secret";
        let signature = compute_test_signature(body, wrong_secret);

        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Signature-256",
            format!("sha256={}", signature).parse().unwrap(),
        );

        let result = validate_webhook_signature(&headers, body, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_webhook_alert_payload_validation() {
        use crate::dto::WebhookAlertPayload;
        use chrono::Utc;

        // Valid payload
        let valid = WebhookAlertPayload {
            source: "splunk".to_string(),
            alert_type: "malware".to_string(),
            severity: Some("high".to_string()),
            title: "Malware Detected".to_string(),
            description: Some("Suspicious file detected".to_string()),
            data: serde_json::json!({"file": "malware.exe"}),
            timestamp: Some(Utc::now()),
            tags: vec!["malware".to_string()],
        };
        assert!(valid.validate().is_ok());

        // Missing required field: source
        let missing_source = WebhookAlertPayload {
            source: "".to_string(),
            alert_type: "malware".to_string(),
            severity: Some("high".to_string()),
            title: "Malware Detected".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: None,
            tags: vec![],
        };
        assert!(missing_source.validate().is_err());

        // Missing required field: alert_type
        let missing_type = WebhookAlertPayload {
            source: "splunk".to_string(),
            alert_type: "".to_string(),
            severity: Some("high".to_string()),
            title: "Malware Detected".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: None,
            tags: vec![],
        };
        assert!(missing_type.validate().is_err());

        // Missing required field: title
        let missing_title = WebhookAlertPayload {
            source: "splunk".to_string(),
            alert_type: "malware".to_string(),
            severity: Some("high".to_string()),
            title: "".to_string(),
            description: None,
            data: serde_json::json!({}),
            timestamp: None,
            tags: vec![],
        };
        assert!(missing_title.validate().is_err());
    }

    #[test]
    fn test_webhook_accepted_response_serialization() {
        use uuid::Uuid;

        let response = WebhookAcceptedResponse {
            accepted: true,
            message: "Alert received".to_string(),
            alert_id: Some("alert-123".to_string()),
            incident_id: Some(Uuid::new_v4()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"accepted\":true"));
        assert!(json.contains("\"message\":\"Alert received\""));
        assert!(json.contains("alert-123"));
    }
}
