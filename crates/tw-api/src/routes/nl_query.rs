//! Natural language query bridge to Python NL engine.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::warn;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;

const MAX_NL_QUERY_LENGTH: usize = 5_000;
const MAX_BACKEND_NAME_LENGTH: usize = 64;

/// Creates NL query routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/query", post(translate_query))
}

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct NLQueryRequest {
    pub query: String,
    #[serde(default = "default_backend")]
    pub backend: String,
    #[serde(default)]
    pub context: serde_json::Value,
}

fn default_backend() -> String {
    "splunk".to_string()
}

fn normalize_backend(backend: &str) -> String {
    let trimmed = backend.trim();
    if trimmed.is_empty() {
        default_backend()
    } else {
        trimmed.to_string()
    }
}

fn is_valid_backend_identifier(backend: &str) -> bool {
    if backend.is_empty() || backend.len() > MAX_BACKEND_NAME_LENGTH {
        return false;
    }

    backend
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

#[derive(Debug, Deserialize, Serialize)]
pub struct NLQueryResponse {
    pub query_string: String,
    pub query_type: String,
    pub intent: String,
    pub confidence: f64,
    pub entities: Vec<serde_json::Value>,
    pub metadata: serde_json::Value,
}

// ============================================================================
// Handler
// ============================================================================

async fn translate_query(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<NLQueryRequest>,
) -> Result<Json<NLQueryResponse>, ApiError> {
    let query = request.query.trim();
    if query.is_empty() {
        return Err(ApiError::BadRequest(
            "NL query cannot be empty.".to_string(),
        ));
    }
    if query.len() > MAX_NL_QUERY_LENGTH {
        return Err(ApiError::BadRequest(format!(
            "NL query is too long (max {} characters).",
            MAX_NL_QUERY_LENGTH
        )));
    }

    let backend = normalize_backend(&request.backend);
    if !is_valid_backend_identifier(&backend) {
        return Err(ApiError::BadRequest(
            "Invalid backend name. Use letters, numbers, '-' or '_'.".to_string(),
        ));
    }

    let nl_url = state.nl_query_url.as_deref().ok_or_else(|| {
        ApiError::BadRequest(
            "NL query service is not configured. Set NL_QUERY_URL environment variable."
                .to_string(),
        )
    })?;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| ApiError::Internal(format!("Failed to build NL query client: {}", e)))?;
    let response = client
        .post(format!("{}/api/nl/query", nl_url.trim_end_matches('/')))
        .json(&serde_json::json!({
            "query": query,
            "backend": backend,
            "context": request.context,
        }))
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "nl_query_service_request_failed");
            ApiError::Internal("NL query service is unavailable.".to_string())
        })?;

    if !response.status().is_success() {
        let status = response.status();
        warn!(status = %status, "nl_query_service_non_success_status");
        return Err(ApiError::Internal(format!(
            "NL query service returned {}",
            status
        )));
    }

    let nl_response: NLQueryResponse = response.json().await.map_err(|e| {
        warn!(error = %e, "nl_query_service_invalid_response");
        ApiError::Internal("Failed to parse NL query service response.".to_string())
    })?;

    Ok(Json(nl_response))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_backend() {
        assert_eq!(default_backend(), "splunk");
    }

    #[test]
    fn test_normalize_backend() {
        assert_eq!(normalize_backend(""), "splunk");
        assert_eq!(normalize_backend("   "), "splunk");
        assert_eq!(normalize_backend("elasticsearch"), "elasticsearch");
    }

    #[test]
    fn test_backend_identifier_validation() {
        assert!(is_valid_backend_identifier("splunk"));
        assert!(is_valid_backend_identifier("elastic-search_2"));
        assert!(!is_valid_backend_identifier(""));
        assert!(!is_valid_backend_identifier("backend with spaces"));
        assert!(!is_valid_backend_identifier("backend;drop table"));
    }

    #[test]
    fn test_nl_query_request_deserialization() {
        let json = serde_json::json!({
            "query": "show me critical incidents from last 24 hours"
        });

        let req: NLQueryRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.query, "show me critical incidents from last 24 hours");
        assert_eq!(req.backend, "splunk");
    }

    #[test]
    fn test_nl_query_request_with_backend() {
        let json = serde_json::json!({
            "query": "find failed logins",
            "backend": "elasticsearch",
            "context": {"user_id": "analyst-1"}
        });

        let req: NLQueryRequest = serde_json::from_value(json).unwrap();
        assert_eq!(req.backend, "elasticsearch");
    }

    #[test]
    fn test_nl_query_response_serialization() {
        let response = NLQueryResponse {
            query_string: "index=\"main\" severity=\"critical\"".to_string(),
            query_type: "SPL".to_string(),
            intent: "search_incidents".to_string(),
            confidence: 0.95,
            entities: vec![],
            metadata: serde_json::json!({}),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("query_string"));
        assert!(json.contains("critical"));
    }
}
