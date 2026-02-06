//! Natural language query bridge to Python NL engine.

use axum::{extract::State, routing::post, Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;

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

#[derive(Debug, Serialize)]
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
    let nl_url = state.nl_query_url.as_deref().ok_or_else(|| {
        ApiError::BadRequest(
            "NL query service is not configured. Set NL_QUERY_URL environment variable."
                .to_string(),
        )
    })?;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("{}/api/nl/query", nl_url))
        .json(&serde_json::json!({
            "query": request.query,
            "backend": request.backend,
            "context": request.context,
        }))
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("NL query service error: {}", e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::Internal(format!(
            "NL query service returned {}: {}",
            status, body
        )));
    }

    let nl_response: serde_json::Value = response
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to parse NL response: {}", e)))?;

    Ok(Json(NLQueryResponse {
        query_string: nl_response["query_string"]
            .as_str()
            .unwrap_or("")
            .to_string(),
        query_type: nl_response["query_type"].as_str().unwrap_or("").to_string(),
        intent: nl_response["intent"].as_str().unwrap_or("").to_string(),
        confidence: nl_response["confidence"].as_f64().unwrap_or(0.0),
        entities: nl_response["entities"]
            .as_array()
            .cloned()
            .unwrap_or_default(),
        metadata: nl_response["metadata"].clone(),
    }))
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
