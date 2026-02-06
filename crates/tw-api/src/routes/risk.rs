//! Risk scoring API endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::error::ApiError;
use crate::state::AppState;

/// Creates risk scoring routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/weights", get(get_weights).put(update_weights))
        .route(
            "/incidents/:id/risk",
            get(get_risk_score).post(calculate_risk_score),
        )
}

// ============================================================================
// DTOs
// ============================================================================

/// Response containing a risk score for an incident.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RiskScoreResponse {
    /// The incident ID.
    pub incident_id: Uuid,
    /// Component score from base incident severity.
    pub base_severity: f32,
    /// Component score from asset criticality.
    pub asset_criticality: f32,
    /// Component score from known vulnerabilities.
    pub vulnerability_risk: f32,
    /// Component score from external exposure.
    pub exposure_risk: f32,
    /// Component score from historical patterns.
    pub historical_risk: f32,
    /// Weighted composite score (0-100).
    pub composite_score: f32,
    /// Individual risk factors.
    pub factors: Vec<RiskFactorResponse>,
    /// When the score was calculated.
    pub calculated_at: DateTime<Utc>,
}

/// A single risk factor in the response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RiskFactorResponse {
    /// Factor name.
    pub name: String,
    /// Factor description.
    pub description: String,
    /// Impact on the score.
    pub score_impact: f32,
    /// Data source.
    pub source: String,
}

/// Request to update risk weights.
#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct RiskWeightsRequest {
    /// Weight for base severity (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub base_severity: f32,
    /// Weight for asset criticality (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub asset_criticality: f32,
    /// Weight for vulnerability risk (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub vulnerability_risk: f32,
    /// Weight for exposure risk (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub exposure_risk: f32,
    /// Weight for historical risk (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub historical_risk: f32,
}

/// Response containing the current risk weights.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RiskWeightsResponse {
    pub base_severity: f32,
    pub asset_criticality: f32,
    pub vulnerability_risk: f32,
    pub exposure_risk: f32,
    pub historical_risk: f32,
}

impl Default for RiskWeightsResponse {
    fn default() -> Self {
        Self {
            base_severity: 0.40,
            asset_criticality: 0.25,
            vulnerability_risk: 0.15,
            exposure_risk: 0.10,
            historical_risk: 0.10,
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Get the risk score for an incident.
async fn get_risk_score(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<RiskScoreResponse>, ApiError> {
    // TODO: Look up cached risk score from database
    Err(ApiError::NotImplemented(format!(
        "Risk score lookup for incident {} not yet implemented",
        id
    )))
}

/// Calculate (or recalculate) the risk score for an incident.
async fn calculate_risk_score(
    State(_state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<RiskScoreResponse>), ApiError> {
    // TODO: Fetch incident, assets, vulnerabilities, exposures, history
    // and compute the composite risk score
    Err(ApiError::NotImplemented(format!(
        "Risk score calculation for incident {} not yet implemented",
        id
    )))
}

/// Get the current risk weights.
async fn get_weights(
    State(_state): State<AppState>,
) -> Result<Json<RiskWeightsResponse>, ApiError> {
    // Return default weights for now; in production this would
    // be fetched from configuration/database
    Ok(Json(RiskWeightsResponse::default()))
}

/// Update the risk weights.
async fn update_weights(
    State(_state): State<AppState>,
    Json(request): Json<RiskWeightsRequest>,
) -> Result<Json<RiskWeightsResponse>, ApiError> {
    request.validate().map_err(ApiError::from)?;

    let total = request.base_severity
        + request.asset_criticality
        + request.vulnerability_risk
        + request.exposure_risk
        + request.historical_risk;

    if (total - 1.0).abs() > 0.01 {
        return Err(ApiError::BadRequest(format!(
            "Weights must sum to approximately 1.0, got {}",
            total
        )));
    }

    // TODO: Persist updated weights to database/config
    Ok(Json(RiskWeightsResponse {
        base_severity: request.base_severity,
        asset_criticality: request.asset_criticality,
        vulnerability_risk: request.vulnerability_risk,
        exposure_risk: request.exposure_risk,
        historical_risk: request.historical_risk,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_weights_response_default() {
        let weights = RiskWeightsResponse::default();
        let total = weights.base_severity
            + weights.asset_criticality
            + weights.vulnerability_risk
            + weights.exposure_risk
            + weights.historical_risk;
        assert!((total - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_risk_score_response_serialization() {
        let response = RiskScoreResponse {
            incident_id: Uuid::new_v4(),
            base_severity: 80.0,
            asset_criticality: 70.0,
            vulnerability_risk: 50.0,
            exposure_risk: 30.0,
            historical_risk: 20.0,
            composite_score: 62.5,
            factors: vec![RiskFactorResponse {
                name: "CVE-2024-1234".to_string(),
                description: "Critical RCE".to_string(),
                score_impact: 20.0,
                source: "qualys".to_string(),
            }],
            calculated_at: Utc::now(),
        };

        let json = serde_json::to_string(&response).unwrap();
        let deserialized: RiskScoreResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.composite_score, 62.5);
        assert_eq!(deserialized.factors.len(), 1);
    }

    #[test]
    fn test_risk_weights_request_serialization() {
        let json = serde_json::json!({
            "base_severity": 0.40,
            "asset_criticality": 0.25,
            "vulnerability_risk": 0.15,
            "exposure_risk": 0.10,
            "historical_risk": 0.10,
        });

        let request: RiskWeightsRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.base_severity, 0.40);
        assert_eq!(request.historical_risk, 0.10);
    }

    #[test]
    fn test_risk_weights_response_serialization() {
        let weights = RiskWeightsResponse {
            base_severity: 0.50,
            asset_criticality: 0.20,
            vulnerability_risk: 0.15,
            exposure_risk: 0.10,
            historical_risk: 0.05,
        };

        let json = serde_json::to_string(&weights).unwrap();
        let deserialized: RiskWeightsResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.base_severity, 0.50);
        assert_eq!(deserialized.historical_risk, 0.05);
    }

    #[test]
    fn test_risk_factor_response_serialization() {
        let factor = RiskFactorResponse {
            name: "exposed-ssh".to_string(),
            description: "SSH port open to internet".to_string(),
            score_impact: 10.0,
            source: "censys".to_string(),
        };

        let json = serde_json::to_string(&factor).unwrap();
        assert!(json.contains("exposed-ssh"));
        assert!(json.contains("censys"));
    }
}
