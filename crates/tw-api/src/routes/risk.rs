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

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::db::{create_incident_repository, create_settings_repository, IncidentRepository};
use tw_core::incident::Severity;
use tw_core::risk::{IncidentRiskScore, RiskFactor, RiskScoreInput, RiskWeights};

const RISK_WEIGHTS_KEY: &str = "risk_weights_v1";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

fn risk_score_key(incident_id: Uuid) -> String {
    format!("risk_score:{}", incident_id)
}

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

impl From<RiskWeights> for RiskWeightsResponse {
    fn from(value: RiskWeights) -> Self {
        Self {
            base_severity: value.base_severity,
            asset_criticality: value.asset_criticality,
            vulnerability_risk: value.vulnerability_risk,
            exposure_risk: value.exposure_risk,
            historical_risk: value.historical_risk,
        }
    }
}

impl From<RiskWeightsResponse> for RiskWeights {
    fn from(value: RiskWeightsResponse) -> Self {
        Self {
            base_severity: value.base_severity,
            asset_criticality: value.asset_criticality,
            vulnerability_risk: value.vulnerability_risk,
            exposure_risk: value.exposure_risk,
            historical_risk: value.historical_risk,
        }
    }
}

fn risk_score_to_response(score: &IncidentRiskScore) -> RiskScoreResponse {
    RiskScoreResponse {
        incident_id: score.incident_id,
        base_severity: score.base_severity,
        asset_criticality: score.asset_criticality,
        vulnerability_risk: score.vulnerability_risk,
        exposure_risk: score.exposure_risk,
        historical_risk: score.historical_risk,
        composite_score: score.composite_score,
        factors: score
            .factors
            .iter()
            .map(|f| RiskFactorResponse {
                name: f.name.clone(),
                description: f.description.clone(),
                score_impact: f.score_impact,
                source: f.source.clone(),
            })
            .collect(),
        calculated_at: score.calculated_at,
    }
}

async fn load_weights(state: &AppState, tenant_id: Uuid) -> Result<RiskWeights, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, RISK_WEIGHTS_KEY)
        .await
        .map_err(ApiError::from)?;
    match raw {
        Some(raw) => serde_json::from_str::<RiskWeightsResponse>(&raw)
            .map(RiskWeights::from)
            .map_err(|e| ApiError::Internal(format!("Failed to parse stored risk weights: {}", e))),
        None => Ok(RiskWeights::default()),
    }
}

async fn save_weights(
    state: &AppState,
    tenant_id: Uuid,
    weights: &RiskWeights,
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let payload = serde_json::to_string(&RiskWeightsResponse::from(weights.clone()))
        .map_err(|e| ApiError::Internal(format!("Failed to serialize risk weights: {}", e)))?;
    repo.save_raw(tenant_id, RISK_WEIGHTS_KEY, &payload)
        .await
        .map_err(ApiError::from)
}

async fn load_cached_risk_score(
    state: &AppState,
    tenant_id: Uuid,
    incident_id: Uuid,
) -> Result<Option<IncidentRiskScore>, ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let raw = repo
        .get_raw(tenant_id, &risk_score_key(incident_id))
        .await
        .map_err(ApiError::from)?;
    match raw {
        Some(raw) => serde_json::from_str::<IncidentRiskScore>(&raw)
            .map(Some)
            .map_err(|e| ApiError::Internal(format!("Failed to parse cached risk score: {}", e))),
        None => Ok(None),
    }
}

async fn save_cached_risk_score(
    state: &AppState,
    tenant_id: Uuid,
    score: &IncidentRiskScore,
) -> Result<(), ApiError> {
    let repo = create_settings_repository(&state.db, state.encryptor.clone());
    let payload = serde_json::to_string(score)
        .map_err(|e| ApiError::Internal(format!("Failed to serialize risk score: {}", e)))?;
    repo.save_raw(tenant_id, &risk_score_key(score.incident_id), &payload)
        .await
        .map_err(ApiError::from)
}

fn severity_to_score(severity: Severity) -> f32 {
    match severity {
        Severity::Info => 20.0,
        Severity::Low => 40.0,
        Severity::Medium => 60.0,
        Severity::High => 80.0,
        Severity::Critical => 95.0,
    }
}

fn numeric_metadata_value(
    metadata: &std::collections::HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<f32> {
    metadata
        .get(key)
        .and_then(|v| v.as_f64())
        .map(|v| v as f32)
        .map(|v| v.clamp(0.0, 100.0))
}

async fn calculate_and_store_risk_score(
    state: &AppState,
    tenant_id: Uuid,
    incident_id: Uuid,
) -> Result<IncidentRiskScore, ApiError> {
    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let incident = incident_repo
        .get_for_tenant(incident_id, tenant_id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", incident_id)))?;

    let weights = load_weights(state, tenant_id).await?;

    let base_severity = severity_to_score(incident.severity);
    let analysis_risk = incident
        .analysis
        .as_ref()
        .map(|a| a.risk_score as f32)
        .unwrap_or(base_severity);
    let asset_criticality =
        numeric_metadata_value(&incident.metadata, "asset_criticality").unwrap_or(analysis_risk);
    let vulnerability_risk = numeric_metadata_value(&incident.metadata, "vulnerability_risk")
        .unwrap_or(analysis_risk * 0.8);
    let exposure_risk = numeric_metadata_value(&incident.metadata, "exposure_risk").unwrap_or(35.0);
    let historical_risk = numeric_metadata_value(&incident.metadata, "historical_risk")
        .unwrap_or_else(|| {
            if incident.tags.iter().any(|t| t == "repeat_offender") {
                70.0
            } else {
                25.0
            }
        });

    let mut factors = vec![RiskFactor {
        name: "severity".to_string(),
        description: format!("Incident severity {}", incident.severity),
        score_impact: base_severity * weights.base_severity,
        source: "incident".to_string(),
    }];

    if let Some(analysis) = &incident.analysis {
        factors.push(RiskFactor {
            name: "analysis_score".to_string(),
            description: "AI analysis risk score".to_string(),
            score_impact: analysis.risk_score as f32 * weights.asset_criticality,
            source: "analysis".to_string(),
        });
    }

    let score = IncidentRiskScore::calculate(
        RiskScoreInput {
            incident_id,
            base_severity,
            asset_criticality,
            vulnerability_risk,
            exposure_risk,
            historical_risk,
            factors,
        },
        &weights,
    );

    save_cached_risk_score(state, tenant_id, &score).await?;
    Ok(score)
}

// ============================================================================
// Handlers
// ============================================================================

/// Get the risk score for an incident.
async fn get_risk_score(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<RiskScoreResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    if let Some(cached) = load_cached_risk_score(&state, tenant_id, id).await? {
        return Ok(Json(risk_score_to_response(&cached)));
    }

    let calculated = calculate_and_store_risk_score(&state, tenant_id, id).await?;
    Ok(Json(risk_score_to_response(&calculated)))
}

/// Calculate (or recalculate) the risk score for an incident.
async fn calculate_risk_score(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(id): Path<Uuid>,
) -> Result<(StatusCode, Json<RiskScoreResponse>), ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let score = calculate_and_store_risk_score(&state, tenant_id, id).await?;
    Ok((StatusCode::OK, Json(risk_score_to_response(&score))))
}

/// Get the current risk weights.
async fn get_weights(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<RiskWeightsResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let weights = load_weights(&state, tenant_id).await?;
    Ok(Json(RiskWeightsResponse::from(weights)))
}

/// Update the risk weights.
async fn update_weights(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
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

    let validated_weights = RiskWeightsResponse {
        base_severity: request.base_severity,
        asset_criticality: request.asset_criticality,
        vulnerability_risk: request.vulnerability_risk,
        exposure_risk: request.exposure_risk,
        historical_risk: request.historical_risk,
    };
    let weights = RiskWeights::from(validated_weights);
    let tenant_id = tenant_id_or_default(tenant);
    save_weights(&state, tenant_id, &weights).await?;
    Ok(Json(RiskWeightsResponse::from(weights)))
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
