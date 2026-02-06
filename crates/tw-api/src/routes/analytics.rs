//! Analytics API endpoints for incident metrics, analyst performance, and security posture.
//!
//! This module provides read-only endpoints for dashboard analytics and reporting.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::analytics::{
    AnalystMetrics, Granularity, IncidentMetrics, SecurityPosture, TechniqueCount, TrendDataPoint,
};

/// Creates analytics routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/incidents", get(get_incident_metrics))
        .route("/analysts", get(get_analyst_metrics))
        .route("/posture", get(get_security_posture))
        .route("/trends", get(get_trends))
}

// ============================================================================
// Query DTOs
// ============================================================================

/// Query parameters for incident metrics.
#[derive(Debug, Deserialize, Validate)]
pub struct IncidentMetricsQuery {
    /// Start of time range.
    pub start: Option<DateTime<Utc>>,
    /// End of time range.
    pub end: Option<DateTime<Utc>>,
}

/// Query parameters for analyst metrics.
#[derive(Debug, Deserialize, Validate)]
pub struct AnalystMetricsQuery {
    /// Filter by specific analyst.
    pub analyst_id: Option<Uuid>,
    /// Start of time range.
    pub start: Option<DateTime<Utc>>,
    /// End of time range.
    pub end: Option<DateTime<Utc>>,
    /// Maximum results.
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<usize>,
}

/// Query parameters for trend data.
#[derive(Debug, Deserialize, Validate)]
pub struct TrendsQuery {
    /// Start of time range.
    pub start: Option<DateTime<Utc>>,
    /// End of time range.
    pub end: Option<DateTime<Utc>>,
    /// Time granularity.
    pub granularity: Option<String>,
    /// Metric type (incidents, resolution_time, accuracy).
    pub metric: Option<String>,
}

// ============================================================================
// Response DTOs
// ============================================================================

/// Incident metrics response.
#[derive(Debug, Serialize, ToSchema)]
pub struct IncidentMetricsResponse {
    pub total_incidents: u64,
    pub by_severity: HashMap<String, u64>,
    pub by_status: HashMap<String, u64>,
    pub by_type: HashMap<String, u64>,
    pub mttd_seconds: Option<f64>,
    pub mttr_seconds: Option<f64>,
}

impl From<IncidentMetrics> for IncidentMetricsResponse {
    fn from(m: IncidentMetrics) -> Self {
        Self {
            total_incidents: m.total_incidents,
            by_severity: m.by_severity,
            by_status: m.by_status,
            by_type: m.by_type,
            mttd_seconds: m.mttd_seconds,
            mttr_seconds: m.mttr_seconds,
        }
    }
}

/// Analyst metrics response.
#[derive(Debug, Serialize, ToSchema)]
pub struct AnalystMetricsResponse {
    pub analysts: Vec<AnalystMetricItem>,
}

/// Single analyst metric item.
#[derive(Debug, Serialize, ToSchema)]
pub struct AnalystMetricItem {
    pub analyst_id: Uuid,
    pub incidents_handled: u64,
    pub avg_resolution_time_secs: Option<f64>,
    pub feedback_score: Option<f64>,
}

impl From<AnalystMetrics> for AnalystMetricItem {
    fn from(m: AnalystMetrics) -> Self {
        Self {
            analyst_id: m.analyst_id,
            incidents_handled: m.incidents_handled,
            avg_resolution_time_secs: m.avg_resolution_time_secs,
            feedback_score: m.feedback_score,
        }
    }
}

/// Security posture response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityPostureResponse {
    pub overall_score: f64,
    pub open_critical: u64,
    pub open_high: u64,
    pub ai_accuracy: Option<f64>,
    pub top_techniques: Vec<TechniqueCountResponse>,
    pub trends: Vec<TrendPointResponse>,
}

/// Technique count in response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TechniqueCountResponse {
    pub technique_id: String,
    pub name: String,
    pub count: u64,
}

impl From<TechniqueCount> for TechniqueCountResponse {
    fn from(tc: TechniqueCount) -> Self {
        Self {
            technique_id: tc.technique_id,
            name: tc.name,
            count: tc.count,
        }
    }
}

/// Trend data point in response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrendPointResponse {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub label: Option<String>,
}

impl From<TrendDataPoint> for TrendPointResponse {
    fn from(p: TrendDataPoint) -> Self {
        Self {
            timestamp: p.timestamp,
            value: p.value,
            label: p.label,
        }
    }
}

/// Trends response.
#[derive(Debug, Serialize, ToSchema)]
pub struct TrendsResponse {
    pub metric: String,
    pub granularity: String,
    pub data: Vec<TrendPointResponse>,
}

impl From<SecurityPosture> for SecurityPostureResponse {
    fn from(p: SecurityPosture) -> Self {
        Self {
            overall_score: p.overall_score,
            open_critical: p.open_critical,
            open_high: p.open_high,
            ai_accuracy: p.ai_accuracy,
            top_techniques: p.top_techniques.into_iter().map(|t| t.into()).collect(),
            trends: p.trends.into_iter().map(|t| t.into()).collect(),
        }
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Get incident metrics.
async fn get_incident_metrics(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<IncidentMetricsQuery>,
) -> Result<Json<IncidentMetricsResponse>, ApiError> {
    query.validate()?;

    // In a real implementation, we would compute from the database.
    // Return placeholder metrics for now.
    let metrics = IncidentMetrics::default();
    Ok(Json(IncidentMetricsResponse::from(metrics)))
}

/// Get analyst performance metrics.
async fn get_analyst_metrics(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<AnalystMetricsQuery>,
) -> Result<Json<AnalystMetricsResponse>, ApiError> {
    query.validate()?;

    // In a real implementation, we would aggregate from the database.
    Ok(Json(AnalystMetricsResponse { analysts: vec![] }))
}

/// Get security posture overview.
async fn get_security_posture(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
) -> Result<Json<SecurityPostureResponse>, ApiError> {
    // In a real implementation, we would compute from the database.
    let posture = SecurityPosture::new(SecurityPosture::calculate_score(0, 0, None));
    Ok(Json(SecurityPostureResponse::from(posture)))
}

/// Get trend data.
async fn get_trends(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<TrendsQuery>,
) -> Result<Json<TrendsResponse>, ApiError> {
    query.validate()?;

    let granularity_str = query.granularity.as_deref().unwrap_or("daily");
    let _granularity = Granularity::parse(granularity_str).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "Invalid granularity: {}. Must be hourly, daily, weekly, or monthly",
            granularity_str
        ))
    })?;

    let metric = query.metric.as_deref().unwrap_or("incidents");

    // In a real implementation, we would compute from the database.
    Ok(Json(TrendsResponse {
        metric: metric.to_string(),
        granularity: granularity_str.to_string(),
        data: vec![],
    }))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_metrics_response_from() {
        let mut metrics = IncidentMetrics::default();
        metrics.total_incidents = 50;
        metrics.by_severity.insert("high".to_string(), 20);
        metrics.mttd_seconds = Some(120.0);

        let response = IncidentMetricsResponse::from(metrics);

        assert_eq!(response.total_incidents, 50);
        assert_eq!(response.by_severity.get("high"), Some(&20));
        assert_eq!(response.mttd_seconds, Some(120.0));
    }

    #[test]
    fn test_analyst_metric_item_from() {
        let analyst_id = Uuid::new_v4();
        let mut metrics = AnalystMetrics::new(analyst_id);
        metrics.incidents_handled = 25;
        metrics.feedback_score = Some(4.5);

        let item = AnalystMetricItem::from(metrics);

        assert_eq!(item.analyst_id, analyst_id);
        assert_eq!(item.incidents_handled, 25);
        assert_eq!(item.feedback_score, Some(4.5));
    }

    #[test]
    fn test_security_posture_response_from() {
        let mut posture = SecurityPosture::new(85.0);
        posture.open_critical = 1;
        posture.open_high = 3;
        posture.ai_accuracy = Some(0.92);
        posture.top_techniques.push(TechniqueCount {
            technique_id: "T1566".to_string(),
            name: "Phishing".to_string(),
            count: 15,
        });

        let response = SecurityPostureResponse::from(posture);

        assert_eq!(response.overall_score, 85.0);
        assert_eq!(response.open_critical, 1);
        assert_eq!(response.top_techniques.len(), 1);
        assert_eq!(response.top_techniques[0].technique_id, "T1566");
    }

    #[test]
    fn test_technique_count_response_from() {
        let tc = TechniqueCount {
            technique_id: "T1059".to_string(),
            name: "Command and Scripting Interpreter".to_string(),
            count: 10,
        };

        let response = TechniqueCountResponse::from(tc);
        assert_eq!(response.technique_id, "T1059");
        assert_eq!(response.count, 10);
    }

    #[test]
    fn test_trend_point_response_from() {
        let now = Utc::now();
        let point = TrendDataPoint::new(now, 42.0).with_label("critical");

        let response = TrendPointResponse::from(point);
        assert_eq!(response.value, 42.0);
        assert_eq!(response.label, Some("critical".to_string()));
    }

    #[test]
    fn test_trends_response_serialization() {
        let response = TrendsResponse {
            metric: "incidents".to_string(),
            granularity: "daily".to_string(),
            data: vec![],
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"metric\":\"incidents\""));
        assert!(json.contains("\"granularity\":\"daily\""));
    }

    #[test]
    fn test_analyst_metrics_response_serialization() {
        let response = AnalystMetricsResponse { analysts: vec![] };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"analysts\":[]"));
    }

    #[test]
    fn test_incident_metrics_response_serialization() {
        let response = IncidentMetricsResponse {
            total_incidents: 0,
            by_severity: HashMap::new(),
            by_status: HashMap::new(),
            by_type: HashMap::new(),
            mttd_seconds: None,
            mttr_seconds: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"total_incidents\":0"));
    }
}
