//! Analytics API endpoints for incident metrics, analyst performance, and security posture.
//!
//! This module provides read-only endpoints for dashboard analytics and reporting.

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Duration, Utc};
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
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_feedback_repository, create_incident_repository, FeedbackFilter, IncidentFilter,
    Pagination,
};
use tw_core::incident::{IncidentStatus, Severity};

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

/// Statuses considered "open" for analytics purposes.
const OPEN_STATUSES: &[IncidentStatus] = &[
    IncidentStatus::New,
    IncidentStatus::Enriching,
    IncidentStatus::Analyzing,
    IncidentStatus::PendingReview,
    IncidentStatus::PendingApproval,
    IncidentStatus::Executing,
    IncidentStatus::Escalated,
];

/// All severity levels for iteration.
const ALL_SEVERITIES: &[Severity] = &[
    Severity::Info,
    Severity::Low,
    Severity::Medium,
    Severity::High,
    Severity::Critical,
];

/// All status values for iteration.
const ALL_STATUSES: &[IncidentStatus] = &[
    IncidentStatus::New,
    IncidentStatus::Enriching,
    IncidentStatus::Analyzing,
    IncidentStatus::PendingReview,
    IncidentStatus::PendingApproval,
    IncidentStatus::Executing,
    IncidentStatus::Resolved,
    IncidentStatus::FalsePositive,
    IncidentStatus::Dismissed,
    IncidentStatus::Escalated,
    IncidentStatus::Closed,
];

/// Get incident metrics.
async fn get_incident_metrics(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<IncidentMetricsQuery>,
) -> Result<Json<IncidentMetricsResponse>, ApiError> {
    query.validate()?;

    let incident_repo = create_incident_repository(&state.db);

    // Build base filter with time range
    let base_filter = IncidentFilter {
        since: query.start,
        until: query.end,
        ..Default::default()
    };

    // Total count
    let total_incidents = incident_repo.count(&base_filter).await?;

    // Count by severity
    let mut by_severity = HashMap::new();
    for severity in ALL_SEVERITIES {
        let filter = IncidentFilter {
            severity: Some(vec![*severity]),
            since: query.start,
            until: query.end,
            ..Default::default()
        };
        let count = incident_repo.count(&filter).await?;
        if count > 0 {
            by_severity.insert(severity.as_db_str().to_string(), count);
        }
    }

    // Count by status
    let mut by_status = HashMap::new();
    for status in ALL_STATUSES {
        let filter = IncidentFilter {
            status: Some(vec![status.clone()]),
            since: query.start,
            until: query.end,
            ..Default::default()
        };
        let count = incident_repo.count(&filter).await?;
        if count > 0 {
            by_status.insert(status.as_db_str().to_string(), count);
        }
    }

    // Count by type: fetch a page of incidents and count source types.
    // For large datasets, a dedicated DB query would be more efficient,
    // but this works for the initial wiring.
    let mut by_type: HashMap<String, u64> = HashMap::new();
    let page = Pagination::new(1, 1000);
    let incidents = incident_repo.list(&base_filter, &page).await?;
    for inc in &incidents {
        let source_type = inc.source.to_string();
        // Extract the category prefix (e.g., "SIEM" from "SIEM:Splunk")
        let category = source_type
            .split(':')
            .next()
            .unwrap_or(&source_type)
            .to_string();
        *by_type.entry(category).or_insert(0) += 1;
    }

    // Compute MTTR from resolved incidents
    let mut total_resolution_secs: f64 = 0.0;
    let mut resolved_count: u64 = 0;
    for inc in &incidents {
        if inc.status == IncidentStatus::Resolved || inc.status == IncidentStatus::FalsePositive {
            let diff = (inc.updated_at - inc.created_at).num_seconds() as f64;
            if diff > 0.0 {
                total_resolution_secs += diff;
                resolved_count += 1;
            }
        }
    }
    let mttr_seconds = if resolved_count > 0 {
        Some(total_resolution_secs / resolved_count as f64)
    } else {
        None
    };

    let metrics = IncidentMetrics {
        total_incidents,
        by_severity,
        by_status,
        by_type,
        mttd_seconds: None, // Requires detection timestamp data not yet tracked
        mttr_seconds,
    };

    Ok(Json(IncidentMetricsResponse::from(metrics)))
}

/// Get analyst performance metrics.
async fn get_analyst_metrics(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<AnalystMetricsQuery>,
) -> Result<Json<AnalystMetricsResponse>, ApiError> {
    query.validate()?;

    let feedback_repo = create_feedback_repository(&state.db);

    // Build feedback filter for the time range
    let filter = FeedbackFilter {
        tenant_id: Some(DEFAULT_TENANT_ID),
        analyst_id: query.analyst_id,
        since: query.start,
        until: query.end,
        ..Default::default()
    };

    let limit = query.limit.unwrap_or(20).min(100) as u32;
    let page = Pagination::new(1, limit);
    let result = feedback_repo.list(&filter, &page).await?;

    // Aggregate by analyst
    let mut analyst_map: HashMap<Uuid, (u64, f64)> = HashMap::new();
    for fb in &result.items {
        let entry = analyst_map.entry(fb.analyst_id).or_insert((0, 0.0));
        entry.0 += 1;
        // Count "correct" feedback as score 1.0
        if fb.corrected_verdict.is_none() && fb.corrected_severity.is_none() {
            entry.1 += 1.0;
        }
    }

    let analysts: Vec<AnalystMetricItem> = analyst_map
        .into_iter()
        .map(|(analyst_id, (count, correct))| {
            let score = if count > 0 {
                Some(correct / count as f64)
            } else {
                None
            };
            AnalystMetricItem {
                analyst_id,
                incidents_handled: count,
                avg_resolution_time_secs: None,
                feedback_score: score,
            }
        })
        .collect();

    Ok(Json(AnalystMetricsResponse { analysts }))
}

/// Get security posture overview.
async fn get_security_posture(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
) -> Result<Json<SecurityPostureResponse>, ApiError> {
    let incident_repo = create_incident_repository(&state.db);
    let feedback_repo = create_feedback_repository(&state.db);

    // Count open critical incidents
    let critical_filter = IncidentFilter {
        severity: Some(vec![Severity::Critical]),
        status: Some(OPEN_STATUSES.to_vec()),
        ..Default::default()
    };
    let open_critical = incident_repo.count(&critical_filter).await?;

    // Count open high incidents
    let high_filter = IncidentFilter {
        severity: Some(vec![Severity::High]),
        status: Some(OPEN_STATUSES.to_vec()),
        ..Default::default()
    };
    let open_high = incident_repo.count(&high_filter).await?;

    // Get AI accuracy from feedback stats
    let stats = feedback_repo.get_stats(DEFAULT_TENANT_ID).await?;
    let ai_accuracy = if stats.total_feedback > 0 {
        Some(stats.accuracy_rate)
    } else {
        None
    };

    let score = SecurityPosture::calculate_score(open_critical, open_high, ai_accuracy);
    let mut posture = SecurityPosture::new(score);
    posture.open_critical = open_critical;
    posture.open_high = open_high;
    posture.ai_accuracy = ai_accuracy;

    Ok(Json(SecurityPostureResponse::from(posture)))
}

/// Get trend data.
async fn get_trends(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Query(query): Query<TrendsQuery>,
) -> Result<Json<TrendsResponse>, ApiError> {
    query.validate()?;

    let granularity_str = query.granularity.as_deref().unwrap_or("daily");
    let granularity = Granularity::parse(granularity_str).ok_or_else(|| {
        ApiError::BadRequest(format!(
            "Invalid granularity: {}. Must be hourly, daily, weekly, or monthly",
            granularity_str
        ))
    })?;

    let metric = query.metric.as_deref().unwrap_or("incidents");

    let now = Utc::now();
    let end = query.end.unwrap_or(now);
    let start = query.start.unwrap_or_else(|| end - Duration::days(30));

    let incident_repo = create_incident_repository(&state.db);

    // Generate time buckets based on granularity
    let bucket_duration = match granularity {
        Granularity::Hourly => Duration::hours(1),
        Granularity::Daily => Duration::days(1),
        Granularity::Weekly => Duration::weeks(1),
        Granularity::Monthly => Duration::days(30),
    };

    let mut data = Vec::new();
    let mut bucket_start = start;

    while bucket_start < end {
        let bucket_end = (bucket_start + bucket_duration).min(end);

        let filter = IncidentFilter {
            since: Some(bucket_start),
            until: Some(bucket_end),
            ..Default::default()
        };

        let value = match metric {
            "incidents" => incident_repo.count(&filter).await? as f64,
            "resolution_time" => {
                // Compute average resolution time for resolved incidents in this bucket
                let resolved_filter = IncidentFilter {
                    status: Some(vec![
                        IncidentStatus::Resolved,
                        IncidentStatus::FalsePositive,
                    ]),
                    since: Some(bucket_start),
                    until: Some(bucket_end),
                    ..Default::default()
                };
                let page = Pagination::new(1, 500);
                let resolved = incident_repo.list(&resolved_filter, &page).await?;
                if resolved.is_empty() {
                    0.0
                } else {
                    let total_secs: f64 = resolved
                        .iter()
                        .map(|i| (i.updated_at - i.created_at).num_seconds() as f64)
                        .sum();
                    total_secs / resolved.len() as f64
                }
            }
            _ => incident_repo.count(&filter).await? as f64,
        };

        data.push(TrendPointResponse::from(TrendDataPoint::new(
            bucket_start,
            value,
        )));

        bucket_start = bucket_end;
    }

    Ok(Json(TrendsResponse {
        metric: metric.to_string(),
        granularity: granularity_str.to_string(),
        data,
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
        let mut by_severity = std::collections::HashMap::new();
        by_severity.insert("high".to_string(), 20);
        let metrics = IncidentMetrics {
            total_incidents: 50,
            by_severity,
            mttd_seconds: Some(120.0),
            ..Default::default()
        };

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

    #[test]
    fn test_open_statuses_are_valid() {
        // Ensure all open statuses are not terminal states
        for status in OPEN_STATUSES {
            assert!(
                !matches!(
                    status,
                    IncidentStatus::Resolved
                        | IncidentStatus::FalsePositive
                        | IncidentStatus::Dismissed
                        | IncidentStatus::Closed
                ),
                "Status {:?} should not be in OPEN_STATUSES",
                status
            );
        }
    }

    #[test]
    fn test_all_statuses_complete() {
        assert_eq!(
            ALL_STATUSES.len(),
            11,
            "All 11 IncidentStatus variants should be covered"
        );
    }

    #[test]
    fn test_all_severities_complete() {
        assert_eq!(
            ALL_SEVERITIES.len(),
            5,
            "All 5 Severity variants should be covered"
        );
    }
}
