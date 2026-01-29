//! Metrics endpoints.

use axum::{extract::State, routing::get, Json, Router};
use std::collections::HashMap;

use crate::dto::{ActionMetrics, IncidentMetrics, MetricsResponse, PerformanceMetrics};
use crate::error::ApiError;
use crate::state::AppState;

/// Creates metrics routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/api/metrics", get(json_metrics))
}

/// Prometheus metrics endpoint.
#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus metrics", content_type = "text/plain")
    ),
    tag = "Metrics"
)]
async fn prometheus_metrics(State(_state): State<AppState>) -> String {
    // TODO: Export actual metrics
    // This would integrate with metrics-exporter-prometheus

    let mut output = String::new();

    output.push_str("# HELP triage_warden_incidents_total Total number of incidents\n");
    output.push_str("# TYPE triage_warden_incidents_total counter\n");
    output.push_str("triage_warden_incidents_total 0\n\n");

    output.push_str("# HELP triage_warden_incidents_active Current active incidents\n");
    output.push_str("# TYPE triage_warden_incidents_active gauge\n");
    output.push_str("triage_warden_incidents_active 0\n\n");

    output.push_str("# HELP triage_warden_actions_total Total actions executed\n");
    output.push_str("# TYPE triage_warden_actions_total counter\n");
    output.push_str("triage_warden_actions_total 0\n\n");

    output.push_str("# HELP triage_warden_triage_duration_seconds Time to triage incidents\n");
    output.push_str("# TYPE triage_warden_triage_duration_seconds histogram\n");
    output.push_str("triage_warden_triage_duration_seconds_bucket{le=\"60\"} 0\n");
    output.push_str("triage_warden_triage_duration_seconds_bucket{le=\"300\"} 0\n");
    output.push_str("triage_warden_triage_duration_seconds_bucket{le=\"900\"} 0\n");
    output.push_str("triage_warden_triage_duration_seconds_bucket{le=\"+Inf\"} 0\n");
    output.push_str("triage_warden_triage_duration_seconds_sum 0\n");
    output.push_str("triage_warden_triage_duration_seconds_count 0\n");

    output
}

/// JSON metrics endpoint for dashboard.
#[utoipa::path(
    get,
    path = "/api/metrics",
    responses(
        (status = 200, description = "Metrics in JSON format", body = MetricsResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Metrics"
)]
async fn json_metrics(
    State(_state): State<AppState>,
) -> Result<Json<MetricsResponse>, ApiError> {
    // TODO: Query actual metrics from database

    let by_status: HashMap<String, u64> = [
        ("new".to_string(), 0),
        ("enriching".to_string(), 0),
        ("analyzing".to_string(), 0),
        ("pending_review".to_string(), 0),
        ("pending_approval".to_string(), 0),
        ("resolved".to_string(), 0),
        ("false_positive".to_string(), 0),
    ]
    .into_iter()
    .collect();

    let by_severity: HashMap<String, u64> = [
        ("critical".to_string(), 0),
        ("high".to_string(), 0),
        ("medium".to_string(), 0),
        ("low".to_string(), 0),
        ("info".to_string(), 0),
    ]
    .into_iter()
    .collect();

    Ok(Json(MetricsResponse {
        incidents: IncidentMetrics {
            total: 0,
            by_status,
            by_severity,
            created_last_hour: 0,
            resolved_last_hour: 0,
        },
        actions: ActionMetrics {
            total_executed: 0,
            success_rate: 0.0,
            pending_approvals: 0,
        },
        performance: PerformanceMetrics {
            mean_time_to_triage_seconds: None,
            mean_time_to_respond_seconds: None,
            auto_resolution_rate: None,
        },
    }))
}
