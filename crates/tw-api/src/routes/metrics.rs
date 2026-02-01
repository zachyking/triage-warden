//! Metrics endpoints.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use metrics::{counter, describe_counter, describe_histogram, histogram};
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
pub async fn prometheus_metrics(State(state): State<AppState>) -> impl IntoResponse {
    match &state.prometheus_handle {
        Some(handle) => {
            let metrics = handle.render();
            (
                StatusCode::OK,
                [(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )],
                metrics,
            )
        }
        None => {
            // Fallback if Prometheus is not initialized
            (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                "Prometheus metrics not initialized".to_string(),
            )
        }
    }
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
async fn json_metrics(State(_state): State<AppState>) -> Result<Json<MetricsResponse>, ApiError> {
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

/// Registers metric descriptions for Triage Warden.
/// This should be called once during server initialization.
pub fn register_metrics() {
    // Incident counter with labels for severity and status
    describe_counter!(
        "triage_warden_incidents_total",
        "Total number of incidents processed by Triage Warden"
    );

    // Actions counter with labels for action_type and status
    describe_counter!(
        "triage_warden_actions_total",
        "Total number of actions executed by Triage Warden"
    );

    // Triage duration histogram
    describe_histogram!(
        "triage_warden_triage_duration_seconds",
        "Time taken to triage incidents in seconds"
    );
}

/// Records an incident with the given severity and status.
pub fn record_incident(severity: &str, status: &str) {
    counter!(
        "triage_warden_incidents_total",
        "severity" => severity.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

/// Records an action with the given action type and status.
pub fn record_action(action_type: &str, status: &str) {
    counter!(
        "triage_warden_actions_total",
        "action_type" => action_type.to_string(),
        "status" => status.to_string()
    )
    .increment(1);
}

/// Records triage duration in seconds.
pub fn record_triage_duration(duration_seconds: f64) {
    histogram!("triage_warden_triage_duration_seconds").record(duration_seconds);
}
