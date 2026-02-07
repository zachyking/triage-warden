//! Metrics endpoints.

use axum::{
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use metrics::{counter, describe_counter, describe_histogram, histogram};
use uuid::Uuid;

use crate::auth::RequireAnalyst;
use crate::dto::{ActionMetrics, IncidentMetrics, MetricsResponse, PerformanceMetrics};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;

/// Creates metrics routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .route("/api/v1/metrics", get(json_metrics))
        .route("/api/metrics", get(json_metrics))
}

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
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
    path = "/api/v1/metrics",
    responses(
        (status = 200, description = "Metrics in JSON format", body = MetricsResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Metrics"
)]
async fn json_metrics(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<MetricsResponse>, ApiError> {
    use tw_core::db::create_metrics_repository;

    let tenant_id = tenant_id_or_default(tenant);
    let metrics_repo = create_metrics_repository(&state.db);

    // Run all metrics queries in parallel for efficiency
    let (incident_result, action_result, perf_result) = tokio::join!(
        metrics_repo.get_incident_metrics_for_tenant(tenant_id),
        metrics_repo.get_action_metrics_for_tenant(tenant_id),
        metrics_repo.get_performance_metrics_for_tenant(tenant_id),
    );

    let incident_metrics = incident_result.map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch incident metrics");
        ApiError::Internal("Failed to fetch incident metrics".into())
    })?;

    let action_metrics = action_result.map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch action metrics");
        ApiError::Internal("Failed to fetch action metrics".into())
    })?;

    let perf_metrics = perf_result.map_err(|e| {
        tracing::error!(error = %e, "Failed to fetch performance metrics");
        ApiError::Internal("Failed to fetch performance metrics".into())
    })?;

    // Calculate success rate
    let success_rate = if action_metrics.total_executed > 0 {
        (action_metrics.success_count as f64 / action_metrics.total_executed as f64) * 100.0
    } else {
        0.0
    };

    // Calculate auto-resolution rate
    let auto_resolution_rate = if perf_metrics.total_resolved_count > 0 {
        Some(
            (perf_metrics.auto_resolved_count as f64 / perf_metrics.total_resolved_count as f64)
                * 100.0,
        )
    } else {
        None
    };

    // Ensure all statuses and severities have entries (even if zero)
    let mut by_status = incident_metrics.by_status;
    for status in [
        "new",
        "enriching",
        "analyzing",
        "pending_review",
        "pending_approval",
        "executing",
        "resolved",
        "false_positive",
        "escalated",
        "closed",
    ] {
        by_status.entry(status.to_string()).or_insert(0);
    }

    let mut by_severity = incident_metrics.by_severity;
    for severity in ["info", "low", "medium", "high", "critical"] {
        by_severity.entry(severity.to_string()).or_insert(0);
    }

    Ok(Json(MetricsResponse {
        incidents: IncidentMetrics {
            total: incident_metrics.total,
            by_status,
            by_severity,
            created_last_hour: incident_metrics.created_last_hour,
            resolved_last_hour: incident_metrics.resolved_last_hour,
        },
        actions: ActionMetrics {
            total_executed: action_metrics.total_executed,
            success_rate,
            pending_approvals: action_metrics.pending_approvals,
        },
        performance: PerformanceMetrics {
            mean_time_to_triage_seconds: perf_metrics.mean_time_to_triage_seconds,
            mean_time_to_respond_seconds: perf_metrics.mean_time_to_respond_seconds,
            auto_resolution_rate,
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
