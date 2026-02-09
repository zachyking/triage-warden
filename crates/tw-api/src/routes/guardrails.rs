//! Guardrail simulation, rollback, and anomaly endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;
use tokio::sync::RwLock;
use tw_core::guardrails::{
    ActionRollbackInfo, Anomaly, AnomalyThresholds, AutomationActivity, AutomationAnomalyDetector,
    AutomationBaseline, DryRunExecutor, ExecutionGuardrails, GuardrailCheckContext,
    RollbackRegistry, RollbackStatus,
};
use uuid::Uuid;

static ROLLBACK_STORE: OnceLock<RwLock<RollbackRegistry>> = OnceLock::new();

fn rollback_store() -> &'static RwLock<RollbackRegistry> {
    ROLLBACK_STORE.get_or_init(|| RwLock::new(RollbackRegistry::default()))
}

/// Creates guardrail routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/simulate", post(simulate_action))
        .route("/rollback/register", post(register_rollback))
        .route("/rollback/:action_id", get(get_rollback))
        .route("/rollback/:action_id/status", post(update_rollback_status))
        .route("/anomaly/check", post(check_anomaly))
}

#[derive(Debug, Deserialize)]
struct SimulateRequest {
    incident_id: Uuid,
    action_type: String,
    target: String,
    #[serde(default)]
    actions_taken_count: u32,
    #[serde(default)]
    actions_taken_this_hour: u32,
    #[serde(default)]
    affected_assets: Vec<String>,
    #[serde(default)]
    previous_actions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SimulateResponse {
    would_execute: bool,
    estimated_impact: u32,
    warnings: Vec<String>,
    required_approvals: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterRollbackRequest {
    action_id: Uuid,
    rollback_action: String,
    rollback_payload: serde_json::Value,
    rollback_deadline: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
struct UpdateRollbackStatusRequest {
    status: RollbackStatus,
}

#[derive(Debug, Serialize)]
struct RollbackResponse {
    info: Option<ActionRollbackInfo>,
}

#[derive(Debug, Deserialize)]
struct AnomalyCheckRequest {
    baseline: AutomationBaseline,
    activity: AutomationActivity,
    thresholds: Option<AnomalyThresholds>,
}

#[derive(Debug, Serialize)]
struct AnomalyCheckResponse {
    anomaly: Option<Anomaly>,
    auto_paused: bool,
}

async fn simulate_action(
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<SimulateRequest>,
) -> Result<Json<SimulateResponse>, ApiError> {
    let context = GuardrailCheckContext {
        incident_id: request.incident_id,
        action_type: request.action_type,
        target: request.target,
        actions_taken_count: request.actions_taken_count,
        actions_taken_this_hour: request.actions_taken_this_hour,
        affected_assets: request.affected_assets,
        timestamp: Utc::now(),
        previous_actions: request.previous_actions,
    };

    let executor = DryRunExecutor::new(ExecutionGuardrails::default());
    let result = executor.simulate(&context);
    Ok(Json(SimulateResponse {
        would_execute: result.would_execute,
        estimated_impact: result.estimated_impact,
        warnings: result.guardrail_warnings,
        required_approvals: result.required_approvals,
    }))
}

async fn register_rollback(
    State(_state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Json(request): Json<RegisterRollbackRequest>,
) -> Result<Json<ActionRollbackInfo>, ApiError> {
    let info = ActionRollbackInfo::reversible(
        request.action_id,
        request.rollback_action,
        request.rollback_payload,
        request.rollback_deadline,
    );
    rollback_store().write().await.upsert(info.clone());
    Ok(Json(info))
}

async fn get_rollback(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(action_id): Path<Uuid>,
) -> Result<Json<RollbackResponse>, ApiError> {
    let info = rollback_store().read().await.get(action_id).cloned();
    Ok(Json(RollbackResponse { info }))
}

async fn update_rollback_status(
    State(_state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Path(action_id): Path<Uuid>,
    Json(request): Json<UpdateRollbackStatusRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let updated = rollback_store()
        .write()
        .await
        .mark_status(action_id, request.status);
    Ok(Json(serde_json::json!({ "updated": updated })))
}

async fn check_anomaly(
    State(_state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<AnomalyCheckRequest>,
) -> Result<Json<AnomalyCheckResponse>, ApiError> {
    let detector = AutomationAnomalyDetector {
        baseline: request.baseline,
        thresholds: request.thresholds.unwrap_or_default(),
    };
    let anomaly = detector.check(&request.activity);
    let auto_paused = matches!(
        anomaly,
        Some(Anomaly::UnusualVolume | Anomaly::UnusualTargetCount)
    );
    Ok(Json(AnomalyCheckResponse {
        anomaly,
        auto_paused,
    }))
}
