//! Compliance report and evidence endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::compliance::{
    default_controls_for_framework, ComplianceFramework, ComplianceReport, ControlAssessment,
    ControlStatus, DateRange, EvidenceItem, EvidencePackage,
};
use tw_core::db::{
    create_audit_repository, create_settings_repository, AuditRepository, SettingsRepository,
};

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates compliance routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports/generate", post(generate_report))
        .route("/reports/:report_id", get(get_report))
        .route("/evidence/package", post(create_evidence_package))
        .route("/metrics", get(security_metrics))
}

#[derive(Debug, Deserialize)]
struct GenerateReportRequest {
    framework: ComplianceFramework,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
struct EvidencePackageRequest {
    name: String,
    request_id: Option<String>,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct SecurityMetricsResponse {
    total_security_events: usize,
    action_executed_events: usize,
    failed_events: usize,
    guardrail_triggered_events: usize,
    last_7d_events: usize,
}

async fn generate_report(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<GenerateReportRequest>,
) -> Result<Json<ComplianceReport>, ApiError> {
    if request.period_end <= request.period_start {
        return Err(ApiError::validation_field(
            "period_end",
            "invalid_range",
            "period_end must be after period_start",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let entries = audit_repo
        .get_recent_for_tenant(tenant_id, 10_000)
        .await
        .map_err(ApiError::from)?;
    let entries_in_range: Vec<_> = entries
        .into_iter()
        .filter(|(_, entry)| {
            entry.timestamp >= request.period_start && entry.timestamp <= request.period_end
        })
        .collect();

    let evidence: Vec<EvidenceItem> = entries_in_range
        .iter()
        .map(|(_, entry)| {
            EvidenceItem::new(
                format!("Audit event {:?}", entry.action),
                Some(entry.id),
                vec!["audit".to_string(), "auto-generated".to_string()],
            )
        })
        .collect();

    let templates = default_controls_for_framework(&request.framework);
    let controls: Vec<ControlAssessment> = templates
        .into_iter()
        .map(|template| {
            let status = if entries_in_range.is_empty() {
                ControlStatus::Partial
            } else {
                ControlStatus::Compliant
            };
            ControlAssessment {
                control_id: template.id.to_string(),
                description: template.description.to_string(),
                status,
                evidence_refs: evidence.iter().take(10).map(|e| e.id).collect(),
                notes: Some("Auto-assessed from audit telemetry".to_string()),
            }
        })
        .collect();

    let report = ComplianceReport::new(
        request.framework,
        DateRange {
            start: request.period_start,
            end: request.period_end,
        },
        controls,
        evidence,
    );

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("compliance_report_{}", report.id);
    settings_repo
        .save_raw(
            tenant_id,
            &key,
            &serde_json::to_string(&report)
                .map_err(|e| ApiError::Internal(format!("failed to store report: {e}")))?,
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Json(report))
}

async fn get_report(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(report_id): Path<uuid::Uuid>,
) -> Result<Json<ComplianceReport>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("compliance_report_{report_id}");
    let raw = settings_repo
        .get_raw(tenant_id, &key)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Compliance report {} not found", report_id)))?;

    let report: ComplianceReport = serde_json::from_str(&raw)
        .map_err(|e| ApiError::Internal(format!("failed to parse report: {e}")))?;
    Ok(Json(report))
}

async fn create_evidence_package(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<EvidencePackageRequest>,
) -> Result<Json<EvidencePackage>, ApiError> {
    if request.period_end <= request.period_start {
        return Err(ApiError::validation_field(
            "period_end",
            "invalid_range",
            "period_end must be after period_start",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let entries = audit_repo
        .get_recent_for_tenant(tenant_id, 10_000)
        .await
        .map_err(ApiError::from)?;
    let evidence_items: Vec<EvidenceItem> = entries
        .into_iter()
        .filter(|(_, entry)| {
            entry.timestamp >= request.period_start && entry.timestamp <= request.period_end
        })
        .map(|(_, entry)| {
            EvidenceItem::new(
                format!("Audit evidence {:?}", entry.action),
                Some(entry.id),
                vec!["audit".to_string()],
            )
        })
        .collect();

    let mut package = EvidencePackage::new(
        request.name,
        request.request_id,
        request.period_start,
        request.period_end,
        evidence_items,
    );
    package.add_custody_event("system", "evidence_packaged", None);

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("evidence_package_{}", package.id);
    settings_repo
        .save_raw(
            tenant_id,
            &key,
            &serde_json::to_string(&package).map_err(|e| {
                ApiError::Internal(format!("failed to store evidence package: {e}"))
            })?,
        )
        .await
        .map_err(ApiError::from)?;

    Ok(Json(package))
}

async fn security_metrics(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<SecurityMetricsResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let entries = audit_repo
        .get_recent_for_tenant(tenant_id, 20_000)
        .await
        .map_err(ApiError::from)?;

    let now = Utc::now();
    let last_7d_cutoff = now - Duration::days(7);

    let total_security_events = entries.len();
    let action_executed_events = entries
        .iter()
        .filter(|(_, entry)| matches!(entry.action, tw_core::incident::AuditAction::ActionExecuted))
        .count();
    let failed_events = entries
        .iter()
        .filter(|(_, entry)| {
            matches!(
                entry.action,
                tw_core::incident::AuditAction::ActionFailed
                    | tw_core::incident::AuditAction::ActionDenied
            )
        })
        .count();
    let guardrail_triggered_events = entries
        .iter()
        .filter(|(_, entry)| match &entry.details {
            Some(details) => details
                .get("guardrail")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            None => false,
        })
        .count();
    let last_7d_events = entries
        .iter()
        .filter(|(_, entry)| entry.timestamp >= last_7d_cutoff)
        .count();

    Ok(Json(SecurityMetricsResponse {
        total_security_events,
        action_executed_events,
        failed_events,
        guardrail_triggered_events,
        last_7d_events,
    }))
}
