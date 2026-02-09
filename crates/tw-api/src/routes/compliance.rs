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

const COMPLIANCE_REPORT_INDEX_KEY: &str = "compliance_report_index";
const EVIDENCE_PACKAGE_INDEX_KEY: &str = "compliance_evidence_package_index";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates compliance routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/reports", get(list_reports))
        .route("/reports/generate", post(generate_report))
        .route("/reports/:report_id", get(get_report))
        .route("/reports/:report_id/verify", get(verify_report))
        .route("/evidence/package", post(create_evidence_package))
        .route("/evidence/packages", get(list_evidence_packages))
        .route("/evidence/package/:package_id", get(get_evidence_package))
        .route(
            "/evidence/package/:package_id/verify",
            get(verify_evidence_package),
        )
        .route(
            "/evidence/package/:package_id/custody",
            post(add_evidence_custody_event),
        )
        .route("/metrics", get(security_metrics))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ReportIndexEntry {
    report_id: uuid::Uuid,
    framework: ComplianceFramework,
    period_start: DateTime<Utc>,
    period_end: DateTime<Utc>,
    generated_at: DateTime<Utc>,
    checksum: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct EvidencePackageIndexEntry {
    package_id: uuid::Uuid,
    name: String,
    request_id: Option<String>,
    generated_at: DateTime<Utc>,
    checksum: String,
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

#[derive(Debug, Deserialize)]
struct CustodyEventRequest {
    actor: String,
    action: String,
    notes: Option<String>,
}

#[derive(Debug, Serialize)]
struct SecurityMetricsResponse {
    total_security_events: usize,
    action_executed_events: usize,
    failed_events: usize,
    guardrail_triggered_events: usize,
    last_7d_events: usize,
}

#[derive(Debug, Serialize)]
struct VerifyIntegrityResponse {
    valid: bool,
    stored_checksum: String,
    computed_checksum: String,
    reason: Option<String>,
}

async fn list_reports(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<ReportIndexEntry>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut entries = load_report_index(settings_repo.as_ref(), tenant_id).await?;
    entries.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
    Ok(Json(entries))
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

    let mut index = load_report_index(settings_repo.as_ref(), tenant_id).await?;
    index.retain(|entry| entry.report_id != report.id);
    index.push(ReportIndexEntry {
        report_id: report.id,
        framework: report.framework.clone(),
        period_start: report.period.start,
        period_end: report.period.end,
        generated_at: report.summary.generated_at,
        checksum: report.checksum.clone(),
    });
    save_report_index(settings_repo.as_ref(), tenant_id, &index).await?;

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

async fn verify_report(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(report_id): Path<uuid::Uuid>,
) -> Result<Json<VerifyIntegrityResponse>, ApiError> {
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

    let computed = report.compute_checksum();
    let stored = report.checksum.clone();
    let mut valid = stored == computed;
    let mut reason = if valid {
        None
    } else {
        Some("Report checksum mismatch".to_string())
    };

    let index = load_report_index(settings_repo.as_ref(), tenant_id).await?;
    if let Some(indexed) = index.iter().find(|entry| entry.report_id == report_id) {
        if indexed.checksum != stored {
            valid = false;
            reason = Some("Stored report checksum differs from report index".to_string());
        }
    }

    Ok(Json(VerifyIntegrityResponse {
        valid,
        stored_checksum: stored,
        computed_checksum: computed,
        reason,
    }))
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

    let mut index = load_evidence_package_index(settings_repo.as_ref(), tenant_id).await?;
    index.retain(|entry| entry.package_id != package.id);
    index.push(EvidencePackageIndexEntry {
        package_id: package.id,
        name: package.name.clone(),
        request_id: package.request_id.clone(),
        generated_at: package.generated_at,
        checksum: package.checksum.clone(),
    });
    save_evidence_package_index(settings_repo.as_ref(), tenant_id, &index).await?;

    Ok(Json(package))
}

async fn list_evidence_packages(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<Vec<EvidencePackageIndexEntry>>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let mut entries = load_evidence_package_index(settings_repo.as_ref(), tenant_id).await?;
    entries.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
    Ok(Json(entries))
}

async fn get_evidence_package(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(package_id): Path<uuid::Uuid>,
) -> Result<Json<EvidencePackage>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("evidence_package_{package_id}");
    let raw = settings_repo
        .get_raw(tenant_id, &key)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Evidence package {} not found", package_id)))?;
    let package: EvidencePackage = serde_json::from_str(&raw)
        .map_err(|e| ApiError::Internal(format!("failed to parse evidence package: {e}")))?;
    Ok(Json(package))
}

async fn verify_evidence_package(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Path(package_id): Path<uuid::Uuid>,
) -> Result<Json<VerifyIntegrityResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("evidence_package_{package_id}");
    let raw = settings_repo
        .get_raw(tenant_id, &key)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Evidence package {} not found", package_id)))?;
    let package: EvidencePackage = serde_json::from_str(&raw)
        .map_err(|e| ApiError::Internal(format!("failed to parse evidence package: {e}")))?;
    let computed = package.compute_checksum();
    let stored = package.checksum.clone();
    let mut valid = stored == computed;
    let mut reason = if valid {
        None
    } else {
        Some("Evidence package checksum mismatch".to_string())
    };

    let index = load_evidence_package_index(settings_repo.as_ref(), tenant_id).await?;
    if let Some(indexed) = index.iter().find(|entry| entry.package_id == package_id) {
        if indexed.checksum != stored {
            valid = false;
            reason = Some("Stored package checksum differs from package index".to_string());
        }
    }

    Ok(Json(VerifyIntegrityResponse {
        valid,
        stored_checksum: stored,
        computed_checksum: computed,
        reason,
    }))
}

async fn add_evidence_custody_event(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Path(package_id): Path<uuid::Uuid>,
    Json(request): Json<CustodyEventRequest>,
) -> Result<Json<EvidencePackage>, ApiError> {
    if request.actor.trim().is_empty() {
        return Err(ApiError::validation_field(
            "actor",
            "required",
            "actor is required",
        ));
    }
    if request.action.trim().is_empty() {
        return Err(ApiError::validation_field(
            "action",
            "required",
            "action is required",
        ));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let key = format!("evidence_package_{package_id}");
    let raw = settings_repo
        .get_raw(tenant_id, &key)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::NotFound(format!("Evidence package {} not found", package_id)))?;

    let mut package: EvidencePackage = serde_json::from_str(&raw)
        .map_err(|e| ApiError::Internal(format!("failed to parse evidence package: {e}")))?;
    package.add_custody_event(
        request.actor.trim(),
        request.action.trim(),
        request.notes.clone(),
    );

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

    let mut index = load_evidence_package_index(settings_repo.as_ref(), tenant_id).await?;
    index.retain(|entry| entry.package_id != package_id);
    index.push(EvidencePackageIndexEntry {
        package_id,
        name: package.name.clone(),
        request_id: package.request_id.clone(),
        generated_at: package.generated_at,
        checksum: package.checksum.clone(),
    });
    save_evidence_package_index(settings_repo.as_ref(), tenant_id, &index).await?;

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

async fn load_report_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<Vec<ReportIndexEntry>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, COMPLIANCE_REPORT_INDEX_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let parsed = serde_json::from_str::<Vec<ReportIndexEntry>>(&raw)
            .map_err(|e| ApiError::BadRequest(format!("invalid compliance report index: {e}")))?;
        return Ok(parsed);
    }

    Ok(Vec::new())
}

async fn save_report_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    entries: &[ReportIndexEntry],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(entries)
        .map_err(|e| ApiError::Internal(format!("failed to serialize report index: {e}")))?;
    repo.save_raw(tenant_id, COMPLIANCE_REPORT_INDEX_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}

async fn load_evidence_package_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<Vec<EvidencePackageIndexEntry>, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, EVIDENCE_PACKAGE_INDEX_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let parsed = serde_json::from_str::<Vec<EvidencePackageIndexEntry>>(&raw).map_err(|e| {
            ApiError::BadRequest(format!("invalid evidence package index payload: {e}"))
        })?;
        return Ok(parsed);
    }

    Ok(Vec::new())
}

async fn save_evidence_package_index(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    entries: &[EvidencePackageIndexEntry],
) -> Result<(), ApiError> {
    let payload = serde_json::to_string(entries)
        .map_err(|e| ApiError::Internal(format!("failed to serialize evidence index: {e}")))?;
    repo.save_raw(tenant_id, EVIDENCE_PACKAGE_INDEX_KEY, &payload)
        .await
        .map_err(ApiError::from)?;
    Ok(())
}
