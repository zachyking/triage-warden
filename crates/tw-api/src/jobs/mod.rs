//! Background scheduler jobs for Stage 6 security workflows.

use crate::routes::audit::run_verify_job_for_tenant;
use crate::routes::privacy::run_retention_cleanup_job_for_tenant;
use crate::state::AppState;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_settings_repository, create_tenant_repository, SettingsRepository, TenantFilter,
};
use tw_core::tenant::TenantStatus;

const VERIFY_SCHEDULER_LAST_KEY: &str = "immutable_audit_verify_scheduler_last";
const CLEANUP_SCHEDULER_LAST_KEY: &str = "privacy_cleanup_scheduler_last";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VerifySchedulerStatus {
    tenant_id: uuid::Uuid,
    timestamp: DateTime<Utc>,
    valid: bool,
    entries: usize,
    reason: Option<String>,
    alert_created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CleanupSchedulerStatus {
    tenant_id: uuid::Uuid,
    timestamp: DateTime<Utc>,
    dsar_requests_processed: usize,
    dsar_requests_completed: usize,
    dsar_plans_completed: usize,
    dsar_pending_manual_review: usize,
    audit_rows_affected: u64,
}

/// Spawns Stage 6 recurring jobs and returns task handles.
pub fn spawn_stage6_scheduler(state: AppState) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();

    if env_bool("TW_STAGE6_VERIFY_JOB_ENABLED", true) {
        let verify_interval_secs = env_u64("TW_STAGE6_VERIFY_JOB_INTERVAL_SECS", 3600);
        let verify_limit = env_u32("TW_STAGE6_VERIFY_JOB_LIMIT", 5000);
        let state_clone = state.clone();
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(verify_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(e) = run_verify_cycle(&state_clone, verify_limit).await {
                    error!("Stage 6 verify scheduler cycle failed: {}", e);
                }
            }
        }));
        info!(
            interval_secs = verify_interval_secs,
            verify_limit, "Stage 6 immutable verify scheduler enabled"
        );
    } else {
        info!("Stage 6 immutable verify scheduler disabled");
    }

    if env_bool("TW_STAGE6_CLEANUP_JOB_ENABLED", true) {
        let cleanup_interval_secs = env_u64("TW_STAGE6_CLEANUP_JOB_INTERVAL_SECS", 3600);
        let state_clone = state;
        handles.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(e) = run_cleanup_cycle(&state_clone).await {
                    error!("Stage 6 cleanup scheduler cycle failed: {}", e);
                }
            }
        }));
        info!(
            interval_secs = cleanup_interval_secs,
            "Stage 6 privacy cleanup scheduler enabled"
        );
    } else {
        info!("Stage 6 privacy cleanup scheduler disabled");
    }

    handles
}

async fn run_verify_cycle(state: &AppState, limit: u32) -> Result<(), String> {
    let tenant_ids = list_operational_tenant_ids(state).await?;
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());

    for tenant_id in tenant_ids {
        match run_verify_job_for_tenant(state, tenant_id, limit).await {
            Ok(result) => {
                let status = VerifySchedulerStatus {
                    tenant_id,
                    timestamp: result.timestamp,
                    valid: result.valid,
                    entries: result.entries,
                    reason: result.reason,
                    alert_created: result.alert_created,
                };
                persist_status(
                    settings_repo.as_ref(),
                    tenant_id,
                    VERIFY_SCHEDULER_LAST_KEY,
                    &status,
                )
                .await?;
                if !status.valid {
                    warn!(
                        tenant_id = %tenant_id,
                        reason = ?status.reason,
                        "Stage 6 verify scheduler detected immutable audit validation failure"
                    );
                }
            }
            Err(e) => {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Stage 6 verify scheduler failed for tenant"
                );
            }
        }
    }

    Ok(())
}

async fn run_cleanup_cycle(state: &AppState) -> Result<(), String> {
    let tenant_ids = list_operational_tenant_ids(state).await?;
    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());

    for tenant_id in tenant_ids {
        match run_retention_cleanup_job_for_tenant(state, tenant_id).await {
            Ok(result) => {
                let status = CleanupSchedulerStatus {
                    tenant_id: result.tenant_id,
                    timestamp: result.timestamp,
                    dsar_requests_processed: result.dsar_requests_processed,
                    dsar_requests_completed: result.dsar_requests_completed,
                    dsar_plans_completed: result.dsar_plans_completed,
                    dsar_pending_manual_review: result.dsar_pending_manual_review,
                    audit_rows_affected: result.audit_rows_affected,
                };
                persist_status(
                    settings_repo.as_ref(),
                    tenant_id,
                    CLEANUP_SCHEDULER_LAST_KEY,
                    &status,
                )
                .await?;
            }
            Err(e) => {
                warn!(
                    tenant_id = %tenant_id,
                    error = %e,
                    "Stage 6 cleanup scheduler failed for tenant"
                );
            }
        }
    }

    Ok(())
}

async fn list_operational_tenant_ids(state: &AppState) -> Result<Vec<uuid::Uuid>, String> {
    let repo = create_tenant_repository(&state.db);
    let filter = TenantFilter {
        status: Some(TenantStatus::Active),
        ..Default::default()
    };
    let tenants = repo
        .list(&filter)
        .await
        .map_err(|e| format!("failed to list tenants for scheduler: {e}"))?;

    let mut tenant_ids: Vec<uuid::Uuid> = tenants.into_iter().map(|tenant| tenant.id).collect();
    if tenant_ids.is_empty() {
        tenant_ids.push(DEFAULT_TENANT_ID);
    }
    tenant_ids.sort_unstable();
    tenant_ids.dedup();
    Ok(tenant_ids)
}

async fn persist_status<T: Serialize>(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
    key: &str,
    value: &T,
) -> Result<(), String> {
    let payload = serde_json::to_string(value)
        .map_err(|e| format!("failed to serialize scheduler status: {e}"))?;
    repo.save_raw(tenant_id, key, &payload)
        .await
        .map_err(|e| format!("failed to persist scheduler status: {e}"))?;
    Ok(())
}

fn env_bool(name: &str, default: bool) -> bool {
    std::env::var(name)
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}
