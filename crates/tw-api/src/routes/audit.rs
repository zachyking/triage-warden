//! Immutable audit chain endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tw_core::audit::immutable::ImmutableAuditPayload;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_audit_repository, create_settings_repository, AuditRepository, SettingsRepository,
};
use tw_core::{
    verify_immutable_audit_chain, AuditActor, AuditEventType, AuditOutcome, AuditResource,
    ImmutableAuditLog,
};

const IMMUTABLE_ANCHOR_KEY: &str = "immutable_audit_anchor";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates immutable audit routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/immutable/anchor", post(anchor_chain))
        .route("/immutable/verify", get(verify_chain))
        .route("/immutable/export", get(export_chain))
}

#[derive(Debug, Deserialize)]
struct AuditQuery {
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct AnchorResponse {
    anchored: bool,
    entries: usize,
    root_hash: String,
}

#[derive(Debug, Serialize)]
struct VerifyResponse {
    valid: bool,
    entries: usize,
    current_root: Option<String>,
    anchored_root: Option<String>,
    reason: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExportResponse {
    entries: Vec<ImmutableAuditLog>,
    root_hash: Option<String>,
}

async fn anchor_chain(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AnchorResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let root_hash = chain.last().map(|e| e.hash.clone()).unwrap_or_default();

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    settings_repo
        .save_raw(tenant_id, IMMUTABLE_ANCHOR_KEY, &root_hash)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(AnchorResponse {
        anchored: true,
        entries: chain.len(),
        root_hash,
    }))
}

async fn verify_chain(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let current_root = chain.last().map(|e| e.hash.clone());

    let settings_repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let anchored_root = settings_repo
        .get_raw(tenant_id, IMMUTABLE_ANCHOR_KEY)
        .await
        .map_err(ApiError::from)?;

    let chain_valid = verify_immutable_audit_chain(&chain).is_ok();
    let anchor_matches = match (&current_root, &anchored_root) {
        (Some(current), Some(anchor)) => current == anchor,
        (_, None) => true,
        _ => false,
    };

    Ok(Json(VerifyResponse {
        valid: chain_valid && anchor_matches,
        entries: chain.len(),
        current_root,
        anchored_root,
        reason: if chain_valid {
            if anchor_matches {
                None
            } else {
                Some("Current root hash does not match anchored root".to_string())
            }
        } else {
            Some("Immutable chain verification failed".to_string())
        },
    }))
}

async fn export_chain(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<AuditQuery>,
) -> Result<Json<ExportResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let chain = build_immutable_chain(&state, tenant_id, query.limit.unwrap_or(5000)).await?;
    let root_hash = chain.last().map(|entry| entry.hash.clone());
    Ok(Json(ExportResponse {
        entries: chain,
        root_hash,
    }))
}

async fn build_immutable_chain(
    state: &AppState,
    tenant_id: uuid::Uuid,
    limit: u32,
) -> Result<Vec<ImmutableAuditLog>, ApiError> {
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);
    let mut entries = audit_repo
        .get_recent_for_tenant(tenant_id, limit)
        .await
        .map_err(ApiError::from)?;
    entries.sort_by_key(|(_, entry)| entry.timestamp);

    let mut chain: Vec<ImmutableAuditLog> = Vec::new();
    for (incident_id, entry) in entries {
        let previous = chain.last();
        let immutable = ImmutableAuditLog::from_seed(
            entry.id,
            entry.timestamp,
            previous,
            ImmutableAuditPayload::new(
                map_event_type(&entry.action),
                AuditActor {
                    id: entry.actor.clone(),
                    kind: "actor".to_string(),
                },
                AuditResource {
                    kind: "incident".to_string(),
                    id: Some(incident_id.to_string()),
                },
                format!("{:?}", entry.action),
                AuditOutcome::Success,
                entry.details.unwrap_or_default(),
            ),
        );
        chain.push(immutable);
    }
    Ok(chain)
}

fn map_event_type(action: &tw_core::incident::AuditAction) -> AuditEventType {
    match action {
        tw_core::incident::AuditAction::IncidentCreated => AuditEventType::ActionRequested,
        tw_core::incident::AuditAction::StatusChanged(_) => AuditEventType::ActionExecuted,
        tw_core::incident::AuditAction::ActionApproved => AuditEventType::ActionApproved,
        tw_core::incident::AuditAction::ActionDenied => AuditEventType::ActionRejected,
        tw_core::incident::AuditAction::ActionExecuted => AuditEventType::ActionExecuted,
        tw_core::incident::AuditAction::ActionFailed => AuditEventType::ActionFailed,
        tw_core::incident::AuditAction::AnalysisCompleted => AuditEventType::AiAnalysisRequested,
        _ => AuditEventType::Custom(format!("{:?}", action)),
    }
}
