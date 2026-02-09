//! Privacy and data-security endpoints.

use crate::auth::{RequireAdmin, RequireAnalyst};
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{create_settings_repository, SettingsRepository};
use tw_core::privacy::{
    DataCategory, DataMasker, DataType, DeletionStrategy, MaskingStrategy, RetentionManager,
    RetentionPolicy, SensitiveDataClassifier,
};

const RETENTION_SETTINGS_KEY: &str = "privacy_retention_policies";

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> uuid::Uuid {
    tenant.map(|ctx| ctx.tenant_id).unwrap_or(DEFAULT_TENANT_ID)
}

/// Creates privacy routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/classify", post(classify_text))
        .route("/mask", post(mask_text))
        .route(
            "/retention",
            get(get_retention_policies).put(save_retention_policies),
        )
        .route("/retention/evaluate", post(evaluate_retention))
        .route("/route-llm", post(route_llm_provider))
}

#[derive(Debug, Deserialize)]
struct ClassifyRequest {
    text: String,
}

#[derive(Debug, Serialize)]
struct MatchResponse {
    category: String,
    pattern: String,
    start: usize,
    end: usize,
    confidence: f32,
}

#[derive(Debug, Serialize)]
struct ClassifyResponse {
    matches: Vec<MatchResponse>,
}

#[derive(Debug, Deserialize)]
struct MaskRequest {
    text: String,
    #[serde(default)]
    strategies: HashMap<String, MaskingStrategy>,
}

#[derive(Debug, Serialize)]
struct MaskResponse {
    masked_text: String,
    mappings: Vec<MaskMappingResponse>,
}

#[derive(Debug, Serialize)]
struct MaskMappingResponse {
    category: String,
    replacement: String,
    start: usize,
    end: usize,
}

#[derive(Debug, Deserialize)]
struct SaveRetentionRequest {
    policies: Vec<RetentionPolicyInput>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct RetentionPolicyInput {
    data_type: DataType,
    retention_days: u32,
    deletion_strategy: DeletionStrategy,
}

#[derive(Debug, Serialize)]
struct RetentionPoliciesResponse {
    policies: Vec<RetentionPolicyInput>,
}

#[derive(Debug, Deserialize)]
struct RetentionEvaluateRequest {
    data_type: DataType,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct RetentionEvaluateResponse {
    expired: bool,
    delete_after: DateTime<Utc>,
    strategy: DeletionStrategy,
}

#[derive(Debug, Deserialize)]
struct RouteLlmRequest {
    data_sensitivity: String,
}

#[derive(Debug, Serialize)]
struct RouteLlmResponse {
    selected_provider: String,
    reason: String,
}

async fn classify_text(
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<ClassifyRequest>,
) -> Result<Json<ClassifyResponse>, ApiError> {
    let classifier = SensitiveDataClassifier::with_default_patterns();
    let matches = classifier
        .classify(&request.text)
        .into_iter()
        .map(|m| MatchResponse {
            category: m.category.as_key(),
            pattern: m.pattern_name,
            start: m.start,
            end: m.end,
            confidence: m.confidence,
        })
        .collect();
    Ok(Json(ClassifyResponse { matches }))
}

async fn mask_text(
    RequireAnalyst(_user): RequireAnalyst,
    Json(request): Json<MaskRequest>,
) -> Result<Json<MaskResponse>, ApiError> {
    let classifier = SensitiveDataClassifier::with_default_patterns();
    let mut masker = DataMasker::new(classifier, HashMap::new());
    for (category, strategy) in request.strategies {
        if let Some(parsed) = parse_category(&category) {
            masker.set_strategy(parsed, strategy);
        }
    }
    let masked = masker.mask(&request.text);
    Ok(Json(MaskResponse {
        masked_text: masked.text,
        mappings: masked
            .mappings
            .into_iter()
            .map(|m| MaskMappingResponse {
                category: m.category.as_key(),
                replacement: m.replacement,
                start: m.original_range.0,
                end: m.original_range.1,
            })
            .collect(),
    }))
}

async fn get_retention_policies(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
) -> Result<Json<RetentionPoliciesResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    if let Some(raw) = repo
        .get_raw(tenant_id, RETENTION_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let policies: Vec<RetentionPolicyInput> =
            serde_json::from_str(&raw).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        return Ok(Json(RetentionPoliciesResponse { policies }));
    }

    let default = RetentionManager::default()
        .all_policies()
        .into_iter()
        .map(|p| RetentionPolicyInput {
            data_type: p.data_type,
            retention_days: p.retention_days,
            deletion_strategy: p.deletion_strategy,
        })
        .collect();
    Ok(Json(RetentionPoliciesResponse { policies: default }))
}

async fn save_retention_policies(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<SaveRetentionRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if request.policies.is_empty() {
        return Err(ApiError::validation_field(
            "policies",
            "required",
            "At least one policy is required",
        ));
    }
    for policy in &request.policies {
        if policy.retention_days == 0 {
            return Err(ApiError::validation_field(
                "retention_days",
                "min",
                "Retention days must be greater than zero",
            ));
        }
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let payload = serde_json::to_string(&request.policies)
        .map_err(|e| ApiError::Internal(format!("failed to serialize policies: {e}")))?;
    repo.save_raw(tenant_id, RETENTION_SETTINGS_KEY, &payload)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(serde_json::json!({ "saved": true })))
}

async fn evaluate_retention(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<RetentionEvaluateRequest>,
) -> Result<Json<RetentionEvaluateResponse>, ApiError> {
    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let manager = load_retention_manager(repo.as_ref(), tenant_id).await?;
    let decision = manager
        .evaluate(request.data_type, request.created_at)
        .ok_or_else(|| ApiError::BadRequest("No retention policy for data type".to_string()))?;
    Ok(Json(RetentionEvaluateResponse {
        expired: decision.expired,
        delete_after: decision.delete_after,
        strategy: decision.strategy,
    }))
}

async fn route_llm_provider(
    State(state): State<AppState>,
    RequireAdmin(_user): RequireAdmin,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<RouteLlmRequest>,
) -> Result<Json<RouteLlmResponse>, ApiError> {
    let sensitivity = request.data_sensitivity.to_ascii_lowercase();
    let force_local = matches!(
        sensitivity.as_str(),
        "confidential" | "restricted" | "high" | "secret"
    );

    if force_local {
        return Ok(Json(RouteLlmResponse {
            selected_provider: "local".to_string(),
            reason: "Sensitive data requires local LLM routing".to_string(),
        }));
    }

    let tenant_id = tenant_id_or_default(tenant);
    let repo: Box<dyn SettingsRepository> =
        create_settings_repository(&state.db, state.encryptor.clone());
    let llm = repo.get_llm(tenant_id).await.map_err(ApiError::from)?;

    Ok(Json(RouteLlmResponse {
        selected_provider: llm.provider,
        reason: "Using tenant-configured LLM provider for non-sensitive data".to_string(),
    }))
}

async fn load_retention_manager(
    repo: &dyn SettingsRepository,
    tenant_id: uuid::Uuid,
) -> Result<RetentionManager, ApiError> {
    if let Some(raw) = repo
        .get_raw(tenant_id, RETENTION_SETTINGS_KEY)
        .await
        .map_err(ApiError::from)?
    {
        let policies: Vec<RetentionPolicyInput> =
            serde_json::from_str(&raw).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let manager = RetentionManager::new(
            policies
                .into_iter()
                .map(|p| RetentionPolicy {
                    data_type: p.data_type,
                    retention_days: p.retention_days,
                    deletion_strategy: p.deletion_strategy,
                })
                .collect(),
        );
        return Ok(manager);
    }
    Ok(RetentionManager::default())
}

fn parse_category(value: &str) -> Option<DataCategory> {
    match value.to_ascii_lowercase().as_str() {
        "pii" => Some(DataCategory::Pii),
        "credential" => Some(DataCategory::Credential),
        "financial" => Some(DataCategory::Financial),
        "health" => Some(DataCategory::Health),
        "internal" => Some(DataCategory::Internal),
        custom if custom.starts_with("custom:") => Some(DataCategory::Custom(
            custom.trim_start_matches("custom:").to_string(),
        )),
        _ => None,
    }
}
