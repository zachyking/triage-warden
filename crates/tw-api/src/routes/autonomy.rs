//! Autonomy configuration API endpoints.
//!
//! This module provides REST endpoints for managing the autonomy configuration
//! that controls how much freedom the AI response system has to auto-execute actions.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::error::ApiError;
use crate::state::AppState;

use tw_core::autonomy::{
    AutonomyAuditEntry, AutonomyConfig, AutonomyDecision, AutonomyLevel, TimeBasedRule,
};

// ============================================================================
// DTOs
// ============================================================================

/// Response containing the current autonomy configuration.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AutonomyConfigResponse {
    pub tenant_id: String,
    pub default_level: String,
    pub per_action_overrides: HashMap<String, String>,
    pub per_severity_overrides: HashMap<String, String>,
    pub time_based_rules: Vec<TimeBasedRuleDto>,
    pub emergency_contacts: Vec<String>,
    pub updated_at: String,
    pub updated_by: String,
}

/// DTO for a time-based rule.
#[derive(Debug, Serialize, Deserialize, ToSchema, Clone)]
pub struct TimeBasedRuleDto {
    pub name: String,
    pub start_hour: u32,
    pub end_hour: u32,
    pub days_of_week: Vec<u32>,
    pub level: String,
}

/// Request to update the autonomy configuration.
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct UpdateAutonomyConfigRequest {
    pub default_level: Option<String>,
    pub per_action_overrides: Option<HashMap<String, String>>,
    pub per_severity_overrides: Option<HashMap<String, String>>,
    pub time_based_rules: Option<Vec<TimeBasedRuleDto>>,
    pub emergency_contacts: Option<Vec<String>>,
}

/// Response containing the resolved autonomy level.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ResolvedLevelResponse {
    pub level: String,
    pub auto_execute: bool,
    pub reason: String,
}

/// Request to resolve autonomy level for a specific action.
#[derive(Debug, Serialize, Deserialize, Validate, ToSchema)]
pub struct ResolveAutonomyRequest {
    pub action: String,
    pub severity: String,
}

/// Query params for the audit log.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    pub limit: Option<u32>,
    pub incident_id: Option<Uuid>,
}

/// Response for an audit entry.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditEntryResponse {
    pub id: String,
    pub tenant_id: String,
    pub incident_id: String,
    pub action: String,
    pub resolved_level: String,
    pub auto_execute: bool,
    pub reason: String,
    pub executed: bool,
    pub outcome: Option<String>,
    pub timestamp: String,
}

// ============================================================================
// Conversion helpers
// ============================================================================

fn config_to_response(config: &AutonomyConfig) -> AutonomyConfigResponse {
    AutonomyConfigResponse {
        tenant_id: config.tenant_id.to_string(),
        default_level: config.default_level.as_db_str().to_string(),
        per_action_overrides: config
            .per_action_overrides
            .iter()
            .map(|(k, v)| (k.clone(), v.as_db_str().to_string()))
            .collect(),
        per_severity_overrides: config
            .per_severity_overrides
            .iter()
            .map(|(k, v)| (k.clone(), v.as_db_str().to_string()))
            .collect(),
        time_based_rules: config
            .time_based_rules
            .iter()
            .map(|r| TimeBasedRuleDto {
                name: r.name.clone(),
                start_hour: r.start_hour,
                end_hour: r.end_hour,
                days_of_week: r.days_of_week.clone(),
                level: r.level.as_db_str().to_string(),
            })
            .collect(),
        emergency_contacts: config.emergency_contacts.clone(),
        updated_at: config.updated_at.to_rfc3339(),
        updated_by: config.updated_by.clone(),
    }
}

fn decision_to_response(decision: &AutonomyDecision) -> ResolvedLevelResponse {
    ResolvedLevelResponse {
        level: decision.resolved_level.as_db_str().to_string(),
        auto_execute: decision.auto_execute,
        reason: decision.reason.clone(),
    }
}

fn audit_entry_to_response(entry: &AutonomyAuditEntry) -> AuditEntryResponse {
    AuditEntryResponse {
        id: entry.id.to_string(),
        tenant_id: entry.tenant_id.to_string(),
        incident_id: entry.incident_id.to_string(),
        action: entry.action.clone(),
        resolved_level: entry.decision.resolved_level.as_db_str().to_string(),
        auto_execute: entry.decision.auto_execute,
        reason: entry.decision.reason.clone(),
        executed: entry.executed,
        outcome: entry.outcome.clone(),
        timestamp: entry.timestamp.to_rfc3339(),
    }
}

fn parse_autonomy_level(s: &str) -> Result<AutonomyLevel, ApiError> {
    AutonomyLevel::from_db_str(s)
        .ok_or_else(|| ApiError::BadRequest(format!("Invalid autonomy level: '{}'", s)))
}

// ============================================================================
// Routes
// ============================================================================

/// Creates autonomy routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/config", get(get_autonomy_config))
        .route("/config", put(update_autonomy_config))
        .route("/level", get(get_current_level))
        .route("/audit", get(get_audit_log))
        .route("/resolve", post(resolve_level))
}

// ============================================================================
// Handlers
// ============================================================================

/// Get the current autonomy configuration.
async fn get_autonomy_config(
    State(_state): State<AppState>,
) -> Result<Json<AutonomyConfigResponse>, ApiError> {
    // In a production system, this would load from a database.
    // For now, return the default configuration.
    let config = AutonomyConfig::default();
    Ok(Json(config_to_response(&config)))
}

/// Update the autonomy configuration.
async fn update_autonomy_config(
    State(_state): State<AppState>,
    Json(request): Json<UpdateAutonomyConfigRequest>,
) -> Result<(StatusCode, Json<AutonomyConfigResponse>), ApiError> {
    let mut config = AutonomyConfig::default();

    if let Some(level_str) = &request.default_level {
        config.default_level = parse_autonomy_level(level_str)?;
    }

    if let Some(overrides) = &request.per_action_overrides {
        let mut parsed = HashMap::new();
        for (action, level_str) in overrides {
            parsed.insert(action.clone(), parse_autonomy_level(level_str)?);
        }
        config.per_action_overrides = parsed;
    }

    if let Some(overrides) = &request.per_severity_overrides {
        let mut parsed = HashMap::new();
        for (severity, level_str) in overrides {
            parsed.insert(severity.clone(), parse_autonomy_level(level_str)?);
        }
        config.per_severity_overrides = parsed;
    }

    if let Some(rules) = &request.time_based_rules {
        let mut parsed = Vec::new();
        for rule_dto in rules {
            let level = parse_autonomy_level(&rule_dto.level)?;
            if rule_dto.start_hour > 23 || rule_dto.end_hour > 24 {
                return Err(ApiError::BadRequest(
                    "Hour values must be 0-23 for start and 0-24 for end".to_string(),
                ));
            }
            for day in &rule_dto.days_of_week {
                if *day > 6 {
                    return Err(ApiError::BadRequest(
                        "Day of week must be 0 (Sunday) through 6 (Saturday)".to_string(),
                    ));
                }
            }
            parsed.push(TimeBasedRule {
                name: rule_dto.name.clone(),
                start_hour: rule_dto.start_hour,
                end_hour: rule_dto.end_hour,
                days_of_week: rule_dto.days_of_week.clone(),
                level,
            });
        }
        config.time_based_rules = parsed;
    }

    if let Some(contacts) = &request.emergency_contacts {
        config.emergency_contacts = contacts.clone();
    }

    config.updated_at = Utc::now();
    config.updated_by = "api".to_string();

    Ok((StatusCode::OK, Json(config_to_response(&config))))
}

/// Get the current resolved autonomy level (using defaults).
async fn get_current_level(
    State(_state): State<AppState>,
) -> Result<Json<ResolvedLevelResponse>, ApiError> {
    let config = AutonomyConfig::default();
    let now = Utc::now();
    let decision = config.resolve_level("default", "medium", &now);
    Ok(Json(decision_to_response(&decision)))
}

/// Resolve the autonomy level for a specific action and severity.
async fn resolve_level(
    State(_state): State<AppState>,
    Json(request): Json<ResolveAutonomyRequest>,
) -> Result<Json<ResolvedLevelResponse>, ApiError> {
    if request.action.is_empty() {
        return Err(ApiError::BadRequest("Action is required".to_string()));
    }
    if request.severity.is_empty() {
        return Err(ApiError::BadRequest("Severity is required".to_string()));
    }

    let config = AutonomyConfig::default();
    let now = Utc::now();
    let decision = config.resolve_level(&request.action, &request.severity, &now);
    Ok(Json(decision_to_response(&decision)))
}

/// Get the autonomy audit log.
async fn get_audit_log(
    State(_state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEntryResponse>>, ApiError> {
    // In production, this would query the database.
    // For now, return an empty list.
    let _limit = query.limit.unwrap_or(50);
    let _incident_id = query.incident_id;
    let entries: Vec<AutonomyAuditEntry> = vec![];
    let responses: Vec<AuditEntryResponse> = entries.iter().map(audit_entry_to_response).collect();
    Ok(Json(responses))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_to_response() {
        let config = AutonomyConfig::default();
        let response = config_to_response(&config);
        assert_eq!(response.default_level, "supervised");
        assert!(response.per_action_overrides.is_empty());
    }

    #[test]
    fn test_decision_to_response() {
        let decision = AutonomyDecision {
            action: "block_ip".to_string(),
            incident_severity: "high".to_string(),
            resolved_level: AutonomyLevel::Supervised,
            auto_execute: false,
            reason: "Default".to_string(),
            timestamp: Utc::now(),
        };
        let response = decision_to_response(&decision);
        assert_eq!(response.level, "supervised");
        assert!(!response.auto_execute);
    }

    #[test]
    fn test_audit_entry_to_response() {
        let decision = AutonomyDecision {
            action: "block_ip".to_string(),
            incident_severity: "high".to_string(),
            resolved_level: AutonomyLevel::Supervised,
            auto_execute: false,
            reason: "Default".to_string(),
            timestamp: Utc::now(),
        };
        let entry = AutonomyAuditEntry::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "block_ip".to_string(),
            decision,
        );
        let response = audit_entry_to_response(&entry);
        assert_eq!(response.action, "block_ip");
        assert_eq!(response.resolved_level, "supervised");
        assert!(!response.executed);
    }

    #[test]
    fn test_parse_autonomy_level_valid() {
        assert_eq!(
            parse_autonomy_level("assisted").unwrap(),
            AutonomyLevel::Assisted
        );
        assert_eq!(
            parse_autonomy_level("supervised").unwrap(),
            AutonomyLevel::Supervised
        );
        assert_eq!(
            parse_autonomy_level("autonomous").unwrap(),
            AutonomyLevel::Autonomous
        );
        assert_eq!(
            parse_autonomy_level("full_autonomous").unwrap(),
            AutonomyLevel::FullAutonomous
        );
    }

    #[test]
    fn test_parse_autonomy_level_invalid() {
        assert!(parse_autonomy_level("invalid").is_err());
        assert!(parse_autonomy_level("").is_err());
    }
}
