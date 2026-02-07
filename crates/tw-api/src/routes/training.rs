//! Training data export endpoints.
//!
//! This module provides API endpoints for exporting analyst feedback and incident
//! data as training examples for ML model fine-tuning.

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::middleware::OptionalTenant;
use crate::state::AppState;
use tw_core::db::{create_feedback_repository, create_incident_repository};
use tw_core::feedback::FeedbackType;
use tw_core::training::{
    ExportConfig, ExportFormat, ExportOutput, ExportStats, TrainingDataExporter,
};

fn tenant_id_or_default(tenant: Option<tw_core::tenant::TenantContext>) -> Uuid {
    tenant
        .map(|ctx| ctx.tenant_id)
        .unwrap_or(tw_core::auth::DEFAULT_TENANT_ID)
}

/// Creates training data routes.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/export", get(export_training_data))
        .route("/export", post(export_training_data_post))
        .route("/stats", get(get_training_stats))
        .route("/preview", get(preview_training_data))
}

// ============================================================================
// Request/Response DTOs
// ============================================================================

/// Query parameters for training data export.
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ExportQuery {
    /// Export format: jsonl (default), json, or csv.
    #[serde(default)]
    pub format: Option<String>,

    /// Only include corrections (exclude confirmations).
    #[serde(default)]
    pub corrections_only: Option<bool>,

    /// Minimum quality score (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub min_quality_score: Option<f64>,

    /// Maximum number of examples to export.
    #[validate(range(min = 1, max = 10000))]
    pub limit: Option<u32>,

    /// Export examples created after this timestamp (ISO 8601).
    pub since: Option<DateTime<Utc>>,

    /// Export examples created before this timestamp (ISO 8601).
    pub until: Option<DateTime<Utc>>,

    /// Filter by feedback types (comma-separated).
    pub feedback_types: Option<String>,

    /// Whether to mask PII in the exported data (default: true).
    #[serde(default)]
    pub mask_pii: Option<bool>,

    /// Include full incident data (default: false for summary).
    #[serde(default)]
    pub include_full_incident: Option<bool>,
}

impl ExportQuery {
    /// Converts query parameters to ExportConfig.
    fn to_config(&self) -> ExportConfig {
        let format = self
            .format
            .as_ref()
            .and_then(|f| ExportFormat::parse(f))
            .unwrap_or_default();

        let feedback_types = self.feedback_types.as_ref().map(|types| {
            types
                .split(',')
                .filter_map(|t| parse_feedback_type(t.trim()))
                .collect()
        });

        ExportConfig {
            format,
            corrections_only: self.corrections_only.unwrap_or(false),
            min_quality_score: self.min_quality_score.unwrap_or(0.0),
            limit: self.limit,
            since: self.since,
            until: self.until,
            feedback_types,
            mask_pii: self.mask_pii.unwrap_or(true),
            include_full_incident: self.include_full_incident.unwrap_or(false),
        }
    }
}

/// Request body for training data export (POST).
#[derive(Debug, Clone, Deserialize, Validate, ToSchema)]
pub struct ExportRequest {
    /// Export format: jsonl (default), json, or csv.
    #[serde(default)]
    pub format: Option<String>,

    /// Only include corrections (exclude confirmations).
    #[serde(default)]
    pub corrections_only: bool,

    /// Minimum quality score (0.0 - 1.0).
    #[validate(range(min = 0.0, max = 1.0))]
    pub min_quality_score: Option<f64>,

    /// Maximum number of examples to export.
    #[validate(range(min = 1, max = 10000))]
    pub limit: Option<u32>,

    /// Export examples created after this timestamp.
    pub since: Option<DateTime<Utc>>,

    /// Export examples created before this timestamp.
    pub until: Option<DateTime<Utc>>,

    /// Filter by feedback types.
    pub feedback_types: Option<Vec<String>>,

    /// Whether to mask PII in the exported data (default: true).
    #[serde(default = "default_true")]
    pub mask_pii: bool,

    /// Include full incident data (default: false for summary).
    #[serde(default)]
    pub include_full_incident: bool,
}

fn default_true() -> bool {
    true
}

impl ExportRequest {
    /// Converts request body to ExportConfig.
    fn to_config(&self) -> ExportConfig {
        let format = self
            .format
            .as_ref()
            .and_then(|f| ExportFormat::parse(f))
            .unwrap_or_default();

        let feedback_types = self.feedback_types.as_ref().map(|types| {
            types
                .iter()
                .filter_map(|t| parse_feedback_type(t))
                .collect()
        });

        ExportConfig {
            format,
            corrections_only: self.corrections_only,
            min_quality_score: self.min_quality_score.unwrap_or(0.0),
            limit: self.limit,
            since: self.since,
            until: self.until,
            feedback_types,
            mask_pii: self.mask_pii,
            include_full_incident: self.include_full_incident,
        }
    }
}

/// Response for training data export.
#[derive(Debug, Serialize, ToSchema)]
pub struct ExportResponse {
    /// Number of examples exported.
    pub count: u64,
    /// Export format used.
    pub format: String,
    /// Whether PII was masked.
    pub pii_masked: bool,
    /// When the export started.
    pub started_at: DateTime<Utc>,
    /// When the export completed.
    pub completed_at: DateTime<Utc>,
}

/// Response for training data statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct StatsResponse {
    /// Total number of training examples available.
    pub total_examples: u64,
    /// Number of correction examples.
    pub corrections: u64,
    /// Number of confirmation examples.
    pub confirmations: u64,
    /// Breakdown by feedback type.
    pub by_feedback_type: HashMap<String, u64>,
    /// Breakdown by verdict.
    pub by_verdict: HashMap<String, u64>,
    /// Breakdown by severity.
    pub by_severity: HashMap<String, u64>,
    /// Average quality score.
    pub avg_quality_score: f64,
    /// Date range of available examples.
    pub date_range: Option<DateRangeResponse>,
}

/// Date range for statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct DateRangeResponse {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

impl From<ExportStats> for StatsResponse {
    fn from(stats: ExportStats) -> Self {
        Self {
            total_examples: stats.total_examples,
            corrections: stats.corrections,
            confirmations: stats.confirmations,
            by_feedback_type: stats.by_feedback_type,
            by_verdict: stats.by_verdict,
            by_severity: stats.by_severity,
            avg_quality_score: stats.avg_quality_score,
            date_range: stats.date_range.map(|dr| DateRangeResponse {
                from: dr.from,
                to: dr.to,
            }),
        }
    }
}

/// Preview response showing a sample of training examples.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewResponse {
    /// Sample training examples.
    pub examples: Vec<PreviewExample>,
    /// Total examples matching the filter.
    pub total_matching: u64,
    /// Whether PII was masked in the preview.
    pub pii_masked: bool,
}

/// A training example in preview format.
#[derive(Debug, Serialize, ToSchema)]
pub struct PreviewExample {
    /// Example ID.
    pub id: Uuid,
    /// Incident ID.
    pub incident_id: Uuid,
    /// Expected verdict.
    pub verdict: String,
    /// Expected severity.
    pub severity: String,
    /// Whether this is a correction.
    pub is_correction: bool,
    /// Quality score.
    pub quality_score: f64,
    /// Feedback type.
    pub feedback_type: String,
    /// Truncated input (first 500 chars).
    pub input_preview: String,
    /// Creation timestamp.
    pub created_at: DateTime<Utc>,
}

// ============================================================================
// Route Handlers
// ============================================================================

/// Export training data (GET).
///
/// Exports analyst feedback and incident data as training examples for ML models.
/// Returns the data in the requested format (JSONL, JSON, or CSV).
#[utoipa::path(
    get,
    path = "/api/training/export",
    params(
        ("format" = Option<String>, Query, description = "Export format: jsonl, json, csv"),
        ("corrections_only" = Option<bool>, Query, description = "Only include corrections"),
        ("min_quality_score" = Option<f64>, Query, description = "Minimum quality score (0.0-1.0)"),
        ("limit" = Option<u32>, Query, description = "Maximum examples to export"),
        ("since" = Option<DateTime<Utc>>, Query, description = "Export examples after this time"),
        ("until" = Option<DateTime<Utc>>, Query, description = "Export examples before this time"),
        ("feedback_types" = Option<String>, Query, description = "Filter by feedback types (comma-separated)"),
        ("mask_pii" = Option<bool>, Query, description = "Mask PII in export (default: true)"),
    ),
    responses(
        (status = 200, description = "Training data exported successfully"),
        (status = 204, description = "No training data found matching criteria"),
        (status = 400, description = "Invalid query parameters"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Training"
)]
async fn export_training_data(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ExportQuery>,
) -> Result<Response, ApiError> {
    query.validate()?;

    let config = query.to_config();
    let tenant_id = tenant_id_or_default(tenant);
    export_with_config(state, tenant_id, config).await
}

/// Export training data (POST).
///
/// Exports analyst feedback and incident data as training examples for ML models.
/// Accepts a JSON body with export configuration.
#[utoipa::path(
    post,
    path = "/api/training/export",
    request_body = ExportRequest,
    responses(
        (status = 200, description = "Training data exported successfully"),
        (status = 204, description = "No training data found matching criteria"),
        (status = 400, description = "Invalid request body"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Training"
)]
async fn export_training_data_post(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Json(request): Json<ExportRequest>,
) -> Result<Response, ApiError> {
    request.validate()?;

    let config = request.to_config();
    let tenant_id = tenant_id_or_default(tenant);
    export_with_config(state, tenant_id, config).await
}

/// Get training data statistics.
///
/// Returns statistics about available training data without exporting.
#[utoipa::path(
    get,
    path = "/api/training/stats",
    params(
        ("corrections_only" = Option<bool>, Query, description = "Only count corrections"),
        ("min_quality_score" = Option<f64>, Query, description = "Minimum quality score"),
        ("since" = Option<DateTime<Utc>>, Query, description = "Count examples after this time"),
        ("until" = Option<DateTime<Utc>>, Query, description = "Count examples before this time"),
    ),
    responses(
        (status = 200, description = "Training statistics", body = StatsResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Training"
)]
async fn get_training_stats(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ExportQuery>,
) -> Result<Json<StatsResponse>, ApiError> {
    query.validate()?;

    let config = query.to_config();
    let tenant_id = tenant_id_or_default(tenant);

    // Fetch feedback and incidents
    let (feedback_list, incidents) = fetch_training_data(&state, tenant_id, &config).await?;

    // Generate examples and calculate stats
    let exporter = TrainingDataExporter::new(config);
    let examples = exporter.generate_examples(&feedback_list, &incidents);
    let stats = exporter.calculate_stats(&examples);

    Ok(Json(stats.into()))
}

/// Preview training data.
///
/// Returns a preview of training examples without full export.
#[utoipa::path(
    get,
    path = "/api/training/preview",
    params(
        ("corrections_only" = Option<bool>, Query, description = "Only include corrections"),
        ("min_quality_score" = Option<f64>, Query, description = "Minimum quality score"),
        ("limit" = Option<u32>, Query, description = "Max examples to preview (default: 10)"),
        ("mask_pii" = Option<bool>, Query, description = "Mask PII in preview (default: true)"),
    ),
    responses(
        (status = 200, description = "Training data preview", body = PreviewResponse),
        (status = 500, description = "Internal server error")
    ),
    tag = "Training"
)]
async fn preview_training_data(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    OptionalTenant(tenant): OptionalTenant,
    Query(query): Query<ExportQuery>,
) -> Result<Json<PreviewResponse>, ApiError> {
    query.validate()?;

    let mut config = query.to_config();
    // Limit preview to reasonable size
    config.limit = Some(config.limit.unwrap_or(10).min(50));
    let tenant_id = tenant_id_or_default(tenant);

    // Fetch feedback and incidents
    let (feedback_list, incidents) = fetch_training_data(&state, tenant_id, &config).await?;

    // Generate examples
    let exporter = TrainingDataExporter::new(config.clone());
    let examples = exporter.generate_examples(&feedback_list, &incidents);

    let preview_examples: Vec<PreviewExample> = examples
        .iter()
        .map(|e| PreviewExample {
            id: e.id,
            incident_id: e.metadata.incident_id,
            verdict: format!("{:?}", e.expected_output.verdict),
            severity: format!("{:?}", e.expected_output.severity),
            is_correction: e.metadata.is_correction,
            quality_score: e.metadata.quality_score,
            feedback_type: format!("{:?}", e.metadata.feedback_type),
            input_preview: truncate_for_preview(&e.input, 500),
            created_at: e.created_at,
        })
        .collect();

    Ok(Json(PreviewResponse {
        examples: preview_examples,
        total_matching: examples.len() as u64,
        pii_masked: config.mask_pii,
    }))
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Exports training data with the given configuration.
async fn export_with_config(
    state: AppState,
    tenant_id: Uuid,
    config: ExportConfig,
) -> Result<Response, ApiError> {
    let format = config.format;

    // Fetch feedback and incidents
    let (feedback_list, incidents) = fetch_training_data(&state, tenant_id, &config).await?;

    // Generate examples and export
    let exporter = TrainingDataExporter::new(config);
    let examples = exporter.generate_examples(&feedback_list, &incidents);

    if examples.is_empty() {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let result = exporter
        .export(&examples)
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Return appropriate response based on output type
    match result.output {
        ExportOutput::Content { data } => {
            let content_type = format.content_type();
            let extension = format.extension();
            let filename = format!(
                "training_data_{}.{}",
                Utc::now().format("%Y%m%d_%H%M%S"),
                extension
            );

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, content_type),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"{}\"", filename),
                    ),
                ],
                data,
            )
                .into_response())
        }
        ExportOutput::File { path: _ } => {
            // For file-based exports, return metadata
            Ok(Json(ExportResponse {
                count: result.count,
                format: format!("{:?}", result.format).to_lowercase(),
                pii_masked: result.pii_masked,
                started_at: result.started_at,
                completed_at: result.completed_at,
            })
            .into_response())
        }
    }
}

/// Fetches feedback and incident data for training export.
async fn fetch_training_data(
    state: &AppState,
    tenant_id: Uuid,
    config: &ExportConfig,
) -> Result<
    (
        Vec<tw_core::feedback::AnalystFeedback>,
        HashMap<Uuid, tw_core::incident::Incident>,
    ),
    ApiError,
> {
    let feedback_repo = create_feedback_repository(&state.db);
    let incident_repo = create_incident_repository(&state.db);

    // Fetch feedback for training
    let feedback_list = feedback_repo
        .get_for_training(
            tenant_id,
            config.corrections_only,
            config.since,
            config.until,
            config.limit.map(|l| l as usize),
        )
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    // Collect unique incident IDs
    let incident_ids: Vec<Uuid> = feedback_list
        .iter()
        .map(|f| f.incident_id)
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    // Fetch corresponding incidents
    let mut incidents = HashMap::new();
    for id in incident_ids {
        if let Ok(Some(incident)) = incident_repo.get_for_tenant(id, tenant_id).await {
            incidents.insert(id, incident);
        }
    }

    Ok((feedback_list, incidents))
}

/// Parses a feedback type from string.
fn parse_feedback_type(s: &str) -> Option<FeedbackType> {
    match s.to_lowercase().as_str() {
        "correct" => Some(FeedbackType::Correct),
        "incorrect_verdict" | "incorrectverdict" => Some(FeedbackType::IncorrectVerdict),
        "incorrect_severity" | "incorrectseverity" => Some(FeedbackType::IncorrectSeverity),
        "missing_context" | "missingcontext" => Some(FeedbackType::MissingContext),
        "incorrect_mitre" | "incorrectmitre" => Some(FeedbackType::IncorrectMitre),
        "other" => Some(FeedbackType::Other),
        _ => None,
    }
}

/// Truncates a string for preview purposes.
fn truncate_for_preview(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut end = max_len;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}...", &s[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_feedback_type() {
        assert_eq!(parse_feedback_type("correct"), Some(FeedbackType::Correct));
        assert_eq!(
            parse_feedback_type("incorrect_verdict"),
            Some(FeedbackType::IncorrectVerdict)
        );
        assert_eq!(
            parse_feedback_type("INCORRECT_SEVERITY"),
            Some(FeedbackType::IncorrectSeverity)
        );
        assert_eq!(
            parse_feedback_type("MissingContext"),
            Some(FeedbackType::MissingContext)
        );
        assert_eq!(parse_feedback_type("invalid"), None);
    }

    #[test]
    fn test_truncate_for_preview() {
        let short = "short text";
        assert_eq!(truncate_for_preview(short, 100), "short text");

        let long = "a".repeat(100);
        let truncated = truncate_for_preview(&long, 50);
        assert!(truncated.len() <= 53); // 50 + "..."
        assert!(truncated.ends_with("..."));
    }

    #[test]
    fn test_export_query_to_config() {
        let query = ExportQuery {
            format: Some("json".to_string()),
            corrections_only: Some(true),
            min_quality_score: Some(0.5),
            limit: Some(100),
            since: None,
            until: None,
            feedback_types: Some("correct,incorrect_verdict".to_string()),
            mask_pii: Some(false),
            include_full_incident: Some(true),
        };

        let config = query.to_config();

        assert_eq!(config.format, ExportFormat::Json);
        assert!(config.corrections_only);
        assert_eq!(config.min_quality_score, 0.5);
        assert_eq!(config.limit, Some(100));
        assert!(!config.mask_pii);
        assert!(config.include_full_incident);

        let types = config.feedback_types.unwrap();
        assert!(types.contains(&FeedbackType::Correct));
        assert!(types.contains(&FeedbackType::IncorrectVerdict));
    }

    #[test]
    fn test_export_request_to_config() {
        let request = ExportRequest {
            format: Some("csv".to_string()),
            corrections_only: true,
            min_quality_score: Some(0.7),
            limit: Some(50),
            since: None,
            until: None,
            feedback_types: Some(vec!["incorrect_mitre".to_string()]),
            mask_pii: true,
            include_full_incident: false,
        };

        let config = request.to_config();

        assert_eq!(config.format, ExportFormat::Csv);
        assert!(config.corrections_only);
        assert_eq!(config.min_quality_score, 0.7);
        assert_eq!(config.limit, Some(50));
        assert!(config.mask_pii);
        assert!(!config.include_full_incident);

        let types = config.feedback_types.unwrap();
        assert!(types.contains(&FeedbackType::IncorrectMitre));
    }
}
