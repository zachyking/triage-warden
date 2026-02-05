//! Investigation report generation endpoints (Stage 2.1.3).
//!
//! This module provides API endpoints for generating and exporting
//! investigation reports in various formats (JSON, HTML, PDF).

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::RequireAnalyst;
use crate::error::ApiError;
use crate::state::AppState;
use tw_core::auth::DEFAULT_TENANT_ID;
use tw_core::db::{
    create_audit_repository, create_incident_repository, AuditRepository, IncidentRepository,
};
use tw_core::incident::Incident;

/// Creates report routes.
pub fn routes() -> Router<AppState> {
    Router::new().route("/:id/report", get(generate_report))
}

/// Query parameters for report generation.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ReportQuery {
    /// Output format: json, html, or pdf. Defaults to json.
    #[serde(default = "default_format")]
    pub format: String,
    /// Whether to include raw alert data in the report.
    #[serde(default = "default_true")]
    pub include_raw_data: bool,
}

fn default_format() -> String {
    "json".to_string()
}

fn default_true() -> bool {
    true
}

/// Report metadata in API response.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReportMetadataResponse {
    pub incident_id: Uuid,
    pub generated_at: String,
    pub generated_by: String,
    pub report_version: String,
    pub format: String,
}

/// Generate an investigation report for an incident.
///
/// This endpoint generates a comprehensive investigation report that includes:
/// - Executive summary
/// - Verdict and confidence
/// - Investigation timeline
/// - Evidence table with citations
/// - MITRE ATT&CK mappings
/// - Indicators of compromise
/// - Recommended actions
/// - Detailed reasoning
/// - Audit log
#[utoipa::path(
    get,
    path = "/api/incidents/{id}/report",
    params(
        ("id" = Uuid, Path, description = "Incident ID"),
        ("format" = Option<String>, Query, description = "Output format: json, html, or pdf"),
        ("include_raw_data" = Option<bool>, Query, description = "Include raw alert data in report")
    ),
    responses(
        (status = 200, description = "Investigation report generated successfully"),
        (status = 404, description = "Incident not found"),
        (status = 422, description = "Incident has no analysis to generate report from"),
        (status = 500, description = "Internal server error")
    ),
    tag = "Reports"
)]
async fn generate_report(
    State(state): State<AppState>,
    RequireAnalyst(_user): RequireAnalyst,
    Path(id): Path<Uuid>,
    Query(query): Query<ReportQuery>,
) -> Result<Response, ApiError> {
    let incident_repo: Box<dyn IncidentRepository> = create_incident_repository(&state.db);
    let audit_repo: Box<dyn AuditRepository> = create_audit_repository(&state.db);

    // Fetch the incident
    let incident: Incident = incident_repo
        .get(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Incident {} not found", id)))?;

    // Ensure the incident has an analysis
    let analysis = incident.analysis.as_ref().ok_or_else(|| {
        ApiError::UnprocessableEntity(
            "Incident has no analysis. Run triage analysis before generating a report.".to_string(),
        )
    })?;

    // Get audit log for this incident
    let audit_entries = audit_repo.get_for_incident(DEFAULT_TENANT_ID, id).await?;

    // Build the report data structure
    let report_data =
        build_report_data(&incident, analysis, &audit_entries, query.include_raw_data);

    // Generate the response based on format
    match query.format.to_lowercase().as_str() {
        "json" => {
            let json_body = serde_json::to_string_pretty(&report_data)
                .map_err(|e| ApiError::Internal(format!("Failed to serialize report: {}", e)))?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"incident_{}_report.json\"", id),
                    ),
                ],
                json_body,
            )
                .into_response())
        }
        "html" => {
            let html_content = generate_html_report(&report_data)?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (
                        header::CONTENT_DISPOSITION,
                        &format!("attachment; filename=\"incident_{}_report.html\"", id),
                    ),
                ],
                html_content,
            )
                .into_response())
        }
        "pdf" => {
            // PDF generation requires the Python report generator
            // For now, return a placeholder or instruct to use the Python module
            Err(ApiError::NotImplemented(
                "PDF generation is not yet implemented in the Rust API. \
                 Use the Python tw_ai.reports module for PDF export."
                    .to_string(),
            ))
        }
        _ => Err(ApiError::BadRequest(format!(
            "Unsupported format: {}. Use 'json', 'html', or 'pdf'",
            query.format
        ))),
    }
}

/// Report data structure for serialization.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ReportData {
    pub metadata: ReportMetadataResponse,
    pub executive_summary: String,
    pub verdict: VerdictSummary,
    pub alert: AlertSummary,
    pub timeline: Vec<TimelineEntry>,
    pub evidence: Vec<EvidenceEntry>,
    pub evidence_summary: EvidenceSummaryData,
    pub mitre_techniques: Vec<MitreTechniqueEntry>,
    pub indicators: Vec<IndicatorEntry>,
    pub recommended_actions: Vec<ActionEntry>,
    pub reasoning: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_alert_data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enrichments: Option<Vec<serde_json::Value>>,
    pub audit_log: Vec<AuditLogEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct VerdictSummary {
    pub verdict: String,
    pub verdict_display: String,
    pub confidence: f64,
    pub calibrated_confidence: Option<f64>,
    pub severity: String,
    pub severity_display: String,
    pub risk_score: u8,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AlertSummary {
    pub alert_id: String,
    pub source: String,
    pub alert_type: Option<String>,
    pub title: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TimelineEntry {
    pub order: u32,
    pub timestamp: String,
    pub action: String,
    pub result: String,
    pub tool: Option<String>,
    pub status: String,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EvidenceEntry {
    pub order: usize,
    pub source_type: String,
    pub source_name: String,
    pub data_type: String,
    pub finding: String,
    pub relevance: String,
    pub confidence: f64,
    pub link: Option<String>,
    pub raw_value: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct EvidenceSummaryData {
    pub total_evidence: usize,
    pub average_confidence: f64,
    pub high_confidence_count: usize,
    pub medium_confidence_count: usize,
    pub low_confidence_count: usize,
    pub sources_used: Vec<String>,
    pub data_types_found: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MitreTechniqueEntry {
    pub technique_id: String,
    pub name: String,
    pub tactic: String,
    pub relevance: String,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct IndicatorEntry {
    pub indicator_type: String,
    pub value: String,
    pub verdict: String,
    pub context: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ActionEntry {
    pub order: usize,
    pub action: String,
    pub priority: String,
    pub reason: String,
    pub requires_approval: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct AuditLogEntry {
    pub timestamp: String,
    pub action: String,
    pub actor: String,
    pub details: Option<String>,
}

/// Build the report data structure from incident and analysis.
fn build_report_data(
    incident: &Incident,
    analysis: &tw_core::incident::TriageAnalysis,
    audit_entries: &[tw_core::incident::AuditEntry],
    include_raw_data: bool,
) -> ReportData {
    let now = chrono::Utc::now();

    // Build metadata
    let metadata = ReportMetadataResponse {
        incident_id: incident.id,
        generated_at: now.to_rfc3339(),
        generated_by: "Triage Warden".to_string(),
        report_version: "1.0".to_string(),
        format: "json".to_string(),
    };

    // Build executive summary
    let verdict_display = format_verdict(&analysis.verdict);
    let confidence_desc = if analysis.confidence >= 0.9 {
        "very high"
    } else if analysis.confidence >= 0.75 {
        "high"
    } else if analysis.confidence >= 0.5 {
        "moderate"
    } else if analysis.confidence >= 0.25 {
        "low"
    } else {
        "very low"
    };

    let executive_summary = format!(
        "A security incident from {} was analyzed and classified as {}. \
         This assessment is made with {} confidence ({}%). {}",
        incident.source,
        verdict_display,
        confidence_desc,
        (analysis.confidence * 100.0).round(),
        if !analysis.recommendations.is_empty() {
            format!(
                "Primary recommended action: {}",
                analysis.recommendations[0]
            )
        } else {
            String::new()
        }
    );

    // Build verdict summary
    let verdict = VerdictSummary {
        verdict: format!("{:?}", analysis.verdict).to_lowercase(),
        verdict_display: verdict_display.clone(),
        confidence: analysis.confidence,
        calibrated_confidence: analysis.calibrated_confidence,
        severity: format!("{:?}", incident.severity).to_lowercase(),
        severity_display: format!("{}", incident.severity),
        risk_score: analysis.risk_score,
    };

    // Build alert summary
    let alert = AlertSummary {
        alert_id: incident
            .alert_data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or(&incident.id.to_string())
            .to_string(),
        source: format!("{}", incident.source),
        alert_type: incident
            .alert_data
            .get("alert_type")
            .and_then(|v| v.as_str())
            .map(String::from),
        title: incident
            .alert_data
            .get("title")
            .and_then(|v| v.as_str())
            .map(String::from),
        created_at: incident.created_at.to_rfc3339(),
    };

    // Build timeline from investigation steps
    let timeline: Vec<TimelineEntry> = analysis
        .investigation_steps
        .iter()
        .map(|step| TimelineEntry {
            order: step.order,
            timestamp: step.timestamp.to_rfc3339(),
            action: step.action.clone(),
            result: step.result.clone(),
            tool: step.tool.clone(),
            status: format!("{:?}", step.status).to_lowercase(),
            duration_ms: step.duration_ms,
        })
        .collect();

    // Build evidence entries
    let evidence: Vec<EvidenceEntry> = analysis
        .evidence
        .iter()
        .enumerate()
        .map(|(i, e)| EvidenceEntry {
            order: i + 1,
            source_type: format!("{}", e.source),
            source_name: extract_source_name(&e.source),
            data_type: format!("{}", e.data_type),
            finding: e.relevance.clone(),
            relevance: e.relevance.clone(),
            confidence: e.confidence,
            link: e.link.clone(),
            raw_value: e.value.clone(),
        })
        .collect();

    // Build evidence summary
    let evidence_summary = build_evidence_summary(&analysis.evidence);

    // Build MITRE techniques
    let mitre_techniques: Vec<MitreTechniqueEntry> = analysis
        .mitre_techniques
        .iter()
        .map(|t| {
            let technique_path = t.id.replace('.', "/");
            MitreTechniqueEntry {
                technique_id: t.id.clone(),
                name: t.name.clone(),
                tactic: t.tactic.clone(),
                relevance: format!("Confidence: {}%", (t.confidence * 100.0).round()),
                url: format!("https://attack.mitre.org/techniques/{}/", technique_path),
            }
        })
        .collect();

    // Build indicators
    let indicators: Vec<IndicatorEntry> = analysis
        .iocs
        .iter()
        .map(|ioc| IndicatorEntry {
            indicator_type: format!("{:?}", ioc.ioc_type).to_lowercase(),
            value: ioc.value.clone(),
            verdict: ioc
                .score
                .map(|s| {
                    if s >= 0.7 {
                        "malicious"
                    } else if s >= 0.4 {
                        "suspicious"
                    } else {
                        "benign"
                    }
                })
                .unwrap_or("unknown")
                .to_string(),
            context: ioc.context.clone(),
        })
        .collect();

    // Build recommended actions
    let recommended_actions: Vec<ActionEntry> = analysis
        .recommendations
        .iter()
        .enumerate()
        .map(|(i, rec)| ActionEntry {
            order: i + 1,
            action: rec.clone(),
            priority: if i == 0 {
                "immediate"
            } else if i < 3 {
                "high"
            } else {
                "medium"
            }
            .to_string(),
            reason: format!("Recommended based on {} verdict", verdict_display),
            requires_approval: i == 0, // First action requires approval
        })
        .collect();

    // Build audit log
    let audit_log: Vec<AuditLogEntry> = audit_entries
        .iter()
        .map(|entry| AuditLogEntry {
            timestamp: entry.timestamp.to_rfc3339(),
            action: format!("{:?}", entry.action),
            actor: entry.actor.clone(),
            details: entry.details.as_ref().map(|d| d.to_string()),
        })
        .collect();

    ReportData {
        metadata,
        executive_summary,
        verdict,
        alert,
        timeline,
        evidence,
        evidence_summary,
        mitre_techniques,
        indicators,
        recommended_actions,
        reasoning: analysis.reasoning.clone(),
        raw_alert_data: if include_raw_data {
            Some(incident.alert_data.clone())
        } else {
            None
        },
        enrichments: if include_raw_data {
            Some(
                incident
                    .enrichments
                    .iter()
                    .map(|e| serde_json::to_value(e).unwrap_or_default())
                    .collect(),
            )
        } else {
            None
        },
        audit_log,
    }
}

/// Format verdict for display.
fn format_verdict(verdict: &tw_core::incident::TriageVerdict) -> String {
    match verdict {
        tw_core::incident::TriageVerdict::TruePositive => "True Positive".to_string(),
        tw_core::incident::TriageVerdict::LikelyTruePositive => "Likely True Positive".to_string(),
        tw_core::incident::TriageVerdict::Suspicious => "Suspicious".to_string(),
        tw_core::incident::TriageVerdict::LikelyFalsePositive => {
            "Likely False Positive".to_string()
        }
        tw_core::incident::TriageVerdict::FalsePositive => "False Positive".to_string(),
        tw_core::incident::TriageVerdict::Inconclusive => "Inconclusive".to_string(),
    }
}

/// Extract source name from EvidenceSource.
fn extract_source_name(source: &tw_core::incident::EvidenceSource) -> String {
    match source {
        tw_core::incident::EvidenceSource::Siem { platform, .. } => platform.clone(),
        tw_core::incident::EvidenceSource::Edr { platform, .. } => platform.clone(),
        tw_core::incident::EvidenceSource::ThreatIntel { provider, .. } => provider.clone(),
        tw_core::incident::EvidenceSource::Email { gateway, .. } => gateway
            .clone()
            .unwrap_or_else(|| "Email Headers".to_string()),
        tw_core::incident::EvidenceSource::IdentityProvider { provider, .. } => provider.clone(),
        tw_core::incident::EvidenceSource::CloudSecurity { provider, .. } => provider.clone(),
        tw_core::incident::EvidenceSource::Enrichment { source, .. } => source.clone(),
        tw_core::incident::EvidenceSource::Manual { analyst_name, .. } => analyst_name
            .clone()
            .unwrap_or_else(|| "Analyst".to_string()),
        tw_core::incident::EvidenceSource::Custom { source_name, .. } => source_name.clone(),
    }
}

/// Build evidence summary statistics.
fn build_evidence_summary(evidence: &[tw_core::incident::Evidence]) -> EvidenceSummaryData {
    if evidence.is_empty() {
        return EvidenceSummaryData {
            total_evidence: 0,
            average_confidence: 0.0,
            high_confidence_count: 0,
            medium_confidence_count: 0,
            low_confidence_count: 0,
            sources_used: vec![],
            data_types_found: vec![],
        };
    }

    let total = evidence.len();
    let avg_confidence = evidence.iter().map(|e| e.confidence).sum::<f64>() / total as f64;
    let high = evidence.iter().filter(|e| e.confidence >= 0.8).count();
    let medium = evidence
        .iter()
        .filter(|e| e.confidence >= 0.5 && e.confidence < 0.8)
        .count();
    let low = evidence.iter().filter(|e| e.confidence < 0.5).count();

    let sources: Vec<String> = evidence
        .iter()
        .map(|e| extract_source_name(&e.source))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let data_types: Vec<String> = evidence
        .iter()
        .map(|e| format!("{}", e.data_type))
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    EvidenceSummaryData {
        total_evidence: total,
        average_confidence: (avg_confidence * 100.0).round() / 100.0,
        high_confidence_count: high,
        medium_confidence_count: medium,
        low_confidence_count: low,
        sources_used: sources,
        data_types_found: data_types,
    }
}

/// Generate HTML report content.
fn generate_html_report(report: &ReportData) -> Result<String, ApiError> {
    // Generate a basic HTML report inline
    // In production, this would use a templating engine like Tera
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Investigation Report - {incident_id}</title>
    <style>
        :root {{
            --primary-color: #1a365d;
            --secondary-color: #2c5282;
            --success-color: #22543d;
            --warning-color: #744210;
            --danger-color: #742a2a;
            --border-color: #e2e8f0;
            --light-bg: #f7fafc;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            font-size: 14px;
            line-height: 1.6;
            color: #2d3748;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        h1 {{ color: var(--primary-color); font-size: 24px; border-bottom: 3px solid var(--primary-color); padding-bottom: 10px; }}
        h2 {{ color: var(--secondary-color); font-size: 18px; margin-top: 25px; border-bottom: 2px solid var(--border-color); padding-bottom: 8px; }}
        .metadata {{ background: var(--light-bg); padding: 15px; border-radius: 6px; margin-bottom: 20px; }}
        .executive-summary {{ background: linear-gradient(135deg, #ebf4ff 0%, #f0fff4 100%); padding: 20px; border-radius: 8px; border-left: 4px solid var(--primary-color); margin: 20px 0; }}
        .verdict-card {{ display: flex; align-items: center; gap: 20px; padding: 20px; background: var(--light-bg); border-radius: 8px; margin: 15px 0; }}
        .verdict-badge {{ padding: 8px 16px; border-radius: 20px; font-weight: 600; }}
        .verdict-true_positive {{ background: #fed7d7; color: #742a2a; }}
        .verdict-false_positive {{ background: #c6f6d5; color: #22543d; }}
        .verdict-suspicious {{ background: #feebc8; color: #744210; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px 12px; text-align: left; border: 1px solid var(--border-color); }}
        th {{ background: var(--primary-color); color: white; }}
        tr:nth-child(even) {{ background: var(--light-bg); }}
        .mitre-card {{ background: var(--light-bg); padding: 15px; border-radius: 6px; margin-bottom: 10px; border-left: 3px solid #3182ce; }}
        .action-card {{ padding: 15px; background: var(--light-bg); border-radius: 6px; margin-bottom: 10px; }}
        .priority-immediate {{ background: #742a2a; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .priority-high {{ background: #c53030; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        .priority-medium {{ background: #dd6b20; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border-color); text-align: center; color: #718096; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>Investigation Report</h1>

    <div class="metadata">
        <strong>Incident ID:</strong> {incident_id}<br>
        <strong>Generated:</strong> {generated_at}<br>
        <strong>Alert Source:</strong> {alert_source}
    </div>

    <h2>Executive Summary</h2>
    <div class="executive-summary">
        {executive_summary}
    </div>

    <div class="verdict-card">
        <span class="verdict-badge verdict-{verdict_class}">{verdict_display}</span>
        <span><strong>Confidence:</strong> {confidence}%</span>
        <span><strong>Severity:</strong> {severity}</span>
        <span><strong>Risk Score:</strong> {risk_score}</span>
    </div>

    {timeline_section}

    {evidence_section}

    {mitre_section}

    {indicators_section}

    {actions_section}

    {reasoning_section}

    <footer>
        <p>Generated by {generated_by} | Report Version {report_version}</p>
        <p>Generated at {generated_at}</p>
    </footer>
</body>
</html>"#,
        incident_id = report.metadata.incident_id,
        generated_at = report.metadata.generated_at,
        generated_by = report.metadata.generated_by,
        report_version = report.metadata.report_version,
        alert_source = report.alert.source,
        executive_summary = report.executive_summary,
        verdict_class = report.verdict.verdict.replace('_', "-"),
        verdict_display = report.verdict.verdict_display,
        confidence = (report.verdict.confidence * 100.0).round(),
        severity = report.verdict.severity_display,
        risk_score = report.verdict.risk_score,
        timeline_section = generate_timeline_html(&report.timeline),
        evidence_section = generate_evidence_html(&report.evidence, &report.evidence_summary),
        mitre_section = generate_mitre_html(&report.mitre_techniques),
        indicators_section = generate_indicators_html(&report.indicators),
        actions_section = generate_actions_html(&report.recommended_actions),
        reasoning_section = generate_reasoning_html(&report.reasoning),
    );

    Ok(html)
}

fn generate_timeline_html(timeline: &[TimelineEntry]) -> String {
    if timeline.is_empty() {
        return String::new();
    }

    let rows: String = timeline
        .iter()
        .map(|entry| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                entry.order,
                entry.action,
                entry.result,
                entry.tool.as_deref().unwrap_or("-"),
                entry.status
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<h2>Investigation Timeline</h2>
        <table>
            <thead>
                <tr><th>#</th><th>Action</th><th>Result</th><th>Tool</th><th>Status</th></tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>"#,
        rows = rows
    )
}

fn generate_evidence_html(evidence: &[EvidenceEntry], summary: &EvidenceSummaryData) -> String {
    if evidence.is_empty() {
        return String::new();
    }

    let rows: String = evidence
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}%</td><td>{}</td></tr>",
                e.order,
                e.source_name,
                e.data_type,
                e.finding,
                (e.confidence * 100.0).round(),
                e.link
                    .as_ref()
                    .map(|l| format!("<a href=\"{}\" target=\"_blank\">View</a>", l))
                    .unwrap_or_else(|| "-".to_string())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<h2>Evidence ({total} items, avg confidence: {avg}%)</h2>
        <table>
            <thead>
                <tr><th>#</th><th>Source</th><th>Type</th><th>Finding</th><th>Confidence</th><th>Link</th></tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>"#,
        total = summary.total_evidence,
        avg = (summary.average_confidence * 100.0).round(),
        rows = rows
    )
}

fn generate_mitre_html(techniques: &[MitreTechniqueEntry]) -> String {
    if techniques.is_empty() {
        return String::new();
    }

    let cards: String = techniques
        .iter()
        .map(|t| {
            format!(
                r#"<div class="mitre-card">
                    <strong>{}</strong> - {} ({})
                    <br><small>{}</small>
                    <br><a href="{}" target="_blank">View on MITRE ATT&CK</a>
                </div>"#,
                t.technique_id, t.name, t.tactic, t.relevance, t.url
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!("<h2>MITRE ATT&CK Techniques</h2>\n{}", cards)
}

fn generate_indicators_html(indicators: &[IndicatorEntry]) -> String {
    if indicators.is_empty() {
        return String::new();
    }

    let rows: String = indicators
        .iter()
        .map(|i| {
            format!(
                "<tr><td>{}</td><td style=\"font-family: monospace;\">{}</td><td>{}</td><td>{}</td></tr>",
                i.indicator_type.to_uppercase(),
                i.value,
                i.verdict,
                i.context.as_deref().unwrap_or("-")
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"<h2>Indicators of Compromise</h2>
        <table>
            <thead>
                <tr><th>Type</th><th>Value</th><th>Verdict</th><th>Context</th></tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>"#,
        rows = rows
    )
}

fn generate_actions_html(actions: &[ActionEntry]) -> String {
    if actions.is_empty() {
        return String::new();
    }

    let cards: String = actions
        .iter()
        .map(|a| {
            format!(
                r#"<div class="action-card">
                    <span class="priority-{}">{}</span>
                    <strong>{}</strong>
                    <br><small>{}</small>
                </div>"#,
                a.priority,
                a.priority.to_uppercase(),
                a.action,
                a.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!("<h2>Recommended Actions</h2>\n{}", cards)
}

fn generate_reasoning_html(reasoning: &str) -> String {
    if reasoning.is_empty() {
        return String::new();
    }

    format!(
        r#"<h2>Detailed Analysis Reasoning</h2>
        <div style="background: #f7fafc; padding: 20px; border-radius: 6px; white-space: pre-wrap; font-family: monospace; font-size: 13px;">
            {}
        </div>"#,
        html_escape(reasoning)
    )
}

/// Simple HTML escaping for text content.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_verdict() {
        assert_eq!(
            format_verdict(&tw_core::incident::TriageVerdict::TruePositive),
            "True Positive"
        );
        assert_eq!(
            format_verdict(&tw_core::incident::TriageVerdict::FalsePositive),
            "False Positive"
        );
        assert_eq!(
            format_verdict(&tw_core::incident::TriageVerdict::Suspicious),
            "Suspicious"
        );
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("foo & bar"), "foo &amp; bar");
        assert_eq!(html_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_default_format() {
        assert_eq!(default_format(), "json");
    }

    #[test]
    fn test_default_true() {
        assert!(default_true());
    }
}
