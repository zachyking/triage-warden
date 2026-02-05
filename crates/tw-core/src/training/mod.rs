//! Training data models for ML model fine-tuning and improvement.
//!
//! This module provides data structures and utilities for exporting analyst feedback
//! and incident data as training examples for machine learning models.

mod exporter;

pub use exporter::{ExportError, ExportResultType, TrainingDataExporter};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::feedback::{AnalystFeedback, FeedbackType};
use crate::incident::{Incident, Severity, TriageVerdict};

/// A training example for model fine-tuning.
///
/// Contains the input prompt (incident data) and expected output (verdict/analysis),
/// along with metadata for tracking and filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    /// Unique identifier for this training example.
    pub id: Uuid,
    /// The incident context formatted as model input.
    pub input: String,
    /// The expected model output (verdict and reasoning).
    pub expected_output: ExpectedOutput,
    /// Metadata about this training example.
    pub metadata: TrainingMetadata,
    /// When this training example was created.
    pub created_at: DateTime<Utc>,
}

impl TrainingExample {
    /// Creates a new training example from an incident and feedback.
    pub fn from_incident_and_feedback(incident: &Incident, feedback: &AnalystFeedback) -> Self {
        let input = format_incident_as_prompt(incident);
        let expected_output = ExpectedOutput::from_feedback(feedback, incident);
        let metadata = TrainingMetadata::from_incident_and_feedback(incident, feedback);

        Self {
            id: Uuid::new_v4(),
            input,
            expected_output,
            metadata,
            created_at: Utc::now(),
        }
    }
}

/// The expected output for a training example.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedOutput {
    /// The correct verdict (from analyst feedback or original if correct).
    pub verdict: TriageVerdict,
    /// The correct severity.
    pub severity: Severity,
    /// Reasoning explanation (if available from analysis).
    pub reasoning: Option<String>,
    /// Correct MITRE ATT&CK technique IDs.
    pub mitre_techniques: Vec<String>,
    /// Recommendations (from original analysis if available).
    pub recommendations: Vec<String>,
}

impl ExpectedOutput {
    /// Creates expected output from feedback and incident data.
    pub fn from_feedback(feedback: &AnalystFeedback, incident: &Incident) -> Self {
        // Use corrected values if provided, otherwise use originals
        let verdict = feedback.effective_verdict().clone();
        let severity = feedback.effective_severity();

        // Get MITRE techniques from feedback (corrected) or incident analysis
        let mitre_techniques = feedback
            .corrected_mitre_techniques
            .clone()
            .or_else(|| {
                if feedback.original_mitre_techniques.is_empty() {
                    incident
                        .analysis
                        .as_ref()
                        .map(|a| a.mitre_techniques.iter().map(|t| t.id.clone()).collect())
                } else {
                    Some(feedback.original_mitre_techniques.clone())
                }
            })
            .unwrap_or_default();

        // Get recommendations from incident analysis if available
        let recommendations = incident
            .analysis
            .as_ref()
            .map(|a| a.recommendations.clone())
            .unwrap_or_default();

        // Get reasoning from analysis or feedback notes
        let reasoning = incident
            .analysis
            .as_ref()
            .map(|a| a.reasoning.clone())
            .or_else(|| feedback.notes.clone());

        Self {
            verdict,
            severity,
            reasoning,
            mitre_techniques,
            recommendations,
        }
    }
}

/// Metadata about a training example for tracking and filtering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    /// ID of the source incident.
    pub incident_id: Uuid,
    /// ID of the feedback that created this example.
    pub feedback_id: Uuid,
    /// ID of the analyst who provided feedback.
    pub analyst_id: Uuid,
    /// Tenant that owns this data.
    pub tenant_id: Uuid,
    /// Type of feedback (indicates what was corrected).
    pub feedback_type: FeedbackType,
    /// Original AI confidence score.
    pub original_confidence: f64,
    /// Whether this example is a correction (vs confirmation).
    pub is_correction: bool,
    /// Alert source type.
    pub alert_source: String,
    /// When the incident was created.
    pub incident_created_at: DateTime<Utc>,
    /// When the feedback was created.
    pub feedback_created_at: DateTime<Utc>,
    /// Quality score for this training example (0.0 - 1.0).
    /// Higher scores indicate more reliable training data.
    pub quality_score: f64,
}

impl TrainingMetadata {
    /// Creates metadata from incident and feedback.
    pub fn from_incident_and_feedback(incident: &Incident, feedback: &AnalystFeedback) -> Self {
        let quality_score = calculate_quality_score(feedback);

        Self {
            incident_id: incident.id,
            feedback_id: feedback.id,
            analyst_id: feedback.analyst_id,
            tenant_id: feedback.tenant_id,
            feedback_type: feedback.feedback_type,
            original_confidence: feedback.original_confidence,
            is_correction: feedback.is_correction(),
            alert_source: format!("{}", incident.source),
            incident_created_at: incident.created_at,
            feedback_created_at: feedback.created_at,
            quality_score,
        }
    }
}

/// Configuration for training data export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportConfig {
    /// Export format.
    pub format: ExportFormat,
    /// Whether to include only corrections (vs all feedback).
    pub corrections_only: bool,
    /// Minimum quality score threshold (0.0 - 1.0).
    pub min_quality_score: f64,
    /// Maximum number of examples to export.
    pub limit: Option<u32>,
    /// Export examples created after this timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Export examples created before this timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Filter by feedback type.
    pub feedback_types: Option<Vec<FeedbackType>>,
    /// Whether to mask PII in the exported data.
    pub mask_pii: bool,
    /// Whether to include full incident data (vs summary).
    pub include_full_incident: bool,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            format: ExportFormat::Jsonl,
            corrections_only: false,
            min_quality_score: 0.0,
            limit: None,
            since: None,
            until: None,
            feedback_types: None,
            mask_pii: true,
            include_full_incident: false,
        }
    }
}

/// Supported export formats for training data.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    /// JSON Lines format (one JSON object per line).
    #[default]
    Jsonl,
    /// Standard JSON array format.
    Json,
    /// CSV format with flattened fields.
    Csv,
}

impl ExportFormat {
    /// Returns the file extension for this format.
    pub fn extension(&self) -> &'static str {
        match self {
            ExportFormat::Jsonl => "jsonl",
            ExportFormat::Json => "json",
            ExportFormat::Csv => "csv",
        }
    }

    /// Returns the MIME type for this format.
    pub fn content_type(&self) -> &'static str {
        match self {
            ExportFormat::Jsonl => "application/jsonl",
            ExportFormat::Json => "application/json",
            ExportFormat::Csv => "text/csv",
        }
    }

    /// Parses an export format from a string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "jsonl" | "jsonlines" => Some(ExportFormat::Jsonl),
            "json" => Some(ExportFormat::Json),
            "csv" => Some(ExportFormat::Csv),
            _ => None,
        }
    }
}

/// Result of a training data export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportResult {
    /// Number of examples exported.
    pub count: u64,
    /// Export format used.
    pub format: ExportFormat,
    /// Whether PII was masked.
    pub pii_masked: bool,
    /// Timestamp when export started.
    pub started_at: DateTime<Utc>,
    /// Timestamp when export completed.
    pub completed_at: DateTime<Utc>,
    /// Export content (for API responses) or file path (for file exports).
    pub output: ExportOutput,
}

/// Output of an export operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExportOutput {
    /// Inline content (for smaller exports).
    Content { data: String },
    /// File path (for larger exports saved to disk).
    File { path: String },
}

/// Statistics about exported training data.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExportStats {
    /// Total number of training examples.
    pub total_examples: u64,
    /// Number of correction examples.
    pub corrections: u64,
    /// Number of confirmation examples.
    pub confirmations: u64,
    /// Breakdown by feedback type.
    pub by_feedback_type: std::collections::HashMap<String, u64>,
    /// Breakdown by verdict.
    pub by_verdict: std::collections::HashMap<String, u64>,
    /// Breakdown by severity.
    pub by_severity: std::collections::HashMap<String, u64>,
    /// Average quality score.
    pub avg_quality_score: f64,
    /// Date range of examples.
    pub date_range: Option<DateRange>,
}

/// A date range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateRange {
    pub from: DateTime<Utc>,
    pub to: DateTime<Utc>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Formats an incident as a prompt for model input.
///
/// This creates a structured text representation of the incident that can be
/// used as input to an LLM for triage analysis.
fn format_incident_as_prompt(incident: &Incident) -> String {
    let mut prompt = String::new();

    // Alert metadata
    prompt.push_str("=== SECURITY INCIDENT FOR TRIAGE ===\n\n");
    prompt.push_str(&format!("Source: {}\n", incident.source));
    prompt.push_str(&format!("Severity: {:?}\n", incident.severity));
    prompt.push_str(&format!("Created: {}\n", incident.created_at));

    // Tags
    if !incident.tags.is_empty() {
        prompt.push_str(&format!("Tags: {}\n", incident.tags.join(", ")));
    }

    // Alert data
    prompt.push_str("\n--- ALERT DATA ---\n");
    if let Ok(pretty_alert) = serde_json::to_string_pretty(&incident.alert_data) {
        prompt.push_str(&pretty_alert);
    } else {
        prompt.push_str(&incident.alert_data.to_string());
    }
    prompt.push('\n');

    // Enrichments
    if !incident.enrichments.is_empty() {
        prompt.push_str("\n--- ENRICHMENTS ---\n");
        for enrichment in &incident.enrichments {
            prompt.push_str(&format!(
                "\n[{:?}] from {}\n",
                enrichment.enrichment_type, enrichment.source
            ));
            if let Ok(pretty_data) = serde_json::to_string_pretty(&enrichment.data) {
                prompt.push_str(&pretty_data);
            } else {
                prompt.push_str(&enrichment.data.to_string());
            }
            prompt.push('\n');
        }
    }

    prompt.push_str("\n=== END INCIDENT DATA ===\n");

    prompt
}

/// Calculates a quality score for a training example.
///
/// Higher scores indicate more reliable training data based on:
/// - Feedback type (corrections are more valuable than confirmations)
/// - Presence of notes/reasoning
/// - Analyst confidence indicators
fn calculate_quality_score(feedback: &AnalystFeedback) -> f64 {
    let mut score: f64 = 0.5; // Base score

    // Corrections are more valuable for training
    if feedback.is_correction() {
        score += 0.2;
    }

    // Notes add context and reliability
    if feedback.notes.is_some() {
        score += 0.15;
    }

    // MITRE corrections show deep analysis
    if feedback.corrected_mitre_techniques.is_some() {
        score += 0.1;
    }

    // Low original confidence with correction is valuable
    if feedback.is_correction() && feedback.original_confidence < 0.7 {
        score += 0.05;
    }

    score.min(1.0)
}

/// Masks PII patterns in text.
///
/// This function identifies and masks common PII patterns like:
/// - Email addresses
/// - IP addresses
/// - Phone numbers
/// - SSN/ID numbers
pub fn mask_pii(text: &str) -> String {
    use regex::Regex;

    let mut result = text.to_string();

    // Email addresses
    if let Ok(re) = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}") {
        result = re.replace_all(&result, "[EMAIL_REDACTED]").to_string();
    }

    // IP addresses
    if let Ok(re) = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b") {
        result = re.replace_all(&result, "[IP_REDACTED]").to_string();
    }

    // Phone numbers (various formats)
    if let Ok(re) = Regex::new(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b") {
        result = re.replace_all(&result, "[PHONE_REDACTED]").to_string();
    }

    // SSN patterns
    if let Ok(re) = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b") {
        result = re.replace_all(&result, "[SSN_REDACTED]").to_string();
    }

    // Credit card numbers (basic pattern)
    if let Ok(re) = Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b") {
        result = re.replace_all(&result, "[CARD_REDACTED]").to_string();
    }

    result
}

/// Masks PII in a training example.
pub fn mask_training_example_pii(example: &mut TrainingExample) {
    example.input = mask_pii(&example.input);
    if let Some(ref mut reasoning) = example.expected_output.reasoning {
        *reasoning = mask_pii(reasoning);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{Alert, AlertSource, DEFAULT_TENANT_ID};

    fn create_test_incident() -> Incident {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Suspected phishing email".to_string(),
            description: Some("User reported suspicious email".to_string()),
            data: serde_json::json!({
                "subject": "Urgent: Update your password",
                "sender": "attacker@malicious.com",
                "recipient": "user@company.com"
            }),
            timestamp: Utc::now(),
            tags: vec!["phishing".to_string()],
        };
        Incident::from_alert(alert)
    }

    fn create_test_feedback(incident: &Incident) -> AnalystFeedback {
        AnalystFeedback::with_corrected_verdict(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::LikelyFalsePositive,
            TriageVerdict::TruePositive,
            Severity::High,
            0.65,
        )
        .with_notes("Confirmed phishing attempt after analysis".to_string())
    }

    #[test]
    fn test_training_example_creation() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(&incident);

        let example = TrainingExample::from_incident_and_feedback(&incident, &feedback);

        assert!(!example.id.is_nil());
        assert!(!example.input.is_empty());
        assert_eq!(example.expected_output.verdict, TriageVerdict::TruePositive);
        assert!(example.metadata.is_correction);
        assert_eq!(example.metadata.incident_id, incident.id);
        assert_eq!(example.metadata.feedback_id, feedback.id);
    }

    #[test]
    fn test_expected_output_uses_corrected_verdict() {
        let incident = create_test_incident();
        let feedback = AnalystFeedback::with_corrected_verdict(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::Medium,
            0.8,
        );

        let output = ExpectedOutput::from_feedback(&feedback, &incident);

        assert_eq!(output.verdict, TriageVerdict::TruePositive);
        assert_eq!(output.severity, Severity::Medium);
    }

    #[test]
    fn test_expected_output_uses_original_when_correct() {
        let incident = create_test_incident();
        let feedback = AnalystFeedback::correct(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::High,
            0.9,
        );

        let output = ExpectedOutput::from_feedback(&feedback, &incident);

        assert_eq!(output.verdict, TriageVerdict::TruePositive);
        assert_eq!(output.severity, Severity::High);
    }

    #[test]
    fn test_quality_score_calculation() {
        let incident = create_test_incident();

        // Correction with notes should have higher score
        let feedback_with_notes = AnalystFeedback::with_corrected_verdict(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::High,
            0.5,
        )
        .with_notes("Detailed analysis".to_string());

        let score_with_notes = calculate_quality_score(&feedback_with_notes);

        // Confirmation without notes should have lower score
        let feedback_no_notes = AnalystFeedback::correct(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::High,
            0.9,
        );

        let score_no_notes = calculate_quality_score(&feedback_no_notes);

        assert!(score_with_notes > score_no_notes);
        assert!(score_with_notes <= 1.0);
        assert!(score_no_notes >= 0.0);
    }

    #[test]
    fn test_export_format_extension() {
        assert_eq!(ExportFormat::Jsonl.extension(), "jsonl");
        assert_eq!(ExportFormat::Json.extension(), "json");
        assert_eq!(ExportFormat::Csv.extension(), "csv");
    }

    #[test]
    fn test_export_format_content_type() {
        assert_eq!(ExportFormat::Jsonl.content_type(), "application/jsonl");
        assert_eq!(ExportFormat::Json.content_type(), "application/json");
        assert_eq!(ExportFormat::Csv.content_type(), "text/csv");
    }

    #[test]
    fn test_export_format_from_str() {
        assert_eq!(ExportFormat::parse("jsonl"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("JSONLINES"), Some(ExportFormat::Jsonl));
        assert_eq!(ExportFormat::parse("json"), Some(ExportFormat::Json));
        assert_eq!(ExportFormat::parse("csv"), Some(ExportFormat::Csv));
        assert_eq!(ExportFormat::parse("invalid"), None);
    }

    #[test]
    fn test_mask_pii_email() {
        let text = "Contact user at john.doe@example.com for details";
        let masked = mask_pii(text);
        assert!(!masked.contains("john.doe@example.com"));
        assert!(masked.contains("[EMAIL_REDACTED]"));
    }

    #[test]
    fn test_mask_pii_ip() {
        let text = "Connection from 192.168.1.100 detected";
        let masked = mask_pii(text);
        assert!(!masked.contains("192.168.1.100"));
        assert!(masked.contains("[IP_REDACTED]"));
    }

    #[test]
    fn test_mask_pii_phone() {
        let text = "Call back at (555) 123-4567";
        let masked = mask_pii(text);
        assert!(!masked.contains("555"));
        assert!(masked.contains("[PHONE_REDACTED]"));
    }

    #[test]
    fn test_mask_pii_ssn() {
        let text = "SSN: 123-45-6789";
        let masked = mask_pii(text);
        assert!(!masked.contains("123-45-6789"));
        assert!(masked.contains("[SSN_REDACTED]"));
    }

    #[test]
    fn test_format_incident_as_prompt() {
        let incident = create_test_incident();
        let prompt = format_incident_as_prompt(&incident);

        assert!(prompt.contains("SECURITY INCIDENT FOR TRIAGE"));
        assert!(prompt.contains("Email:M365"));
        assert!(prompt.contains("ALERT DATA"));
        assert!(prompt.contains("phishing"));
    }

    #[test]
    fn test_export_config_default() {
        let config = ExportConfig::default();

        assert_eq!(config.format, ExportFormat::Jsonl);
        assert!(!config.corrections_only);
        assert_eq!(config.min_quality_score, 0.0);
        assert!(config.mask_pii);
        assert!(config.limit.is_none());
    }

    #[test]
    fn test_training_metadata_quality_score() {
        let incident = create_test_incident();

        // Correction with notes
        let feedback = AnalystFeedback::with_corrected_verdict(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::High,
            0.5,
        )
        .with_notes("Analysis notes".to_string());

        let metadata = TrainingMetadata::from_incident_and_feedback(&incident, &feedback);

        assert!(metadata.quality_score > 0.5);
        assert!(metadata.is_correction);
    }

    #[test]
    fn test_mask_training_example_pii() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(&incident);

        let mut example = TrainingExample::from_incident_and_feedback(&incident, &feedback);

        // Add some PII to the input
        example.input = "Alert from user@company.com at IP 10.0.0.1".to_string();
        example.expected_output.reasoning = Some("User john@test.com reported issue".to_string());

        mask_training_example_pii(&mut example);

        assert!(!example.input.contains("user@company.com"));
        assert!(!example.input.contains("10.0.0.1"));
        assert!(!example
            .expected_output
            .reasoning
            .as_ref()
            .unwrap()
            .contains("john@test.com"));
    }
}
