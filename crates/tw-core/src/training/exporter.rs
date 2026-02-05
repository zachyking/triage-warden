//! Training data export service.
//!
//! This module provides the `TrainingDataExporter` service that combines feedback
//! and incident data to generate training examples for model fine-tuning.

use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

use super::{
    mask_training_example_pii, DateRange, ExportConfig, ExportFormat, ExportOutput, ExportResult,
    ExportStats, TrainingExample,
};
use crate::feedback::AnalystFeedback;
use crate::incident::Incident;

/// Error type for training data export operations.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// Database error during export.
    #[error("Database error: {0}")]
    Database(String),

    /// Serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// CSV serialization error.
    #[error("CSV error: {0}")]
    Csv(String),

    /// IO error during export.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// No data to export.
    #[error("No training data found matching the criteria")]
    NoData,
}

/// Result type for export operations.
pub type ExportResultType<T> = Result<T, ExportError>;

/// Service for exporting training data from feedback and incidents.
///
/// This service provides methods to:
/// - Generate training examples from feedback + incident pairs
/// - Export data in multiple formats (JSON, JSONL, CSV)
/// - Calculate export statistics
/// - Apply PII masking
pub struct TrainingDataExporter {
    /// Configuration for the export.
    config: ExportConfig,
}

impl TrainingDataExporter {
    /// Creates a new exporter with the given configuration.
    pub fn new(config: ExportConfig) -> Self {
        Self { config }
    }

    /// Creates a new exporter with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(ExportConfig::default())
    }

    /// Updates the export configuration.
    pub fn with_config(mut self, config: ExportConfig) -> Self {
        self.config = config;
        self
    }

    /// Generates training examples from feedback and incident pairs.
    ///
    /// Each feedback entry is paired with its corresponding incident to create
    /// a training example. The resulting examples are filtered based on the
    /// export configuration (quality score, feedback types, etc.).
    pub fn generate_examples(
        &self,
        feedback_list: &[AnalystFeedback],
        incidents: &HashMap<Uuid, Incident>,
    ) -> Vec<TrainingExample> {
        let mut examples: Vec<TrainingExample> = feedback_list
            .iter()
            .filter_map(|feedback| {
                // Get the corresponding incident
                let incident = incidents.get(&feedback.incident_id)?;

                // Create the training example
                let mut example = TrainingExample::from_incident_and_feedback(incident, feedback);

                // Apply quality score filter
                if example.metadata.quality_score < self.config.min_quality_score {
                    return None;
                }

                // Apply corrections-only filter
                if self.config.corrections_only && !example.metadata.is_correction {
                    return None;
                }

                // Apply feedback type filter
                if let Some(ref types) = self.config.feedback_types {
                    if !types.contains(&example.metadata.feedback_type) {
                        return None;
                    }
                }

                // Apply date range filters
                if let Some(since) = self.config.since {
                    if example.metadata.feedback_created_at < since {
                        return None;
                    }
                }
                if let Some(until) = self.config.until {
                    if example.metadata.feedback_created_at > until {
                        return None;
                    }
                }

                // Apply PII masking if configured
                if self.config.mask_pii {
                    mask_training_example_pii(&mut example);
                }

                Some(example)
            })
            .collect();

        // Apply limit if configured
        if let Some(limit) = self.config.limit {
            examples.truncate(limit as usize);
        }

        examples
    }

    /// Exports training examples to the configured format.
    pub fn export(&self, examples: &[TrainingExample]) -> ExportResultType<ExportResult> {
        if examples.is_empty() {
            return Err(ExportError::NoData);
        }

        let started_at = Utc::now();
        let data = self.format_examples(examples)?;
        let completed_at = Utc::now();

        Ok(ExportResult {
            count: examples.len() as u64,
            format: self.config.format,
            pii_masked: self.config.mask_pii,
            started_at,
            completed_at,
            output: ExportOutput::Content { data },
        })
    }

    /// Formats examples according to the configured format.
    fn format_examples(&self, examples: &[TrainingExample]) -> ExportResultType<String> {
        match self.config.format {
            ExportFormat::Jsonl => self.format_jsonl(examples),
            ExportFormat::Json => self.format_json(examples),
            ExportFormat::Csv => self.format_csv(examples),
        }
    }

    /// Formats examples as JSON Lines (one JSON object per line).
    fn format_jsonl(&self, examples: &[TrainingExample]) -> ExportResultType<String> {
        let lines: Result<Vec<String>, _> = examples.iter().map(serde_json::to_string).collect();
        Ok(lines?.join("\n"))
    }

    /// Formats examples as a JSON array.
    fn format_json(&self, examples: &[TrainingExample]) -> ExportResultType<String> {
        Ok(serde_json::to_string_pretty(examples)?)
    }

    /// Formats examples as CSV.
    fn format_csv(&self, examples: &[TrainingExample]) -> ExportResultType<String> {
        let mut csv = String::new();

        // Header
        csv.push_str("id,incident_id,feedback_id,analyst_id,verdict,severity,is_correction,quality_score,feedback_type,input,reasoning\n");

        // Rows
        for example in examples {
            let reasoning = example
                .expected_output
                .reasoning
                .as_ref()
                .map(|r| escape_csv_field(r))
                .unwrap_or_default();

            let row = format!(
                "{},{},{},{},{:?},{:?},{},{},{:?},{},{}\n",
                example.id,
                example.metadata.incident_id,
                example.metadata.feedback_id,
                example.metadata.analyst_id,
                example.expected_output.verdict,
                example.expected_output.severity,
                example.metadata.is_correction,
                example.metadata.quality_score,
                example.metadata.feedback_type,
                escape_csv_field(&example.input),
                reasoning,
            );
            csv.push_str(&row);
        }

        Ok(csv)
    }

    /// Calculates statistics for a set of training examples.
    pub fn calculate_stats(&self, examples: &[TrainingExample]) -> ExportStats {
        let mut stats = ExportStats {
            total_examples: examples.len() as u64,
            corrections: 0,
            confirmations: 0,
            by_feedback_type: HashMap::new(),
            by_verdict: HashMap::new(),
            by_severity: HashMap::new(),
            avg_quality_score: 0.0,
            date_range: None,
        };

        if examples.is_empty() {
            return stats;
        }

        let mut total_quality = 0.0;
        let mut min_date = examples[0].metadata.feedback_created_at;
        let mut max_date = examples[0].metadata.feedback_created_at;

        for example in examples {
            // Count corrections vs confirmations
            if example.metadata.is_correction {
                stats.corrections += 1;
            } else {
                stats.confirmations += 1;
            }

            // By feedback type
            let feedback_type_key = format!("{:?}", example.metadata.feedback_type);
            *stats.by_feedback_type.entry(feedback_type_key).or_insert(0) += 1;

            // By verdict
            let verdict_key = format!("{:?}", example.expected_output.verdict);
            *stats.by_verdict.entry(verdict_key).or_insert(0) += 1;

            // By severity
            let severity_key = format!("{:?}", example.expected_output.severity);
            *stats.by_severity.entry(severity_key).or_insert(0) += 1;

            // Quality score
            total_quality += example.metadata.quality_score;

            // Date range
            if example.metadata.feedback_created_at < min_date {
                min_date = example.metadata.feedback_created_at;
            }
            if example.metadata.feedback_created_at > max_date {
                max_date = example.metadata.feedback_created_at;
            }
        }

        stats.avg_quality_score = total_quality / examples.len() as f64;
        stats.date_range = Some(DateRange {
            from: min_date,
            to: max_date,
        });

        stats
    }
}

/// Escapes a string for CSV format.
fn escape_csv_field(field: &str) -> String {
    // If the field contains special characters, quote it
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feedback::FeedbackType;
    use crate::incident::{Alert, AlertSource, Severity, TriageVerdict, DEFAULT_TENANT_ID};

    fn create_test_incident() -> Incident {
        let alert = Alert {
            id: "test-alert".to_string(),
            source: AlertSource::EmailSecurity("M365".to_string()),
            alert_type: "phishing".to_string(),
            severity: Severity::High,
            title: "Suspected phishing".to_string(),
            description: None,
            data: serde_json::json!({"subject": "Test"}),
            timestamp: Utc::now(),
            tags: vec![],
        };
        Incident::from_alert(alert)
    }

    fn create_test_feedback(incident_id: Uuid, is_correction: bool) -> AnalystFeedback {
        if is_correction {
            AnalystFeedback::with_corrected_verdict(
                incident_id,
                DEFAULT_TENANT_ID,
                Uuid::new_v4(),
                TriageVerdict::FalsePositive,
                TriageVerdict::TruePositive,
                Severity::High,
                0.6,
            )
        } else {
            AnalystFeedback::correct(
                incident_id,
                DEFAULT_TENANT_ID,
                Uuid::new_v4(),
                TriageVerdict::TruePositive,
                Severity::High,
                0.9,
            )
        }
    }

    #[test]
    fn test_generate_examples_basic() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(incident.id, true);

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        let exporter = TrainingDataExporter::with_defaults();
        let examples = exporter.generate_examples(&[feedback], &incidents);

        assert_eq!(examples.len(), 1);
        assert!(examples[0].metadata.is_correction);
    }

    #[test]
    fn test_generate_examples_corrections_only() {
        let incident1 = create_test_incident();
        let incident2 = create_test_incident();

        let feedback1 = create_test_feedback(incident1.id, true); // correction
        let feedback2 = create_test_feedback(incident2.id, false); // confirmation

        let mut incidents = HashMap::new();
        incidents.insert(incident1.id, incident1);
        incidents.insert(incident2.id, incident2);

        let config = ExportConfig {
            corrections_only: true,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback1, feedback2], &incidents);

        assert_eq!(examples.len(), 1);
        assert!(examples[0].metadata.is_correction);
    }

    #[test]
    fn test_generate_examples_quality_filter() {
        let incident = create_test_incident();
        let feedback = AnalystFeedback::correct(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::High,
            0.9,
        );

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        // High quality threshold should filter out basic confirmations
        let config = ExportConfig {
            min_quality_score: 0.9,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);

        // Basic confirmation without notes has quality ~0.5
        assert!(examples.is_empty());
    }

    #[test]
    fn test_generate_examples_limit() {
        let mut incidents = HashMap::new();
        let mut feedback_list = Vec::new();

        for _ in 0..10 {
            let incident = create_test_incident();
            let feedback = create_test_feedback(incident.id, true);
            feedback_list.push(feedback);
            incidents.insert(incident.id, incident);
        }

        let config = ExportConfig {
            limit: Some(5),
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&feedback_list, &incidents);

        assert_eq!(examples.len(), 5);
    }

    #[test]
    fn test_export_jsonl() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(incident.id, true);

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        let config = ExportConfig {
            format: ExportFormat::Jsonl,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);
        let result = exporter.export(&examples).unwrap();

        assert_eq!(result.format, ExportFormat::Jsonl);
        assert_eq!(result.count, 1);

        if let ExportOutput::Content { data } = result.output {
            // JSONL should be valid JSON per line
            let parsed: TrainingExample = serde_json::from_str(&data).unwrap();
            assert!(!parsed.id.is_nil());
        } else {
            panic!("Expected Content output");
        }
    }

    #[test]
    fn test_export_json() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(incident.id, true);

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        let config = ExportConfig {
            format: ExportFormat::Json,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);
        let result = exporter.export(&examples).unwrap();

        assert_eq!(result.format, ExportFormat::Json);

        if let ExportOutput::Content { data } = result.output {
            let parsed: Vec<TrainingExample> = serde_json::from_str(&data).unwrap();
            assert_eq!(parsed.len(), 1);
        } else {
            panic!("Expected Content output");
        }
    }

    #[test]
    fn test_export_csv() {
        let incident = create_test_incident();
        let feedback = create_test_feedback(incident.id, true);

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        let config = ExportConfig {
            format: ExportFormat::Csv,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);
        let result = exporter.export(&examples).unwrap();

        assert_eq!(result.format, ExportFormat::Csv);

        if let ExportOutput::Content { data } = result.output {
            assert!(data.contains("id,incident_id,feedback_id"));
            assert!(data.contains("TruePositive"));
        } else {
            panic!("Expected Content output");
        }
    }

    #[test]
    fn test_export_no_data() {
        let exporter = TrainingDataExporter::with_defaults();
        let result = exporter.export(&[]);

        assert!(matches!(result, Err(ExportError::NoData)));
    }

    #[test]
    fn test_calculate_stats() {
        let mut incidents = HashMap::new();
        let mut feedback_list = Vec::new();

        // Create mix of corrections and confirmations
        for i in 0..5 {
            let incident = create_test_incident();
            let feedback = create_test_feedback(incident.id, i % 2 == 0);
            feedback_list.push(feedback);
            incidents.insert(incident.id, incident);
        }

        let exporter = TrainingDataExporter::with_defaults();
        let examples = exporter.generate_examples(&feedback_list, &incidents);
        let stats = exporter.calculate_stats(&examples);

        assert_eq!(stats.total_examples, 5);
        assert_eq!(stats.corrections, 3); // i=0,2,4
        assert_eq!(stats.confirmations, 2); // i=1,3
        assert!(stats.avg_quality_score > 0.0);
        assert!(stats.date_range.is_some());
    }

    #[test]
    fn test_calculate_stats_empty() {
        let exporter = TrainingDataExporter::with_defaults();
        let stats = exporter.calculate_stats(&[]);

        assert_eq!(stats.total_examples, 0);
        assert_eq!(stats.corrections, 0);
        assert_eq!(stats.confirmations, 0);
        assert_eq!(stats.avg_quality_score, 0.0);
        assert!(stats.date_range.is_none());
    }

    #[test]
    fn test_escape_csv_field() {
        assert_eq!(escape_csv_field("simple"), "simple");
        assert_eq!(escape_csv_field("with,comma"), "\"with,comma\"");
        assert_eq!(escape_csv_field("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(escape_csv_field("with\nnewline"), "\"with\nnewline\"");
    }

    #[test]
    fn test_pii_masking_in_export() {
        let mut incident = create_test_incident();
        incident.alert_data = serde_json::json!({
            "sender": "attacker@malicious.com",
            "recipient_ip": "192.168.1.100"
        });

        let feedback = create_test_feedback(incident.id, true);

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        let config = ExportConfig {
            mask_pii: true,
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);

        assert_eq!(examples.len(), 1);
        // PII should be masked in the input
        assert!(!examples[0].input.contains("attacker@malicious.com"));
        assert!(!examples[0].input.contains("192.168.1.100"));
    }

    #[test]
    fn test_feedback_type_filter() {
        let incident = create_test_incident();
        let feedback = AnalystFeedback::with_corrected_verdict(
            incident.id,
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::High,
            0.5,
        );

        let mut incidents = HashMap::new();
        incidents.insert(incident.id, incident);

        // Filter for only IncorrectSeverity (should exclude IncorrectVerdict)
        let config = ExportConfig {
            feedback_types: Some(vec![FeedbackType::IncorrectSeverity]),
            ..Default::default()
        };
        let exporter = TrainingDataExporter::new(config);
        let examples = exporter.generate_examples(&[feedback], &incidents);

        assert!(examples.is_empty());
    }
}
