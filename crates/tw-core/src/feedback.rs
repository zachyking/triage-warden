//! Analyst feedback data models for Triage Warden.
//!
//! This module defines the data structures for collecting analyst feedback on
//! AI-generated verdicts and analyses. Feedback is used to improve the AI system
//! over time through continuous learning and calibration.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::incident::{Severity, TriageVerdict};

/// Represents feedback from an analyst on an AI-generated triage analysis.
///
/// Analysts can provide feedback to indicate whether the AI's verdict was correct,
/// and optionally provide corrections. This data is used for:
/// - Tracking AI accuracy metrics
/// - Training data for model fine-tuning
/// - Confidence calibration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalystFeedback {
    /// Unique identifier for this feedback entry.
    pub id: Uuid,
    /// The incident this feedback relates to.
    pub incident_id: Uuid,
    /// Tenant that owns this feedback (multi-tenancy support).
    pub tenant_id: Uuid,
    /// The analyst who provided the feedback.
    pub analyst_id: Uuid,
    /// The original verdict from the AI analysis.
    pub original_verdict: TriageVerdict,
    /// The corrected verdict, if the analyst disagreed.
    pub corrected_verdict: Option<TriageVerdict>,
    /// The original severity from the incident/AI analysis.
    pub original_severity: Severity,
    /// The corrected severity, if the analyst disagreed.
    pub corrected_severity: Option<Severity>,
    /// The original confidence score from the AI (0.0 - 1.0).
    pub original_confidence: f64,
    /// Type of feedback being provided.
    pub feedback_type: FeedbackType,
    /// Optional notes from the analyst explaining their feedback.
    pub notes: Option<String>,
    /// Original MITRE ATT&CK technique IDs from the AI analysis.
    pub original_mitre_techniques: Vec<String>,
    /// Corrected MITRE ATT&CK technique IDs, if applicable.
    pub corrected_mitre_techniques: Option<Vec<String>>,
    /// Timestamp when the feedback was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp of the last update (if edited).
    pub updated_at: DateTime<Utc>,
}

impl AnalystFeedback {
    /// Creates a new feedback entry indicating the AI verdict was correct.
    pub fn correct(
        incident_id: Uuid,
        tenant_id: Uuid,
        analyst_id: Uuid,
        original_verdict: TriageVerdict,
        original_severity: Severity,
        original_confidence: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            incident_id,
            tenant_id,
            analyst_id,
            original_verdict,
            corrected_verdict: None,
            original_severity,
            corrected_severity: None,
            original_confidence,
            feedback_type: FeedbackType::Correct,
            notes: None,
            original_mitre_techniques: Vec::new(),
            corrected_mitre_techniques: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a new feedback entry with a corrected verdict.
    pub fn with_corrected_verdict(
        incident_id: Uuid,
        tenant_id: Uuid,
        analyst_id: Uuid,
        original_verdict: TriageVerdict,
        corrected_verdict: TriageVerdict,
        original_severity: Severity,
        original_confidence: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            incident_id,
            tenant_id,
            analyst_id,
            original_verdict,
            corrected_verdict: Some(corrected_verdict),
            original_severity,
            corrected_severity: None,
            original_confidence,
            feedback_type: FeedbackType::IncorrectVerdict,
            notes: None,
            original_mitre_techniques: Vec::new(),
            corrected_mitre_techniques: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a new feedback entry with a corrected severity.
    pub fn with_corrected_severity(
        incident_id: Uuid,
        tenant_id: Uuid,
        analyst_id: Uuid,
        original_verdict: TriageVerdict,
        original_severity: Severity,
        corrected_severity: Severity,
        original_confidence: f64,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            incident_id,
            tenant_id,
            analyst_id,
            original_verdict,
            corrected_verdict: None,
            original_severity,
            corrected_severity: Some(corrected_severity),
            original_confidence,
            feedback_type: FeedbackType::IncorrectSeverity,
            notes: None,
            original_mitre_techniques: Vec::new(),
            corrected_mitre_techniques: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Returns true if this feedback indicates a correction was made.
    pub fn is_correction(&self) -> bool {
        matches!(
            self.feedback_type,
            FeedbackType::IncorrectVerdict
                | FeedbackType::IncorrectSeverity
                | FeedbackType::IncorrectMitre
        )
    }

    /// Returns true if the verdict was corrected.
    pub fn verdict_was_corrected(&self) -> bool {
        self.corrected_verdict.is_some()
    }

    /// Returns true if the severity was corrected.
    pub fn severity_was_corrected(&self) -> bool {
        self.corrected_severity.is_some()
    }

    /// Returns the effective verdict (corrected if available, otherwise original).
    pub fn effective_verdict(&self) -> &TriageVerdict {
        self.corrected_verdict
            .as_ref()
            .unwrap_or(&self.original_verdict)
    }

    /// Returns the effective severity (corrected if available, otherwise original).
    pub fn effective_severity(&self) -> Severity {
        self.corrected_severity.unwrap_or(self.original_severity)
    }

    /// Adds a note to the feedback.
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    /// Sets the original MITRE techniques.
    pub fn with_original_mitre(mut self, techniques: Vec<String>) -> Self {
        self.original_mitre_techniques = techniques;
        self
    }

    /// Sets corrected MITRE techniques.
    pub fn with_corrected_mitre(mut self, techniques: Vec<String>) -> Self {
        self.corrected_mitre_techniques = Some(techniques);
        if !matches!(self.feedback_type, FeedbackType::IncorrectMitre) {
            self.feedback_type = FeedbackType::IncorrectMitre;
        }
        self
    }
}

/// Type of feedback being provided by the analyst.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum FeedbackType {
    /// The AI verdict and analysis were correct.
    Correct,
    /// The AI verdict was incorrect (wrong true/false positive assessment).
    IncorrectVerdict,
    /// The AI severity assessment was incorrect.
    IncorrectSeverity,
    /// The AI was missing important context that would have changed the analysis.
    MissingContext,
    /// The MITRE ATT&CK mapping was incorrect.
    IncorrectMitre,
    /// Other type of issue not covered by specific categories.
    Other,
}

impl FeedbackType {
    /// Returns the database-compatible string representation (snake_case).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            FeedbackType::Correct => "correct",
            FeedbackType::IncorrectVerdict => "incorrect_verdict",
            FeedbackType::IncorrectSeverity => "incorrect_severity",
            FeedbackType::MissingContext => "missing_context",
            FeedbackType::IncorrectMitre => "incorrect_mitre",
            FeedbackType::Other => "other",
        }
    }

    /// Parses a FeedbackType from a database string.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "correct" => Some(FeedbackType::Correct),
            "incorrect_verdict" => Some(FeedbackType::IncorrectVerdict),
            "incorrect_severity" => Some(FeedbackType::IncorrectSeverity),
            "missing_context" => Some(FeedbackType::MissingContext),
            "incorrect_mitre" => Some(FeedbackType::IncorrectMitre),
            "other" => Some(FeedbackType::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for FeedbackType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeedbackType::Correct => write!(f, "Correct"),
            FeedbackType::IncorrectVerdict => write!(f, "Incorrect Verdict"),
            FeedbackType::IncorrectSeverity => write!(f, "Incorrect Severity"),
            FeedbackType::MissingContext => write!(f, "Missing Context"),
            FeedbackType::IncorrectMitre => write!(f, "Incorrect MITRE"),
            FeedbackType::Other => write!(f, "Other"),
        }
    }
}

/// Summary statistics for feedback data.
///
/// Used to track AI performance metrics over time.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedbackStats {
    /// Total number of feedback entries.
    pub total_feedback: u64,
    /// Number of entries where the AI was correct.
    pub correct_count: u64,
    /// Number of entries with incorrect verdict.
    pub incorrect_verdict_count: u64,
    /// Number of entries with incorrect severity.
    pub incorrect_severity_count: u64,
    /// Number of entries with missing context.
    pub missing_context_count: u64,
    /// Number of entries with incorrect MITRE mapping.
    pub incorrect_mitre_count: u64,
    /// Number of entries with other issues.
    pub other_count: u64,
    /// Overall accuracy rate (0.0 - 1.0).
    pub accuracy_rate: f64,
    /// Verdict-specific accuracy rate.
    pub verdict_accuracy_rate: f64,
    /// Severity-specific accuracy rate.
    pub severity_accuracy_rate: f64,
    /// Confidence calibration metrics (Stage 2.2.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calibration_metrics: Option<CalibrationStats>,
}

/// Confidence calibration statistics (Stage 2.2.4).
///
/// Tracks how well the AI's confidence scores correlate with actual accuracy.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CalibrationStats {
    /// Mean raw confidence across all feedback entries.
    pub mean_raw_confidence: f64,
    /// Mean accuracy (fraction correct) across all feedback entries.
    pub mean_accuracy: f64,
    /// Expected Calibration Error (lower is better).
    /// Measures how far off confidence predictions are from actual accuracy.
    pub expected_calibration_error: f64,
    /// Brier Score (lower is better).
    /// Mean squared error of probability predictions.
    pub brier_score: f64,
    /// Overconfidence rate: fraction of predictions where confidence > accuracy.
    pub overconfidence_rate: f64,
    /// Underconfidence rate: fraction of predictions where confidence < accuracy.
    pub underconfidence_rate: f64,
    /// Number of samples used for calibration calculation.
    pub sample_count: u64,
    /// Accuracy in each confidence bucket for reliability analysis.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub confidence_buckets: Vec<ConfidenceBucketStats>,
}

/// Statistics for a single confidence bucket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBucketStats {
    /// Lower bound of the bucket (inclusive).
    pub lower: f64,
    /// Upper bound of the bucket (exclusive).
    pub upper: f64,
    /// Mean confidence in this bucket.
    pub mean_confidence: f64,
    /// Actual accuracy (fraction correct) in this bucket.
    pub actual_accuracy: f64,
    /// Number of samples in this bucket.
    pub count: u64,
    /// Calibration gap: confidence - accuracy (positive = overconfident).
    pub calibration_gap: f64,
}

impl ConfidenceBucketStats {
    /// Creates a new bucket with the given bounds.
    pub fn new(lower: f64, upper: f64) -> Self {
        Self {
            lower,
            upper,
            mean_confidence: 0.0,
            actual_accuracy: 0.0,
            count: 0,
            calibration_gap: 0.0,
        }
    }

    /// Updates the bucket statistics with a sum of confidences and correct predictions.
    pub fn update(&mut self, confidence_sum: f64, correct_count: u64, total_count: u64) {
        self.count = total_count;
        if total_count > 0 {
            self.mean_confidence = confidence_sum / total_count as f64;
            self.actual_accuracy = correct_count as f64 / total_count as f64;
            self.calibration_gap = self.mean_confidence - self.actual_accuracy;
        }
    }
}

impl CalibrationStats {
    /// Creates calibration stats from feedback data.
    ///
    /// # Arguments
    ///
    /// * `confidences` - Raw confidence scores from the AI
    /// * `outcomes` - Whether each prediction was correct
    /// * `num_buckets` - Number of buckets for reliability analysis
    pub fn from_feedback(confidences: &[f64], outcomes: &[bool], num_buckets: usize) -> Self {
        let n = confidences.len();
        if n == 0 {
            return Self::default();
        }

        let correct_count = outcomes.iter().filter(|&&o| o).count();
        let mean_accuracy = correct_count as f64 / n as f64;
        let mean_confidence = confidences.iter().sum::<f64>() / n as f64;

        // Compute Brier score
        let brier_score: f64 = confidences
            .iter()
            .zip(outcomes.iter())
            .map(|(&conf, &outcome)| {
                let target = if outcome { 1.0 } else { 0.0 };
                (conf - target).powi(2)
            })
            .sum::<f64>()
            / n as f64;

        // Compute buckets and ECE
        let bucket_width = 1.0 / num_buckets as f64;
        let mut buckets: Vec<ConfidenceBucketStats> = (0..num_buckets)
            .map(|i| {
                ConfidenceBucketStats::new(i as f64 * bucket_width, (i + 1) as f64 * bucket_width)
            })
            .collect();

        let mut bucket_conf_sums = vec![0.0; num_buckets];
        let mut bucket_correct_counts = vec![0u64; num_buckets];
        let mut bucket_counts = vec![0u64; num_buckets];

        for (&conf, &outcome) in confidences.iter().zip(outcomes.iter()) {
            let bucket_idx = ((conf / bucket_width).floor() as usize).min(num_buckets - 1);
            bucket_conf_sums[bucket_idx] += conf;
            if outcome {
                bucket_correct_counts[bucket_idx] += 1;
            }
            bucket_counts[bucket_idx] += 1;
        }

        let mut ece = 0.0;
        let mut overconfident_count = 0usize;
        let mut underconfident_count = 0usize;

        for (i, bucket) in buckets.iter_mut().enumerate() {
            bucket.update(
                bucket_conf_sums[i],
                bucket_correct_counts[i],
                bucket_counts[i],
            );

            if bucket.count > 0 {
                // Weighted ECE contribution
                ece += (bucket.count as f64 / n as f64) * bucket.calibration_gap.abs();

                // Count over/under confidence
                if bucket.calibration_gap > 0.05 {
                    overconfident_count += bucket.count as usize;
                } else if bucket.calibration_gap < -0.05 {
                    underconfident_count += bucket.count as usize;
                }
            }
        }

        Self {
            mean_raw_confidence: mean_confidence,
            mean_accuracy,
            expected_calibration_error: ece,
            brier_score,
            overconfidence_rate: overconfident_count as f64 / n as f64,
            underconfidence_rate: underconfident_count as f64 / n as f64,
            sample_count: n as u64,
            confidence_buckets: buckets,
        }
    }

    /// Returns a qualitative assessment of calibration quality.
    pub fn quality(&self) -> CalibrationQuality {
        if self.expected_calibration_error < 0.05 {
            CalibrationQuality::Excellent
        } else if self.expected_calibration_error < 0.10 {
            CalibrationQuality::Good
        } else if self.expected_calibration_error < 0.15 {
            CalibrationQuality::Fair
        } else {
            CalibrationQuality::Poor
        }
    }
}

/// Qualitative assessment of calibration quality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationQuality {
    /// ECE < 0.05 - Very well calibrated
    Excellent,
    /// ECE < 0.10 - Well calibrated
    Good,
    /// ECE < 0.15 - Acceptable calibration
    Fair,
    /// ECE >= 0.15 - Needs improvement
    Poor,
}

impl std::fmt::Display for CalibrationQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalibrationQuality::Excellent => write!(f, "Excellent"),
            CalibrationQuality::Good => write!(f, "Good"),
            CalibrationQuality::Fair => write!(f, "Fair"),
            CalibrationQuality::Poor => write!(f, "Poor"),
        }
    }
}

impl FeedbackStats {
    /// Calculates the accuracy rate based on counts.
    pub fn calculate_accuracy(&mut self) {
        if self.total_feedback == 0 {
            self.accuracy_rate = 0.0;
            self.verdict_accuracy_rate = 0.0;
            self.severity_accuracy_rate = 0.0;
            return;
        }

        // Overall accuracy: percentage of correct verdicts
        self.accuracy_rate = self.correct_count as f64 / self.total_feedback as f64;

        // Verdict accuracy: percentage NOT marked as incorrect verdict
        let verdict_incorrect = self.incorrect_verdict_count;
        self.verdict_accuracy_rate =
            (self.total_feedback - verdict_incorrect) as f64 / self.total_feedback as f64;

        // Severity accuracy: percentage NOT marked as incorrect severity
        let severity_incorrect = self.incorrect_severity_count;
        self.severity_accuracy_rate =
            (self.total_feedback - severity_incorrect) as f64 / self.total_feedback as f64;
    }

    /// Adds calibration statistics to the feedback stats.
    pub fn with_calibration_stats(mut self, calibration: CalibrationStats) -> Self {
        self.calibration_metrics = Some(calibration);
        self
    }

    /// Returns the calibration quality if calibration metrics are available.
    pub fn calibration_quality(&self) -> Option<CalibrationQuality> {
        self.calibration_metrics.as_ref().map(|c| c.quality())
    }
}

/// Aggregate feedback statistics grouped by a dimension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackStatsByDimension {
    /// The dimension value (e.g., incident type, model name).
    pub dimension: String,
    /// Statistics for this dimension.
    pub stats: FeedbackStats,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::DEFAULT_TENANT_ID;

    #[test]
    fn test_feedback_correct() {
        let feedback = AnalystFeedback::correct(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::High,
            0.85,
        );

        assert_eq!(feedback.feedback_type, FeedbackType::Correct);
        assert!(feedback.corrected_verdict.is_none());
        assert!(feedback.corrected_severity.is_none());
        assert!(!feedback.is_correction());
    }

    #[test]
    fn test_feedback_with_corrected_verdict() {
        let feedback = AnalystFeedback::with_corrected_verdict(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::FalsePositive,
            TriageVerdict::TruePositive,
            Severity::Medium,
            0.75,
        );

        assert_eq!(feedback.feedback_type, FeedbackType::IncorrectVerdict);
        assert_eq!(
            feedback.corrected_verdict,
            Some(TriageVerdict::TruePositive)
        );
        assert!(feedback.is_correction());
        assert!(feedback.verdict_was_corrected());
        assert!(!feedback.severity_was_corrected());
        assert_eq!(*feedback.effective_verdict(), TriageVerdict::TruePositive);
    }

    #[test]
    fn test_feedback_with_corrected_severity() {
        let feedback = AnalystFeedback::with_corrected_severity(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::TruePositive,
            Severity::Low,
            Severity::Critical,
            0.90,
        );

        assert_eq!(feedback.feedback_type, FeedbackType::IncorrectSeverity);
        assert_eq!(feedback.corrected_severity, Some(Severity::Critical));
        assert!(feedback.is_correction());
        assert!(!feedback.verdict_was_corrected());
        assert!(feedback.severity_was_corrected());
        assert_eq!(feedback.effective_severity(), Severity::Critical);
    }

    #[test]
    fn test_feedback_builder_pattern() {
        let feedback = AnalystFeedback::correct(
            Uuid::new_v4(),
            DEFAULT_TENANT_ID,
            Uuid::new_v4(),
            TriageVerdict::Suspicious,
            Severity::Medium,
            0.65,
        )
        .with_notes("Good analysis, just confirming".to_string())
        .with_original_mitre(vec!["T1566.001".to_string(), "T1204".to_string()]);

        assert_eq!(
            feedback.notes,
            Some("Good analysis, just confirming".to_string())
        );
        assert_eq!(feedback.original_mitre_techniques.len(), 2);
    }

    #[test]
    fn test_feedback_type_db_roundtrip() {
        for feedback_type in [
            FeedbackType::Correct,
            FeedbackType::IncorrectVerdict,
            FeedbackType::IncorrectSeverity,
            FeedbackType::MissingContext,
            FeedbackType::IncorrectMitre,
            FeedbackType::Other,
        ] {
            let db_str = feedback_type.as_db_str();
            let parsed = FeedbackType::from_db_str(db_str);
            assert_eq!(parsed, Some(feedback_type));
        }
    }

    #[test]
    fn test_feedback_stats_calculation() {
        let mut stats = FeedbackStats {
            total_feedback: 100,
            correct_count: 80,
            incorrect_verdict_count: 10,
            incorrect_severity_count: 5,
            missing_context_count: 3,
            incorrect_mitre_count: 2,
            other_count: 0,
            ..Default::default()
        };

        stats.calculate_accuracy();

        assert!((stats.accuracy_rate - 0.80).abs() < 0.001);
        assert!((stats.verdict_accuracy_rate - 0.90).abs() < 0.001);
        assert!((stats.severity_accuracy_rate - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_feedback_stats_empty() {
        let mut stats = FeedbackStats::default();
        stats.calculate_accuracy();

        assert_eq!(stats.accuracy_rate, 0.0);
        assert_eq!(stats.verdict_accuracy_rate, 0.0);
        assert_eq!(stats.severity_accuracy_rate, 0.0);
    }
}
