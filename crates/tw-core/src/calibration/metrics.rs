//! Calibration quality metrics.
//!
//! This module provides metrics for evaluating calibration quality,
//! including Expected Calibration Error (ECE), Maximum Calibration Error (MCE),
//! and Brier Score.

use serde::{Deserialize, Serialize};

/// Default number of bins for ECE/MCE computation.
const DEFAULT_NUM_BINS: usize = 10;

/// A single bucket in a reliability diagram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceBucket {
    /// Lower bound of the bucket (inclusive).
    pub lower: f64,
    /// Upper bound of the bucket (exclusive, except for last bucket).
    pub upper: f64,
    /// Mean predicted confidence in this bucket.
    pub mean_confidence: f64,
    /// Mean accuracy (fraction correct) in this bucket.
    pub mean_accuracy: f64,
    /// Number of samples in this bucket.
    pub count: usize,
    /// Calibration error for this bucket (|confidence - accuracy|).
    pub calibration_error: f64,
}

impl ConfidenceBucket {
    /// Creates a new empty bucket.
    pub fn new(lower: f64, upper: f64) -> Self {
        Self {
            lower,
            upper,
            mean_confidence: 0.0,
            mean_accuracy: 0.0,
            count: 0,
            calibration_error: 0.0,
        }
    }

    /// Returns the midpoint of this bucket.
    pub fn midpoint(&self) -> f64 {
        (self.lower + self.upper) / 2.0
    }

    /// Returns true if this bucket is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// A point on the reliability diagram.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReliabilityDiagramPoint {
    /// The mean predicted confidence for this point.
    pub mean_confidence: f64,
    /// The observed accuracy for this confidence level.
    pub accuracy: f64,
    /// Number of samples.
    pub count: usize,
}

/// Comprehensive calibration metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationMetrics {
    /// Expected Calibration Error (weighted average of per-bucket errors).
    pub expected_calibration_error: f64,
    /// Maximum Calibration Error (worst-case per-bucket error).
    pub max_calibration_error: f64,
    /// Brier Score (mean squared error of probability predictions).
    pub brier_score: f64,
    /// Brier Score before calibration (for comparison).
    pub brier_score_before: f64,
    /// Overall accuracy of predictions.
    pub accuracy: f64,
    /// Total number of samples.
    pub sample_count: usize,
    /// Confidence buckets for detailed analysis.
    pub buckets: Vec<ConfidenceBucket>,
    /// Reliability diagram points.
    pub reliability_diagram: Vec<ReliabilityDiagramPoint>,
    /// Calibration improvement (before - after).
    pub ece_improvement: f64,
}

impl CalibrationMetrics {
    /// Computes all calibration metrics.
    ///
    /// # Arguments
    ///
    /// * `calibrated_confidences` - Confidence scores after calibration
    /// * `raw_confidences` - Original confidence scores (for comparison)
    /// * `outcomes` - Ground truth (true if prediction was correct)
    pub fn compute(
        calibrated_confidences: &[f64],
        raw_confidences: &[f64],
        outcomes: &[bool],
    ) -> Self {
        let n = calibrated_confidences.len();
        assert_eq!(n, raw_confidences.len());
        assert_eq!(n, outcomes.len());

        if n == 0 {
            return Self::empty();
        }

        // Compute Brier scores
        let brier_after = compute_brier_score(calibrated_confidences, outcomes);
        let brier_before = compute_brier_score(raw_confidences, outcomes);

        // Compute ECE and buckets for calibrated confidences
        let (ece, mce, buckets) =
            compute_ece_and_buckets(calibrated_confidences, outcomes, DEFAULT_NUM_BINS);

        // Compute ECE for raw confidences (for comparison)
        let (ece_before, _, _) =
            compute_ece_and_buckets(raw_confidences, outcomes, DEFAULT_NUM_BINS);

        // Compute accuracy
        let correct = outcomes.iter().filter(|&&o| o).count();
        let accuracy = correct as f64 / n as f64;

        // Build reliability diagram
        let reliability_diagram: Vec<ReliabilityDiagramPoint> = buckets
            .iter()
            .filter(|b| !b.is_empty())
            .map(|b| ReliabilityDiagramPoint {
                mean_confidence: b.mean_confidence,
                accuracy: b.mean_accuracy,
                count: b.count,
            })
            .collect();

        Self {
            expected_calibration_error: ece,
            max_calibration_error: mce,
            brier_score: brier_after,
            brier_score_before: brier_before,
            accuracy,
            sample_count: n,
            buckets,
            reliability_diagram,
            ece_improvement: ece_before - ece,
        }
    }

    /// Creates empty metrics (for when there's no data).
    pub fn empty() -> Self {
        Self {
            expected_calibration_error: 0.0,
            max_calibration_error: 0.0,
            brier_score: 0.0,
            brier_score_before: 0.0,
            accuracy: 0.0,
            sample_count: 0,
            buckets: Vec::new(),
            reliability_diagram: Vec::new(),
            ece_improvement: 0.0,
        }
    }

    /// Returns true if the calibration improved after calibration.
    pub fn improved(&self) -> bool {
        self.ece_improvement > 0.0
    }

    /// Returns a summary string.
    pub fn summary(&self) -> String {
        format!(
            "ECE: {:.4}, MCE: {:.4}, Brier: {:.4} (was {:.4}), Accuracy: {:.2}%, Samples: {}",
            self.expected_calibration_error,
            self.max_calibration_error,
            self.brier_score,
            self.brier_score_before,
            self.accuracy * 100.0,
            self.sample_count
        )
    }

    /// Returns a quality assessment based on ECE.
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
pub enum CalibrationQuality {
    /// ECE < 0.05
    Excellent,
    /// ECE < 0.10
    Good,
    /// ECE < 0.15
    Fair,
    /// ECE >= 0.15
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

/// Computes the Brier Score.
///
/// Brier Score measures the mean squared error of probability predictions.
/// Lower is better. Range: [0, 1].
///
/// # Formula
///
/// BS = (1/n) * Σ (confidence_i - outcome_i)²
pub fn compute_brier_score(confidences: &[f64], outcomes: &[bool]) -> f64 {
    if confidences.is_empty() {
        return 0.0;
    }

    let n = confidences.len() as f64;
    let sum: f64 = confidences
        .iter()
        .zip(outcomes.iter())
        .map(|(&conf, &outcome)| {
            let target = if outcome { 1.0 } else { 0.0 };
            (conf - target).powi(2)
        })
        .sum();

    sum / n
}

/// Computes Expected Calibration Error (ECE).
///
/// ECE is the weighted average of the absolute difference between
/// confidence and accuracy across bins.
///
/// # Formula
///
/// ECE = Σ (n_b / n) * |accuracy(b) - confidence(b)|
pub fn compute_ece(confidences: &[f64], outcomes: &[bool], num_bins: usize) -> f64 {
    compute_ece_and_buckets(confidences, outcomes, num_bins).0
}

/// Computes Maximum Calibration Error (MCE).
///
/// MCE is the maximum absolute difference between confidence and accuracy
/// across all bins. This captures the worst-case calibration error.
pub fn compute_mce(confidences: &[f64], outcomes: &[bool], num_bins: usize) -> f64 {
    compute_ece_and_buckets(confidences, outcomes, num_bins).1
}

/// Internal function that computes ECE, MCE, and buckets together.
fn compute_ece_and_buckets(
    confidences: &[f64],
    outcomes: &[bool],
    num_bins: usize,
) -> (f64, f64, Vec<ConfidenceBucket>) {
    let n = confidences.len();
    if n == 0 || num_bins == 0 {
        return (0.0, 0.0, Vec::new());
    }

    let bin_width = 1.0 / num_bins as f64;

    // Initialize buckets
    let mut buckets: Vec<ConfidenceBucket> = (0..num_bins)
        .map(|i| {
            let lower = i as f64 * bin_width;
            let upper = (i + 1) as f64 * bin_width;
            ConfidenceBucket::new(lower, upper)
        })
        .collect();

    // Accumulate sums for each bucket
    let mut bucket_conf_sums: Vec<f64> = vec![0.0; num_bins];
    let mut bucket_correct_sums: Vec<f64> = vec![0.0; num_bins];
    let mut bucket_counts: Vec<usize> = vec![0; num_bins];

    for (&conf, &outcome) in confidences.iter().zip(outcomes.iter()) {
        let bin_idx = ((conf / bin_width).floor() as usize).min(num_bins - 1);
        bucket_conf_sums[bin_idx] += conf;
        bucket_correct_sums[bin_idx] += if outcome { 1.0 } else { 0.0 };
        bucket_counts[bin_idx] += 1;
    }

    // Compute bucket statistics
    let mut ece = 0.0;
    let mut mce: f64 = 0.0;

    for (i, bucket) in buckets.iter_mut().enumerate() {
        bucket.count = bucket_counts[i];

        if bucket.count > 0 {
            bucket.mean_confidence = bucket_conf_sums[i] / bucket.count as f64;
            bucket.mean_accuracy = bucket_correct_sums[i] / bucket.count as f64;
            bucket.calibration_error = (bucket.mean_confidence - bucket.mean_accuracy).abs();

            // Weighted contribution to ECE
            let weight = bucket.count as f64 / n as f64;
            ece += weight * bucket.calibration_error;

            // Update MCE
            mce = mce.max(bucket.calibration_error);
        }
    }

    (ece, mce, buckets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_brier_score_perfect() {
        // Perfect predictions
        let confidences = vec![1.0, 1.0, 0.0, 0.0];
        let outcomes = vec![true, true, false, false];

        let brier = compute_brier_score(&confidences, &outcomes);
        assert!(
            (brier - 0.0).abs() < 1e-9,
            "Perfect predictions should have Brier = 0"
        );
    }

    #[test]
    fn test_brier_score_worst() {
        // Worst possible predictions
        let confidences = vec![1.0, 1.0, 0.0, 0.0];
        let outcomes = vec![false, false, true, true];

        let brier = compute_brier_score(&confidences, &outcomes);
        assert!(
            (brier - 1.0).abs() < 1e-9,
            "Worst predictions should have Brier = 1"
        );
    }

    #[test]
    fn test_brier_score_uncertain() {
        // Always predict 0.5
        let confidences = vec![0.5, 0.5, 0.5, 0.5];
        let outcomes = vec![true, true, false, false];

        let brier = compute_brier_score(&confidences, &outcomes);
        // (0.5-1)^2 + (0.5-1)^2 + (0.5-0)^2 + (0.5-0)^2 / 4 = 0.25
        assert!(
            (brier - 0.25).abs() < 1e-9,
            "50% predictions should have Brier = 0.25"
        );
    }

    #[test]
    fn test_ece_perfect_calibration() {
        // Perfectly calibrated: 50% confidence, 50% accuracy
        let confidences = vec![0.5, 0.5, 0.5, 0.5];
        let outcomes = vec![true, true, false, false];

        let ece = compute_ece(&confidences, &outcomes, 10);
        assert!(
            ece < 0.01,
            "Perfect calibration should have very low ECE: {}",
            ece
        );
    }

    #[test]
    fn test_ece_overconfident() {
        // Overconfident: 90% confidence but only 50% accuracy
        let confidences = vec![0.9, 0.9, 0.9, 0.9];
        let outcomes = vec![true, true, false, false];

        let ece = compute_ece(&confidences, &outcomes, 10);
        // Should be around 0.4 (90% - 50% = 40%)
        assert!(
            (ece - 0.4).abs() < 0.1,
            "Overconfident should have high ECE: {}",
            ece
        );
    }

    #[test]
    fn test_ece_underconfident() {
        // Underconfident: 20% confidence but 80% accuracy
        let confidences = vec![0.2, 0.2, 0.2, 0.2, 0.2];
        let outcomes = vec![true, true, true, true, false];

        let ece = compute_ece(&confidences, &outcomes, 10);
        // Should be around 0.6 (80% - 20% = 60%)
        assert!(ece > 0.5, "Underconfident should have high ECE: {}", ece);
    }

    #[test]
    fn test_mce() {
        // Different buckets with different calibration errors
        let confidences = vec![0.1, 0.1, 0.9, 0.9];
        let outcomes = vec![false, false, true, false]; // Low is good, high is bad

        let mce = compute_mce(&confidences, &outcomes, 10);
        // The 0.9 bucket has 50% accuracy but 90% confidence -> error = 0.4
        assert!(mce > 0.3, "MCE should capture worst bucket: {}", mce);
    }

    #[test]
    fn test_calibration_metrics_compute() {
        let calibrated = vec![0.5, 0.5, 0.8, 0.8];
        let raw = vec![0.6, 0.6, 0.9, 0.9];
        let outcomes = vec![true, false, true, true];

        let metrics = CalibrationMetrics::compute(&calibrated, &raw, &outcomes);

        assert_eq!(metrics.sample_count, 4);
        assert!(metrics.accuracy > 0.5); // 3/4 correct
        assert!(metrics.brier_score >= 0.0 && metrics.brier_score <= 1.0);
        assert!(metrics.expected_calibration_error >= 0.0);
    }

    #[test]
    fn test_calibration_metrics_empty() {
        let metrics = CalibrationMetrics::compute(&[], &[], &[]);

        assert_eq!(metrics.sample_count, 0);
        assert_eq!(metrics.expected_calibration_error, 0.0);
        assert_eq!(metrics.brier_score, 0.0);
    }

    #[test]
    fn test_calibration_quality() {
        let mut metrics = CalibrationMetrics::empty();

        metrics.expected_calibration_error = 0.03;
        assert_eq!(metrics.quality(), CalibrationQuality::Excellent);

        metrics.expected_calibration_error = 0.08;
        assert_eq!(metrics.quality(), CalibrationQuality::Good);

        metrics.expected_calibration_error = 0.12;
        assert_eq!(metrics.quality(), CalibrationQuality::Fair);

        metrics.expected_calibration_error = 0.20;
        assert_eq!(metrics.quality(), CalibrationQuality::Poor);
    }

    #[test]
    fn test_confidence_bucket() {
        let bucket = ConfidenceBucket::new(0.2, 0.4);

        assert_eq!(bucket.lower, 0.2);
        assert_eq!(bucket.upper, 0.4);
        // Use approximate comparison for floating point midpoint
        assert!((bucket.midpoint() - 0.3).abs() < 1e-9);
        assert!(bucket.is_empty());
    }

    #[test]
    fn test_calibration_metrics_summary() {
        let calibrated = vec![0.5; 100];
        let raw = vec![0.6; 100];
        let outcomes: Vec<bool> = (0..100).map(|i| i < 50).collect();

        let metrics = CalibrationMetrics::compute(&calibrated, &raw, &outcomes);
        let summary = metrics.summary();

        assert!(summary.contains("ECE"));
        assert!(summary.contains("Brier"));
        assert!(summary.contains("Samples: 100"));
    }

    #[test]
    fn test_reliability_diagram_points() {
        // Create data that spans multiple buckets
        let mut calibrated = Vec::new();
        let mut raw = Vec::new();
        let mut outcomes = Vec::new();

        // Low confidence bucket (0.1-0.2): 20% accuracy
        for _ in 0..10 {
            calibrated.push(0.15);
            raw.push(0.15);
        }
        outcomes.extend(vec![
            true, true, false, false, false, false, false, false, false, false,
        ]);

        // High confidence bucket (0.8-0.9): 80% accuracy
        for _ in 0..10 {
            calibrated.push(0.85);
            raw.push(0.85);
        }
        outcomes.extend(vec![
            true, true, true, true, true, true, true, true, false, false,
        ]);

        let metrics = CalibrationMetrics::compute(&calibrated, &raw, &outcomes);

        // Should have at least 2 points in reliability diagram
        assert!(
            metrics.reliability_diagram.len() >= 2,
            "Should have multiple reliability diagram points: {:?}",
            metrics.reliability_diagram
        );

        // Check that we have points at low and high confidence
        let has_low = metrics
            .reliability_diagram
            .iter()
            .any(|p| p.mean_confidence < 0.3);
        let has_high = metrics
            .reliability_diagram
            .iter()
            .any(|p| p.mean_confidence > 0.7);
        assert!(has_low, "Should have low confidence point");
        assert!(has_high, "Should have high confidence point");
    }
}
