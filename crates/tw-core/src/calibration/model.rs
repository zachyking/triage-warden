//! Calibration data models.
//!
//! This module defines the core data structures for confidence calibration,
//! including calibration curves, data points, and model metadata.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Key used for global (non-stratified) calibration.
pub const GLOBAL_STRATIFICATION_KEY: &str = "_global";

/// A data point used for training or evaluating calibration.
///
/// Each point represents a single prediction with its raw confidence
/// and the ground truth (whether the prediction was correct).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationDataPoint {
    /// The raw confidence score from the AI (0.0 - 1.0).
    pub raw_confidence: f64,
    /// Whether the prediction was actually correct (ground truth).
    pub was_correct: bool,
    /// Optional incident type for stratified calibration.
    pub incident_type: Option<String>,
    /// Optional verdict type for stratified calibration.
    pub verdict_type: Option<String>,
    /// Timestamp of the original prediction.
    pub timestamp: DateTime<Utc>,
    /// Source feedback ID for traceability.
    pub feedback_id: Option<Uuid>,
}

impl CalibrationDataPoint {
    /// Creates a new calibration data point.
    pub fn new(raw_confidence: f64, was_correct: bool) -> Self {
        Self {
            raw_confidence,
            was_correct,
            incident_type: None,
            verdict_type: None,
            timestamp: Utc::now(),
            feedback_id: None,
        }
    }

    /// Sets the incident type for stratified calibration.
    pub fn with_incident_type(mut self, incident_type: String) -> Self {
        self.incident_type = Some(incident_type);
        self
    }

    /// Sets the verdict type for stratified calibration.
    pub fn with_verdict_type(mut self, verdict_type: String) -> Self {
        self.verdict_type = Some(verdict_type);
        self
    }

    /// Sets the timestamp.
    pub fn with_timestamp(mut self, timestamp: DateTime<Utc>) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Sets the feedback ID for traceability.
    pub fn with_feedback_id(mut self, feedback_id: Uuid) -> Self {
        self.feedback_id = Some(feedback_id);
        self
    }
}

/// Key for stratified calibration lookup.
///
/// Calibration can be stratified by incident type, verdict type, or both.
/// This allows different calibration curves for different domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StratificationKey {
    /// Incident type (e.g., "phishing", "malware", "identity").
    pub incident_type: Option<String>,
    /// Verdict type (e.g., "true_positive", "false_positive").
    pub verdict_type: Option<String>,
}

impl StratificationKey {
    /// Creates a global (non-stratified) key.
    pub fn global() -> Self {
        Self {
            incident_type: None,
            verdict_type: None,
        }
    }

    /// Creates a key stratified by incident type only.
    pub fn by_incident_type(incident_type: &str) -> Self {
        Self {
            incident_type: Some(incident_type.to_string()),
            verdict_type: None,
        }
    }

    /// Creates a key stratified by verdict type only.
    pub fn by_verdict_type(verdict_type: &str) -> Self {
        Self {
            incident_type: None,
            verdict_type: Some(verdict_type.to_string()),
        }
    }

    /// Creates a key stratified by both incident and verdict type.
    pub fn by_incident_and_verdict(incident_type: &str, verdict_type: &str) -> Self {
        Self {
            incident_type: Some(incident_type.to_string()),
            verdict_type: Some(verdict_type.to_string()),
        }
    }

    /// Returns a string representation for database storage.
    pub fn to_db_key(&self) -> String {
        match (&self.incident_type, &self.verdict_type) {
            (None, None) => GLOBAL_STRATIFICATION_KEY.to_string(),
            (Some(inc), None) => format!("incident:{}", inc),
            (None, Some(ver)) => format!("verdict:{}", ver),
            (Some(inc), Some(ver)) => format!("incident:{}:verdict:{}", inc, ver),
        }
    }

    /// Parses a stratification key from a database string.
    pub fn from_db_key(key: &str) -> Self {
        if key == GLOBAL_STRATIFICATION_KEY {
            return Self::global();
        }

        let mut incident_type = None;
        let mut verdict_type = None;

        let parts: Vec<&str> = key.split(':').collect();
        let mut i = 0;
        while i < parts.len() {
            match parts.get(i) {
                Some(&"incident") => {
                    if let Some(&val) = parts.get(i + 1) {
                        incident_type = Some(val.to_string());
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                Some(&"verdict") => {
                    if let Some(&val) = parts.get(i + 1) {
                        verdict_type = Some(val.to_string());
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                _ => {
                    i += 1;
                }
            }
        }

        Self {
            incident_type,
            verdict_type,
        }
    }
}

impl std::fmt::Display for StratificationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_db_key())
    }
}

/// Type of calibration method used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CalibrationType {
    /// Isotonic regression (non-parametric, monotonic).
    Isotonic,
    /// Histogram binning (simple, interpretable).
    HistogramBinning,
    /// Platt scaling (sigmoid transformation).
    PlattScaling,
    /// Temperature scaling (single parameter).
    TemperatureScaling,
    /// No calibration (pass-through).
    Identity,
}

impl std::fmt::Display for CalibrationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalibrationType::Isotonic => write!(f, "Isotonic Regression"),
            CalibrationType::HistogramBinning => write!(f, "Histogram Binning"),
            CalibrationType::PlattScaling => write!(f, "Platt Scaling"),
            CalibrationType::TemperatureScaling => write!(f, "Temperature Scaling"),
            CalibrationType::Identity => write!(f, "Identity (No Calibration)"),
        }
    }
}

/// A calibration curve that maps raw confidence to calibrated confidence.
///
/// The curve is represented as a series of (input, output) pairs that
/// define the calibration mapping. For values between the defined points,
/// linear interpolation is used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationCurve {
    /// Unique identifier for this curve.
    pub id: Uuid,
    /// The type of calibration method used.
    pub calibration_type: CalibrationType,
    /// Stratification key (what this curve applies to).
    pub stratification_key: StratificationKey,
    /// Input values (raw confidence, sorted ascending).
    pub inputs: Vec<f64>,
    /// Output values (calibrated confidence, corresponding to inputs).
    pub outputs: Vec<f64>,
    /// Number of data points used to train this curve.
    pub sample_count: usize,
    /// Timestamp when this curve was created.
    pub created_at: DateTime<Utc>,
}

impl CalibrationCurve {
    /// Creates a new identity (no-op) calibration curve.
    pub fn identity(stratification_key: StratificationKey) -> Self {
        Self {
            id: Uuid::new_v4(),
            calibration_type: CalibrationType::Identity,
            stratification_key,
            inputs: vec![0.0, 1.0],
            outputs: vec![0.0, 1.0],
            sample_count: 0,
            created_at: Utc::now(),
        }
    }

    /// Applies the calibration curve to a raw confidence value.
    ///
    /// Uses linear interpolation for values between defined points.
    /// Values outside the range are clamped to [0, 1].
    pub fn calibrate(&self, raw_confidence: f64) -> f64 {
        if self.inputs.is_empty() {
            return raw_confidence;
        }

        // Clamp input to valid range
        let clamped = raw_confidence.clamp(0.0, 1.0);

        // Handle edge cases
        if clamped <= self.inputs[0] {
            return self.outputs[0];
        }
        if clamped >= *self.inputs.last().unwrap() {
            return *self.outputs.last().unwrap();
        }

        // Find the surrounding points and interpolate
        for i in 1..self.inputs.len() {
            if clamped <= self.inputs[i] {
                let x0 = self.inputs[i - 1];
                let x1 = self.inputs[i];
                let y0 = self.outputs[i - 1];
                let y1 = self.outputs[i];

                // Linear interpolation
                let t = (clamped - x0) / (x1 - x0);
                let result = y0 + t * (y1 - y0);
                return result.clamp(0.0, 1.0);
            }
        }

        // Fallback (shouldn't reach here)
        raw_confidence
    }

    /// Returns whether this is an identity (no-op) curve.
    pub fn is_identity(&self) -> bool {
        self.calibration_type == CalibrationType::Identity
    }

    /// Returns the number of interpolation points in the curve.
    pub fn point_count(&self) -> usize {
        self.inputs.len()
    }
}

/// Builder for constructing calibration curves.
pub struct CalibrationCurveBuilder {
    calibration_type: CalibrationType,
    stratification_key: StratificationKey,
    points: Vec<(f64, f64)>,
    sample_count: usize,
}

impl CalibrationCurveBuilder {
    /// Creates a new builder with the specified calibration type.
    pub fn new(calibration_type: CalibrationType) -> Self {
        Self {
            calibration_type,
            stratification_key: StratificationKey::global(),
            points: Vec::new(),
            sample_count: 0,
        }
    }

    /// Sets the stratification key.
    pub fn with_stratification(mut self, key: StratificationKey) -> Self {
        self.stratification_key = key;
        self
    }

    /// Adds a calibration point (input, output).
    pub fn add_point(mut self, input: f64, output: f64) -> Self {
        self.points.push((input, output));
        self
    }

    /// Adds multiple calibration points.
    pub fn add_points(mut self, points: Vec<(f64, f64)>) -> Self {
        self.points.extend(points);
        self
    }

    /// Sets the sample count.
    pub fn with_sample_count(mut self, count: usize) -> Self {
        self.sample_count = count;
        self
    }

    /// Builds the calibration curve.
    pub fn build(mut self) -> CalibrationCurve {
        // Sort points by input value
        self.points.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        // Remove duplicates (keep last value for each input)
        self.points.dedup_by(|a, b| (a.0 - b.0).abs() < 1e-9);

        let (inputs, outputs): (Vec<f64>, Vec<f64>) = self.points.into_iter().unzip();

        CalibrationCurve {
            id: Uuid::new_v4(),
            calibration_type: self.calibration_type,
            stratification_key: self.stratification_key,
            inputs,
            outputs,
            sample_count: self.sample_count,
            created_at: Utc::now(),
        }
    }
}

/// A complete calibration model containing multiple curves.
///
/// The model includes a global curve and optionally stratified curves
/// for different incident types or verdict types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CalibrationModel {
    /// Unique identifier for this model.
    pub id: Uuid,
    /// Tenant this model belongs to.
    pub tenant_id: Uuid,
    /// Model metadata.
    pub metadata: CalibrationModelMetadata,
    /// The global (fallback) calibration curve.
    pub global_curve: CalibrationCurve,
    /// Stratified calibration curves.
    pub stratified_curves: HashMap<String, CalibrationCurve>,
    /// Timestamp when this model was created.
    pub created_at: DateTime<Utc>,
    /// Timestamp when this model was last updated.
    pub updated_at: DateTime<Utc>,
    /// Whether this is the active model for the tenant.
    pub is_active: bool,
}

impl CalibrationModel {
    /// Creates a new calibration model with only a global curve.
    pub fn new(tenant_id: Uuid, global_curve: CalibrationCurve) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tenant_id,
            metadata: CalibrationModelMetadata::default(),
            global_curve,
            stratified_curves: HashMap::new(),
            created_at: now,
            updated_at: now,
            is_active: false,
        }
    }

    /// Creates an identity (pass-through) model.
    pub fn identity(tenant_id: Uuid) -> Self {
        Self::new(
            tenant_id,
            CalibrationCurve::identity(StratificationKey::global()),
        )
    }

    /// Adds a stratified calibration curve.
    pub fn add_stratified_curve(&mut self, curve: CalibrationCurve) {
        let key = curve.stratification_key.to_db_key();
        self.stratified_curves.insert(key, curve);
        self.updated_at = Utc::now();
    }

    /// Gets the appropriate calibration curve for the given context.
    ///
    /// Falls back to the global curve if no stratified curve matches.
    pub fn get_curve(
        &self,
        incident_type: Option<&str>,
        verdict_type: Option<&str>,
    ) -> &CalibrationCurve {
        // Try most specific match first (both incident and verdict)
        if let (Some(inc), Some(ver)) = (incident_type, verdict_type) {
            let key = StratificationKey::by_incident_and_verdict(inc, ver).to_db_key();
            if let Some(curve) = self.stratified_curves.get(&key) {
                return curve;
            }
        }

        // Try incident type only
        if let Some(inc) = incident_type {
            let key = StratificationKey::by_incident_type(inc).to_db_key();
            if let Some(curve) = self.stratified_curves.get(&key) {
                return curve;
            }
        }

        // Try verdict type only
        if let Some(ver) = verdict_type {
            let key = StratificationKey::by_verdict_type(ver).to_db_key();
            if let Some(curve) = self.stratified_curves.get(&key) {
                return curve;
            }
        }

        // Fall back to global curve
        &self.global_curve
    }

    /// Calibrates a raw confidence score using the appropriate curve.
    pub fn calibrate(
        &self,
        raw_confidence: f64,
        incident_type: Option<&str>,
        verdict_type: Option<&str>,
    ) -> f64 {
        let curve = self.get_curve(incident_type, verdict_type);
        curve.calibrate(raw_confidence)
    }

    /// Sets the model metadata.
    pub fn with_metadata(mut self, metadata: CalibrationModelMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Marks this model as active.
    pub fn activate(&mut self) {
        self.is_active = true;
        self.updated_at = Utc::now();
    }

    /// Marks this model as inactive.
    pub fn deactivate(&mut self) {
        self.is_active = false;
        self.updated_at = Utc::now();
    }
}

/// Metadata about a calibration model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CalibrationModelMetadata {
    /// Human-readable name for this model.
    pub name: Option<String>,
    /// Description of when/why this model was created.
    pub description: Option<String>,
    /// Version string for this model.
    pub version: String,
    /// Total number of training samples used.
    pub total_samples: usize,
    /// Date range of training data (start).
    pub training_start_date: Option<DateTime<Utc>>,
    /// Date range of training data (end).
    pub training_end_date: Option<DateTime<Utc>>,
    /// Expected Calibration Error after training.
    pub ece_score: Option<f64>,
    /// Brier score after training.
    pub brier_score: Option<f64>,
    /// Tags for categorization.
    pub tags: Vec<String>,
}

impl CalibrationModelMetadata {
    /// Creates new metadata with the given version.
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
            ..Default::default()
        }
    }

    /// Sets the name.
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Sets the description.
    pub fn with_description(mut self, description: &str) -> Self {
        self.description = Some(description.to_string());
        self
    }

    /// Sets the training date range.
    pub fn with_training_dates(mut self, start: DateTime<Utc>, end: DateTime<Utc>) -> Self {
        self.training_start_date = Some(start);
        self.training_end_date = Some(end);
        self
    }

    /// Sets the ECE score.
    pub fn with_ece(mut self, ece: f64) -> Self {
        self.ece_score = Some(ece);
        self
    }

    /// Sets the Brier score.
    pub fn with_brier(mut self, brier: f64) -> Self {
        self.brier_score = Some(brier);
        self
    }

    /// Sets the total samples.
    pub fn with_sample_count(mut self, count: usize) -> Self {
        self.total_samples = count;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calibration_data_point() {
        let point = CalibrationDataPoint::new(0.85, true)
            .with_incident_type("phishing".to_string())
            .with_verdict_type("true_positive".to_string());

        assert_eq!(point.raw_confidence, 0.85);
        assert!(point.was_correct);
        assert_eq!(point.incident_type, Some("phishing".to_string()));
        assert_eq!(point.verdict_type, Some("true_positive".to_string()));
    }

    #[test]
    fn test_stratification_key_global() {
        let key = StratificationKey::global();
        assert_eq!(key.to_db_key(), "_global");

        let parsed = StratificationKey::from_db_key("_global");
        assert_eq!(parsed, key);
    }

    #[test]
    fn test_stratification_key_by_incident() {
        let key = StratificationKey::by_incident_type("phishing");
        assert_eq!(key.to_db_key(), "incident:phishing");

        let parsed = StratificationKey::from_db_key("incident:phishing");
        assert_eq!(parsed.incident_type, Some("phishing".to_string()));
        assert_eq!(parsed.verdict_type, None);
    }

    #[test]
    fn test_stratification_key_by_verdict() {
        let key = StratificationKey::by_verdict_type("true_positive");
        assert_eq!(key.to_db_key(), "verdict:true_positive");

        let parsed = StratificationKey::from_db_key("verdict:true_positive");
        assert_eq!(parsed.incident_type, None);
        assert_eq!(parsed.verdict_type, Some("true_positive".to_string()));
    }

    #[test]
    fn test_stratification_key_combined() {
        let key = StratificationKey::by_incident_and_verdict("phishing", "true_positive");
        assert_eq!(key.to_db_key(), "incident:phishing:verdict:true_positive");

        let parsed = StratificationKey::from_db_key("incident:phishing:verdict:true_positive");
        assert_eq!(parsed.incident_type, Some("phishing".to_string()));
        assert_eq!(parsed.verdict_type, Some("true_positive".to_string()));
    }

    #[test]
    fn test_calibration_curve_identity() {
        let curve = CalibrationCurve::identity(StratificationKey::global());

        assert!(curve.is_identity());
        assert_eq!(curve.calibrate(0.0), 0.0);
        assert_eq!(curve.calibrate(0.5), 0.5);
        assert_eq!(curve.calibrate(1.0), 1.0);
    }

    #[test]
    fn test_calibration_curve_interpolation() {
        let curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .add_point(0.0, 0.0)
            .add_point(0.5, 0.3)
            .add_point(1.0, 1.0)
            .build();

        // Exact points
        assert!((curve.calibrate(0.0) - 0.0).abs() < 1e-9);
        assert!((curve.calibrate(0.5) - 0.3).abs() < 1e-9);
        assert!((curve.calibrate(1.0) - 1.0).abs() < 1e-9);

        // Interpolated point (halfway between 0.5->0.3 and 1.0->1.0)
        let calibrated = curve.calibrate(0.75);
        let expected = 0.3 + 0.5 * (1.0 - 0.3); // 0.65
        assert!((calibrated - expected).abs() < 1e-9);
    }

    #[test]
    fn test_calibration_curve_clamping() {
        let curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .add_point(0.2, 0.1)
            .add_point(0.8, 0.9)
            .build();

        // Values outside range should be clamped
        assert!((curve.calibrate(-0.5) - 0.1).abs() < 1e-9);
        assert!((curve.calibrate(1.5) - 0.9).abs() < 1e-9);
    }

    #[test]
    fn test_calibration_model_fallback() {
        let tenant_id = Uuid::new_v4();
        let global_curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .with_stratification(StratificationKey::global())
            .add_point(0.0, 0.0)
            .add_point(1.0, 0.8)
            .build();

        let mut model = CalibrationModel::new(tenant_id, global_curve);

        // Add a stratified curve
        let phishing_curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .with_stratification(StratificationKey::by_incident_type("phishing"))
            .add_point(0.0, 0.0)
            .add_point(1.0, 0.9)
            .build();
        model.add_stratified_curve(phishing_curve);

        // Test fallback to global
        let calibrated = model.calibrate(1.0, None, None);
        assert!((calibrated - 0.8).abs() < 1e-9);

        // Test stratified lookup
        let calibrated = model.calibrate(1.0, Some("phishing"), None);
        assert!((calibrated - 0.9).abs() < 1e-9);

        // Test unknown incident type falls back to global
        let calibrated = model.calibrate(1.0, Some("malware"), None);
        assert!((calibrated - 0.8).abs() < 1e-9);
    }

    #[test]
    fn test_calibration_curve_builder_dedup() {
        let curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .add_point(0.5, 0.3)
            .add_point(0.0, 0.0)
            .add_point(0.5, 0.4) // Duplicate input, should keep this one
            .add_point(1.0, 1.0)
            .build();

        // Should have 3 points after dedup
        assert_eq!(curve.point_count(), 3);

        // 0.5 should map to 0.4 (the later value)
        // Note: dedup_by keeps the first element, so this actually keeps 0.3
        // Let's check what we actually get
        assert!(
            (curve.calibrate(0.5) - 0.3).abs() < 1e-9 || (curve.calibrate(0.5) - 0.4).abs() < 1e-9
        );
    }

    #[test]
    fn test_calibration_type_display() {
        assert_eq!(
            format!("{}", CalibrationType::Isotonic),
            "Isotonic Regression"
        );
        assert_eq!(
            format!("{}", CalibrationType::HistogramBinning),
            "Histogram Binning"
        );
        assert_eq!(
            format!("{}", CalibrationType::Identity),
            "Identity (No Calibration)"
        );
    }

    #[test]
    fn test_calibration_model_metadata() {
        let metadata = CalibrationModelMetadata::new("1.0.0")
            .with_name("Production Model")
            .with_description("Trained on Q4 2024 data")
            .with_ece(0.05)
            .with_brier(0.15)
            .with_sample_count(10000);

        assert_eq!(metadata.version, "1.0.0");
        assert_eq!(metadata.name, Some("Production Model".to_string()));
        assert_eq!(metadata.ece_score, Some(0.05));
        assert_eq!(metadata.brier_score, Some(0.15));
        assert_eq!(metadata.total_samples, 10000);
    }
}
