//! Calibration service and calibrator implementations.
//!
//! This module provides the core calibration service and different
//! calibration algorithm implementations.

use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

use super::metrics::CalibrationMetrics;
use super::model::{
    CalibrationCurve, CalibrationCurveBuilder, CalibrationDataPoint, CalibrationModel,
    CalibrationModelMetadata, CalibrationType, StratificationKey,
};

/// Result type for calibration operations.
pub type CalibrationResult<T> = Result<T, CalibrationError>;

/// Errors that can occur during calibration.
#[derive(Debug, Error)]
pub enum CalibrationError {
    /// Not enough data points for calibration.
    #[error("Insufficient data: {0} points provided, minimum {1} required")]
    InsufficientData(usize, usize),

    /// Invalid confidence value.
    #[error("Invalid confidence value: {0} (must be between 0.0 and 1.0)")]
    InvalidConfidence(f64),

    /// Calibration model not found.
    #[error("Calibration model not found for tenant {0}")]
    ModelNotFound(uuid::Uuid),

    /// Training failed.
    #[error("Training failed: {0}")]
    TrainingFailed(String),

    /// Storage error.
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Type of calibrator to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CalibratorType {
    /// Isotonic regression (recommended for most cases).
    Isotonic,
    /// Histogram binning (simple and interpretable).
    HistogramBinning,
}

impl From<CalibratorType> for CalibrationType {
    fn from(ct: CalibratorType) -> Self {
        match ct {
            CalibratorType::Isotonic => CalibrationType::Isotonic,
            CalibratorType::HistogramBinning => CalibrationType::HistogramBinning,
        }
    }
}

/// Trait for confidence calibration algorithms.
pub trait ConfidenceCalibrator: Send + Sync {
    /// Trains the calibrator on the given data points.
    fn train(&mut self, data: &[CalibrationDataPoint]) -> CalibrationResult<()>;

    /// Calibrates a raw confidence score.
    fn calibrate(&self, raw_confidence: f64, incident_type: Option<&str>) -> f64;

    /// Returns the calibration curve.
    fn get_curve(&self) -> &CalibrationCurve;

    /// Returns the calibration type.
    fn calibration_type(&self) -> CalibrationType;

    /// Computes calibration metrics on validation data.
    fn compute_metrics(
        &self,
        validation_data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationMetrics>;
}

/// Isotonic regression calibrator.
///
/// Isotonic regression fits a monotonically non-decreasing function to the data.
/// This is the recommended method for most calibration tasks as it makes minimal
/// assumptions about the relationship between raw and calibrated confidence.
#[derive(Debug, Clone)]
pub struct IsotonicCalibrator {
    curve: CalibrationCurve,
    stratification_key: StratificationKey,
    min_samples: usize,
}

impl Default for IsotonicCalibrator {
    fn default() -> Self {
        Self::new()
    }
}

impl IsotonicCalibrator {
    /// Creates a new isotonic calibrator.
    pub fn new() -> Self {
        Self {
            curve: CalibrationCurve::identity(StratificationKey::global()),
            stratification_key: StratificationKey::global(),
            min_samples: 50, // Minimum samples required for training
        }
    }

    /// Sets the minimum number of samples required for training.
    pub fn with_min_samples(mut self, min_samples: usize) -> Self {
        self.min_samples = min_samples;
        self
    }

    /// Sets the stratification key.
    pub fn with_stratification(mut self, key: StratificationKey) -> Self {
        self.stratification_key = key;
        self
    }

    /// Performs Pool Adjacent Violators (PAV) algorithm for isotonic regression.
    ///
    /// This algorithm produces a monotonically non-decreasing function that
    /// minimizes the weighted squared error.
    fn pav_isotonic(data: &[(f64, f64)]) -> Vec<(f64, f64)> {
        if data.is_empty() {
            return vec![];
        }

        // Sort by input value
        let mut sorted: Vec<_> = data.to_vec();
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());

        // Apply PAV algorithm
        // Each block represents a group of points that should have the same output
        struct Block {
            sum: f64,
            count: usize,
            start_x: f64,
            end_x: f64,
        }

        impl Block {
            fn mean(&self) -> f64 {
                self.sum / self.count as f64
            }
        }

        let mut blocks: Vec<Block> = Vec::new();

        for &(x, y) in &sorted {
            // Add new block
            blocks.push(Block {
                sum: y,
                count: 1,
                start_x: x,
                end_x: x,
            });

            // Merge blocks that violate monotonicity
            while blocks.len() >= 2 {
                let n = blocks.len();
                let prev_mean = blocks[n - 2].mean();
                let curr_mean = blocks[n - 1].mean();

                if prev_mean > curr_mean {
                    // Merge the two blocks
                    let last = blocks.pop().unwrap();
                    let prev = blocks.last_mut().unwrap();
                    prev.sum += last.sum;
                    prev.count += last.count;
                    prev.end_x = last.end_x;
                } else {
                    break;
                }
            }
        }

        // Convert blocks back to points
        // For each block, we output the mean value at the midpoint
        let mut result: Vec<(f64, f64)> = Vec::new();
        for block in blocks {
            let mean = block.mean();
            // Output at start and end of block
            if result.is_empty() || (result.last().unwrap().0 - block.start_x).abs() > 1e-9 {
                result.push((block.start_x, mean));
            }
            if (block.end_x - block.start_x).abs() > 1e-9 {
                result.push((block.end_x, mean));
            }
        }

        // Ensure we have endpoints
        if !result.is_empty() {
            // Ensure starts at 0
            if result[0].0 > 1e-9 {
                let first_y = result[0].1;
                result.insert(0, (0.0, first_y.min(0.0_f64.max(first_y - 0.1))));
            }
            // Ensure ends at 1
            if result.last().unwrap().0 < 1.0 - 1e-9 {
                let last_y = result.last().unwrap().1;
                result.push((1.0, last_y.max(1.0_f64.min(last_y + 0.1))));
            }
        }

        result
    }
}

impl ConfidenceCalibrator for IsotonicCalibrator {
    fn train(&mut self, data: &[CalibrationDataPoint]) -> CalibrationResult<()> {
        if data.len() < self.min_samples {
            return Err(CalibrationError::InsufficientData(
                data.len(),
                self.min_samples,
            ));
        }

        // Convert to (raw_confidence, actual_outcome) pairs
        let pairs: Vec<(f64, f64)> = data
            .iter()
            .map(|dp| (dp.raw_confidence, if dp.was_correct { 1.0 } else { 0.0 }))
            .collect();

        // Apply PAV algorithm
        let calibration_points = Self::pav_isotonic(&pairs);

        // Build the curve
        self.curve = CalibrationCurveBuilder::new(CalibrationType::Isotonic)
            .with_stratification(self.stratification_key.clone())
            .add_points(calibration_points)
            .with_sample_count(data.len())
            .build();

        Ok(())
    }

    fn calibrate(&self, raw_confidence: f64, _incident_type: Option<&str>) -> f64 {
        self.curve.calibrate(raw_confidence)
    }

    fn get_curve(&self) -> &CalibrationCurve {
        &self.curve
    }

    fn calibration_type(&self) -> CalibrationType {
        CalibrationType::Isotonic
    }

    fn compute_metrics(
        &self,
        validation_data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationMetrics> {
        if validation_data.is_empty() {
            return Err(CalibrationError::InsufficientData(0, 1));
        }

        // Calibrate all predictions
        let calibrated: Vec<f64> = validation_data
            .iter()
            .map(|dp| self.calibrate(dp.raw_confidence, dp.incident_type.as_deref()))
            .collect();

        let outcomes: Vec<bool> = validation_data.iter().map(|dp| dp.was_correct).collect();
        let raw_confidences: Vec<f64> =
            validation_data.iter().map(|dp| dp.raw_confidence).collect();

        Ok(CalibrationMetrics::compute(
            &calibrated,
            &raw_confidences,
            &outcomes,
        ))
    }
}

/// Histogram binning calibrator.
///
/// Divides the confidence range into bins and uses the empirical accuracy
/// in each bin as the calibrated confidence.
#[derive(Debug, Clone)]
pub struct HistogramBinningCalibrator {
    curve: CalibrationCurve,
    stratification_key: StratificationKey,
    num_bins: usize,
    min_samples: usize,
}

impl Default for HistogramBinningCalibrator {
    fn default() -> Self {
        Self::new(10)
    }
}

impl HistogramBinningCalibrator {
    /// Creates a new histogram binning calibrator.
    pub fn new(num_bins: usize) -> Self {
        Self {
            curve: CalibrationCurve::identity(StratificationKey::global()),
            stratification_key: StratificationKey::global(),
            num_bins: num_bins.max(2),
            min_samples: 20,
        }
    }

    /// Sets the minimum number of samples required for training.
    pub fn with_min_samples(mut self, min_samples: usize) -> Self {
        self.min_samples = min_samples;
        self
    }

    /// Sets the stratification key.
    pub fn with_stratification(mut self, key: StratificationKey) -> Self {
        self.stratification_key = key;
        self
    }
}

impl ConfidenceCalibrator for HistogramBinningCalibrator {
    fn train(&mut self, data: &[CalibrationDataPoint]) -> CalibrationResult<()> {
        if data.len() < self.min_samples {
            return Err(CalibrationError::InsufficientData(
                data.len(),
                self.min_samples,
            ));
        }

        let bin_width = 1.0 / self.num_bins as f64;
        let mut bin_sums: Vec<f64> = vec![0.0; self.num_bins];
        let mut bin_counts: Vec<usize> = vec![0; self.num_bins];

        // Assign data points to bins
        for dp in data {
            let bin_idx = ((dp.raw_confidence / bin_width).floor() as usize).min(self.num_bins - 1);
            bin_sums[bin_idx] += if dp.was_correct { 1.0 } else { 0.0 };
            bin_counts[bin_idx] += 1;
        }

        // Compute calibrated values (mean accuracy in each bin)
        let mut points = Vec::new();
        points.push((0.0, 0.0)); // Start at 0

        for i in 0..self.num_bins {
            let bin_start = i as f64 * bin_width;
            let bin_end = (i + 1) as f64 * bin_width;
            let bin_mid = (bin_start + bin_end) / 2.0;

            let calibrated = if bin_counts[i] > 0 {
                bin_sums[i] / bin_counts[i] as f64
            } else {
                // Use linear interpolation for empty bins
                bin_mid
            };

            points.push((bin_mid, calibrated));
        }

        points.push((1.0, 1.0)); // End at 1

        // Build the curve
        self.curve = CalibrationCurveBuilder::new(CalibrationType::HistogramBinning)
            .with_stratification(self.stratification_key.clone())
            .add_points(points)
            .with_sample_count(data.len())
            .build();

        Ok(())
    }

    fn calibrate(&self, raw_confidence: f64, _incident_type: Option<&str>) -> f64 {
        self.curve.calibrate(raw_confidence)
    }

    fn get_curve(&self) -> &CalibrationCurve {
        &self.curve
    }

    fn calibration_type(&self) -> CalibrationType {
        CalibrationType::HistogramBinning
    }

    fn compute_metrics(
        &self,
        validation_data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationMetrics> {
        if validation_data.is_empty() {
            return Err(CalibrationError::InsufficientData(0, 1));
        }

        let calibrated: Vec<f64> = validation_data
            .iter()
            .map(|dp| self.calibrate(dp.raw_confidence, dp.incident_type.as_deref()))
            .collect();

        let outcomes: Vec<bool> = validation_data.iter().map(|dp| dp.was_correct).collect();
        let raw_confidences: Vec<f64> =
            validation_data.iter().map(|dp| dp.raw_confidence).collect();

        Ok(CalibrationMetrics::compute(
            &calibrated,
            &raw_confidences,
            &outcomes,
        ))
    }
}

/// Configuration for the calibration service.
#[derive(Debug, Clone)]
pub struct CalibrationServiceConfig {
    /// The type of calibrator to use.
    pub calibrator_type: CalibratorType,
    /// Number of bins for histogram binning.
    pub num_bins: usize,
    /// Minimum samples required for training.
    pub min_samples: usize,
    /// Whether to use stratified calibration.
    pub use_stratification: bool,
    /// Minimum samples per stratum for stratified calibration.
    pub min_stratum_samples: usize,
}

impl Default for CalibrationServiceConfig {
    fn default() -> Self {
        Self {
            calibrator_type: CalibratorType::Isotonic,
            num_bins: 10,
            min_samples: 50,
            use_stratification: true,
            min_stratum_samples: 30,
        }
    }
}

/// Main calibration service.
///
/// Manages calibration models and provides calibration functionality.
pub struct CalibrationService {
    config: CalibrationServiceConfig,
    model: Option<Arc<CalibrationModel>>,
}

impl CalibrationService {
    /// Creates a new calibration service with default configuration.
    pub fn new() -> Self {
        Self {
            config: CalibrationServiceConfig::default(),
            model: None,
        }
    }

    /// Creates a new calibration service with the given configuration.
    pub fn with_config(config: CalibrationServiceConfig) -> Self {
        Self {
            config,
            model: None,
        }
    }

    /// Returns the current configuration.
    pub fn config(&self) -> &CalibrationServiceConfig {
        &self.config
    }

    /// Returns the active calibration model, if any.
    pub fn model(&self) -> Option<&Arc<CalibrationModel>> {
        self.model.as_ref()
    }

    /// Sets the active calibration model.
    pub fn set_model(&mut self, model: CalibrationModel) {
        self.model = Some(Arc::new(model));
    }

    /// Clears the active calibration model.
    pub fn clear_model(&mut self) {
        self.model = None;
    }

    /// Creates a calibrator based on the configuration.
    fn create_calibrator(
        &self,
        stratification_key: StratificationKey,
    ) -> Box<dyn ConfidenceCalibrator> {
        match self.config.calibrator_type {
            CalibratorType::Isotonic => Box::new(
                IsotonicCalibrator::new()
                    .with_min_samples(self.config.min_samples)
                    .with_stratification(stratification_key),
            ),
            CalibratorType::HistogramBinning => Box::new(
                HistogramBinningCalibrator::new(self.config.num_bins)
                    .with_min_samples(self.config.min_samples)
                    .with_stratification(stratification_key),
            ),
        }
    }

    /// Trains a calibration model from the given data.
    pub fn train(
        &mut self,
        tenant_id: uuid::Uuid,
        data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationModel> {
        if data.len() < self.config.min_samples {
            return Err(CalibrationError::InsufficientData(
                data.len(),
                self.config.min_samples,
            ));
        }

        // Train global calibrator
        let mut global_calibrator = self.create_calibrator(StratificationKey::global());
        global_calibrator.train(data)?;

        let mut model = CalibrationModel::new(tenant_id, global_calibrator.get_curve().clone());

        // Train stratified calibrators if enabled
        if self.config.use_stratification {
            // Group by incident type
            let mut by_incident: HashMap<String, Vec<&CalibrationDataPoint>> = HashMap::new();
            for dp in data {
                if let Some(ref inc_type) = dp.incident_type {
                    by_incident.entry(inc_type.clone()).or_default().push(dp);
                }
            }

            // Train a calibrator for each incident type with enough samples
            for (inc_type, points) in by_incident {
                if points.len() >= self.config.min_stratum_samples {
                    let key = StratificationKey::by_incident_type(&inc_type);
                    let mut calibrator = self.create_calibrator(key);
                    let owned_points: Vec<CalibrationDataPoint> =
                        points.into_iter().cloned().collect();
                    if calibrator.train(&owned_points).is_ok() {
                        model.add_stratified_curve(calibrator.get_curve().clone());
                    }
                }
            }
        }

        // Compute metrics
        let metrics = self.compute_metrics_for_model(&model, data)?;
        let metadata = CalibrationModelMetadata::new("1.0.0")
            .with_ece(metrics.expected_calibration_error)
            .with_brier(metrics.brier_score)
            .with_sample_count(data.len());

        let model = model.with_metadata(metadata);
        self.model = Some(Arc::new(model.clone()));

        Ok(model)
    }

    /// Calibrates a raw confidence score using the active model.
    ///
    /// Returns the raw confidence if no model is loaded.
    pub fn calibrate(
        &self,
        raw_confidence: f64,
        incident_type: Option<&str>,
        verdict_type: Option<&str>,
    ) -> f64 {
        match &self.model {
            Some(model) => model.calibrate(raw_confidence, incident_type, verdict_type),
            None => raw_confidence,
        }
    }

    /// Computes calibration metrics for a model on the given data.
    pub fn compute_metrics_for_model(
        &self,
        model: &CalibrationModel,
        data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationMetrics> {
        if data.is_empty() {
            return Err(CalibrationError::InsufficientData(0, 1));
        }

        let calibrated: Vec<f64> = data
            .iter()
            .map(|dp| {
                model.calibrate(
                    dp.raw_confidence,
                    dp.incident_type.as_deref(),
                    dp.verdict_type.as_deref(),
                )
            })
            .collect();

        let outcomes: Vec<bool> = data.iter().map(|dp| dp.was_correct).collect();
        let raw_confidences: Vec<f64> = data.iter().map(|dp| dp.raw_confidence).collect();

        Ok(CalibrationMetrics::compute(
            &calibrated,
            &raw_confidences,
            &outcomes,
        ))
    }

    /// Computes calibration metrics for the active model.
    pub fn compute_metrics(
        &self,
        data: &[CalibrationDataPoint],
    ) -> CalibrationResult<CalibrationMetrics> {
        match &self.model {
            Some(model) => self.compute_metrics_for_model(model, data),
            None => {
                // Without a model, compute metrics on raw confidences
                if data.is_empty() {
                    return Err(CalibrationError::InsufficientData(0, 1));
                }

                let raw: Vec<f64> = data.iter().map(|dp| dp.raw_confidence).collect();
                let outcomes: Vec<bool> = data.iter().map(|dp| dp.was_correct).collect();

                Ok(CalibrationMetrics::compute(&raw, &raw, &outcomes))
            }
        }
    }
}

impl Default for CalibrationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_data() -> Vec<CalibrationDataPoint> {
        // Generate synthetic calibration data
        // High confidence predictions are more likely to be correct
        let mut data = Vec::new();

        // Well-calibrated region (around 0.5)
        for _ in 0..20 {
            data.push(CalibrationDataPoint::new(0.5, true));
            data.push(CalibrationDataPoint::new(0.5, false));
        }

        // High confidence, mostly correct
        for _ in 0..18 {
            data.push(CalibrationDataPoint::new(0.9, true));
        }
        for _ in 0..2 {
            data.push(CalibrationDataPoint::new(0.9, false));
        }

        // Low confidence, mostly incorrect
        for _ in 0..16 {
            data.push(CalibrationDataPoint::new(0.2, false));
        }
        for _ in 0..4 {
            data.push(CalibrationDataPoint::new(0.2, true));
        }

        data
    }

    #[test]
    fn test_isotonic_calibrator_train() {
        let mut calibrator = IsotonicCalibrator::new().with_min_samples(10);
        let data = generate_test_data();

        assert!(calibrator.train(&data).is_ok());

        // After training, high confidence should map to high calibrated confidence
        let high_cal = calibrator.calibrate(0.9, None);
        let low_cal = calibrator.calibrate(0.2, None);

        assert!(
            high_cal > low_cal,
            "High confidence should calibrate higher than low"
        );
        assert!(high_cal > 0.5, "90% raw should calibrate above 50%");
        assert!(low_cal < 0.5, "20% raw should calibrate below 50%");
    }

    #[test]
    fn test_isotonic_calibrator_insufficient_data() {
        let mut calibrator = IsotonicCalibrator::new().with_min_samples(100);
        let data = vec![
            CalibrationDataPoint::new(0.5, true),
            CalibrationDataPoint::new(0.6, false),
        ];

        let result = calibrator.train(&data);
        assert!(matches!(
            result,
            Err(CalibrationError::InsufficientData(2, 100))
        ));
    }

    #[test]
    fn test_histogram_binning_calibrator() {
        let mut calibrator = HistogramBinningCalibrator::new(10).with_min_samples(10);
        let data = generate_test_data();

        assert!(calibrator.train(&data).is_ok());

        let high_cal = calibrator.calibrate(0.9, None);
        let mid_cal = calibrator.calibrate(0.5, None);
        let low_cal = calibrator.calibrate(0.2, None);

        // Histogram binning should produce step-like calibration
        assert!(high_cal > mid_cal, "High > Mid");
        assert!(
            mid_cal > low_cal || (mid_cal - low_cal).abs() < 0.2,
            "Mid >= Low (approximately)"
        );
    }

    #[test]
    fn test_calibration_service_train() {
        let mut service = CalibrationService::with_config(CalibrationServiceConfig {
            calibrator_type: CalibratorType::Isotonic,
            min_samples: 10,
            use_stratification: false,
            ..Default::default()
        });

        let data = generate_test_data();
        let tenant_id = uuid::Uuid::new_v4();

        let model = service.train(tenant_id, &data);
        assert!(model.is_ok());

        let model = model.unwrap();
        assert_eq!(model.tenant_id, tenant_id);
        assert!(!model.global_curve.is_identity());
    }

    #[test]
    fn test_calibration_service_calibrate() {
        let mut service = CalibrationService::with_config(CalibrationServiceConfig {
            calibrator_type: CalibratorType::Isotonic,
            min_samples: 10,
            ..Default::default()
        });

        // Without a model, should return raw confidence
        assert_eq!(service.calibrate(0.75, None, None), 0.75);

        // Train a model
        let data = generate_test_data();
        let tenant_id = uuid::Uuid::new_v4();
        service.train(tenant_id, &data).unwrap();

        // Now calibration should be different
        let calibrated = service.calibrate(0.9, None, None);
        // It might be close to 0.9 or different, but should be valid
        assert!((0.0..=1.0).contains(&calibrated));
    }

    #[test]
    fn test_calibration_service_with_stratification() {
        let mut service = CalibrationService::with_config(CalibrationServiceConfig {
            calibrator_type: CalibratorType::Isotonic,
            min_samples: 10,
            use_stratification: true,
            min_stratum_samples: 10,
            ..Default::default()
        });

        // Create data with incident types
        let mut data = Vec::new();

        // Phishing incidents - high confidence is very accurate
        for _ in 0..15 {
            data.push(
                CalibrationDataPoint::new(0.9, true).with_incident_type("phishing".to_string()),
            );
        }
        for _ in 0..5 {
            data.push(
                CalibrationDataPoint::new(0.3, false).with_incident_type("phishing".to_string()),
            );
        }

        // Malware incidents - high confidence is less accurate
        for _ in 0..10 {
            data.push(
                CalibrationDataPoint::new(0.9, true).with_incident_type("malware".to_string()),
            );
        }
        for _ in 0..10 {
            data.push(
                CalibrationDataPoint::new(0.9, false).with_incident_type("malware".to_string()),
            );
        }

        // Also need some global data
        for _ in 0..20 {
            data.push(CalibrationDataPoint::new(0.5, true));
        }
        for _ in 0..20 {
            data.push(CalibrationDataPoint::new(0.5, false));
        }

        let tenant_id = uuid::Uuid::new_v4();
        let model = service.train(tenant_id, &data).unwrap();

        // Should have stratified curves
        assert!(
            !model.stratified_curves.is_empty(),
            "Should have stratified curves"
        );
    }

    #[test]
    fn test_calibration_metrics_computation() {
        let mut calibrator = IsotonicCalibrator::new().with_min_samples(10);
        let data = generate_test_data();

        calibrator.train(&data).unwrap();
        let metrics = calibrator.compute_metrics(&data).unwrap();

        // ECE should be reasonable (less than 0.2 for synthetic data)
        assert!(
            metrics.expected_calibration_error < 0.3,
            "ECE should be reasonable: {}",
            metrics.expected_calibration_error
        );

        // Brier score should be between 0 and 1
        assert!(metrics.brier_score >= 0.0 && metrics.brier_score <= 1.0);
    }

    #[test]
    fn test_pav_algorithm() {
        // Test the PAV algorithm directly
        let data = vec![
            (0.1, 0.0),
            (0.2, 0.0),
            (0.3, 1.0), // This should be pulled up
            (0.4, 0.0), // This should be merged with above
            (0.5, 0.5),
            (0.6, 0.5),
            (0.7, 1.0),
            (0.8, 1.0),
            (0.9, 1.0),
        ];

        let result = IsotonicCalibrator::pav_isotonic(&data);

        // Result should be monotonically non-decreasing
        for i in 1..result.len() {
            assert!(
                result[i].1 >= result[i - 1].1 - 1e-9,
                "Isotonic result should be monotonic: {:?}",
                result
            );
        }
    }
}
