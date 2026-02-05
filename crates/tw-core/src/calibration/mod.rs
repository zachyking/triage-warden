//! Confidence Calibration for Triage Warden (Task 2.2.4).
//!
//! This module provides confidence calibration for AI-generated triage analyses.
//! Calibration ensures that when the AI reports 90% confidence, it is actually
//! correct approximately 90% of the time.
//!
//! ## Key Components
//!
//! - [`ConfidenceCalibrator`]: Trait defining the calibration interface
//! - [`IsotonicCalibrator`]: Implementation using isotonic regression
//! - [`CalibrationCurve`]: Represents a learned calibration mapping
//! - [`CalibrationMetrics`]: Quality metrics (ECE, Brier score, etc.)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use tw_core::calibration::{ConfidenceCalibrator, IsotonicCalibrator};
//!
//! // Train calibrator from historical feedback
//! let calibrator = IsotonicCalibrator::train(&training_data)?;
//!
//! // Calibrate a raw confidence score
//! let raw_confidence = 0.85;
//! let calibrated = calibrator.calibrate(raw_confidence, Some("phishing"));
//!
//! // Check calibration quality
//! let metrics = calibrator.compute_metrics(&validation_data)?;
//! println!("ECE: {:.4}", metrics.expected_calibration_error);
//! ```

mod metrics;
mod model;
mod service;

pub use metrics::{
    compute_brier_score, compute_ece, compute_mce, CalibrationMetrics, ConfidenceBucket,
    ReliabilityDiagramPoint,
};
pub use model::{
    CalibrationCurve, CalibrationCurveBuilder, CalibrationDataPoint, CalibrationModel,
    CalibrationModelMetadata, CalibrationType, StratificationKey, GLOBAL_STRATIFICATION_KEY,
};
pub use service::{
    CalibrationError, CalibrationResult, CalibrationService, CalibrationServiceConfig,
    CalibratorType, ConfidenceCalibrator, HistogramBinningCalibrator, IsotonicCalibrator,
};
