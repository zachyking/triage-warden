//! Privacy controls for sensitive data handling and retention.

pub mod classifier;
pub mod masker;
pub mod retention;

pub use classifier::{
    ClassificationPattern, DataCategory, SensitiveDataClassifier, SensitiveDataMatch,
};
pub use masker::{DataMasker, MaskMapping, MaskedText, MaskingStrategy};
pub use retention::{
    DataType, DeletionStrategy, RetentionCleanupAction, RetentionCleanupReport, RetentionDecision,
    RetentionManager, RetentionPolicy, RetentionRecord,
};
