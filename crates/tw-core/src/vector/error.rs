//! Vector store error types.

use thiserror::Error;

/// Errors that can occur during vector store operations.
#[derive(Debug, Error)]
pub enum VectorStoreError {
    /// Collection already exists.
    #[error("collection '{0}' already exists")]
    CollectionExists(String),

    /// Collection not found.
    #[error("collection '{0}' not found")]
    CollectionNotFound(String),

    /// Vector not found.
    #[error("vector '{0}' not found in collection '{1}'")]
    VectorNotFound(String, String),

    /// Dimension mismatch between vector and collection.
    #[error("dimension mismatch: expected {expected}, got {actual}")]
    DimensionMismatch { expected: usize, actual: usize },

    /// Invalid vector ID.
    #[error("invalid vector ID: {0}")]
    InvalidId(String),

    /// Connection error.
    #[error("connection error: {0}")]
    Connection(String),

    /// Operation timed out.
    #[error("operation timed out after {0} seconds")]
    Timeout(u64),

    /// Serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Configuration(String),

    /// Internal error from the vector database.
    #[error("internal error: {0}")]
    Internal(String),

    /// Rate limit exceeded.
    #[error("rate limit exceeded, retry after {retry_after_secs} seconds")]
    RateLimited { retry_after_secs: u64 },

    /// Batch operation partially failed.
    #[error("batch operation failed for {failed_count} of {total_count} items")]
    PartialBatchFailure {
        failed_count: usize,
        total_count: usize,
        errors: Vec<String>,
    },
}

impl VectorStoreError {
    /// Check if this error is retryable.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            VectorStoreError::Connection(_)
                | VectorStoreError::Timeout(_)
                | VectorStoreError::RateLimited { .. }
        )
    }

    /// Get retry delay in seconds if applicable.
    pub fn retry_after(&self) -> Option<u64> {
        match self {
            VectorStoreError::RateLimited { retry_after_secs } => Some(*retry_after_secs),
            VectorStoreError::Timeout(_) => Some(1),
            VectorStoreError::Connection(_) => Some(5),
            _ => None,
        }
    }
}

/// Result type for vector store operations.
pub type VectorStoreResult<T> = Result<T, VectorStoreError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_retryable() {
        assert!(VectorStoreError::Connection("failed".into()).is_retryable());
        assert!(VectorStoreError::Timeout(30).is_retryable());
        assert!(VectorStoreError::RateLimited {
            retry_after_secs: 60
        }
        .is_retryable());

        assert!(!VectorStoreError::CollectionNotFound("test".into()).is_retryable());
        assert!(!VectorStoreError::DimensionMismatch {
            expected: 384,
            actual: 256
        }
        .is_retryable());
    }

    #[test]
    fn test_error_retry_after() {
        assert_eq!(
            VectorStoreError::RateLimited {
                retry_after_secs: 60
            }
            .retry_after(),
            Some(60)
        );
        assert_eq!(VectorStoreError::Timeout(30).retry_after(), Some(1));
        assert_eq!(
            VectorStoreError::Connection("failed".into()).retry_after(),
            Some(5)
        );
        assert_eq!(
            VectorStoreError::CollectionNotFound("test".into()).retry_after(),
            None
        );
    }
}
