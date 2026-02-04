//! Cache error types.

use thiserror::Error;

/// Errors that can occur during cache operations.
#[derive(Error, Debug, Clone)]
pub enum CacheError {
    /// Failed to connect to the cache backend.
    #[error("Cache connection failed: {0}")]
    Connection(String),

    /// Failed to serialize or deserialize cache data.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// The requested key was not found in the cache.
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Timed out waiting for a lock on the cache key.
    #[error("Lock timeout for key: {0}")]
    LockTimeout(String),

    /// An unknown error occurred.
    #[error("Unknown cache error: {0}")]
    Unknown(String),
}

/// Result type for cache operations.
pub type CacheResult<T> = Result<T, CacheError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_error_display() {
        let err = CacheError::Connection("redis://localhost:6379".to_string());
        assert!(err.to_string().contains("redis://localhost:6379"));

        let err = CacheError::KeyNotFound("user:123".to_string());
        assert!(err.to_string().contains("user:123"));

        let err = CacheError::LockTimeout("enrichment:ip:192.168.1.1".to_string());
        assert!(err.to_string().contains("enrichment:ip:192.168.1.1"));

        let err = CacheError::Serialization("invalid JSON".to_string());
        assert!(err.to_string().contains("invalid JSON"));

        let err = CacheError::Unknown("unexpected error".to_string());
        assert!(err.to_string().contains("unexpected error"));
    }

    #[test]
    fn test_cache_error_clone() {
        let err = CacheError::Connection("test".to_string());
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }
}
