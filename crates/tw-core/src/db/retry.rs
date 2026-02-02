//! Retry logic for transient database errors.
//!
//! This module provides utilities for retrying database operations that may fail
//! due to transient errors such as connection timeouts, pool exhaustion, or
//! temporary network issues.

use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, warn};

use super::DbError;

/// Configuration for retry behavior.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial delay between retries.
    pub initial_delay: Duration,
    /// Maximum delay between retries.
    pub max_delay: Duration,
    /// Multiplier for exponential backoff.
    pub backoff_multiplier: f64,
    /// Whether to add jitter to delays.
    pub jitter: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter: true,
        }
    }
}

impl RetryConfig {
    /// Creates a new retry configuration with no retries (fail immediately).
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Default::default()
        }
    }

    /// Creates a configuration for aggressive retrying (more attempts, shorter delays).
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            backoff_multiplier: 1.5,
            jitter: true,
        }
    }

    /// Creates a configuration for conservative retrying (fewer attempts, longer delays).
    pub fn conservative() -> Self {
        Self {
            max_retries: 2,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 3.0,
            jitter: true,
        }
    }

    /// Calculates the delay for a given attempt number (0-indexed).
    fn calculate_delay(&self, attempt: u32) -> Duration {
        let base_delay =
            self.initial_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32);
        let capped_delay = base_delay.min(self.max_delay.as_millis() as f64);

        let final_delay = if self.jitter {
            // Add up to 25% jitter
            let jitter_factor = 1.0 + (rand_jitter() * 0.25);
            capped_delay * jitter_factor
        } else {
            capped_delay
        };

        Duration::from_millis(final_delay as u64)
    }
}

/// Simple pseudo-random jitter factor (0.0 to 1.0).
fn rand_jitter() -> f64 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos % 1000) as f64 / 1000.0
}

/// Determines if an error is transient and worth retrying.
pub fn is_transient_error(error: &DbError) -> bool {
    match error {
        // Pool exhaustion is transient - connections may become available
        DbError::PoolExhausted => true,
        // Connection errors are often transient
        DbError::Connection(msg) => {
            // Retry on common transient connection issues
            let msg_lower = msg.to_lowercase();
            msg_lower.contains("timeout")
                || msg_lower.contains("connection refused")
                || msg_lower.contains("connection reset")
                || msg_lower.contains("broken pipe")
                || msg_lower.contains("network")
                || msg_lower.contains("temporarily unavailable")
        }
        // Transaction errors may be transient (deadlock, lock wait timeout)
        DbError::Transaction(msg) => {
            let msg_lower = msg.to_lowercase();
            msg_lower.contains("deadlock")
                || msg_lower.contains("lock wait timeout")
                || msg_lower.contains("busy")
        }
        // Query errors - check for transient indicators
        DbError::Query(msg) => {
            let msg_lower = msg.to_lowercase();
            msg_lower.contains("timeout")
                || msg_lower.contains("deadlock")
                || msg_lower.contains("lock wait")
                || msg_lower.contains("busy")
                || msg_lower.contains("database is locked")
        }
        // Serialization, constraint, and configuration errors are not transient
        DbError::Serialization(_) | DbError::Constraint(_) | DbError::Configuration(_) => false,
        // Not found is not transient
        DbError::NotFound { .. } => false,
        // Migration errors are not transient
        DbError::Migration(_) => false,
    }
}

/// Executes a database operation with retry logic.
///
/// # Arguments
///
/// * `config` - Retry configuration
/// * `operation_name` - Name of the operation for logging
/// * `f` - The async function to execute
///
/// # Returns
///
/// The result of the operation, or the last error if all retries failed.
///
/// # Example
///
/// ```ignore
/// let result = with_retry(
///     RetryConfig::default(),
///     "get_user",
///     || async { repo.get(user_id).await }
/// ).await;
/// ```
pub async fn with_retry<F, Fut, T>(
    config: RetryConfig,
    operation_name: &str,
    f: F,
) -> Result<T, DbError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, DbError>>,
{
    let mut last_error: Option<DbError> = None;

    for attempt in 0..=config.max_retries {
        match f().await {
            Ok(result) => {
                if attempt > 0 {
                    debug!(
                        operation = %operation_name,
                        attempt = attempt + 1,
                        "Database operation succeeded after retry"
                    );
                }
                return Ok(result);
            }
            Err(e) => {
                if !is_transient_error(&e) || attempt == config.max_retries {
                    // Not transient or out of retries
                    if attempt > 0 {
                        warn!(
                            operation = %operation_name,
                            attempts = attempt + 1,
                            error = %e,
                            "Database operation failed after retries"
                        );
                    }
                    return Err(e);
                }

                // Transient error - calculate delay and retry
                let delay = config.calculate_delay(attempt);
                warn!(
                    operation = %operation_name,
                    attempt = attempt + 1,
                    max_retries = config.max_retries,
                    delay_ms = delay.as_millis() as u64,
                    error = %e,
                    "Transient database error, retrying"
                );

                last_error = Some(e);
                sleep(delay).await;
            }
        }
    }

    // This should not be reached, but handle it gracefully
    Err(last_error
        .unwrap_or_else(|| DbError::Query("Retry loop completed unexpectedly".to_string())))
}

/// Wraps a result-returning function to make it retryable.
///
/// This is a convenience macro for creating retry-compatible closures.
#[macro_export]
macro_rules! retryable {
    ($expr:expr) => {
        || async { $expr }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_retry_config_defaults() {
        let config = RetryConfig::default();
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_delay, Duration::from_millis(100));
    }

    #[test]
    fn test_calculate_delay() {
        let config = RetryConfig {
            jitter: false,
            ..Default::default()
        };

        let delay0 = config.calculate_delay(0);
        let delay1 = config.calculate_delay(1);
        let delay2 = config.calculate_delay(2);

        assert_eq!(delay0, Duration::from_millis(100));
        assert_eq!(delay1, Duration::from_millis(200));
        assert_eq!(delay2, Duration::from_millis(400));
    }

    #[test]
    fn test_calculate_delay_capped() {
        let config = RetryConfig {
            max_delay: Duration::from_millis(150),
            jitter: false,
            ..Default::default()
        };

        let delay2 = config.calculate_delay(2);
        assert_eq!(delay2, Duration::from_millis(150));
    }

    #[test]
    fn test_is_transient_error() {
        assert!(is_transient_error(&DbError::PoolExhausted));
        assert!(is_transient_error(&DbError::Connection(
            "connection timeout".to_string()
        )));
        assert!(!is_transient_error(&DbError::NotFound {
            entity: "User".to_string(),
            id: "123".to_string()
        }));
        assert!(!is_transient_error(&DbError::Constraint(
            "duplicate key".to_string()
        )));
    }

    #[tokio::test]
    async fn test_with_retry_success() {
        let result = with_retry(RetryConfig::default(), "test_op", || async {
            Ok::<_, DbError>(42)
        })
        .await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_with_retry_immediate_failure() {
        let result = with_retry(RetryConfig::default(), "test_op", || async {
            Err::<i32, _>(DbError::NotFound {
                entity: "Test".to_string(),
                id: "1".to_string(),
            })
        })
        .await;
        assert!(matches!(result, Err(DbError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_with_retry_eventually_succeeds() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let config = RetryConfig {
            max_retries: 3,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };

        let result = with_retry(config, "test_op", || {
            let attempts = attempts_clone.clone();
            async move {
                let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                if attempt < 2 {
                    Err(DbError::PoolExhausted)
                } else {
                    Ok(42)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_with_retry_exhausted() {
        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = attempts.clone();

        let config = RetryConfig {
            max_retries: 2,
            initial_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            backoff_multiplier: 2.0,
            jitter: false,
        };

        let result = with_retry(config, "test_op", || {
            let attempts = attempts_clone.clone();
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err::<i32, _>(DbError::PoolExhausted)
            }
        })
        .await;

        assert!(matches!(result, Err(DbError::PoolExhausted)));
        assert_eq!(attempts.load(Ordering::SeqCst), 3); // Initial + 2 retries
    }
}
