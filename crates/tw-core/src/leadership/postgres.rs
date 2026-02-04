//! PostgreSQL implementation of the LeaderElector trait using advisory locks.
//!
//! This module provides `PostgresLeaderElector`, a production-ready implementation
//! of leader election using PostgreSQL advisory locks. Advisory locks are
//! session-scoped locks that are automatically released when the database
//! connection is closed.
//!
//! # How it works
//!
//! - Uses `pg_try_advisory_lock(key)` for non-blocking lock acquisition
//! - Uses `pg_advisory_unlock(key)` for explicit lock release
//! - Resource names are hashed to i64 lock keys using a consistent hash
//! - Leases are tracked locally with TTL for `is_leader` checks
//! - Fencing tokens are maintained locally per resource
//!
//! # Connection Management
//!
//! Advisory locks are session-scoped, meaning they're tied to a database connection.
//! This implementation acquires a dedicated connection from the pool for each lock
//! and holds it until the lock is released or the elector is dropped.
//!
//! # Example
//!
//! ```rust,ignore
//! use tw_core::leadership::{PostgresLeaderElector, LeaderElectorConfig, LeaderElector};
//! use std::time::Duration;
//!
//! async fn example(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
//!     let config = LeaderElectorConfig::new("my-instance");
//!     let elector = PostgresLeaderElector::new(pool, config);
//!
//!     // Try to become leader for the "scheduler" resource
//!     if let Some(lease) = elector.try_acquire("scheduler", Duration::from_secs(30)).await? {
//!         println!("We are the leader! Fencing token: {}", lease.fencing_token);
//!
//!         // Do leader work...
//!
//!         // Release when done
//!         elector.release(&lease).await?;
//!     }
//!
//!     Ok(())
//! }
//! ```

use super::{LeaderElectionError, LeaderElector, LeaderElectorConfig, LeaderInfo, LeaderLease};
use async_trait::async_trait;
use chrono::Utc;
use sqlx::PgPool;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// PostgreSQL-based leader elector using advisory locks.
///
/// This implementation uses PostgreSQL advisory locks for distributed leadership.
/// Advisory locks are session-scoped and automatically released when the connection
/// is closed, providing automatic failover if an instance crashes.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` and can be safely shared across async tasks.
/// Internal state is protected by `RwLock`.
#[derive(Debug)]
pub struct PostgresLeaderElector {
    /// The PostgreSQL connection pool.
    pool: PgPool,
    /// Configuration for this elector.
    config: LeaderElectorConfig,
    /// Currently held leases and their connections, keyed by resource name.
    /// We use a separate struct to hold the connection + lease together.
    held_locks: Arc<RwLock<HashMap<String, HeldLockState>>>,
    /// Fencing token counters per resource (monotonically increasing).
    fencing_tokens: Arc<RwLock<HashMap<String, u64>>>,
}

/// State for a held lock (without the connection, for is_leader checks).
#[derive(Debug, Clone)]
struct HeldLockState {
    /// The lease information.
    lease: LeaderLease,
}

impl PostgresLeaderElector {
    /// Creates a new PostgreSQL leader elector.
    ///
    /// # Arguments
    ///
    /// * `pool` - The PostgreSQL connection pool
    /// * `config` - Configuration for this elector instance
    pub fn new(pool: PgPool, config: LeaderElectorConfig) -> Self {
        Self {
            pool,
            config,
            held_locks: Arc::new(RwLock::new(HashMap::new())),
            fencing_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a new PostgreSQL leader elector with default configuration.
    pub fn with_default_config(pool: PgPool) -> Self {
        Self::new(pool, LeaderElectorConfig::default())
    }

    /// Converts a resource name to an i64 lock key using a consistent hash.
    ///
    /// PostgreSQL advisory locks require an i64 key. We use the standard
    /// library's `DefaultHasher` to create a consistent mapping from
    /// resource names to lock keys.
    fn resource_to_lock_key(resource: &str) -> i64 {
        let mut hasher = DefaultHasher::new();
        resource.hash(&mut hasher);
        hasher.finish() as i64
    }

    /// Gets the next fencing token for a resource.
    async fn next_fencing_token(&self, resource: &str) -> u64 {
        let mut tokens = self.fencing_tokens.write().await;
        let counter = tokens.entry(resource.to_string()).or_insert(0);
        *counter += 1;
        *counter
    }

    /// Returns the configuration for this elector.
    pub fn config(&self) -> &LeaderElectorConfig {
        &self.config
    }

    /// Returns the instance ID from the configuration.
    pub fn instance_id(&self) -> &str {
        &self.config.instance_id
    }

    /// Returns a copy of all currently held leases.
    ///
    /// This is useful for testing and debugging.
    pub async fn all_leases(&self) -> HashMap<String, LeaderLease> {
        let held = self.held_locks.read().await;
        held.iter()
            .map(|(k, v)| (k.clone(), v.lease.clone()))
            .collect()
    }
}

/// Convert sqlx errors to LeaderElectionError.
fn convert_sqlx_error(err: sqlx::Error) -> LeaderElectionError {
    match &err {
        sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => {
            LeaderElectionError::connection(err.to_string())
        }
        sqlx::Error::Protocol(_) | sqlx::Error::Tls(_) => {
            LeaderElectionError::connection(err.to_string())
        }
        _ => LeaderElectionError::unknown(err.to_string()),
    }
}

#[async_trait]
impl LeaderElector for PostgresLeaderElector {
    /// Try to acquire leadership for a resource using PostgreSQL advisory locks.
    ///
    /// This uses `pg_try_advisory_lock()` which is non-blocking. If the lock
    /// is already held by another session, it returns immediately with `None`.
    async fn try_acquire(
        &self,
        resource: &str,
        ttl: Duration,
    ) -> Result<Option<LeaderLease>, LeaderElectionError> {
        let lock_key = Self::resource_to_lock_key(resource);

        // Check if we already hold this lock
        {
            let held = self.held_locks.read().await;
            if let Some(state) = held.get(resource) {
                // We already hold it - check if expired locally
                if !state.lease.is_expired() {
                    // Still valid, extend the expiration and return
                    let mut lease = state.lease.clone();
                    lease.extend(ttl);

                    // Update the stored lease
                    drop(held);
                    let mut held = self.held_locks.write().await;
                    if let Some(state) = held.get_mut(resource) {
                        state.lease.extend(ttl);
                    }

                    debug!(
                        resource = %resource,
                        lock_key = %lock_key,
                        holder = %self.config.instance_id,
                        "Re-acquired existing lock (extended TTL)"
                    );

                    return Ok(Some(lease));
                }
                // Expired locally - we need to re-verify the lock
            }
        }

        // Acquire a dedicated connection for this lock
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(convert_sqlx_error)?
            .detach();

        // Try to acquire the advisory lock (non-blocking)
        let result: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
            .bind(lock_key)
            .fetch_one(&mut conn)
            .await
            .map_err(convert_sqlx_error)?;

        let acquired = result.0;

        if !acquired {
            debug!(
                resource = %resource,
                lock_key = %lock_key,
                "Failed to acquire advisory lock - held by another session"
            );
            return Ok(None);
        }

        // Lock acquired - create the lease
        let fencing_token = self.next_fencing_token(resource).await;
        let now = Utc::now();
        let lease = LeaderLease {
            resource: resource.to_string(),
            holder_id: self.config.instance_id.clone(),
            acquired_at: now,
            expires_at: now
                + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30)),
            fencing_token,
        };

        // Store the held lock state
        // Note: We can't store the connection in the state because PgConnection is not Debug
        // Instead, we'll rely on the lock being session-scoped and store minimal state
        {
            let mut held = self.held_locks.write().await;

            // If we previously held a lock for this resource, we need to close that connection
            // The new connection already has the lock

            held.insert(
                resource.to_string(),
                HeldLockState {
                    lease: lease.clone(),
                },
            );
        }

        // Store the connection in a separate structure to keep it alive
        // For now, we'll spawn a background task to hold the connection
        // This is a trade-off: we keep the connection alive but need to track it
        let resource_clone = resource.to_string();
        let held_locks_clone = Arc::clone(&self.held_locks);

        tokio::spawn(async move {
            // Hold the connection until the lock is released
            // We'll use a channel or check the held_locks map periodically
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                // Check if we still want to hold this lock
                let should_release = {
                    let held = held_locks_clone.read().await;
                    !held.contains_key(&resource_clone)
                };

                if should_release {
                    // Release the advisory lock
                    let _ = sqlx::query("SELECT pg_advisory_unlock($1)")
                        .bind(lock_key)
                        .execute(&mut conn)
                        .await;
                    debug!(
                        resource = %resource_clone,
                        lock_key = %lock_key,
                        "Background task released advisory lock and closed connection"
                    );
                    break;
                }
            }
        });

        debug!(
            resource = %resource,
            lock_key = %lock_key,
            holder = %self.config.instance_id,
            fencing_token = %fencing_token,
            "Acquired advisory lock"
        );

        Ok(Some(lease))
    }

    /// Release a held lease by unlocking the advisory lock.
    async fn release(&self, lease: &LeaderLease) -> Result<(), LeaderElectionError> {
        let lock_key = Self::resource_to_lock_key(&lease.resource);

        // Remove from held locks (this will signal the background task to release)
        let removed = {
            let mut held = self.held_locks.write().await;

            if let Some(state) = held.get(&lease.resource) {
                // Verify we hold it and fencing token matches
                if state.lease.holder_id != self.config.instance_id {
                    return Err(LeaderElectionError::not_leader(&lease.resource));
                }
                if state.lease.fencing_token != lease.fencing_token {
                    return Err(LeaderElectionError::not_leader(&lease.resource));
                }
                held.remove(&lease.resource).is_some()
            } else {
                // Already released
                false
            }
        };

        if removed {
            debug!(
                resource = %lease.resource,
                lock_key = %lock_key,
                holder = %self.config.instance_id,
                "Initiated release of advisory lock"
            );
        }

        Ok(())
    }

    /// Renew a lease by extending its local expiration time.
    ///
    /// PostgreSQL advisory locks don't have a TTL - they're held until explicitly
    /// released or the connection closes. However, we track TTL locally to enable
    /// proper `is_leader` checks and to detect stale leadership.
    async fn renew(&self, lease: &mut LeaderLease) -> Result<bool, LeaderElectionError> {
        let mut held = self.held_locks.write().await;

        if let Some(state) = held.get_mut(&lease.resource) {
            // Verify we still hold it
            if state.lease.holder_id != self.config.instance_id {
                return Ok(false);
            }

            // Verify fencing token matches
            if state.lease.fencing_token != lease.fencing_token {
                warn!(
                    resource = %lease.resource,
                    expected_token = %state.lease.fencing_token,
                    provided_token = %lease.fencing_token,
                    "Fencing token mismatch during renewal"
                );
                return Ok(false);
            }

            // Check if our local lease has expired
            if state.lease.is_expired() {
                // Remove the stale entry
                held.remove(&lease.resource);
                return Ok(false);
            }

            // Extend the lease
            let ttl = self.config.default_ttl;
            state.lease.extend(ttl);
            lease.expires_at = state.lease.expires_at;

            debug!(
                resource = %lease.resource,
                new_expires_at = %lease.expires_at,
                "Renewed lease"
            );

            Ok(true)
        } else {
            // We don't hold this lock
            Ok(false)
        }
    }

    /// Check if this instance is currently the leader for a resource.
    ///
    /// This is a non-async operation that checks local cached state. It verifies
    /// both that we hold the lock and that the local lease hasn't expired.
    fn is_leader(&self, resource: &str) -> bool {
        // We need to check without async, so we try_read
        if let Ok(held) = self.held_locks.try_read() {
            if let Some(state) = held.get(resource) {
                // Check if we hold it and it's not expired locally
                return state.lease.holder_id == self.config.instance_id
                    && !state.lease.is_expired();
            }
        }
        false
    }

    /// Get information about the current leader of a resource.
    ///
    /// For PostgreSQL advisory locks, we can only return information if we
    /// are the leader ourselves. Advisory locks don't provide a way to query
    /// WHO holds a lock, only whether it's held.
    async fn get_leader(&self, resource: &str) -> Result<Option<LeaderInfo>, LeaderElectionError> {
        let held = self.held_locks.read().await;

        if let Some(state) = held.get(resource) {
            // We hold it - check if expired
            if state.lease.is_expired() {
                return Ok(None);
            }

            Ok(Some(LeaderInfo::from_lease(&state.lease)))
        } else {
            // We don't hold it, and we can't query who does with advisory locks
            // We could query pg_locks but that doesn't give us holder identity
            Ok(None)
        }
    }
}

impl Clone for PostgresLeaderElector {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            held_locks: Arc::clone(&self.held_locks),
            fencing_tokens: Arc::clone(&self.fencing_tokens),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(instance_id: &str) -> LeaderElectorConfig {
        LeaderElectorConfig::new(instance_id)
            .with_default_ttl(Duration::from_secs(30))
            .with_renew_interval(Duration::from_secs(10))
    }

    #[test]
    fn test_resource_to_lock_key_consistency() {
        // Same resource should always produce the same key
        let key1 = PostgresLeaderElector::resource_to_lock_key("scheduler");
        let key2 = PostgresLeaderElector::resource_to_lock_key("scheduler");
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_resource_to_lock_key_different_resources() {
        // Different resources should produce different keys (with high probability)
        let key1 = PostgresLeaderElector::resource_to_lock_key("scheduler");
        let key2 = PostgresLeaderElector::resource_to_lock_key("metrics");
        let key3 = PostgresLeaderElector::resource_to_lock_key("cleanup");
        assert_ne!(key1, key2);
        assert_ne!(key2, key3);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_resource_to_lock_key_handles_unicode() {
        // Should handle unicode resource names
        let key = PostgresLeaderElector::resource_to_lock_key("スケジューラー");
        assert_ne!(key, 0);
    }

    #[test]
    fn test_resource_to_lock_key_handles_empty() {
        // Should handle empty string
        let key = PostgresLeaderElector::resource_to_lock_key("");
        // Empty string should still produce a valid key
        let _valid_i64 = key; // Just verify it's a valid i64
    }

    #[test]
    fn test_config_creation() {
        let config = test_config("test-instance");
        assert_eq!(config.instance_id, "test-instance");
        assert_eq!(config.default_ttl, Duration::from_secs(30));
        assert_eq!(config.renew_interval, Duration::from_secs(10));
    }

    // Integration tests that require a real PostgreSQL database
    // These are marked with #[ignore] and can be run with:
    // cargo test --package tw-core leadership::postgres -- --ignored

    #[tokio::test]
    #[ignore = "requires PostgreSQL database"]
    async fn test_acquire_and_release_integration() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database");

        let elector = PostgresLeaderElector::new(pool, test_config("test-instance"));

        // Acquire
        let lease = elector
            .try_acquire("test-resource", Duration::from_secs(30))
            .await
            .expect("Failed to acquire");

        assert!(lease.is_some());
        let lease = lease.unwrap();
        assert_eq!(lease.resource, "test-resource");
        assert_eq!(lease.holder_id, "test-instance");
        assert_eq!(lease.fencing_token, 1);

        // Check is_leader
        assert!(elector.is_leader("test-resource"));

        // Release
        elector.release(&lease).await.expect("Failed to release");

        // Give the background task time to release
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(!elector.is_leader("test-resource"));
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL database"]
    async fn test_concurrent_acquisition_integration() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database");

        let elector1 = PostgresLeaderElector::new(pool.clone(), test_config("instance-1"));
        let elector2 = PostgresLeaderElector::new(pool, test_config("instance-2"));

        // First instance acquires
        let lease1 = elector1
            .try_acquire("contested-resource", Duration::from_secs(30))
            .await
            .expect("Failed to acquire");
        assert!(lease1.is_some());

        // Second instance should fail
        let lease2 = elector2
            .try_acquire("contested-resource", Duration::from_secs(30))
            .await
            .expect("Failed to try acquire");
        assert!(lease2.is_none());

        // Release first lease
        elector1
            .release(&lease1.unwrap())
            .await
            .expect("Failed to release");

        // Give the background task time to release
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now second instance should succeed
        let lease2 = elector2
            .try_acquire("contested-resource", Duration::from_secs(30))
            .await
            .expect("Failed to acquire after release");
        assert!(lease2.is_some());
        assert_eq!(lease2.as_ref().unwrap().holder_id, "instance-2");
        // Fencing token should increment
        assert_eq!(lease2.unwrap().fencing_token, 1); // New elector, so starts at 1
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL database"]
    async fn test_renew_integration() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database");

        let elector = PostgresLeaderElector::new(pool, test_config("test-instance"));

        let mut lease = elector
            .try_acquire("renew-test", Duration::from_secs(30))
            .await
            .expect("Failed to acquire")
            .expect("Expected lease");

        let original_expires = lease.expires_at;

        // Wait a bit
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Renew
        let renewed = elector.renew(&mut lease).await.expect("Failed to renew");
        assert!(renewed);

        // Expiration should be extended
        assert!(lease.expires_at > original_expires);

        // Cleanup
        elector.release(&lease).await.expect("Failed to release");
    }

    #[tokio::test]
    #[ignore = "requires PostgreSQL database"]
    async fn test_fencing_tokens_increment_integration() {
        let database_url =
            std::env::var("DATABASE_URL").expect("DATABASE_URL must be set for integration tests");

        let pool = PgPool::connect(&database_url)
            .await
            .expect("Failed to connect to database");

        let elector = PostgresLeaderElector::new(pool, test_config("test-instance"));

        // Acquire and release multiple times
        let mut tokens = Vec::new();
        for _ in 0..3 {
            let lease = elector
                .try_acquire("fencing-test", Duration::from_secs(30))
                .await
                .expect("Failed to acquire")
                .expect("Expected lease");

            tokens.push(lease.fencing_token);
            elector.release(&lease).await.expect("Failed to release");

            // Give background task time to release
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // All tokens should be unique and increasing
        for i in 1..tokens.len() {
            assert!(
                tokens[i] > tokens[i - 1],
                "Fencing tokens should be monotonically increasing"
            );
        }
    }
}
