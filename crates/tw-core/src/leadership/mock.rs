//! Mock implementation of the LeaderElector trait for testing.
//!
//! This module provides `MockLeaderElector`, an in-memory implementation
//! suitable for unit tests. It simulates time-based expiration and supports
//! testing scenarios with multiple contenders.

use super::{LeaderElectionError, LeaderElector, LeaderElectorConfig, LeaderInfo, LeaderLease};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Internal state for a held lease.
#[derive(Debug, Clone)]
pub(crate) struct LeaseState {
    /// The current lease.
    pub(crate) lease: LeaderLease,
}

/// A mock implementation of `LeaderElector` for testing.
///
/// This implementation uses in-memory state with thread-safe interior mutability
/// to simulate leader election behavior. It properly handles:
///
/// - Lease acquisition with fencing tokens
/// - Lease expiration based on real time
/// - Multiple contenders competing for leadership
/// - Lease renewal and release
///
/// # Example
///
/// ```rust
/// use tw_core::leadership::{MockLeaderElector, LeaderElectorConfig, LeaderElector};
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let config = LeaderElectorConfig::new("test-instance");
/// let elector = MockLeaderElector::new(config);
///
/// // Try to acquire leadership
/// if let Some(lease) = elector.try_acquire("scheduler", Duration::from_secs(30)).await? {
///     println!("Acquired leadership with token {}", lease.fencing_token);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct MockLeaderElector {
    /// Configuration for this elector.
    pub(crate) config: LeaderElectorConfig,

    /// Currently held leases, keyed by resource name.
    pub(crate) leases: Arc<RwLock<HashMap<String, LeaseState>>>,

    /// Global fencing token counter per resource.
    /// Monotonically increasing to ensure uniqueness across all acquisitions.
    pub(crate) fencing_tokens: Arc<RwLock<HashMap<String, AtomicU64>>>,

    /// Optional time override for testing.
    /// If set, this is used instead of Utc::now() for expiration checks.
    pub(crate) time_override: Arc<RwLock<Option<DateTime<Utc>>>>,
}

impl MockLeaderElector {
    /// Creates a new mock leader elector with the given configuration.
    pub fn new(config: LeaderElectorConfig) -> Self {
        Self {
            config,
            leases: Arc::new(RwLock::new(HashMap::new())),
            fencing_tokens: Arc::new(RwLock::new(HashMap::new())),
            time_override: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a new mock leader elector with default configuration.
    pub fn with_default_config() -> Self {
        Self::new(LeaderElectorConfig::default())
    }

    /// Sets a time override for testing time-based behavior.
    ///
    /// When set, this time is used instead of the real current time for
    /// expiration checks. This allows testing lease expiration without
    /// waiting for actual time to pass.
    pub async fn set_time_override(&self, time: DateTime<Utc>) {
        let mut override_lock = self.time_override.write().await;
        *override_lock = Some(time);
    }

    /// Clears the time override, returning to real-time behavior.
    pub async fn clear_time_override(&self) {
        let mut override_lock = self.time_override.write().await;
        *override_lock = None;
    }

    /// Advances the simulated time by the given duration.
    ///
    /// If no time override is set, this sets it to now + duration.
    pub async fn advance_time(&self, duration: Duration) {
        let mut override_lock = self.time_override.write().await;
        let current = override_lock.unwrap_or_else(Utc::now);
        *override_lock = Some(
            current + chrono::Duration::from_std(duration).unwrap_or(chrono::Duration::seconds(0)),
        );
    }

    /// Gets the current time, considering any override.
    async fn current_time(&self) -> DateTime<Utc> {
        self.time_override.read().await.unwrap_or_else(Utc::now)
    }

    /// Checks if a lease is expired at the current (possibly overridden) time.
    async fn is_lease_expired(&self, lease: &LeaderLease) -> bool {
        self.current_time().await >= lease.expires_at
    }

    /// Gets the next fencing token for a resource.
    async fn next_fencing_token(&self, resource: &str) -> u64 {
        let mut tokens = self.fencing_tokens.write().await;
        let counter = tokens
            .entry(resource.to_string())
            .or_insert_with(|| AtomicU64::new(0));
        counter.fetch_add(1, Ordering::SeqCst) + 1
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
        let leases = self.leases.read().await;
        leases
            .iter()
            .map(|(k, v)| (k.clone(), v.lease.clone()))
            .collect()
    }

    /// Clears all leases. Useful for resetting state between tests.
    pub async fn clear_all(&self) {
        let mut leases = self.leases.write().await;
        leases.clear();
    }
}

#[async_trait]
impl LeaderElector for MockLeaderElector {
    /// Try to acquire leadership for a resource.
    ///
    /// Returns `Some(LeaderLease)` if leadership was acquired, or `None` if
    /// the resource is already held by another instance and the lease hasn't expired.
    async fn try_acquire(
        &self,
        resource: &str,
        ttl: Duration,
    ) -> Result<Option<LeaderLease>, LeaderElectionError> {
        let mut leases = self.leases.write().await;

        // Check if there's an existing lease
        if let Some(state) = leases.get(resource) {
            // If held by someone else and not expired, we can't acquire
            if state.lease.holder_id != self.config.instance_id
                && !self.is_lease_expired(&state.lease).await
            {
                return Ok(None);
            }

            // If held by us, we can re-acquire (this is idempotent)
            if state.lease.holder_id == self.config.instance_id
                && !self.is_lease_expired(&state.lease).await
            {
                // Return existing lease (maybe with extended time)
                let mut lease = state.lease.clone();
                let now = self.current_time().await;
                lease.expires_at =
                    now + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30));
                leases.insert(
                    resource.to_string(),
                    LeaseState {
                        lease: lease.clone(),
                    },
                );
                return Ok(Some(lease));
            }
        }

        // Acquire new lease
        let fencing_token = self.next_fencing_token(resource).await;
        let now = self.current_time().await;
        let lease = LeaderLease {
            resource: resource.to_string(),
            holder_id: self.config.instance_id.clone(),
            acquired_at: now,
            expires_at: now
                + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30)),
            fencing_token,
        };

        leases.insert(
            resource.to_string(),
            LeaseState {
                lease: lease.clone(),
            },
        );

        Ok(Some(lease))
    }

    /// Release a held lease.
    ///
    /// This allows other instances to immediately acquire leadership without
    /// waiting for the lease to expire.
    async fn release(&self, lease: &LeaderLease) -> Result<(), LeaderElectionError> {
        let mut leases = self.leases.write().await;

        if let Some(state) = leases.get(&lease.resource) {
            // Verify this elector instance is the one that holds the lease
            if state.lease.holder_id != self.config.instance_id {
                return Err(LeaderElectionError::not_leader(&lease.resource));
            }

            // Verify the provided lease matches our current lease
            if state.lease.holder_id != lease.holder_id {
                return Err(LeaderElectionError::not_leader(&lease.resource));
            }

            // Verify fencing token matches (prevent releasing with stale lease)
            if state.lease.fencing_token != lease.fencing_token {
                return Err(LeaderElectionError::NotLeader {
                    resource: lease.resource.clone(),
                });
            }

            leases.remove(&lease.resource);
            Ok(())
        } else {
            // Lease doesn't exist (already released or expired)
            Ok(())
        }
    }

    /// Renew a lease before it expires.
    ///
    /// Returns `true` if the renewal succeeded, `false` if the lease was lost
    /// (either expired or taken by another instance).
    async fn renew(&self, lease: &mut LeaderLease) -> Result<bool, LeaderElectionError> {
        let mut leases = self.leases.write().await;

        if let Some(state) = leases.get(&lease.resource) {
            // Verify we still hold the lease
            if state.lease.holder_id != lease.holder_id {
                return Ok(false);
            }

            // Verify fencing token matches
            if state.lease.fencing_token != lease.fencing_token {
                return Ok(false);
            }

            // Check if expired
            if self.is_lease_expired(&state.lease).await {
                leases.remove(&lease.resource);
                return Ok(false);
            }

            // Extend the lease
            let now = self.current_time().await;
            let new_expires_at = now
                + chrono::Duration::from_std(self.config.default_ttl)
                    .unwrap_or(chrono::Duration::seconds(30));

            let mut updated_lease = state.lease.clone();
            updated_lease.expires_at = new_expires_at;

            leases.insert(
                lease.resource.clone(),
                LeaseState {
                    lease: updated_lease.clone(),
                },
            );

            // Update the caller's lease
            lease.expires_at = new_expires_at;

            Ok(true)
        } else {
            // Lease doesn't exist anymore
            Ok(false)
        }
    }

    /// Check if this instance is currently leader for a resource.
    ///
    /// This is a non-async operation that checks local state. Note that due to
    /// the distributed nature of leader election, this may return stale results
    /// if the lease has expired but hasn't been cleaned up yet.
    fn is_leader(&self, resource: &str) -> bool {
        // We need to check without async, so we try to acquire the lock
        // In a real implementation, this would check local cached state
        if let Ok(leases) = self.leases.try_read() {
            if let Some(state) = leases.get(resource) {
                // Check if we hold it and it's not obviously expired
                // Note: We can't check time override without async, so we use real time
                return state.lease.holder_id == self.config.instance_id
                    && Utc::now() < state.lease.expires_at;
            }
        }
        false
    }

    /// Get current leader info for a resource.
    ///
    /// Returns `Some(LeaderInfo)` if there's a current leader, `None` otherwise.
    async fn get_leader(&self, resource: &str) -> Result<Option<LeaderInfo>, LeaderElectionError> {
        let leases = self.leases.read().await;

        if let Some(state) = leases.get(resource) {
            // Check if expired
            if self.is_lease_expired(&state.lease).await {
                return Ok(None);
            }

            Ok(Some(LeaderInfo::from_lease(&state.lease)))
        } else {
            Ok(None)
        }
    }
}

impl Clone for MockLeaderElector {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            leases: Arc::clone(&self.leases),
            fencing_tokens: Arc::clone(&self.fencing_tokens),
            time_override: Arc::clone(&self.time_override),
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

    #[tokio::test]
    async fn test_acquire_leadership() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let lease = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();

        assert!(lease.is_some());
        let lease = lease.unwrap();
        assert_eq!(lease.resource, "scheduler");
        assert_eq!(lease.holder_id, "instance-1");
        assert_eq!(lease.fencing_token, 1);
    }

    #[tokio::test]
    async fn test_cannot_acquire_held_lease() {
        let elector1 = MockLeaderElector::new(test_config("instance-1"));
        let elector2 = MockLeaderElector {
            config: test_config("instance-2"),
            leases: Arc::clone(&elector1.leases),
            fencing_tokens: Arc::clone(&elector1.fencing_tokens),
            time_override: Arc::clone(&elector1.time_override),
        };

        // Instance 1 acquires
        let lease1 = elector1
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(lease1.is_some());

        // Instance 2 cannot acquire
        let lease2 = elector2
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(lease2.is_none());
    }

    #[tokio::test]
    async fn test_acquire_after_expiration() {
        let elector1 = MockLeaderElector::new(test_config("instance-1"));
        let elector2 = MockLeaderElector {
            config: test_config("instance-2"),
            leases: Arc::clone(&elector1.leases),
            fencing_tokens: Arc::clone(&elector1.fencing_tokens),
            time_override: Arc::clone(&elector1.time_override),
        };

        // Instance 1 acquires with short TTL
        let _lease1 = elector1
            .try_acquire("scheduler", Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();

        // Advance time past expiration
        elector1.advance_time(Duration::from_secs(5)).await;

        // Instance 2 can now acquire
        let lease2 = elector2
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(lease2.is_some());
        let lease2 = lease2.unwrap();
        assert_eq!(lease2.holder_id, "instance-2");
        // Fencing token should increment
        assert_eq!(lease2.fencing_token, 2);
    }

    #[tokio::test]
    async fn test_release_lease() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let lease = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        // Release
        elector.release(&lease).await.unwrap();

        // Can re-acquire immediately
        let new_lease = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();
        assert!(new_lease.is_some());
        // Fencing token increments
        assert_eq!(new_lease.unwrap().fencing_token, 2);
    }

    #[tokio::test]
    async fn test_release_by_non_holder_fails() {
        let elector1 = MockLeaderElector::new(test_config("instance-1"));
        let elector2 = MockLeaderElector {
            config: test_config("instance-2"),
            leases: Arc::clone(&elector1.leases),
            fencing_tokens: Arc::clone(&elector1.fencing_tokens),
            time_override: Arc::clone(&elector1.time_override),
        };

        let lease = elector1
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        // Instance 2 tries to release instance 1's lease
        let result = elector2.release(&lease).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(LeaderElectionError::NotLeader { .. })));
    }

    #[tokio::test]
    async fn test_renew_lease() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let mut lease = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        let original_expires = lease.expires_at;

        // Advance time a bit
        elector.advance_time(Duration::from_secs(10)).await;

        // Renew
        let renewed = elector.renew(&mut lease).await.unwrap();
        assert!(renewed);

        // Expiration should be extended
        assert!(lease.expires_at > original_expires);
    }

    #[tokio::test]
    async fn test_renew_expired_lease_fails() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let mut lease = elector
            .try_acquire("scheduler", Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();

        // Advance time past expiration
        elector.advance_time(Duration::from_secs(5)).await;

        // Renew should fail
        let renewed = elector.renew(&mut lease).await.unwrap();
        assert!(!renewed);
    }

    #[tokio::test]
    async fn test_is_leader() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        assert!(!elector.is_leader("scheduler"));

        elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();

        assert!(elector.is_leader("scheduler"));
    }

    #[tokio::test]
    async fn test_get_leader() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        // No leader initially
        let leader = elector.get_leader("scheduler").await.unwrap();
        assert!(leader.is_none());

        // Acquire and check
        elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();

        let leader = elector.get_leader("scheduler").await.unwrap();
        assert!(leader.is_some());
        assert_eq!(leader.unwrap().holder_id, "instance-1");
    }

    #[tokio::test]
    async fn test_get_leader_expired() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        elector
            .try_acquire("scheduler", Duration::from_secs(1))
            .await
            .unwrap();

        // Advance time past expiration
        elector.advance_time(Duration::from_secs(5)).await;

        let leader = elector.get_leader("scheduler").await.unwrap();
        assert!(leader.is_none());
    }

    #[tokio::test]
    async fn test_fencing_tokens_monotonic() {
        let elector1 = MockLeaderElector::new(test_config("instance-1"));
        let elector2 = MockLeaderElector {
            config: test_config("instance-2"),
            leases: Arc::clone(&elector1.leases),
            fencing_tokens: Arc::clone(&elector1.fencing_tokens),
            time_override: Arc::clone(&elector1.time_override),
        };

        let mut tokens = Vec::new();

        // Acquire and release multiple times
        for _ in 0..3 {
            let lease = elector1
                .try_acquire("scheduler", Duration::from_secs(1))
                .await
                .unwrap()
                .unwrap();
            tokens.push(lease.fencing_token);
            elector1.release(&lease).await.unwrap();
        }

        // Another instance acquires
        let lease = elector2
            .try_acquire("scheduler", Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        tokens.push(lease.fencing_token);

        // All tokens should be unique and increasing
        for i in 1..tokens.len() {
            assert!(
                tokens[i] > tokens[i - 1],
                "Tokens should be monotonically increasing"
            );
        }
    }

    #[tokio::test]
    async fn test_multiple_resources() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let lease1 = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        let lease2 = elector
            .try_acquire("metrics", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(lease1.resource, "scheduler");
        assert_eq!(lease2.resource, "metrics");

        // Each resource has its own fencing token counter
        assert_eq!(lease1.fencing_token, 1);
        assert_eq!(lease2.fencing_token, 1);
    }

    #[tokio::test]
    async fn test_idempotent_acquire() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        let lease1 = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();
        let lease2 = elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap()
            .unwrap();

        // Same holder, same fencing token
        assert_eq!(lease1.holder_id, lease2.holder_id);
        assert_eq!(lease1.fencing_token, lease2.fencing_token);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let elector = MockLeaderElector::new(test_config("instance-1"));

        elector
            .try_acquire("scheduler", Duration::from_secs(30))
            .await
            .unwrap();
        elector
            .try_acquire("metrics", Duration::from_secs(30))
            .await
            .unwrap();

        assert_eq!(elector.all_leases().await.len(), 2);

        elector.clear_all().await;

        assert_eq!(elector.all_leases().await.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_acquisition() {
        use tokio::task::JoinSet;

        // Shared state between elector instances
        let base_elector = MockLeaderElector::new(test_config("instance-0"));

        let mut tasks = JoinSet::new();

        // Spawn 10 concurrent acquisition attempts
        for i in 0..10 {
            let elector = MockLeaderElector {
                config: test_config(&format!("instance-{}", i)),
                leases: Arc::clone(&base_elector.leases),
                fencing_tokens: Arc::clone(&base_elector.fencing_tokens),
                time_override: Arc::clone(&base_elector.time_override),
            };

            tasks.spawn(async move {
                elector
                    .try_acquire("scheduler", Duration::from_secs(30))
                    .await
            });
        }

        let mut successes = 0;
        while let Some(result) = tasks.join_next().await {
            if result.unwrap().unwrap().is_some() {
                successes += 1;
            }
        }

        // Only one should succeed
        assert_eq!(successes, 1);
    }
}
