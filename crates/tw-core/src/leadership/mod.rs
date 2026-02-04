//! Leader election for coordinating singleton tasks across multiple instances.
//!
//! This module provides the [`LeaderElector`] trait and related types for
//! implementing distributed leader election. In a horizontally scaled deployment,
//! only one instance should run certain singleton tasks like:
//!
//! - Scheduled jobs (e.g., periodic cleanup, report generation)
//! - Metrics aggregation
//! - Database maintenance tasks
//!
//! # Overview
//!
//! The leader election system uses a lease-based approach:
//!
//! 1. An instance attempts to acquire a **lease** for a specific **resource**
//! 2. If successful, it becomes the **leader** for that resource
//! 3. The lease has a **TTL** (time-to-live) and must be **renewed** before expiration
//! 4. If the leader fails to renew, another instance can acquire the lease
//!
//! # Fencing Tokens
//!
//! To prevent split-brain scenarios, each lease includes a **fencing token** -
//! a monotonically increasing number assigned on acquisition. If an old leader
//! experiences a network partition and believes it's still the leader, downstream
//! systems can reject its requests based on the stale fencing token.
//!
//! # Example
//!
//! ```rust,no_run
//! use tw_core::leadership::{LeaderElector, LeaderElectorConfig, MockLeaderElector};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = LeaderElectorConfig::new("my-instance");
//!     let elector = MockLeaderElector::new(config);
//!
//!     // Try to become leader for the "scheduler" resource
//!     let ttl = Duration::from_secs(30);
//!     if let Some(mut lease) = elector.try_acquire("scheduler", ttl).await? {
//!         println!("We are the leader! Fencing token: {}", lease.fencing_token);
//!
//!         // Do leader work...
//!
//!         // Periodically renew the lease
//!         if elector.renew(&mut lease).await? {
//!             println!("Lease renewed successfully");
//!         } else {
//!             println!("Lost leadership!");
//!         }
//!
//!         // When done, release the lease
//!         elector.release(&lease).await?;
//!     } else {
//!         println!("Another instance is already the leader");
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! # Implementations
//!
//! - [`MockLeaderElector`]: In-memory implementation for testing
//!
//! Production implementations (e.g., Redis, etcd, PostgreSQL) would be
//! provided in separate crates.

mod error;
mod mock;
#[cfg(feature = "database")]
mod postgres;
mod types;

pub use error::LeaderElectionError;
pub use mock::MockLeaderElector;
#[cfg(feature = "database")]
pub use postgres::PostgresLeaderElector;
pub use types::{default_instance_id, LeaderElectorConfig, LeaderInfo, LeaderLease};

use async_trait::async_trait;
use std::time::Duration;

/// Trait for implementing leader election across distributed instances.
///
/// This trait defines the interface for acquiring, renewing, and releasing
/// leadership leases for singleton resources. Implementations may use various
/// backends such as Redis, etcd, PostgreSQL, or in-memory storage for testing.
///
/// # Thread Safety
///
/// All implementations must be `Send + Sync + 'static` to allow sharing across
/// async tasks and threads.
///
/// # Lease Lifecycle
///
/// ```text
/// ┌─────────────┐     try_acquire()      ┌─────────────┐
/// │  No Leader  │ ────────────────────▶  │   Leader    │
/// └─────────────┘    (lease acquired)    └─────────────┘
///       ▲                                      │
///       │                                      │
///       │  release() or                        │ renew()
///       │  lease expires                       │ (periodically)
///       │                                      │
///       │                                      ▼
///       │                               ┌─────────────┐
///       └────────────────────────────── │   Leader    │
///                                       │  (renewed)  │
///                                       └─────────────┘
/// ```
#[async_trait]
pub trait LeaderElector: Send + Sync + 'static {
    /// Try to acquire leadership for a resource.
    ///
    /// If no other instance holds the lease (or the existing lease has expired),
    /// this instance becomes the leader and receives a [`LeaderLease`].
    ///
    /// # Arguments
    ///
    /// * `resource` - The name of the resource to lead (e.g., "scheduler", "metrics-aggregator")
    /// * `ttl` - How long the lease is valid before it must be renewed
    ///
    /// # Returns
    ///
    /// * `Ok(Some(lease))` - Leadership was acquired
    /// * `Ok(None)` - Another instance holds the lease (not expired)
    /// * `Err(e)` - An error occurred (connection, etc.)
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use tw_core::leadership::{LeaderElector, MockLeaderElector, LeaderElectorConfig};
    /// # use std::time::Duration;
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let elector = MockLeaderElector::new(LeaderElectorConfig::new("test"));
    /// match elector.try_acquire("scheduler", Duration::from_secs(30)).await? {
    ///     Some(lease) => println!("Acquired leadership with token {}", lease.fencing_token),
    ///     None => println!("Resource is held by another instance"),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn try_acquire(
        &self,
        resource: &str,
        ttl: Duration,
    ) -> Result<Option<LeaderLease>, LeaderElectionError>;

    /// Release a held lease, allowing other instances to acquire leadership.
    ///
    /// Call this when your instance is gracefully shutting down or no longer
    /// needs to be the leader. This allows another instance to acquire
    /// leadership immediately rather than waiting for the lease to expire.
    ///
    /// # Arguments
    ///
    /// * `lease` - The lease to release (must have been acquired by this instance)
    ///
    /// # Errors
    ///
    /// Returns [`LeaderElectionError::NotLeader`] if the lease is not held by
    /// this instance (e.g., it was taken by another instance after expiring).
    async fn release(&self, lease: &LeaderLease) -> Result<(), LeaderElectionError>;

    /// Renew a lease before it expires to maintain leadership.
    ///
    /// This should be called periodically (recommended: before TTL/2) to prevent
    /// the lease from expiring. If the lease has already expired or was taken
    /// by another instance, this returns `false`.
    ///
    /// # Arguments
    ///
    /// * `lease` - Mutable reference to the lease; `expires_at` is updated on success
    ///
    /// # Returns
    ///
    /// * `Ok(true)` - Lease was renewed successfully
    /// * `Ok(false)` - Lease was lost (expired or taken by another instance)
    /// * `Err(e)` - An error occurred
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use tw_core::leadership::{LeaderElector, MockLeaderElector, LeaderElectorConfig, LeaderLease};
    /// # use std::time::Duration;
    /// # async fn example(elector: &MockLeaderElector, lease: &mut LeaderLease) -> Result<(), Box<dyn std::error::Error>> {
    /// // Renew the lease
    /// if elector.renew(lease).await? {
    ///     println!("Still the leader, new expiration: {}", lease.expires_at);
    /// } else {
    ///     println!("Lost leadership, stopping leader tasks");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn renew(&self, lease: &mut LeaderLease) -> Result<bool, LeaderElectionError>;

    /// Check if this instance is currently the leader for a resource.
    ///
    /// This is a **non-async** operation that checks local cached state. It's
    /// designed for use in hot paths where async overhead is undesirable.
    ///
    /// **Note:** Due to the distributed nature of leader election, this may
    /// return stale results. For critical operations, use the fencing token
    /// from the lease instead.
    ///
    /// # Arguments
    ///
    /// * `resource` - The resource to check
    ///
    /// # Returns
    ///
    /// `true` if this instance believes it is the leader, `false` otherwise.
    fn is_leader(&self, resource: &str) -> bool;

    /// Get information about the current leader of a resource.
    ///
    /// This returns [`LeaderInfo`] containing the holder ID and lease timing
    /// information. Returns `None` if there is no current leader.
    ///
    /// # Arguments
    ///
    /// * `resource` - The resource to query
    ///
    /// # Returns
    ///
    /// * `Ok(Some(info))` - There is a current leader
    /// * `Ok(None)` - No leader (lease expired or never acquired)
    /// * `Err(e)` - An error occurred
    async fn get_leader(&self, resource: &str) -> Result<Option<LeaderInfo>, LeaderElectionError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify the trait is object-safe and can be used as a trait object.
    #[allow(dead_code)]
    fn assert_trait_object_safe(_: &dyn LeaderElector) {}

    /// Verify the trait bounds allow Arc wrapping.
    #[allow(dead_code)]
    fn assert_arc_compatible(_: std::sync::Arc<dyn LeaderElector>) {}
}
