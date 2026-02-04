//! Types for leader election.
//!
//! This module defines the core data structures used in leader election:
//! - `LeaderLease`: Represents ownership of leadership for a resource
//! - `LeaderInfo`: Information about the current leader of a resource
//! - `LeaderElectorConfig`: Configuration for a leader elector instance

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A lease representing leadership ownership of a resource.
///
/// A `LeaderLease` is acquired when an instance successfully becomes the leader
/// for a resource. The lease has a TTL (time-to-live) and must be renewed before
/// it expires to maintain leadership.
///
/// # Fencing Tokens
///
/// The `fencing_token` is a monotonically increasing value that prevents
/// split-brain scenarios. When an instance believes it is the leader but has
/// actually lost the lease due to network partitions or clock skew, the fencing
/// token allows downstream systems to reject stale requests from the old leader.
///
/// Each time a lease is acquired, the fencing token is incremented. Systems
/// processing leader requests should track the highest fencing token they've seen
/// and reject requests with lower tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderLease {
    /// The resource this lease is for (e.g., "scheduler", "metrics-aggregator").
    pub resource: String,

    /// The unique ID of the instance holding this lease.
    pub holder_id: String,

    /// When the lease was acquired.
    pub acquired_at: DateTime<Utc>,

    /// When the lease expires. Must be renewed before this time.
    pub expires_at: DateTime<Utc>,

    /// Monotonically increasing token for fencing against stale leaders.
    ///
    /// This value is incremented each time leadership is acquired for a resource.
    /// Downstream systems should reject operations from leaders with lower tokens.
    pub fencing_token: u64,
}

impl LeaderLease {
    /// Creates a new lease.
    pub fn new(
        resource: impl Into<String>,
        holder_id: impl Into<String>,
        ttl: Duration,
        fencing_token: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            resource: resource.into(),
            holder_id: holder_id.into(),
            acquired_at: now,
            expires_at: now
                + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30)),
            fencing_token,
        }
    }

    /// Returns `true` if the lease has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }

    /// Returns the remaining time before the lease expires.
    ///
    /// Returns `None` if the lease has already expired.
    pub fn time_remaining(&self) -> Option<Duration> {
        let remaining = self.expires_at - Utc::now();
        if remaining.num_milliseconds() <= 0 {
            None
        } else {
            remaining.to_std().ok()
        }
    }

    /// Returns `true` if the lease should be renewed soon.
    ///
    /// The recommended practice is to renew at TTL/2 to avoid gaps.
    pub fn should_renew(&self, original_ttl: Duration) -> bool {
        if let Some(remaining) = self.time_remaining() {
            remaining <= original_ttl / 2
        } else {
            true // Already expired, definitely should have renewed
        }
    }

    /// Extends the lease by the given duration from now.
    pub fn extend(&mut self, ttl: Duration) {
        self.expires_at =
            Utc::now() + chrono::Duration::from_std(ttl).unwrap_or(chrono::Duration::seconds(30));
    }
}

/// Information about the current leader of a resource.
///
/// This is a read-only view of leadership information that can be
/// retrieved without acquiring the lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderInfo {
    /// The unique ID of the instance that holds leadership.
    pub holder_id: String,

    /// When the leadership was acquired.
    pub acquired_at: DateTime<Utc>,

    /// When the leadership lease expires.
    pub expires_at: DateTime<Utc>,
}

impl LeaderInfo {
    /// Creates a new `LeaderInfo` from a lease.
    pub fn from_lease(lease: &LeaderLease) -> Self {
        Self {
            holder_id: lease.holder_id.clone(),
            acquired_at: lease.acquired_at,
            expires_at: lease.expires_at,
        }
    }

    /// Returns `true` if the leader's lease has expired.
    pub fn is_expired(&self) -> bool {
        Utc::now() >= self.expires_at
    }
}

/// Configuration for a leader elector instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderElectorConfig {
    /// Unique identifier for this instance.
    ///
    /// If not specified, defaults to hostname + process ID.
    pub instance_id: String,

    /// Default TTL for leases when not specified in `try_acquire`.
    #[serde(with = "humantime_serde")]
    pub default_ttl: Duration,

    /// How often to renew leases.
    ///
    /// Should be less than TTL/2 to ensure continuous leadership.
    #[serde(with = "humantime_serde")]
    pub renew_interval: Duration,
}

impl LeaderElectorConfig {
    /// Creates a new configuration with the specified instance ID.
    pub fn new(instance_id: impl Into<String>) -> Self {
        Self {
            instance_id: instance_id.into(),
            default_ttl: Duration::from_secs(30),
            renew_interval: Duration::from_secs(10),
        }
    }

    /// Creates a configuration with the default instance ID (hostname + PID).
    pub fn with_default_instance_id() -> Self {
        Self::new(default_instance_id())
    }

    /// Sets the default TTL for leases.
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Sets the renewal interval.
    pub fn with_renew_interval(mut self, interval: Duration) -> Self {
        self.renew_interval = interval;
        self
    }

    /// Validates the configuration.
    ///
    /// Returns an error if the configuration is invalid (e.g., renew_interval >= TTL/2).
    pub fn validate(&self) -> Result<(), String> {
        if self.instance_id.is_empty() {
            return Err("instance_id cannot be empty".to_string());
        }

        if self.default_ttl.is_zero() {
            return Err("default_ttl must be greater than zero".to_string());
        }

        if self.renew_interval.is_zero() {
            return Err("renew_interval must be greater than zero".to_string());
        }

        if self.renew_interval >= self.default_ttl / 2 {
            return Err(format!(
                "renew_interval ({:?}) should be less than default_ttl/2 ({:?})",
                self.renew_interval,
                self.default_ttl / 2
            ));
        }

        Ok(())
    }
}

impl Default for LeaderElectorConfig {
    fn default() -> Self {
        Self::with_default_instance_id()
    }
}

/// Generates the default instance ID from hostname and process ID.
pub fn default_instance_id() -> String {
    let hostname = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".to_string());
    let pid = std::process::id();
    format!("{}-{}", hostname, pid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leader_lease_creation() {
        let lease = LeaderLease::new("scheduler", "instance-1", Duration::from_secs(30), 1);

        assert_eq!(lease.resource, "scheduler");
        assert_eq!(lease.holder_id, "instance-1");
        assert_eq!(lease.fencing_token, 1);
        assert!(!lease.is_expired());
    }

    #[test]
    fn test_leader_lease_expiration() {
        let mut lease = LeaderLease::new("scheduler", "instance-1", Duration::from_secs(30), 1);

        // Manually set expires_at to the past
        lease.expires_at = Utc::now() - chrono::Duration::seconds(1);

        assert!(lease.is_expired());
        assert!(lease.time_remaining().is_none());
    }

    #[test]
    fn test_leader_lease_should_renew() {
        let ttl = Duration::from_secs(30);
        let lease = LeaderLease::new("scheduler", "instance-1", ttl, 1);

        // Just acquired, shouldn't need to renew yet
        assert!(!lease.should_renew(ttl));
    }

    #[test]
    fn test_leader_lease_should_renew_when_half_expired() {
        let ttl = Duration::from_secs(30);
        let mut lease = LeaderLease::new("scheduler", "instance-1", ttl, 1);

        // Set expires_at to 10 seconds from now (less than TTL/2 = 15s remaining)
        lease.expires_at = Utc::now() + chrono::Duration::seconds(10);

        assert!(lease.should_renew(ttl));
    }

    #[test]
    fn test_leader_lease_extend() {
        let mut lease = LeaderLease::new("scheduler", "instance-1", Duration::from_secs(5), 1);

        // Extend by 60 seconds
        lease.extend(Duration::from_secs(60));

        // Should have at least 59 seconds remaining
        let remaining = lease.time_remaining().unwrap();
        assert!(remaining.as_secs() >= 59);
    }

    #[test]
    fn test_leader_info_from_lease() {
        let lease = LeaderLease::new("scheduler", "instance-1", Duration::from_secs(30), 5);
        let info = LeaderInfo::from_lease(&lease);

        assert_eq!(info.holder_id, "instance-1");
        assert_eq!(info.acquired_at, lease.acquired_at);
        assert_eq!(info.expires_at, lease.expires_at);
    }

    #[test]
    fn test_leader_elector_config_new() {
        let config = LeaderElectorConfig::new("my-instance");

        assert_eq!(config.instance_id, "my-instance");
        assert_eq!(config.default_ttl, Duration::from_secs(30));
        assert_eq!(config.renew_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_leader_elector_config_builder() {
        let config = LeaderElectorConfig::new("my-instance")
            .with_default_ttl(Duration::from_secs(60))
            .with_renew_interval(Duration::from_secs(20));

        assert_eq!(config.default_ttl, Duration::from_secs(60));
        assert_eq!(config.renew_interval, Duration::from_secs(20));
    }

    #[test]
    fn test_leader_elector_config_validation() {
        let valid_config = LeaderElectorConfig::new("my-instance")
            .with_default_ttl(Duration::from_secs(30))
            .with_renew_interval(Duration::from_secs(10));
        assert!(valid_config.validate().is_ok());

        // Empty instance_id
        let invalid_config = LeaderElectorConfig::new("");
        assert!(invalid_config.validate().is_err());

        // renew_interval >= TTL/2
        let invalid_config = LeaderElectorConfig::new("my-instance")
            .with_default_ttl(Duration::from_secs(20))
            .with_renew_interval(Duration::from_secs(15));
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_default_instance_id() {
        let id = default_instance_id();

        // Should contain a dash (hostname-pid format)
        assert!(id.contains('-'));

        // Should end with the current process ID
        let pid = std::process::id().to_string();
        assert!(id.ends_with(&pid));
    }
}
