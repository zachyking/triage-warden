//! Rate limiting for login and API endpoints.
//!
//! This module provides rate limiting using the governor crate to protect
//! against brute force attacks on login and excessive API usage.

use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    num::NonZeroU32,
    sync::{Arc, RwLock},
    time::Duration,
};

/// Default per-IP login attempt limit (attempts per minute).
pub const DEFAULT_LOGIN_RATE_PER_IP: u32 = 5;

/// Default global login attempt limit (attempts per minute).
pub const DEFAULT_LOGIN_RATE_GLOBAL: u32 = 100;

/// Default rate limit window in seconds.
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Per-IP rate limiter type.
type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Login rate limiter that provides both per-IP and global rate limiting.
///
/// # Rate Limits
///
/// - **Per-IP**: Limits login attempts from a single IP address (default: 5/minute)
/// - **Global**: Limits total login attempts across all IPs (default: 100/minute)
///
/// Both limits must pass for a login attempt to be allowed.
#[derive(Clone)]
pub struct LoginRateLimiter {
    /// Per-IP rate limiters, keyed by IP address.
    per_ip: Arc<RwLock<HashMap<IpAddr, Arc<IpRateLimiter>>>>,
    /// Global rate limiter for all login attempts.
    global: Arc<IpRateLimiter>,
    /// Per-IP rate limit (attempts per window).
    per_ip_limit: u32,
    /// Rate limit window duration.
    window: Duration,
}

impl LoginRateLimiter {
    /// Creates a new login rate limiter with default settings.
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_LOGIN_RATE_PER_IP,
            DEFAULT_LOGIN_RATE_GLOBAL,
            Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
        )
    }

    /// Creates a new login rate limiter with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `per_ip_limit` - Maximum login attempts per IP per window
    /// * `global_limit` - Maximum total login attempts per window
    /// * `window` - Rate limit window duration
    pub fn with_config(per_ip_limit: u32, global_limit: u32, window: Duration) -> Self {
        let global_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(global_limit).expect("Global limit must be > 0"));

        Self {
            per_ip: Arc::new(RwLock::new(HashMap::new())),
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_ip_limit,
            window,
        }
    }

    /// Checks if a login attempt from the given IP should be allowed.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the attempt is allowed
    /// - `Err(RateLimitError::PerIpLimitExceeded)` if per-IP limit exceeded
    /// - `Err(RateLimitError::GlobalLimitExceeded)` if global limit exceeded
    pub fn check(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        // Check global limit first
        if self.global.check().is_err() {
            tracing::warn!(
                ip = %ip,
                "Global login rate limit exceeded"
            );
            return Err(RateLimitError::GlobalLimitExceeded);
        }

        // Get or create per-IP limiter
        let limiter = self.get_or_create_ip_limiter(ip);

        // Check per-IP limit
        if limiter.check().is_err() {
            tracing::warn!(
                ip = %ip,
                limit = self.per_ip_limit,
                window_secs = self.window.as_secs(),
                "Per-IP login rate limit exceeded"
            );
            return Err(RateLimitError::PerIpLimitExceeded);
        }

        Ok(())
    }

    /// Gets or creates a rate limiter for the given IP address.
    fn get_or_create_ip_limiter(&self, ip: IpAddr) -> Arc<IpRateLimiter> {
        // Try read lock first for the common case (limiter exists)
        {
            let limiters = self.per_ip.read().unwrap();
            if let Some(limiter) = limiters.get(&ip) {
                return limiter.clone();
            }
        }

        // Need to create a new limiter - take write lock
        let mut limiters = self.per_ip.write().unwrap();

        // Check again in case another thread created it
        if let Some(limiter) = limiters.get(&ip) {
            return limiter.clone();
        }

        // Create new limiter for this IP
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(self.per_ip_limit).expect("Per-IP limit must be > 0"));

        let limiter = Arc::new(RateLimiter::direct(quota));
        limiters.insert(ip, limiter.clone());

        limiter
    }

    /// Clears rate limit state for an IP (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_ip(&self, ip: IpAddr) {
        let mut limiters = self.per_ip.write().unwrap();
        limiters.remove(&ip);
    }

    /// Returns the number of IPs being tracked.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.read().unwrap().len()
    }

    /// Cleans up old IP entries. Should be called periodically.
    ///
    /// This is a simple cleanup that removes entries for IPs that haven't been
    /// seen in a while. In production, consider using a more sophisticated
    /// approach like an LRU cache.
    #[allow(dead_code)]
    pub fn cleanup(&self, max_entries: usize) {
        let mut limiters = self.per_ip.write().unwrap();
        if limiters.len() > max_entries {
            // Simple strategy: clear all and let them rebuild
            // A production system might use LRU eviction
            limiters.clear();
            tracing::info!(max_entries = max_entries, "Cleared rate limiter IP cache");
        }
    }
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during rate limit checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitError {
    /// Per-IP rate limit exceeded.
    PerIpLimitExceeded,
    /// Global rate limit exceeded.
    GlobalLimitExceeded,
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitError::PerIpLimitExceeded => {
                write!(
                    f,
                    "Too many login attempts from this IP. Please try again later."
                )
            }
            RateLimitError::GlobalLimitExceeded => {
                write!(
                    f,
                    "Server is experiencing high load. Please try again later."
                )
            }
        }
    }
}

impl std::error::Error for RateLimitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_rate_limiter_allows_within_limit() {
        let limiter = LoginRateLimiter::with_config(5, 100, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow 5 attempts
        for _ in 0..5 {
            assert!(limiter.check(ip).is_ok());
        }
    }

    #[test]
    fn test_rate_limiter_blocks_over_ip_limit() {
        let limiter = LoginRateLimiter::with_config(3, 100, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check(ip).is_ok());
        }

        // 4th should fail
        assert_eq!(limiter.check(ip), Err(RateLimitError::PerIpLimitExceeded));
    }

    #[test]
    fn test_rate_limiter_different_ips_independent() {
        let limiter = LoginRateLimiter::with_config(2, 100, Duration::from_secs(60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));

        // Each IP should get its own limit
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip1).is_err()); // ip1 exhausted

        assert!(limiter.check(ip2).is_ok()); // ip2 still has quota
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip2).is_err()); // ip2 exhausted
    }

    #[test]
    fn test_global_rate_limit() {
        let limiter = LoginRateLimiter::with_config(10, 3, Duration::from_secs(60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));

        // Per-IP limit is 10, but global is 3
        assert!(limiter.check(ip1).is_ok());
        assert!(limiter.check(ip2).is_ok());
        assert!(limiter.check(ip3).is_ok());

        // Global limit reached - any IP should fail
        assert_eq!(limiter.check(ip4), Err(RateLimitError::GlobalLimitExceeded));
    }

    #[test]
    fn test_clear_ip() {
        let limiter = LoginRateLimiter::with_config(2, 100, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust limit
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_ok());
        assert!(limiter.check(ip).is_err());

        // Clear should allow new attempts (though internal state persists,
        // clearing removes the old limiter)
        limiter.clear_ip(ip);
        assert!(limiter.check(ip).is_ok());
    }

    #[test]
    fn test_tracked_ips() {
        let limiter = LoginRateLimiter::new();

        assert_eq!(limiter.tracked_ips(), 0);

        limiter.check(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).ok();
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.check(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))).ok();
        assert_eq!(limiter.tracked_ips(), 2);

        // Same IP doesn't add new entry
        limiter.check(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).ok();
        assert_eq!(limiter.tracked_ips(), 2);
    }
}
