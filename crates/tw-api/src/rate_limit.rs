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
use uuid::Uuid;

/// Default per-IP login attempt limit (attempts per minute).
pub const DEFAULT_LOGIN_RATE_PER_IP: u32 = 5;

/// Default global login attempt limit (attempts per minute).
pub const DEFAULT_LOGIN_RATE_GLOBAL: u32 = 100;

/// Default rate limit window in seconds.
pub const DEFAULT_RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Default per-IP API request limit (requests per minute).
pub const DEFAULT_API_RATE_PER_IP: u32 = 100;

/// Default per-user API request limit (requests per minute).
pub const DEFAULT_API_RATE_PER_USER: u32 = 200;

/// Default webhook request limit (requests per minute).
pub const DEFAULT_WEBHOOK_RATE: u32 = 1000;

/// Default global API request limit (requests per minute).
pub const DEFAULT_API_RATE_GLOBAL: u32 = 10000;

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

/// API rate limiter that provides per-IP, per-user, webhook, and global rate limiting.
///
/// # Rate Limits
///
/// - **Per-IP**: Limits requests from a single IP address (default: 100/minute)
/// - **Per-User**: Limits requests from a single authenticated user (default: 200/minute)
/// - **Webhook**: Limits webhook requests (default: 1000/minute)
/// - **Global**: Limits total API requests across all sources (default: 10000/minute)
///
/// Multiple limits are checked and all must pass for a request to be allowed.
#[derive(Clone)]
pub struct ApiRateLimiter {
    /// Per-IP rate limiters, keyed by IP address.
    per_ip: Arc<RwLock<HashMap<IpAddr, Arc<IpRateLimiter>>>>,
    /// Per-user rate limiters, keyed by user ID.
    per_user: Arc<RwLock<HashMap<Uuid, Arc<IpRateLimiter>>>>,
    /// Webhook rate limiter.
    webhook: Arc<IpRateLimiter>,
    /// Global rate limiter for all API requests.
    global: Arc<IpRateLimiter>,
    /// Per-IP rate limit (requests per window).
    per_ip_limit: u32,
    /// Per-user rate limit (requests per window).
    per_user_limit: u32,
    /// Rate limit window duration.
    window: Duration,
}

impl ApiRateLimiter {
    /// Creates a new API rate limiter with default settings.
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_API_RATE_PER_IP,
            DEFAULT_API_RATE_PER_USER,
            DEFAULT_WEBHOOK_RATE,
            DEFAULT_API_RATE_GLOBAL,
            Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
        )
    }

    /// Creates a new API rate limiter with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `per_ip_limit` - Maximum requests per IP per window
    /// * `per_user_limit` - Maximum requests per user per window
    /// * `webhook_limit` - Maximum webhook requests per window
    /// * `global_limit` - Maximum total requests per window
    /// * `window` - Rate limit window duration
    pub fn with_config(
        per_ip_limit: u32,
        per_user_limit: u32,
        webhook_limit: u32,
        global_limit: u32,
        window: Duration,
    ) -> Self {
        let webhook_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(webhook_limit).expect("Webhook limit must be > 0"));

        let global_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(global_limit).expect("Global limit must be > 0"));

        Self {
            per_ip: Arc::new(RwLock::new(HashMap::new())),
            per_user: Arc::new(RwLock::new(HashMap::new())),
            webhook: Arc::new(RateLimiter::direct(webhook_quota)),
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_ip_limit,
            per_user_limit,
            window,
        }
    }

    /// Checks if an API request from the given IP should be allowed.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the request is allowed
    /// - `Err(ApiRateLimitError)` if any rate limit is exceeded
    pub fn check_ip(&self, ip: IpAddr) -> Result<(), ApiRateLimitError> {
        // Check global limit first
        if self.global.check().is_err() {
            tracing::warn!(ip = %ip, "Global API rate limit exceeded");
            return Err(ApiRateLimitError::GlobalLimitExceeded);
        }

        // Get or create per-IP limiter
        let limiter = self.get_or_create_ip_limiter(ip);

        // Check per-IP limit
        if limiter.check().is_err() {
            tracing::warn!(
                ip = %ip,
                limit = self.per_ip_limit,
                window_secs = self.window.as_secs(),
                "Per-IP API rate limit exceeded"
            );
            return Err(ApiRateLimitError::PerIpLimitExceeded);
        }

        Ok(())
    }

    /// Checks if an API request from the given user should be allowed.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the request is allowed
    /// - `Err(ApiRateLimitError)` if any rate limit is exceeded
    pub fn check_user(&self, user_id: Uuid, ip: IpAddr) -> Result<(), ApiRateLimitError> {
        // First check IP-based limits
        self.check_ip(ip)?;

        // Get or create per-user limiter
        let limiter = self.get_or_create_user_limiter(user_id);

        // Check per-user limit
        if limiter.check().is_err() {
            tracing::warn!(
                user_id = %user_id,
                limit = self.per_user_limit,
                window_secs = self.window.as_secs(),
                "Per-user API rate limit exceeded"
            );
            return Err(ApiRateLimitError::PerUserLimitExceeded);
        }

        Ok(())
    }

    /// Checks if a webhook request should be allowed.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the request is allowed
    /// - `Err(ApiRateLimitError)` if the webhook rate limit is exceeded
    pub fn check_webhook(&self, ip: IpAddr) -> Result<(), ApiRateLimitError> {
        // Check global limit first
        if self.global.check().is_err() {
            tracing::warn!(ip = %ip, "Global API rate limit exceeded for webhook");
            return Err(ApiRateLimitError::GlobalLimitExceeded);
        }

        // Check webhook-specific limit
        if self.webhook.check().is_err() {
            tracing::warn!(ip = %ip, "Webhook rate limit exceeded");
            return Err(ApiRateLimitError::WebhookLimitExceeded);
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

    /// Gets or creates a rate limiter for the given user ID.
    fn get_or_create_user_limiter(&self, user_id: Uuid) -> Arc<IpRateLimiter> {
        // Try read lock first for the common case (limiter exists)
        {
            let limiters = self.per_user.read().unwrap();
            if let Some(limiter) = limiters.get(&user_id) {
                return limiter.clone();
            }
        }

        // Need to create a new limiter - take write lock
        let mut limiters = self.per_user.write().unwrap();

        // Check again in case another thread created it
        if let Some(limiter) = limiters.get(&user_id) {
            return limiter.clone();
        }

        // Create new limiter for this user
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(self.per_user_limit).expect("Per-user limit must be > 0"));

        let limiter = Arc::new(RateLimiter::direct(quota));
        limiters.insert(user_id, limiter.clone());

        limiter
    }

    /// Clears rate limit state for an IP (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_ip(&self, ip: IpAddr) {
        let mut limiters = self.per_ip.write().unwrap();
        limiters.remove(&ip);
    }

    /// Clears rate limit state for a user (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_user(&self, user_id: Uuid) {
        let mut limiters = self.per_user.write().unwrap();
        limiters.remove(&user_id);
    }

    /// Returns the number of IPs being tracked.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.read().unwrap().len()
    }

    /// Returns the number of users being tracked.
    #[allow(dead_code)]
    pub fn tracked_users(&self) -> usize {
        self.per_user.read().unwrap().len()
    }

    /// Cleans up old entries. Should be called periodically.
    #[allow(dead_code)]
    pub fn cleanup(&self, max_ip_entries: usize, max_user_entries: usize) {
        let mut ip_limiters = self.per_ip.write().unwrap();
        if ip_limiters.len() > max_ip_entries {
            ip_limiters.clear();
            tracing::info!(
                max_entries = max_ip_entries,
                "Cleared API rate limiter IP cache"
            );
        }
        drop(ip_limiters);

        let mut user_limiters = self.per_user.write().unwrap();
        if user_limiters.len() > max_user_entries {
            user_limiters.clear();
            tracing::info!(
                max_entries = max_user_entries,
                "Cleared API rate limiter user cache"
            );
        }
    }
}

impl Default for ApiRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Errors that can occur during API rate limit checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiRateLimitError {
    /// Per-IP rate limit exceeded.
    PerIpLimitExceeded,
    /// Per-user rate limit exceeded.
    PerUserLimitExceeded,
    /// Webhook rate limit exceeded.
    WebhookLimitExceeded,
    /// Global rate limit exceeded.
    GlobalLimitExceeded,
}

impl std::fmt::Display for ApiRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiRateLimitError::PerIpLimitExceeded => {
                write!(
                    f,
                    "Too many requests from this IP address. Please try again later."
                )
            }
            ApiRateLimitError::PerUserLimitExceeded => {
                write!(
                    f,
                    "Too many requests from this user. Please try again later."
                )
            }
            ApiRateLimitError::WebhookLimitExceeded => {
                write!(f, "Webhook rate limit exceeded. Please try again later.")
            }
            ApiRateLimitError::GlobalLimitExceeded => {
                write!(
                    f,
                    "Server is experiencing high load. Please try again later."
                )
            }
        }
    }
}

impl std::error::Error for ApiRateLimitError {}

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

    // ========================================================================
    // ApiRateLimiter Tests
    // ========================================================================

    #[test]
    fn test_api_rate_limiter_allows_within_ip_limit() {
        let limiter = ApiRateLimiter::with_config(5, 10, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Should allow 5 requests from the same IP
        for _ in 0..5 {
            assert!(limiter.check_ip(ip).is_ok());
        }
    }

    #[test]
    fn test_api_rate_limiter_blocks_over_ip_limit() {
        let limiter = ApiRateLimiter::with_config(3, 10, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check_ip(ip).is_ok());
        }

        // 4th should fail
        assert_eq!(
            limiter.check_ip(ip),
            Err(ApiRateLimitError::PerIpLimitExceeded)
        );
    }

    #[test]
    fn test_api_rate_limiter_allows_within_user_limit() {
        let limiter = ApiRateLimiter::with_config(100, 5, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_id = Uuid::new_v4();

        // Should allow 5 requests from the same user
        for _ in 0..5 {
            assert!(limiter.check_user(user_id, ip).is_ok());
        }
    }

    #[test]
    fn test_api_rate_limiter_blocks_over_user_limit() {
        let limiter = ApiRateLimiter::with_config(100, 3, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_id = Uuid::new_v4();

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check_user(user_id, ip).is_ok());
        }

        // 4th should fail
        assert_eq!(
            limiter.check_user(user_id, ip),
            Err(ApiRateLimitError::PerUserLimitExceeded)
        );
    }

    #[test]
    fn test_api_rate_limiter_different_users_independent() {
        let limiter = ApiRateLimiter::with_config(100, 2, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        // Each user should get its own limit
        assert!(limiter.check_user(user1, ip).is_ok());
        assert!(limiter.check_user(user1, ip).is_ok());
        assert!(limiter.check_user(user1, ip).is_err()); // user1 exhausted

        assert!(limiter.check_user(user2, ip).is_ok()); // user2 still has quota
        assert!(limiter.check_user(user2, ip).is_ok());
        assert!(limiter.check_user(user2, ip).is_err()); // user2 exhausted
    }

    #[test]
    fn test_api_rate_limiter_webhook_limit() {
        let limiter = ApiRateLimiter::with_config(100, 100, 3, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check_webhook(ip).is_ok());
        }

        // 4th should fail
        assert_eq!(
            limiter.check_webhook(ip),
            Err(ApiRateLimitError::WebhookLimitExceeded)
        );
    }

    #[test]
    fn test_api_rate_limiter_global_limit() {
        let limiter = ApiRateLimiter::with_config(10, 10, 10, 3, Duration::from_secs(60));
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 4));

        // Per-IP limit is 10, but global is 3
        assert!(limiter.check_ip(ip1).is_ok());
        assert!(limiter.check_ip(ip2).is_ok());
        assert!(limiter.check_ip(ip3).is_ok());

        // Global limit reached - any IP should fail
        assert_eq!(
            limiter.check_ip(ip4),
            Err(ApiRateLimitError::GlobalLimitExceeded)
        );
    }

    #[test]
    fn test_api_rate_limiter_tracked_counts() {
        let limiter = ApiRateLimiter::new();

        assert_eq!(limiter.tracked_ips(), 0);
        assert_eq!(limiter.tracked_users(), 0);

        let ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let user_id = Uuid::new_v4();

        limiter.check_ip(ip).ok();
        assert_eq!(limiter.tracked_ips(), 1);

        limiter.check_user(user_id, ip).ok();
        assert_eq!(limiter.tracked_users(), 1);

        // Same IP/user doesn't add new entry
        limiter.check_ip(ip).ok();
        limiter.check_user(user_id, ip).ok();
        assert_eq!(limiter.tracked_ips(), 1);
        assert_eq!(limiter.tracked_users(), 1);
    }

    #[test]
    fn test_api_rate_limiter_clear_ip() {
        let limiter = ApiRateLimiter::with_config(2, 10, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Exhaust limit
        assert!(limiter.check_ip(ip).is_ok());
        assert!(limiter.check_ip(ip).is_ok());
        assert!(limiter.check_ip(ip).is_err());

        // Clear should allow new attempts
        limiter.clear_ip(ip);
        assert!(limiter.check_ip(ip).is_ok());
    }

    #[test]
    fn test_api_rate_limiter_clear_user() {
        let limiter = ApiRateLimiter::with_config(100, 2, 100, 1000, Duration::from_secs(60));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let user_id = Uuid::new_v4();

        // Exhaust limit
        assert!(limiter.check_user(user_id, ip).is_ok());
        assert!(limiter.check_user(user_id, ip).is_ok());
        assert!(limiter.check_user(user_id, ip).is_err());

        // Clear should allow new attempts
        limiter.clear_user(user_id);
        assert!(limiter.check_user(user_id, ip).is_ok());
    }
}
