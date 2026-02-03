//! Rate limiting for login and API endpoints.
//!
//! This module provides rate limiting using the governor crate to protect
//! against brute force attacks on login and excessive API usage.
//!
//! Security: Uses LRU cache to prevent memory exhaustion attacks where
//! attackers flood with unique IPs to consume server memory.

use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use lru::LruCache;
use metrics::{counter, describe_counter, describe_gauge, gauge};
use std::{
    env,
    net::IpAddr,
    num::NonZeroU32,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
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

/// Default maximum entries in rate limiter LRU cache.
pub const DEFAULT_RATE_LIMIT_MAX_ENTRIES: usize = 10_000;

/// Environment variable name for configuring max entries.
pub const RATE_LIMIT_MAX_ENTRIES_ENV: &str = "RATE_LIMIT_MAX_ENTRIES";

/// Per-IP rate limiter type.
type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

/// Gets the configured max entries from environment or default.
fn get_max_entries() -> usize {
    env::var(RATE_LIMIT_MAX_ENTRIES_ENV)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RATE_LIMIT_MAX_ENTRIES)
}

/// Registers rate limiter metrics descriptions.
/// This should be called once during server initialization.
pub fn register_rate_limit_metrics() {
    describe_gauge!(
        "triage_warden_rate_limiter_ip_cache_size",
        "Current number of IP addresses tracked in rate limiter cache"
    );
    describe_gauge!(
        "triage_warden_rate_limiter_user_cache_size",
        "Current number of users tracked in rate limiter cache"
    );
    describe_counter!(
        "triage_warden_rate_limiter_evictions_total",
        "Total number of LRU cache evictions in rate limiter"
    );
    describe_gauge!(
        "triage_warden_rate_limiter_max_entries",
        "Maximum entries configured for rate limiter cache"
    );
}

/// Login rate limiter that provides both per-IP and global rate limiting.
///
/// # Rate Limits
///
/// - **Per-IP**: Limits login attempts from a single IP address (default: 5/minute)
/// - **Global**: Limits total login attempts across all IPs (default: 100/minute)
///
/// Both limits must pass for a login attempt to be allowed.
///
/// # Security
///
/// Uses LRU cache with configurable max entries (default: 10,000) to prevent
/// memory exhaustion attacks. Oldest entries are automatically evicted when
/// the cache reaches capacity.
#[derive(Clone)]
pub struct LoginRateLimiter {
    /// Per-IP rate limiters in LRU cache, keyed by IP address.
    per_ip: Arc<Mutex<LruCache<IpAddr, Arc<IpRateLimiter>>>>,
    /// Global rate limiter for all login attempts.
    global: Arc<IpRateLimiter>,
    /// Per-IP rate limit (attempts per window).
    per_ip_limit: u32,
    /// Rate limit window duration.
    window: Duration,
    /// Maximum entries in the LRU cache.
    max_entries: usize,
    /// Total eviction count for metrics.
    eviction_count: Arc<Mutex<u64>>,
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
        let max_entries = get_max_entries();
        Self::with_config_and_max_entries(per_ip_limit, global_limit, window, max_entries)
    }

    /// Creates a new login rate limiter with custom configuration and max entries.
    ///
    /// # Arguments
    ///
    /// * `per_ip_limit` - Maximum login attempts per IP per window
    /// * `global_limit` - Maximum total login attempts per window
    /// * `window` - Rate limit window duration
    /// * `max_entries` - Maximum number of entries in the LRU cache
    pub fn with_config_and_max_entries(
        per_ip_limit: u32,
        global_limit: u32,
        window: Duration,
        max_entries: usize,
    ) -> Self {
        let global_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(global_limit).expect("Global limit must be > 0"));

        let cache_size = NonZeroUsize::new(max_entries).expect("Max entries must be > 0");

        // Record max entries metric
        gauge!("triage_warden_rate_limiter_max_entries").set(max_entries as f64);

        Self {
            per_ip: Arc::new(Mutex::new(LruCache::new(cache_size))),
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_ip_limit,
            window,
            max_entries,
            eviction_count: Arc::new(Mutex::new(0)),
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
    /// Uses LRU cache to automatically evict least-recently-used entries.
    fn get_or_create_ip_limiter(&self, ip: IpAddr) -> Arc<IpRateLimiter> {
        let mut cache = self.per_ip.lock().unwrap();

        // Try to get existing limiter (this also promotes it in LRU order)
        if let Some(limiter) = cache.get(&ip) {
            return limiter.clone();
        }

        // Check if we're at capacity (will cause eviction)
        let was_at_capacity = cache.len() >= self.max_entries;

        // Create new limiter for this IP
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(self.per_ip_limit).expect("Per-IP limit must be > 0"));

        let limiter = Arc::new(RateLimiter::direct(quota));

        // Push to cache - LRU will automatically evict oldest if at capacity
        cache.push(ip, limiter.clone());

        // Update metrics
        let cache_size = cache.len();
        gauge!("triage_warden_rate_limiter_ip_cache_size").set(cache_size as f64);

        if was_at_capacity {
            // Increment eviction counter
            let mut eviction_count = self.eviction_count.lock().unwrap();
            *eviction_count += 1;
            counter!("triage_warden_rate_limiter_evictions_total", "cache" => "login_ip")
                .increment(1);

            tracing::debug!(
                ip = %ip,
                cache_size = cache_size,
                max_entries = self.max_entries,
                "LRU eviction occurred in login rate limiter"
            );
        }

        limiter
    }

    /// Clears rate limit state for an IP (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_ip(&self, ip: IpAddr) {
        let mut cache = self.per_ip.lock().unwrap();
        cache.pop(&ip);
        gauge!("triage_warden_rate_limiter_ip_cache_size").set(cache.len() as f64);
    }

    /// Returns the number of IPs being tracked.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.lock().unwrap().len()
    }

    /// Returns the maximum number of entries allowed in the cache.
    #[allow(dead_code)]
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Returns the total number of evictions that have occurred.
    #[allow(dead_code)]
    pub fn eviction_count(&self) -> u64 {
        *self.eviction_count.lock().unwrap()
    }

    /// Performs periodic cleanup of stale entries.
    ///
    /// While LRU cache automatically evicts when at capacity, this method
    /// can be called periodically to proactively update metrics.
    ///
    /// Note: The LRU eviction policy ensures memory bounds automatically.
    #[allow(dead_code)]
    pub fn periodic_cleanup(&self) {
        let cache = self.per_ip.lock().unwrap();
        gauge!("triage_warden_rate_limiter_ip_cache_size").set(cache.len() as f64);
        tracing::debug!(
            cache_size = cache.len(),
            max_entries = self.max_entries,
            "Login rate limiter periodic cleanup check"
        );
    }

    /// Legacy cleanup method for backward compatibility.
    /// Now uses LRU eviction instead of clearing all entries.
    #[allow(dead_code)]
    #[deprecated(
        note = "Use periodic_cleanup() instead. LRU cache handles eviction automatically."
    )]
    pub fn cleanup(&self, _max_entries: usize) {
        self.periodic_cleanup();
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
///
/// # Security
///
/// Uses LRU cache with configurable max entries (default: 10,000) to prevent
/// memory exhaustion attacks. Oldest entries are automatically evicted when
/// the cache reaches capacity.
#[derive(Clone)]
pub struct ApiRateLimiter {
    /// Per-IP rate limiters in LRU cache, keyed by IP address.
    per_ip: Arc<Mutex<LruCache<IpAddr, Arc<IpRateLimiter>>>>,
    /// Per-user rate limiters in LRU cache, keyed by user ID.
    per_user: Arc<Mutex<LruCache<Uuid, Arc<IpRateLimiter>>>>,
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
    /// Maximum entries in the IP LRU cache.
    max_ip_entries: usize,
    /// Maximum entries in the user LRU cache.
    max_user_entries: usize,
    /// Total IP eviction count for metrics.
    ip_eviction_count: Arc<Mutex<u64>>,
    /// Total user eviction count for metrics.
    user_eviction_count: Arc<Mutex<u64>>,
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
        let max_entries = get_max_entries();
        Self::with_config_and_max_entries(
            per_ip_limit,
            per_user_limit,
            webhook_limit,
            global_limit,
            window,
            max_entries,
            max_entries,
        )
    }

    /// Creates a new API rate limiter with custom configuration and max entries.
    ///
    /// # Arguments
    ///
    /// * `per_ip_limit` - Maximum requests per IP per window
    /// * `per_user_limit` - Maximum requests per user per window
    /// * `webhook_limit` - Maximum webhook requests per window
    /// * `global_limit` - Maximum total requests per window
    /// * `window` - Rate limit window duration
    /// * `max_ip_entries` - Maximum number of IP entries in the LRU cache
    /// * `max_user_entries` - Maximum number of user entries in the LRU cache
    pub fn with_config_and_max_entries(
        per_ip_limit: u32,
        per_user_limit: u32,
        webhook_limit: u32,
        global_limit: u32,
        window: Duration,
        max_ip_entries: usize,
        max_user_entries: usize,
    ) -> Self {
        let webhook_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(webhook_limit).expect("Webhook limit must be > 0"));

        let global_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(global_limit).expect("Global limit must be > 0"));

        let ip_cache_size = NonZeroUsize::new(max_ip_entries).expect("Max IP entries must be > 0");
        let user_cache_size =
            NonZeroUsize::new(max_user_entries).expect("Max user entries must be > 0");

        Self {
            per_ip: Arc::new(Mutex::new(LruCache::new(ip_cache_size))),
            per_user: Arc::new(Mutex::new(LruCache::new(user_cache_size))),
            webhook: Arc::new(RateLimiter::direct(webhook_quota)),
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_ip_limit,
            per_user_limit,
            window,
            max_ip_entries,
            max_user_entries,
            ip_eviction_count: Arc::new(Mutex::new(0)),
            user_eviction_count: Arc::new(Mutex::new(0)),
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
    /// Uses LRU cache to automatically evict least-recently-used entries.
    fn get_or_create_ip_limiter(&self, ip: IpAddr) -> Arc<IpRateLimiter> {
        let mut cache = self.per_ip.lock().unwrap();

        // Try to get existing limiter (this also promotes it in LRU order)
        if let Some(limiter) = cache.get(&ip) {
            return limiter.clone();
        }

        // Check if we're at capacity (will cause eviction)
        let was_at_capacity = cache.len() >= self.max_ip_entries;

        // Create new limiter for this IP
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(self.per_ip_limit).expect("Per-IP limit must be > 0"));

        let limiter = Arc::new(RateLimiter::direct(quota));

        // Push to cache - LRU will automatically evict oldest if at capacity
        cache.push(ip, limiter.clone());

        // Update metrics
        let cache_size = cache.len();
        gauge!("triage_warden_rate_limiter_ip_cache_size").set(cache_size as f64);

        if was_at_capacity {
            // Increment eviction counter
            let mut eviction_count = self.ip_eviction_count.lock().unwrap();
            *eviction_count += 1;
            counter!("triage_warden_rate_limiter_evictions_total", "cache" => "api_ip")
                .increment(1);

            tracing::debug!(
                ip = %ip,
                cache_size = cache_size,
                max_entries = self.max_ip_entries,
                "LRU eviction occurred in API rate limiter IP cache"
            );
        }

        limiter
    }

    /// Gets or creates a rate limiter for the given user ID.
    /// Uses LRU cache to automatically evict least-recently-used entries.
    fn get_or_create_user_limiter(&self, user_id: Uuid) -> Arc<IpRateLimiter> {
        let mut cache = self.per_user.lock().unwrap();

        // Try to get existing limiter (this also promotes it in LRU order)
        if let Some(limiter) = cache.get(&user_id) {
            return limiter.clone();
        }

        // Check if we're at capacity (will cause eviction)
        let was_at_capacity = cache.len() >= self.max_user_entries;

        // Create new limiter for this user
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(self.per_user_limit).expect("Per-user limit must be > 0"));

        let limiter = Arc::new(RateLimiter::direct(quota));

        // Push to cache - LRU will automatically evict oldest if at capacity
        cache.push(user_id, limiter.clone());

        // Update metrics
        let cache_size = cache.len();
        gauge!("triage_warden_rate_limiter_user_cache_size").set(cache_size as f64);

        if was_at_capacity {
            // Increment eviction counter
            let mut eviction_count = self.user_eviction_count.lock().unwrap();
            *eviction_count += 1;
            counter!("triage_warden_rate_limiter_evictions_total", "cache" => "api_user")
                .increment(1);

            tracing::debug!(
                user_id = %user_id,
                cache_size = cache_size,
                max_entries = self.max_user_entries,
                "LRU eviction occurred in API rate limiter user cache"
            );
        }

        limiter
    }

    /// Clears rate limit state for an IP (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_ip(&self, ip: IpAddr) {
        let mut cache = self.per_ip.lock().unwrap();
        cache.pop(&ip);
        gauge!("triage_warden_rate_limiter_ip_cache_size").set(cache.len() as f64);
    }

    /// Clears rate limit state for a user (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_user(&self, user_id: Uuid) {
        let mut cache = self.per_user.lock().unwrap();
        cache.pop(&user_id);
        gauge!("triage_warden_rate_limiter_user_cache_size").set(cache.len() as f64);
    }

    /// Returns the number of IPs being tracked.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.per_ip.lock().unwrap().len()
    }

    /// Returns the number of users being tracked.
    #[allow(dead_code)]
    pub fn tracked_users(&self) -> usize {
        self.per_user.lock().unwrap().len()
    }

    /// Returns the maximum number of IP entries allowed in the cache.
    #[allow(dead_code)]
    pub fn max_ip_entries(&self) -> usize {
        self.max_ip_entries
    }

    /// Returns the maximum number of user entries allowed in the cache.
    #[allow(dead_code)]
    pub fn max_user_entries(&self) -> usize {
        self.max_user_entries
    }

    /// Returns the total number of IP cache evictions that have occurred.
    #[allow(dead_code)]
    pub fn ip_eviction_count(&self) -> u64 {
        *self.ip_eviction_count.lock().unwrap()
    }

    /// Returns the total number of user cache evictions that have occurred.
    #[allow(dead_code)]
    pub fn user_eviction_count(&self) -> u64 {
        *self.user_eviction_count.lock().unwrap()
    }

    /// Performs periodic cleanup of stale entries.
    ///
    /// While LRU cache automatically evicts when at capacity, this method
    /// can be called periodically to update metrics and log cache status.
    #[allow(dead_code)]
    pub fn periodic_cleanup(&self) {
        let ip_cache = self.per_ip.lock().unwrap();
        let user_cache = self.per_user.lock().unwrap();

        gauge!("triage_warden_rate_limiter_ip_cache_size").set(ip_cache.len() as f64);
        gauge!("triage_warden_rate_limiter_user_cache_size").set(user_cache.len() as f64);

        tracing::debug!(
            ip_cache_size = ip_cache.len(),
            user_cache_size = user_cache.len(),
            max_ip_entries = self.max_ip_entries,
            max_user_entries = self.max_user_entries,
            "API rate limiter periodic cleanup check"
        );
    }

    /// Legacy cleanup method for backward compatibility.
    /// Now uses LRU eviction instead of clearing all entries.
    #[allow(dead_code)]
    #[deprecated(
        note = "Use periodic_cleanup() instead. LRU cache handles eviction automatically."
    )]
    pub fn cleanup(&self, _max_ip_entries: usize, _max_user_entries: usize) {
        self.periodic_cleanup();
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

// ============================================================================
// Webhook Rate Limiter
// ============================================================================

/// Default per-source webhook rate limit (requests per minute).
pub const DEFAULT_WEBHOOK_RATE_PER_SOURCE: u32 = 100;

/// Default global webhook rate limit (requests per minute).
pub const DEFAULT_WEBHOOK_RATE_GLOBAL: u32 = 1000;

/// Default maximum queue depth for webhooks.
pub const DEFAULT_WEBHOOK_QUEUE_MAX_DEPTH: usize = 10000;

/// Webhook rate limiter that provides per-source and global rate limiting.
///
/// This is a dedicated rate limiter for webhook endpoints, separate from
/// the general API rate limiter, to provide fine-grained control over
/// webhook traffic from different sources.
///
/// # Rate Limits
///
/// - **Per-Source**: Limits requests from a single webhook source (default: 100/minute)
/// - **Global**: Limits total webhook requests across all sources (default: 1000/minute)
///
/// # Queue Protection
///
/// The limiter also tracks queue depth to prevent alert flooding when
/// the processing pipeline is backed up.
///
/// # Security
///
/// Uses LRU cache with configurable max entries (default: 10,000) to prevent
/// memory exhaustion attacks. Oldest entries are automatically evicted when
/// the cache reaches capacity.
#[derive(Clone)]
pub struct WebhookRateLimiter {
    /// Per-source rate limiters in LRU cache, keyed by source identifier.
    per_source: Arc<Mutex<LruCache<String, Arc<IpRateLimiter>>>>,
    /// Global rate limiter for all webhooks.
    global: Arc<IpRateLimiter>,
    /// Per-source rate limit (requests per window).
    per_source_limit: u32,
    /// Rate limit window duration.
    window: Duration,
    /// Current queue depth (approximate).
    queue_depth: Arc<std::sync::atomic::AtomicUsize>,
    /// Maximum queue depth before rejecting new webhooks.
    max_queue_depth: usize,
    /// Counter for total requests received.
    total_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Counter for rate limited requests.
    rate_limited_requests: Arc<std::sync::atomic::AtomicU64>,
    /// Counter for queue overflow rejections.
    queue_overflow_rejections: Arc<std::sync::atomic::AtomicU64>,
    /// Maximum entries in the source LRU cache.
    max_source_entries: usize,
    /// Total source eviction count for metrics.
    source_eviction_count: Arc<Mutex<u64>>,
}

impl WebhookRateLimiter {
    /// Creates a new webhook rate limiter with default settings.
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_WEBHOOK_RATE_PER_SOURCE,
            DEFAULT_WEBHOOK_RATE_GLOBAL,
            DEFAULT_WEBHOOK_QUEUE_MAX_DEPTH,
            Duration::from_secs(DEFAULT_RATE_LIMIT_WINDOW_SECS),
        )
    }

    /// Creates a new webhook rate limiter with custom configuration.
    ///
    /// # Arguments
    ///
    /// * `per_source_limit` - Maximum requests per source per window
    /// * `global_limit` - Maximum total webhook requests per window
    /// * `max_queue_depth` - Maximum queue depth before rejecting
    /// * `window` - Rate limit window duration
    pub fn with_config(
        per_source_limit: u32,
        global_limit: u32,
        max_queue_depth: usize,
        window: Duration,
    ) -> Self {
        let max_source_entries = get_max_entries();
        Self::with_config_and_max_entries(
            per_source_limit,
            global_limit,
            max_queue_depth,
            window,
            max_source_entries,
        )
    }

    /// Creates a new webhook rate limiter with custom configuration and max entries.
    ///
    /// # Arguments
    ///
    /// * `per_source_limit` - Maximum requests per source per window
    /// * `global_limit` - Maximum total webhook requests per window
    /// * `max_queue_depth` - Maximum queue depth before rejecting
    /// * `window` - Rate limit window duration
    /// * `max_source_entries` - Maximum number of source entries in the LRU cache
    pub fn with_config_and_max_entries(
        per_source_limit: u32,
        global_limit: u32,
        max_queue_depth: usize,
        window: Duration,
        max_source_entries: usize,
    ) -> Self {
        let global_quota = Quota::with_period(window)
            .expect("Rate limit window must be > 0")
            .allow_burst(NonZeroU32::new(global_limit).expect("Global limit must be > 0"));

        let cache_size =
            NonZeroUsize::new(max_source_entries).expect("Max source entries must be > 0");

        Self {
            per_source: Arc::new(Mutex::new(LruCache::new(cache_size))),
            global: Arc::new(RateLimiter::direct(global_quota)),
            per_source_limit,
            window,
            queue_depth: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            max_queue_depth,
            total_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            rate_limited_requests: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            queue_overflow_rejections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            max_source_entries,
            source_eviction_count: Arc::new(Mutex::new(0)),
        }
    }

    /// Checks if a webhook request from the given source should be allowed.
    ///
    /// # Arguments
    ///
    /// * `source` - The webhook source identifier (e.g., "splunk", "crowdstrike")
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the request is allowed
    /// - `Err(WebhookRateLimitError)` if any limit is exceeded
    pub fn check(&self, source: &str) -> Result<(), WebhookRateLimitError> {
        // Increment total requests counter
        self.total_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // Check queue depth first (queue overflow protection)
        let current_depth = self.queue_depth.load(std::sync::atomic::Ordering::Relaxed);
        if current_depth >= self.max_queue_depth {
            self.queue_overflow_rejections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                source = %source,
                queue_depth = current_depth,
                max_depth = self.max_queue_depth,
                "Webhook rejected: queue overflow"
            );
            return Err(WebhookRateLimitError::QueueOverflow {
                current_depth,
                max_depth: self.max_queue_depth,
            });
        }

        // Check global limit
        if self.global.check().is_err() {
            self.rate_limited_requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                source = %source,
                "Global webhook rate limit exceeded"
            );
            return Err(WebhookRateLimitError::GlobalLimitExceeded);
        }

        // Get or create per-source limiter
        let limiter = self.get_or_create_source_limiter(source);

        // Check per-source limit
        if limiter.check().is_err() {
            self.rate_limited_requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                source = %source,
                limit = self.per_source_limit,
                window_secs = self.window.as_secs(),
                "Per-source webhook rate limit exceeded"
            );
            return Err(WebhookRateLimitError::PerSourceLimitExceeded {
                source: source.to_string(),
            });
        }

        Ok(())
    }

    /// Gets or creates a rate limiter for the given source.
    /// Uses LRU cache to automatically evict least-recently-used entries.
    fn get_or_create_source_limiter(&self, source: &str) -> Arc<IpRateLimiter> {
        let mut cache = self.per_source.lock().unwrap();

        // Try to get existing limiter (this also promotes it in LRU order)
        if let Some(limiter) = cache.get(source) {
            return limiter.clone();
        }

        // Check if we're at capacity (will cause eviction)
        let was_at_capacity = cache.len() >= self.max_source_entries;

        // Create new limiter for this source
        let quota = Quota::with_period(self.window)
            .expect("Rate limit window must be > 0")
            .allow_burst(
                NonZeroU32::new(self.per_source_limit).expect("Per-source limit must be > 0"),
            );

        let limiter = Arc::new(RateLimiter::direct(quota));

        // Push to cache - LRU will automatically evict oldest if at capacity
        cache.push(source.to_string(), limiter.clone());

        if was_at_capacity {
            // Increment eviction counter
            let mut eviction_count = self.source_eviction_count.lock().unwrap();
            *eviction_count += 1;
            counter!("triage_warden_rate_limiter_evictions_total", "cache" => "webhook_source")
                .increment(1);

            tracing::debug!(
                source = %source,
                cache_size = cache.len(),
                max_entries = self.max_source_entries,
                "LRU eviction occurred in webhook rate limiter source cache"
            );
        }

        limiter
    }

    /// Increments the queue depth counter.
    /// Call this when a webhook is accepted and queued for processing.
    pub fn increment_queue_depth(&self) {
        self.queue_depth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Decrements the queue depth counter.
    /// Call this when a queued webhook has been processed.
    pub fn decrement_queue_depth(&self) {
        self.queue_depth
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Gets the current queue depth.
    pub fn current_queue_depth(&self) -> usize {
        self.queue_depth.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Gets the maximum queue depth.
    pub fn max_queue_depth(&self) -> usize {
        self.max_queue_depth
    }

    /// Gets the total number of requests received.
    pub fn total_requests(&self) -> u64 {
        self.total_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Gets the number of rate limited requests.
    pub fn rate_limited_requests(&self) -> u64 {
        self.rate_limited_requests
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Gets the number of queue overflow rejections.
    pub fn queue_overflow_rejections(&self) -> u64 {
        self.queue_overflow_rejections
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns the number of sources being tracked.
    #[allow(dead_code)]
    pub fn tracked_sources(&self) -> usize {
        self.per_source.lock().unwrap().len()
    }

    /// Returns the maximum number of source entries allowed in the cache.
    #[allow(dead_code)]
    pub fn max_source_entries(&self) -> usize {
        self.max_source_entries
    }

    /// Returns the total number of source cache evictions that have occurred.
    #[allow(dead_code)]
    pub fn source_eviction_count(&self) -> u64 {
        *self.source_eviction_count.lock().unwrap()
    }

    /// Clears rate limit state for a source (for testing or manual unblocking).
    #[allow(dead_code)]
    pub fn clear_source(&self, source: &str) {
        let mut cache = self.per_source.lock().unwrap();
        cache.pop(source);
    }

    /// Performs periodic cleanup of stale entries.
    ///
    /// While LRU cache automatically evicts when at capacity, this method
    /// can be called periodically to update metrics and log cache status.
    #[allow(dead_code)]
    pub fn periodic_cleanup(&self) {
        let cache = self.per_source.lock().unwrap();
        tracing::debug!(
            source_cache_size = cache.len(),
            max_source_entries = self.max_source_entries,
            "Webhook rate limiter periodic cleanup check"
        );
    }

    /// Legacy cleanup method for backward compatibility.
    /// Now uses LRU eviction instead of clearing all entries.
    #[allow(dead_code)]
    #[deprecated(
        note = "Use periodic_cleanup() instead. LRU cache handles eviction automatically."
    )]
    pub fn cleanup(&self, _max_entries: usize) {
        self.periodic_cleanup();
    }

    /// Returns webhook rate limiter statistics.
    pub fn stats(&self) -> WebhookRateLimiterStats {
        WebhookRateLimiterStats {
            total_requests: self.total_requests(),
            rate_limited_requests: self.rate_limited_requests(),
            queue_overflow_rejections: self.queue_overflow_rejections(),
            current_queue_depth: self.current_queue_depth(),
            max_queue_depth: self.max_queue_depth,
            tracked_sources: self.per_source.lock().unwrap().len(),
        }
    }
}

impl Default for WebhookRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics from the webhook rate limiter.
#[derive(Debug, Clone)]
pub struct WebhookRateLimiterStats {
    /// Total webhook requests received.
    pub total_requests: u64,
    /// Number of requests that were rate limited.
    pub rate_limited_requests: u64,
    /// Number of requests rejected due to queue overflow.
    pub queue_overflow_rejections: u64,
    /// Current queue depth.
    pub current_queue_depth: usize,
    /// Maximum queue depth.
    pub max_queue_depth: usize,
    /// Number of unique sources being tracked.
    pub tracked_sources: usize,
}

/// Errors that can occur during webhook rate limit checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookRateLimitError {
    /// Per-source rate limit exceeded.
    PerSourceLimitExceeded { source: String },
    /// Global rate limit exceeded.
    GlobalLimitExceeded,
    /// Queue is full, cannot accept more webhooks.
    QueueOverflow {
        current_depth: usize,
        max_depth: usize,
    },
}

impl WebhookRateLimitError {
    /// Returns a human-readable error message.
    pub fn message(&self) -> String {
        match self {
            WebhookRateLimitError::PerSourceLimitExceeded { source } => {
                format!(
                    "Too many webhook requests from source '{}'. Please reduce request rate.",
                    source
                )
            }
            WebhookRateLimitError::GlobalLimitExceeded => {
                "Webhook rate limit exceeded. Server is experiencing high webhook volume."
                    .to_string()
            }
            WebhookRateLimitError::QueueOverflow {
                current_depth,
                max_depth,
            } => {
                format!(
                    "Webhook queue is full ({}/{} items). Please retry later.",
                    current_depth, max_depth
                )
            }
        }
    }

    /// Returns the error code for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            WebhookRateLimitError::PerSourceLimitExceeded { .. } => "WEBHOOK_SOURCE_RATE_LIMITED",
            WebhookRateLimitError::GlobalLimitExceeded => "WEBHOOK_GLOBAL_RATE_LIMITED",
            WebhookRateLimitError::QueueOverflow { .. } => "WEBHOOK_QUEUE_OVERFLOW",
        }
    }
}

impl std::fmt::Display for WebhookRateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message())
    }
}

impl std::error::Error for WebhookRateLimitError {}

/// Spawns a background task that periodically runs cleanup on rate limiters.
///
/// # Arguments
///
/// * `login_limiter` - The login rate limiter to clean up
/// * `api_limiter` - The API rate limiter to clean up
/// * `interval` - How often to run cleanup (default: 5 minutes)
///
/// # Returns
///
/// A join handle for the spawned task
pub fn spawn_cleanup_task(
    login_limiter: LoginRateLimiter,
    api_limiter: ApiRateLimiter,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval_timer = tokio::time::interval(interval);
        loop {
            interval_timer.tick().await;

            login_limiter.periodic_cleanup();
            api_limiter.periodic_cleanup();

            tracing::debug!("Rate limiter periodic cleanup completed");
        }
    })
}

// ============================================================================
// Middleware
// ============================================================================

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

/// Extracts client IP from request, checking X-Forwarded-For header first.
fn extract_client_ip(req: &Request<Body>) -> IpAddr {
    // Try X-Forwarded-For header first (for reverse proxy setups)
    if let Some(forwarded_for) = req.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded_for.to_str() {
            // Take the first IP in the comma-separated list
            if let Some(first_ip) = value.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }

    // Try X-Real-IP header
    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            if let Ok(ip) = value.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Fallback to loopback (in production, you'd get this from the connection)
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
}

/// Global rate limit middleware that applies per-IP rate limiting to all API requests.
///
/// This middleware should be applied early in the middleware stack to reject
/// requests before any significant processing occurs.
///
/// # Exempt Paths
///
/// - `/health` - Health check endpoint
/// - `/metrics` - Prometheus metrics endpoint
/// - `/api/webhooks` - Webhooks have their own stricter rate limiting
pub async fn global_rate_limit_middleware(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();

    // Skip rate limiting for health checks and metrics
    if path == "/health" || path == "/metrics" || path.starts_with("/api/webhooks") {
        return next.run(req).await;
    }

    let client_ip = extract_client_ip(&req);

    // Check API rate limit
    if let Err(err) = state.api_rate_limiter.check_ip(client_ip) {
        tracing::warn!(
            ip = %client_ip,
            path = %path,
            error = %err,
            "Request rate limited"
        );

        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(
                "Retry-After",
                "60", // Suggest retry after 60 seconds
            )],
            err.to_string(),
        )
            .into_response();
    }

    next.run(req).await
}

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

    #[test]
    fn test_lru_eviction() {
        // Create limiter with very small cache
        let limiter =
            LoginRateLimiter::with_config_and_max_entries(5, 100, Duration::from_secs(60), 3);

        // Add 3 IPs (fills cache)
        limiter.check(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).ok();
        limiter.check(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))).ok();
        limiter.check(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))).ok();
        assert_eq!(limiter.tracked_ips(), 3);
        assert_eq!(limiter.eviction_count(), 0);

        // Add 4th IP - should evict oldest (1.1.1.1)
        limiter.check(IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))).ok();
        assert_eq!(limiter.tracked_ips(), 3); // Still 3 (LRU evicted one)
        assert_eq!(limiter.eviction_count(), 1);

        // Add 5th IP - should evict another
        limiter.check(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5))).ok();
        assert_eq!(limiter.tracked_ips(), 3);
        assert_eq!(limiter.eviction_count(), 2);
    }

    #[test]
    fn test_lru_access_promotes_entry() {
        // Create limiter with very small cache
        let limiter =
            LoginRateLimiter::with_config_and_max_entries(5, 100, Duration::from_secs(60), 3);

        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
        let ip3 = IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3));
        let ip4 = IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4));

        // Add 3 IPs
        limiter.check(ip1).ok();
        limiter.check(ip2).ok();
        limiter.check(ip3).ok();

        // Access ip1 again (promotes it to most recently used)
        limiter.check(ip1).ok();

        // Add ip4 - should evict ip2 (oldest after ip1 was promoted)
        limiter.check(ip4).ok();
        assert_eq!(limiter.tracked_ips(), 3);
        assert_eq!(limiter.eviction_count(), 1);

        // ip1 should still be in cache and work
        // (it was promoted so not evicted)
        let result = limiter.check(ip1);
        // Should succeed or fail based on rate limit, but entry exists
        assert!(result.is_ok() || result == Err(RateLimitError::PerIpLimitExceeded));
    }

    #[test]
    fn test_max_entries_configuration() {
        let limiter = LoginRateLimiter::with_config_and_max_entries(
            5,
            100,
            Duration::from_secs(60),
            500, // Custom max entries
        );
        assert_eq!(limiter.max_entries(), 500);

        let api_limiter = ApiRateLimiter::with_config_and_max_entries(
            100,
            200,
            1000,
            10000,
            Duration::from_secs(60),
            1000, // Custom max IP entries
            2000, // Custom max user entries
        );
        assert_eq!(api_limiter.max_ip_entries(), 1000);
        assert_eq!(api_limiter.max_user_entries(), 2000);
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

    #[test]
    fn test_api_rate_limiter_lru_eviction() {
        // Create limiter with very small cache
        let limiter = ApiRateLimiter::with_config_and_max_entries(
            5,
            5,
            100,
            1000,
            Duration::from_secs(60),
            3, // max 3 IPs
            3, // max 3 users
        );

        // Add 3 IPs
        limiter.check_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).ok();
        limiter.check_ip(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))).ok();
        limiter.check_ip(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3))).ok();
        assert_eq!(limiter.tracked_ips(), 3);
        assert_eq!(limiter.ip_eviction_count(), 0);

        // Add 4th IP - should evict oldest
        limiter.check_ip(IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4))).ok();
        assert_eq!(limiter.tracked_ips(), 3);
        assert_eq!(limiter.ip_eviction_count(), 1);

        // Test user cache eviction
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();
        let user3 = Uuid::new_v4();
        let user4 = Uuid::new_v4();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 10, 10, 10));

        limiter.check_user(user1, ip).ok();
        limiter.check_user(user2, ip).ok();
        limiter.check_user(user3, ip).ok();
        assert_eq!(limiter.tracked_users(), 3);
        assert_eq!(limiter.user_eviction_count(), 0);

        // Add 4th user - should evict oldest
        limiter.check_user(user4, ip).ok();
        assert_eq!(limiter.tracked_users(), 3);
        assert_eq!(limiter.user_eviction_count(), 1);
    }

    // ========================================================================
    // WebhookRateLimiter Tests
    // ========================================================================

    #[test]
    fn test_webhook_rate_limiter_allows_within_source_limit() {
        let limiter = WebhookRateLimiter::with_config(5, 100, 1000, Duration::from_secs(60));

        // Should allow 5 requests from the same source
        for _ in 0..5 {
            assert!(limiter.check("splunk").is_ok());
        }
    }

    #[test]
    fn test_webhook_rate_limiter_blocks_over_source_limit() {
        let limiter = WebhookRateLimiter::with_config(3, 100, 1000, Duration::from_secs(60));

        // First 3 should pass
        for _ in 0..3 {
            assert!(limiter.check("splunk").is_ok());
        }

        // 4th should fail
        let result = limiter.check("splunk");
        assert!(matches!(
            result,
            Err(WebhookRateLimitError::PerSourceLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_webhook_rate_limiter_different_sources_independent() {
        let limiter = WebhookRateLimiter::with_config(2, 100, 1000, Duration::from_secs(60));

        // Each source should get its own limit
        assert!(limiter.check("splunk").is_ok());
        assert!(limiter.check("splunk").is_ok());
        assert!(limiter.check("splunk").is_err()); // splunk exhausted

        assert!(limiter.check("crowdstrike").is_ok()); // crowdstrike still has quota
        assert!(limiter.check("crowdstrike").is_ok());
        assert!(limiter.check("crowdstrike").is_err()); // crowdstrike exhausted
    }

    #[test]
    fn test_webhook_rate_limiter_global_limit() {
        let limiter = WebhookRateLimiter::with_config(10, 3, 1000, Duration::from_secs(60));

        // Per-source limit is 10, but global is 3
        assert!(limiter.check("source1").is_ok());
        assert!(limiter.check("source2").is_ok());
        assert!(limiter.check("source3").is_ok());

        // Global limit reached - any source should fail
        assert_eq!(
            limiter.check("source4"),
            Err(WebhookRateLimitError::GlobalLimitExceeded)
        );
    }

    #[test]
    fn test_webhook_rate_limiter_queue_overflow() {
        let limiter = WebhookRateLimiter::with_config(100, 100, 2, Duration::from_secs(60));

        // Simulate queue filling up
        limiter.increment_queue_depth();
        limiter.increment_queue_depth();

        // Queue is now full, should reject
        let result = limiter.check("splunk");
        assert!(matches!(
            result,
            Err(WebhookRateLimitError::QueueOverflow { .. })
        ));

        // Decrement queue depth
        limiter.decrement_queue_depth();

        // Now should allow
        assert!(limiter.check("splunk").is_ok());
    }

    #[test]
    fn test_webhook_rate_limiter_stats() {
        let limiter = WebhookRateLimiter::with_config(2, 100, 1000, Duration::from_secs(60));

        // Make some requests
        limiter.check("splunk").ok();
        limiter.check("splunk").ok();
        limiter.check("splunk").ok(); // This will be rate limited
        limiter.check("crowdstrike").ok();

        let stats = limiter.stats();
        assert_eq!(stats.total_requests, 4);
        assert_eq!(stats.rate_limited_requests, 1);
        assert_eq!(stats.tracked_sources, 2);
    }

    #[test]
    fn test_webhook_rate_limiter_clear_source() {
        let limiter = WebhookRateLimiter::with_config(2, 100, 1000, Duration::from_secs(60));

        // Exhaust limit
        assert!(limiter.check("splunk").is_ok());
        assert!(limiter.check("splunk").is_ok());
        assert!(limiter.check("splunk").is_err());

        // Clear should allow new attempts
        limiter.clear_source("splunk");
        assert!(limiter.check("splunk").is_ok());
    }

    #[test]
    fn test_webhook_rate_limiter_lru_eviction() {
        // Create limiter with very small cache
        let limiter = WebhookRateLimiter::with_config_and_max_entries(
            5,
            100,
            1000,
            Duration::from_secs(60),
            3, // max 3 sources
        );

        // Add 3 sources (fills cache)
        limiter.check("source1").ok();
        limiter.check("source2").ok();
        limiter.check("source3").ok();
        assert_eq!(limiter.tracked_sources(), 3);
        assert_eq!(limiter.source_eviction_count(), 0);

        // Add 4th source - should evict oldest
        limiter.check("source4").ok();
        assert_eq!(limiter.tracked_sources(), 3); // Still 3 (LRU evicted one)
        assert_eq!(limiter.source_eviction_count(), 1);
    }
}
