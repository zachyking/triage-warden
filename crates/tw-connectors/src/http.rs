//! HTTP utilities for connectors.
//!
//! This module provides HTTP client utilities with retry logic, rate limiting,
//! and caching support for use by all connectors.

use crate::secure_string::SecureString;
use crate::traits::{AuthConfig, ConnectorConfig, ConnectorError, ConnectorResult};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter as GovernorRateLimiter,
};
use moka::future::Cache as MokaCache;
use reqwest::multipart::Form;
use reqwest::{Client, Response, StatusCode};
use serde::{de::DeserializeOwned, Serialize};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::{debug, info, warn};

/// Type alias for the rate limiter.
type RateLimiterType = GovernorRateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// HTTP client with retry, rate limiting, and caching support.
pub struct HttpClient {
    client: Client,
    config: ConnectorConfig,
    /// Current OAuth2 token (if using OAuth2 auth).
    oauth_token: Arc<RwLock<Option<OAuthToken>>>,
    /// Rate limiter for this client.
    rate_limiter: Option<Arc<RateLimiterType>>,
}

/// OAuth2 token with expiration.
///
/// The access token is stored in a `SecureString` to ensure it is
/// zeroized from memory when no longer needed.
#[derive(Clone)]
struct OAuthToken {
    /// The OAuth2 access token (zeroized on drop).
    access_token: SecureString,
    /// When the token expires.
    expires_at: std::time::Instant,
}

impl std::fmt::Debug for OAuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthToken")
            .field("access_token", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per period.
    pub max_requests: u32,
    /// Period duration.
    pub period: Duration,
    /// Maximum burst size.
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            period: Duration::from_secs(60),
            burst_size: 10,
        }
    }
}

impl HttpClient {
    /// Creates a new HTTP client from connector configuration.
    pub fn new(config: ConnectorConfig) -> ConnectorResult<Self> {
        Self::with_rate_limit(config, None)
    }

    /// Creates a new HTTP client with rate limiting.
    pub fn with_rate_limit(
        config: ConnectorConfig,
        rate_limit: Option<RateLimitConfig>,
    ) -> ConnectorResult<Self> {
        // SECURITY: Enforce TLS verification based on build mode
        // TLS verification cannot be disabled in release builds
        let verify_tls = if !config.verify_tls {
            #[cfg(debug_assertions)]
            {
                // In debug/development mode, allow disabling TLS with a warning
                warn!(
                    base_url = %config.base_url,
                    connector_name = %config.name,
                    "TLS certificate verification DISABLED in development mode - connection is vulnerable to MITM attacks"
                );
                false
            }
            #[cfg(not(debug_assertions))]
            {
                // In release/production mode, TLS verification is ALWAYS enabled
                // This cannot be overridden - it's a compile-time security guarantee
                warn!(
                    base_url = %config.base_url,
                    connector_name = %config.name,
                    "Attempted to disable TLS verification in production - request IGNORED for security"
                );
                true // Force TLS verification in production
            }
        } else {
            true // TLS verification requested, always honor it
        };

        let mut builder = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .danger_accept_invalid_certs(!verify_tls)
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90));

        // Add default headers
        let mut headers = reqwest::header::HeaderMap::new();
        for (key, value) in &config.headers {
            if let (Ok(name), Ok(val)) = (
                reqwest::header::HeaderName::try_from(key.as_str()),
                reqwest::header::HeaderValue::try_from(value.as_str()),
            ) {
                headers.insert(name, val);
            }
        }
        builder = builder.default_headers(headers);

        let client = builder
            .build()
            .map_err(|e| ConnectorError::ConfigError(e.to_string()))?;

        // Create rate limiter if configured
        let rate_limiter = rate_limit.map(|rl| {
            let quota = Quota::with_period(rl.period / rl.max_requests)
                .expect("Invalid rate limit period")
                .allow_burst(NonZeroU32::new(rl.burst_size).unwrap_or(NonZeroU32::MIN));
            Arc::new(GovernorRateLimiter::direct(quota))
        });

        Ok(Self {
            client,
            config,
            oauth_token: Arc::new(RwLock::new(None)),
            rate_limiter,
        })
    }

    /// Builds a URL from a path.
    pub fn build_url(&self, path: &str) -> String {
        let base = self.config.base_url.trim_end_matches('/');
        let path = path.trim_start_matches('/');
        format!("{}/{}", base, path)
    }

    /// Gets the base URL.
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Executes a GET request with retry logic.
    pub async fn get(&self, path: &str) -> ConnectorResult<Response> {
        let url = self.build_url(path);
        let request = self.client.get(&url);
        self.execute_with_retry(request).await
    }

    /// Executes a GET request and deserializes the JSON response.
    pub async fn get_json<T: DeserializeOwned>(&self, path: &str) -> ConnectorResult<T> {
        let response = self.get(path).await?;
        self.parse_json_response(response).await
    }

    /// Executes a POST request with retry logic.
    pub async fn post<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> ConnectorResult<Response> {
        let url = self.build_url(path);
        let request = self.client.post(&url).json(body);
        self.execute_with_retry(request).await
    }

    /// Executes a POST request and deserializes the JSON response.
    pub async fn post_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> ConnectorResult<R> {
        let response = self.post(path, body).await?;
        self.parse_json_response(response).await
    }

    /// Executes a multipart/form-data POST request.
    ///
    /// Multipart payloads are typically not cloneable, so this operation
    /// is sent as a single request without automatic retries.
    pub async fn post_multipart(&self, path: &str, form: Form) -> ConnectorResult<Response> {
        let url = self.build_url(path);
        let request = self.client.post(&url).multipart(form);
        self.execute_once(request).await
    }

    /// Executes a PUT request with retry logic.
    pub async fn put<T: Serialize + ?Sized>(
        &self,
        path: &str,
        body: &T,
    ) -> ConnectorResult<Response> {
        let url = self.build_url(path);
        let request = self.client.put(&url).json(body);
        self.execute_with_retry(request).await
    }

    /// Executes a PUT request and deserializes the JSON response.
    pub async fn put_json<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        body: &T,
    ) -> ConnectorResult<R> {
        let response = self.put(path, body).await?;
        self.parse_json_response(response).await
    }

    /// Executes a DELETE request with retry logic.
    pub async fn delete(&self, path: &str) -> ConnectorResult<Response> {
        let url = self.build_url(path);
        let request = self.client.delete(&url);
        self.execute_with_retry(request).await
    }

    /// Parses a JSON response.
    async fn parse_json_response<T: DeserializeOwned>(
        &self,
        response: Response,
    ) -> ConnectorResult<T> {
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        serde_json::from_str(&text).map_err(|e| {
            ConnectorError::InvalidResponse(format!(
                "Failed to parse response (status {}): {} - Body: {}",
                status,
                e,
                text.chars().take(500).collect::<String>()
            ))
        })
    }

    /// Executes a request once with authentication, rate limiting, and error handling.
    async fn execute_once(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> ConnectorResult<Response> {
        if let Some(limiter) = &self.rate_limiter {
            limiter.until_ready().await;
        }

        request = self.add_auth(request).await?;

        let response = request.send().await.map_err(|e| {
            if e.is_timeout() {
                ConnectorError::Timeout(e.to_string())
            } else if e.is_connect() {
                ConnectorError::ConnectionFailed(e.to_string())
            } else {
                ConnectorError::RequestFailed(e.to_string())
            }
        })?;

        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after = response
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60);
            return Err(ConnectorError::RateLimited(retry_after));
        }

        if status.is_client_error() {
            return match status {
                StatusCode::UNAUTHORIZED => {
                    Err(ConnectorError::AuthenticationFailed("Unauthorized".into()))
                }
                StatusCode::FORBIDDEN => {
                    Err(ConnectorError::AuthorizationDenied("Forbidden".into()))
                }
                StatusCode::NOT_FOUND => Err(ConnectorError::NotFound("Resource not found".into())),
                StatusCode::BAD_REQUEST => {
                    let body = response.text().await.unwrap_or_default();
                    Err(ConnectorError::RequestFailed(format!(
                        "Bad request: {}",
                        body
                    )))
                }
                _ => Err(ConnectorError::RequestFailed(format!(
                    "Client error: {}",
                    status
                ))),
            };
        }

        Ok(response)
    }

    /// Executes a request with authentication, rate limiting, retries, and error handling.
    async fn execute_with_retry(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> ConnectorResult<Response> {
        // Wait for rate limiter if configured
        if let Some(limiter) = &self.rate_limiter {
            limiter.until_ready().await;
        }

        // Add authentication
        request = self.add_auth(request).await?;

        let mut last_error = None;
        let mut delay = Duration::from_millis(100);

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                debug!("Retry attempt {} after {:?}", attempt, delay);
                sleep(delay).await;
                // Exponential backoff with jitter
                let jitter = rand_jitter();
                delay = std::cmp::min(delay * 2 + jitter, Duration::from_secs(30));
            }

            // Clone the request builder for retry
            let request_clone = request
                .try_clone()
                .ok_or_else(|| ConnectorError::Internal("Failed to clone request".to_string()))?;

            match request_clone.send().await {
                Ok(response) => {
                    let status = response.status();

                    // Handle rate limiting
                    if status == StatusCode::TOO_MANY_REQUESTS {
                        let retry_after = response
                            .headers()
                            .get("retry-after")
                            .and_then(|v| v.to_str().ok())
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(60);

                        warn!("Rate limited, waiting {} seconds", retry_after);

                        if attempt < self.config.max_retries {
                            sleep(Duration::from_secs(retry_after)).await;
                            continue;
                        }

                        return Err(ConnectorError::RateLimited(retry_after));
                    }

                    // Handle server errors (retry)
                    if status.is_server_error() && attempt < self.config.max_retries {
                        warn!("Server error {}, retrying...", status);
                        last_error = Some(ConnectorError::RequestFailed(format!(
                            "Server error: {}",
                            status
                        )));
                        continue;
                    }

                    // Handle client errors (don't retry)
                    if status.is_client_error() {
                        return match status {
                            StatusCode::UNAUTHORIZED => {
                                Err(ConnectorError::AuthenticationFailed("Unauthorized".into()))
                            }
                            StatusCode::FORBIDDEN => {
                                Err(ConnectorError::AuthorizationDenied("Forbidden".into()))
                            }
                            StatusCode::NOT_FOUND => {
                                Err(ConnectorError::NotFound("Resource not found".into()))
                            }
                            StatusCode::BAD_REQUEST => {
                                let body = response.text().await.unwrap_or_default();
                                Err(ConnectorError::RequestFailed(format!(
                                    "Bad request: {}",
                                    body
                                )))
                            }
                            _ => Err(ConnectorError::RequestFailed(format!(
                                "Client error: {}",
                                status
                            ))),
                        };
                    }

                    return Ok(response);
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(ConnectorError::Timeout(e.to_string()));
                    } else if e.is_connect() {
                        last_error = Some(ConnectorError::ConnectionFailed(e.to_string()));
                    } else {
                        last_error = Some(ConnectorError::RequestFailed(e.to_string()));
                    }

                    if attempt >= self.config.max_retries {
                        break;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| ConnectorError::Internal("Unknown error".to_string())))
    }

    /// Adds authentication to a request.
    async fn add_auth(
        &self,
        request: reqwest::RequestBuilder,
    ) -> ConnectorResult<reqwest::RequestBuilder> {
        match &self.config.auth {
            AuthConfig::None => Ok(request),

            AuthConfig::ApiKey { key, header_name } => {
                Ok(request.header(header_name, key.expose_secret()))
            }

            AuthConfig::BearerToken { token } => {
                Ok(request.header("Authorization", format!("Bearer {}", token.expose_secret())))
            }

            AuthConfig::Basic { username, password } => {
                Ok(request.basic_auth(username, Some(password.expose_secret())))
            }

            AuthConfig::OAuth2 {
                client_id,
                client_secret,
                token_url,
                scopes,
            } => {
                let token = self
                    .get_oauth_token(client_id, client_secret, token_url, scopes)
                    .await?;
                Ok(request.header("Authorization", format!("Bearer {}", token.expose_secret())))
            }
        }
    }

    /// Gets or refreshes an OAuth2 token.
    ///
    /// Returns a `SecureString` containing the access token, ensuring
    /// the token is zeroized from memory when no longer needed.
    async fn get_oauth_token(
        &self,
        client_id: &str,
        client_secret: &SecureString,
        token_url: &str,
        scopes: &[String],
    ) -> ConnectorResult<SecureString> {
        // Check if we have a valid token
        {
            let token = self.oauth_token.read().await;
            if let Some(t) = &*token {
                if t.expires_at > std::time::Instant::now() + Duration::from_secs(60) {
                    return Ok(t.access_token.clone());
                }
            }
        }

        // Fetch a new token
        info!("Fetching new OAuth2 token");

        let params = [
            ("grant_type", "client_credentials"),
            ("client_id", client_id),
            ("client_secret", client_secret.expose_secret()),
            ("scope", &scopes.join(" ")),
        ];

        let response = self
            .client
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| ConnectorError::AuthenticationFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ConnectorError::AuthenticationFailed(format!(
                "OAuth2 token request failed: {}",
                response.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: u64,
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        // Wrap the access token in SecureString immediately
        let secure_access_token = SecureString::new(token_response.access_token);

        let oauth_token = OAuthToken {
            access_token: secure_access_token.clone(),
            expires_at: std::time::Instant::now() + Duration::from_secs(token_response.expires_in),
        };

        // Store the token
        {
            let mut token = self.oauth_token.write().await;
            *token = Some(oauth_token);
        }

        Ok(secure_access_token)
    }
}

/// Generate a small random jitter for exponential backoff.
fn rand_jitter() -> Duration {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::time::Instant::now().hash(&mut hasher);
    let jitter_ms = hasher.finish() % 100;
    Duration::from_millis(jitter_ms)
}

/// Checks if the application is running in production mode.
/// Returns whether TLS verification can be disabled.
///
/// SECURITY: In release builds, this always returns false.
/// TLS verification cannot be disabled in production.
#[inline]
pub fn can_disable_tls_verification() -> bool {
    #[cfg(debug_assertions)]
    {
        true
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// Response cache using moka for high-performance async caching.
pub struct ResponseCache<V: Clone + Send + Sync + 'static> {
    cache: MokaCache<String, V>,
}

impl<V: Clone + Send + Sync + 'static> ResponseCache<V> {
    /// Creates a new cache with the specified TTL and max capacity.
    pub fn new(ttl: Duration, max_capacity: u64) -> Self {
        let cache = MokaCache::builder()
            .time_to_live(ttl)
            .max_capacity(max_capacity)
            .build();
        Self { cache }
    }

    /// Gets a value from the cache.
    pub async fn get(&self, key: &str) -> Option<V> {
        self.cache.get(key).await
    }

    /// Sets a value in the cache.
    pub async fn insert(&self, key: String, value: V) {
        self.cache.insert(key, value).await;
    }

    /// Removes a value from the cache.
    pub async fn invalidate(&self, key: &str) {
        self.cache.invalidate(key).await;
    }

    /// Clears all entries from the cache.
    pub async fn clear(&self) {
        self.cache.invalidate_all();
        // Run pending invalidations
        self.cache.run_pending_tasks().await;
    }

    /// Gets a value or inserts it using the provided async function.
    pub async fn get_or_insert_with<F, Fut>(&self, key: String, f: F) -> V
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = V>,
    {
        if let Some(v) = self.cache.get(&key).await {
            return v;
        }
        let value = f().await;
        self.cache.insert(key, value.clone()).await;
        value
    }

    /// Tries to get a value or inserts it using a fallible async function.
    pub async fn get_or_try_insert_with<F, Fut, E>(&self, key: String, f: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<V, E>>,
    {
        if let Some(v) = self.cache.get(&key).await {
            return Ok(v);
        }
        let value = f().await?;
        self.cache.insert(key, value.clone()).await;
        Ok(value)
    }
}

/// Simple in-memory cache with TTL (legacy, for backwards compatibility).
pub struct Cache<V> {
    entries: Arc<RwLock<std::collections::HashMap<String, CacheEntry<V>>>>,
    default_ttl: Duration,
}

struct CacheEntry<V> {
    value: V,
    expires_at: std::time::Instant,
}

impl<V: Clone> Cache<V> {
    /// Creates a new cache with the specified default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: Arc::new(RwLock::new(std::collections::HashMap::new())),
            default_ttl,
        }
    }

    /// Gets a value from the cache.
    pub async fn get(&self, key: &str) -> Option<V> {
        let entries = self.entries.read().await;
        if let Some(entry) = entries.get(key) {
            if entry.expires_at > std::time::Instant::now() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    /// Sets a value in the cache with the default TTL.
    pub async fn set(&self, key: String, value: V) {
        self.set_with_ttl(key, value, self.default_ttl).await;
    }

    /// Sets a value in the cache with a custom TTL.
    pub async fn set_with_ttl(&self, key: String, value: V, ttl: Duration) {
        let entry = CacheEntry {
            value,
            expires_at: std::time::Instant::now() + ttl,
        };
        let mut entries = self.entries.write().await;
        entries.insert(key, entry);
    }

    /// Removes a value from the cache.
    pub async fn remove(&self, key: &str) -> Option<V> {
        let mut entries = self.entries.write().await;
        entries.remove(key).map(|e| e.value)
    }

    /// Clears expired entries from the cache.
    pub async fn cleanup(&self) {
        let now = std::time::Instant::now();
        let mut entries = self.entries.write().await;
        entries.retain(|_, e| e.expires_at > now);
    }

    /// Clears all entries from the cache.
    pub async fn clear(&self) {
        let mut entries = self.entries.write().await;
        entries.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_config() -> ConnectorConfig {
        ConnectorConfig {
            name: "test".to_string(),
            base_url: "https://api.example.com".to_string(),
            auth: AuthConfig::None,
            timeout_secs: 30,
            max_retries: 3,
            verify_tls: true,
            headers: HashMap::new(),
        }
    }

    #[test]
    fn test_build_url() {
        let config = create_test_config();
        let client = HttpClient::new(config).unwrap();

        assert_eq!(
            client.build_url("/api/v1/resource"),
            "https://api.example.com/api/v1/resource"
        );
        assert_eq!(
            client.build_url("api/v1/resource"),
            "https://api.example.com/api/v1/resource"
        );
    }

    #[tokio::test]
    async fn test_cache_get_set() {
        let cache: Cache<String> = Cache::new(Duration::from_secs(60));

        cache.set("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("value1".to_string()));
        assert_eq!(cache.get("key2").await, None);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache: Cache<String> = Cache::new(Duration::from_millis(50));

        cache.set("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("value1".to_string()));

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(cache.get("key1").await, None);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let cache: Cache<String> = Cache::new(Duration::from_millis(50));

        cache.set("key1".to_string(), "value1".to_string()).await;
        cache
            .set_with_ttl(
                "key2".to_string(),
                "value2".to_string(),
                Duration::from_secs(60),
            )
            .await;

        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.cleanup().await;

        // key1 should be gone, key2 should remain
        assert_eq!(cache.get("key1").await, None);
        assert_eq!(cache.get("key2").await, Some("value2".to_string()));
    }

    #[tokio::test]
    async fn test_response_cache() {
        let cache: ResponseCache<String> = ResponseCache::new(Duration::from_secs(60), 100);

        cache.insert("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("value1".to_string()));
        assert_eq!(cache.get("key2").await, None);
    }

    #[tokio::test]
    async fn test_response_cache_get_or_insert() {
        let cache: ResponseCache<String> = ResponseCache::new(Duration::from_secs(60), 100);

        let value = cache
            .get_or_insert_with("key1".to_string(), || async { "value1".to_string() })
            .await;
        assert_eq!(value, "value1");

        // Should return cached value, not call the function again
        let value = cache
            .get_or_insert_with("key1".to_string(), || async { "value2".to_string() })
            .await;
        assert_eq!(value, "value1");
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.max_requests, 100);
        assert_eq!(config.period, Duration::from_secs(60));
        assert_eq!(config.burst_size, 10);
    }
}
