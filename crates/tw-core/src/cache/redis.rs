//! Redis-based cache implementation.
//!
//! This module provides a production-ready cache implementation using Redis,
//! supporting TTL, distributed locking for atomic get-or-set operations,
//! and efficient batch operations.
//!
//! # Features
//!
//! - **Connection pooling**: Uses `deadpool-redis` for efficient connection management
//! - **Key namespacing**: All keys are prefixed for tenant isolation
//! - **TTL support**: Entries can expire after a configurable duration
//! - **Distributed locking**: Prevents thundering herd with SETNX-based locks
//! - **Batch operations**: MGET/MSET pipelines for efficient bulk access
//!
//! # Example
//!
//! ```ignore
//! use tw_core::cache::{Cache, RedisCache, RedisCacheConfig};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = RedisCacheConfig::new("redis://localhost:6379")
//!         .with_namespace("enrichment")
//!         .with_default_ttl(Duration::from_secs(3600));
//!
//!     let cache = RedisCache::new(config).await?;
//!
//!     // Basic operations
//!     cache.set("ip:1.2.3.4", b"threat_data", Duration::from_secs(300)).await?;
//!     let data = cache.get("ip:1.2.3.4").await?;
//!
//!     // Atomic get-or-set (prevents thundering herd)
//!     let enrichment = cache.get_or_set("ip:5.6.7.8", Duration::from_secs(300), || async {
//!         // Only one caller computes this, others wait
//!         Ok(b"expensive_computation_result".to_vec())
//!     }).await?;
//!
//!     Ok(())
//! }
//! ```

use super::{Cache, CacheError, CacheStats};
use async_trait::async_trait;
use deadpool_redis::{Config as PoolConfig, Pool, Runtime};
use redis::AsyncCommands;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Configuration for the Redis cache.
#[derive(Debug, Clone)]
pub struct RedisCacheConfig {
    /// Redis connection URL (e.g., "redis://localhost:6379").
    pub url: String,
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Default TTL for cache entries when not specified.
    pub default_ttl: Duration,
    /// Key prefix for all cache keys (e.g., "tw" for triage-warden).
    pub key_prefix: String,
    /// TTL for distributed locks in get_or_set operations.
    pub lock_ttl: Duration,
    /// Namespace for tenant/service isolation.
    pub namespace: String,
    /// Maximum retries for acquiring a lock.
    pub lock_max_retries: u32,
    /// Delay between lock acquisition retries.
    pub lock_retry_delay: Duration,
}

impl RedisCacheConfig {
    /// Creates a new configuration with the given Redis URL.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            max_connections: 16,
            default_ttl: Duration::from_secs(3600),
            key_prefix: "tw:cache".to_string(),
            lock_ttl: Duration::from_secs(5),
            namespace: "default".to_string(),
            lock_max_retries: 50,
            lock_retry_delay: Duration::from_millis(100),
        }
    }

    /// Sets the maximum number of connections in the pool.
    pub fn with_max_connections(mut self, max: u32) -> Self {
        self.max_connections = max;
        self
    }

    /// Sets the default TTL for cache entries.
    pub fn with_default_ttl(mut self, ttl: Duration) -> Self {
        self.default_ttl = ttl;
        self
    }

    /// Sets the key prefix for all cache keys.
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = prefix.into();
        self
    }

    /// Sets the lock TTL for distributed locking.
    pub fn with_lock_ttl(mut self, ttl: Duration) -> Self {
        self.lock_ttl = ttl;
        self
    }

    /// Sets the namespace for tenant isolation.
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = namespace.into();
        self
    }

    /// Sets the maximum retries for lock acquisition.
    pub fn with_lock_max_retries(mut self, retries: u32) -> Self {
        self.lock_max_retries = retries;
        self
    }

    /// Sets the delay between lock acquisition retries.
    pub fn with_lock_retry_delay(mut self, delay: Duration) -> Self {
        self.lock_retry_delay = delay;
        self
    }
}

impl Default for RedisCacheConfig {
    fn default() -> Self {
        Self::new("redis://localhost:6379")
    }
}

/// Internal structure for tracking cache statistics.
struct CacheStatsInternal {
    hits: AtomicU64,
    misses: AtomicU64,
}

impl CacheStatsInternal {
    fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::Relaxed);
    }

    fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

/// A Redis-based cache implementation.
///
/// This cache uses Redis for distributed caching with support for TTL,
/// atomic get-or-set operations with distributed locking, and batch operations.
///
/// # Thread Safety
///
/// `RedisCache` is thread-safe and can be shared across multiple tasks.
/// The connection pool handles concurrent access efficiently.
///
/// # Key Format
///
/// Keys are formatted as: `{key_prefix}:{namespace}:{key}`
///
/// For example, with prefix "tw:cache" and namespace "enrichment":
/// - Key "ip:1.2.3.4" becomes "tw:cache:enrichment:ip:1.2.3.4"
/// - Lock key becomes "tw:cache:lock:enrichment:ip:1.2.3.4"
pub struct RedisCache {
    pool: Pool,
    config: RedisCacheConfig,
    stats: Arc<CacheStatsInternal>,
    /// Instance ID for distributed lock ownership.
    instance_id: String,
    /// Cached DBSIZE for stats (approximate).
    cached_size: Arc<RwLock<u64>>,
}

impl RedisCache {
    /// Creates a new Redis cache with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns a `CacheError::Connection` if the Redis connection cannot be established.
    pub async fn new(config: RedisCacheConfig) -> Result<Self, CacheError> {
        let pool_config = PoolConfig::from_url(&config.url);
        let pool = pool_config
            .builder()
            .map_err(|e| CacheError::Connection(format!("Failed to create pool config: {}", e)))?
            .max_size(config.max_connections as usize)
            .runtime(Runtime::Tokio1)
            .build()
            .map_err(|e| CacheError::Connection(format!("Failed to build pool: {}", e)))?;

        // Test the connection
        let mut conn = pool
            .get()
            .await
            .map_err(|e| CacheError::Connection(format!("Failed to get connection: {}", e)))?;

        redis::cmd("PING")
            .query_async::<String>(&mut *conn)
            .await
            .map_err(|e| CacheError::Connection(format!("Redis PING failed: {}", e)))?;

        Ok(Self {
            pool,
            config,
            stats: Arc::new(CacheStatsInternal::new()),
            instance_id: Uuid::new_v4().to_string(),
            cached_size: Arc::new(RwLock::new(0)),
        })
    }

    /// Returns the full key including prefix and namespace.
    fn full_key(&self, key: &str) -> String {
        format!(
            "{}:{}:{}",
            self.config.key_prefix, self.config.namespace, key
        )
    }

    /// Returns the lock key for a given cache key.
    fn lock_key(&self, key: &str) -> String {
        format!(
            "{}:lock:{}:{}",
            self.config.key_prefix, self.config.namespace, key
        )
    }

    /// Gets a connection from the pool.
    async fn get_conn(&self) -> Result<deadpool_redis::Connection, CacheError> {
        self.pool
            .get()
            .await
            .map_err(|e| CacheError::Connection(format!("Failed to get connection: {}", e)))
    }

    /// Tries to acquire a distributed lock for the given key.
    ///
    /// Returns `true` if the lock was acquired, `false` otherwise.
    async fn try_acquire_lock(&self, key: &str) -> Result<bool, CacheError> {
        let lock_key = self.lock_key(key);
        let lock_ttl_secs = self.config.lock_ttl.as_secs().max(1);

        let mut conn = self.get_conn().await?;

        // Use SET with NX and EX options for atomic lock acquisition
        let result: Option<String> = redis::cmd("SET")
            .arg(&lock_key)
            .arg(&self.instance_id)
            .arg("NX")
            .arg("EX")
            .arg(lock_ttl_secs)
            .query_async(&mut *conn)
            .await
            .map_err(|e| CacheError::Unknown(format!("Lock acquisition failed: {}", e)))?;

        Ok(result.is_some())
    }

    /// Releases a distributed lock if we own it.
    async fn release_lock(&self, key: &str) -> Result<(), CacheError> {
        let lock_key = self.lock_key(key);
        let mut conn = self.get_conn().await?;

        // Use a Lua script to atomically check ownership and delete
        // This prevents releasing a lock that was acquired by another instance after expiry
        let script = r#"
            if redis.call("GET", KEYS[1]) == ARGV[1] then
                return redis.call("DEL", KEYS[1])
            else
                return 0
            end
        "#;

        redis::Script::new(script)
            .key(&lock_key)
            .arg(&self.instance_id)
            .invoke_async::<i32>(&mut *conn)
            .await
            .map_err(|e| CacheError::Unknown(format!("Lock release failed: {}", e)))?;

        Ok(())
    }

    /// Resets the statistics counters.
    pub fn reset_stats(&self) {
        self.stats.hits.store(0, Ordering::Relaxed);
        self.stats.misses.store(0, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for RedisCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisCache")
            .field("namespace", &self.config.namespace)
            .field("key_prefix", &self.config.key_prefix)
            .field("instance_id", &self.instance_id)
            .finish()
    }
}

#[async_trait]
impl Cache for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let full_key = self.full_key(key);
        let mut conn = self.get_conn().await?;

        let result: Option<Vec<u8>> = conn
            .get(&full_key)
            .await
            .map_err(|e| CacheError::Unknown(format!("Redis GET failed: {}", e)))?;

        match result {
            Some(value) => {
                self.stats.record_hit();
                Ok(Some(value))
            }
            None => {
                self.stats.record_miss();
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        let full_key = self.full_key(key);
        let mut conn = self.get_conn().await?;

        if ttl.is_zero() {
            // No expiration
            let _: () = conn
                .set(&full_key, value)
                .await
                .map_err(|e| CacheError::Unknown(format!("Redis SET failed: {}", e)))?;
        } else {
            // Set with expiration
            let ttl_secs = ttl.as_secs().max(1);
            let _: () = conn
                .set_ex(&full_key, value, ttl_secs)
                .await
                .map_err(|e| CacheError::Unknown(format!("Redis SETEX failed: {}", e)))?;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, CacheError> {
        let full_key = self.full_key(key);
        let mut conn = self.get_conn().await?;

        let deleted: i32 = conn
            .del(&full_key)
            .await
            .map_err(|e| CacheError::Unknown(format!("Redis DEL failed: {}", e)))?;

        Ok(deleted > 0)
    }

    async fn exists(&self, key: &str) -> Result<bool, CacheError> {
        let full_key = self.full_key(key);
        let mut conn = self.get_conn().await?;

        let exists: bool = conn
            .exists(&full_key)
            .await
            .map_err(|e| CacheError::Unknown(format!("Redis EXISTS failed: {}", e)))?;

        Ok(exists)
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, CacheError> {
        if keys.is_empty() {
            return Ok(vec![]);
        }

        let full_keys: Vec<String> = keys.iter().map(|k| self.full_key(k)).collect();
        let mut conn = self.get_conn().await?;

        // Use MGET for batch retrieval
        let results: Vec<Option<Vec<u8>>> = conn
            .mget(&full_keys)
            .await
            .map_err(|e| CacheError::Unknown(format!("Redis MGET failed: {}", e)))?;

        // Track stats
        for result in &results {
            if result.is_some() {
                self.stats.record_hit();
            } else {
                self.stats.record_miss();
            }
        }

        Ok(results)
    }

    async fn mset(&self, entries: &[(&str, &[u8], Duration)]) -> Result<(), CacheError> {
        if entries.is_empty() {
            return Ok(());
        }

        let mut conn = self.get_conn().await?;

        // Use a pipeline for efficient batch setting
        let mut pipe = redis::pipe();

        for (key, value, ttl) in entries {
            let full_key = self.full_key(key);
            if ttl.is_zero() {
                pipe.set(&full_key, *value);
            } else {
                let ttl_secs = ttl.as_secs().max(1);
                pipe.set_ex(&full_key, *value, ttl_secs);
            }
        }

        pipe.query_async::<()>(&mut *conn)
            .await
            .map_err(|e| CacheError::Unknown(format!("Redis MSET pipeline failed: {}", e)))?;

        Ok(())
    }

    async fn get_or_set<F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        f: F,
    ) -> Result<Vec<u8>, CacheError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Vec<u8>, CacheError>> + Send,
    {
        // First, try a quick read
        if let Some(value) = self.get(key).await? {
            return Ok(value);
        }

        // Try to acquire the distributed lock
        let mut retries = 0;
        let mut lock_acquired = false;

        while retries < self.config.lock_max_retries {
            if self.try_acquire_lock(key).await? {
                lock_acquired = true;
                break;
            }

            // Wait a bit and check if someone else computed the value
            tokio::time::sleep(self.config.lock_retry_delay).await;

            // Double-check if the value is now available
            if let Some(value) = self.get(key).await? {
                return Ok(value);
            }

            retries += 1;
        }

        if !lock_acquired {
            return Err(CacheError::LockTimeout(format!(
                "Failed to acquire lock for key '{}' after {} retries",
                key, self.config.lock_max_retries
            )));
        }

        // We have the lock - double-check the cache (another process might have set it)
        if let Some(value) = self.get(key).await? {
            // Release lock and return the value
            let _ = self.release_lock(key).await;
            return Ok(value);
        }

        // Compute the value
        let result = f().await;

        // Always try to release the lock, even on error
        let release_result = self.release_lock(key).await;

        match result {
            Ok(value) => {
                // Store the computed value
                self.set(key, &value, ttl).await?;

                // Check if lock release failed (log it but don't fail the operation)
                if let Err(e) = release_result {
                    tracing::warn!("Failed to release lock for key '{}': {}", key, e);
                }

                Ok(value)
            }
            Err(e) => {
                // Check if lock release failed (log it but return the original error)
                if let Err(lock_err) = release_result {
                    tracing::warn!("Failed to release lock for key '{}': {}", key, lock_err);
                }

                Err(e)
            }
        }
    }

    fn stats(&self) -> CacheStats {
        let hits = self.stats.hits();
        let misses = self.stats.misses();

        // Get cached size (we can't await in a sync fn)
        let size = match self.cached_size.try_read() {
            Ok(s) => *s,
            Err(_) => 0,
        };

        // Trigger an async size update in the background
        let cache = self.cached_size.clone();
        let pool = self.pool.clone();
        let prefix = self.config.key_prefix.clone();
        let namespace = self.config.namespace.clone();

        tokio::spawn(async move {
            if let Ok(mut conn) = pool.get().await {
                let pattern = format!("{}:{}:*", prefix, namespace);
                if let Ok(keys) = redis::cmd("KEYS")
                    .arg(&pattern)
                    .query_async::<Vec<String>>(&mut *conn)
                    .await
                {
                    if let Ok(mut size) = cache.try_write() {
                        *size = keys.len() as u64;
                    }
                }
            }
        });

        CacheStats::new(hits, misses, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests that require a running Redis instance should be marked with #[ignore].
    /// Run them with: cargo test --package tw-core cache::redis -- --ignored

    fn test_config() -> RedisCacheConfig {
        RedisCacheConfig::new("redis://localhost:6379")
            .with_namespace("test")
            .with_key_prefix("tw:test:cache")
    }

    #[test]
    fn test_config_builder() {
        let config = RedisCacheConfig::new("redis://custom:6380")
            .with_max_connections(32)
            .with_default_ttl(Duration::from_secs(7200))
            .with_key_prefix("custom:prefix")
            .with_lock_ttl(Duration::from_secs(10))
            .with_namespace("tenant1")
            .with_lock_max_retries(100)
            .with_lock_retry_delay(Duration::from_millis(50));

        assert_eq!(config.url, "redis://custom:6380");
        assert_eq!(config.max_connections, 32);
        assert_eq!(config.default_ttl, Duration::from_secs(7200));
        assert_eq!(config.key_prefix, "custom:prefix");
        assert_eq!(config.lock_ttl, Duration::from_secs(10));
        assert_eq!(config.namespace, "tenant1");
        assert_eq!(config.lock_max_retries, 100);
        assert_eq!(config.lock_retry_delay, Duration::from_millis(50));
    }

    #[test]
    fn test_config_default() {
        let config = RedisCacheConfig::default();
        assert_eq!(config.url, "redis://localhost:6379");
        assert_eq!(config.max_connections, 16);
        assert_eq!(config.namespace, "default");
    }

    #[test]
    fn test_key_formatting() {
        // We can test key formatting without Redis
        let config = RedisCacheConfig::new("redis://localhost:6379")
            .with_key_prefix("tw:cache")
            .with_namespace("enrichment");

        let prefix = &config.key_prefix;
        let namespace = &config.namespace;

        let full_key = format!("{}:{}:{}", prefix, namespace, "ip:1.2.3.4");
        assert_eq!(full_key, "tw:cache:enrichment:ip:1.2.3.4");

        let lock_key = format!("{}:lock:{}:{}", prefix, namespace, "ip:1.2.3.4");
        assert_eq!(lock_key, "tw:cache:lock:enrichment:ip:1.2.3.4");
    }

    // Integration tests that require Redis
    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_connection() {
        let config = test_config();
        let cache = RedisCache::new(config).await;
        assert!(cache.is_ok(), "Should connect to Redis: {:?}", cache.err());
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_basic_set_get() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Clean up any existing test key
        let _ = cache.delete("basic_test_key").await;

        // Set a value
        cache
            .set("basic_test_key", b"test_value", Duration::from_secs(60))
            .await
            .unwrap();

        // Get the value
        let result = cache.get("basic_test_key").await.unwrap();
        assert_eq!(result, Some(b"test_value".to_vec()));

        // Clean up
        cache.delete("basic_test_key").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_get_missing() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        let result = cache.get("nonexistent_key_xyz").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_delete() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        cache
            .set("delete_test", b"value", Duration::from_secs(60))
            .await
            .unwrap();

        let deleted = cache.delete("delete_test").await.unwrap();
        assert!(deleted);

        let result = cache.get("delete_test").await.unwrap();
        assert_eq!(result, None);

        // Delete non-existent key
        let deleted = cache.delete("delete_test").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_exists() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Clean up
        let _ = cache.delete("exists_test").await;

        assert!(!cache.exists("exists_test").await.unwrap());

        cache
            .set("exists_test", b"value", Duration::from_secs(60))
            .await
            .unwrap();

        assert!(cache.exists("exists_test").await.unwrap());

        // Clean up
        cache.delete("exists_test").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_ttl_expiration() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Set with very short TTL (1 second minimum for Redis)
        cache
            .set("ttl_test", b"value", Duration::from_secs(1))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.exists("ttl_test").await.unwrap());

        // Wait for expiration
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be expired now
        let result = cache.get("ttl_test").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_mget() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Clean up
        let _ = cache.delete("mget_1").await;
        let _ = cache.delete("mget_2").await;
        let _ = cache.delete("mget_3").await;

        cache
            .set("mget_1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("mget_2", b"value2", Duration::from_secs(60))
            .await
            .unwrap();

        let results = cache.mget(&["mget_1", "mget_2", "mget_3"]).await.unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Some(b"value1".to_vec()));
        assert_eq!(results[1], Some(b"value2".to_vec()));
        assert_eq!(results[2], None);

        // Clean up
        cache.delete("mget_1").await.unwrap();
        cache.delete("mget_2").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_mset() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        let entries: Vec<(&str, &[u8], Duration)> = vec![
            ("mset_1", b"value1", Duration::from_secs(60)),
            ("mset_2", b"value2", Duration::from_secs(60)),
            ("mset_3", b"value3", Duration::ZERO),
        ];

        cache.mset(&entries).await.unwrap();

        assert_eq!(cache.get("mset_1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(cache.get("mset_2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(cache.get("mset_3").await.unwrap(), Some(b"value3".to_vec()));

        // Clean up
        cache.delete("mset_1").await.unwrap();
        cache.delete("mset_2").await.unwrap();
        cache.delete("mset_3").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_get_or_set_missing() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Clean up
        let _ = cache.delete("get_or_set_test").await;

        let result = cache
            .get_or_set("get_or_set_test", Duration::from_secs(60), || async {
                Ok(b"computed_value".to_vec())
            })
            .await
            .unwrap();

        assert_eq!(result, b"computed_value".to_vec());

        // Value should now be cached
        let cached = cache.get("get_or_set_test").await.unwrap();
        assert_eq!(cached, Some(b"computed_value".to_vec()));

        // Clean up
        cache.delete("get_or_set_test").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_get_or_set_existing() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        // Pre-set the value
        cache
            .set("get_or_set_existing", b"existing", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache
            .get_or_set("get_or_set_existing", Duration::from_secs(60), || async {
                // This should not be called
                Ok(b"computed".to_vec())
            })
            .await
            .unwrap();

        // Should return existing value
        assert_eq!(result, b"existing".to_vec());

        // Clean up
        cache.delete("get_or_set_existing").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_stats() {
        let config = test_config();
        let cache = RedisCache::new(config).await.unwrap();

        cache.reset_stats();

        // Generate some misses
        cache.get("nonexistent1").await.unwrap();
        cache.get("nonexistent2").await.unwrap();

        // Set and hit
        cache
            .set("stats_test", b"value", Duration::from_secs(60))
            .await
            .unwrap();
        cache.get("stats_test").await.unwrap();

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 2);

        // Clean up
        cache.delete("stats_test").await.unwrap();
    }

    #[tokio::test]
    #[ignore]
    async fn test_redis_cache_concurrent_get_or_set() {
        use std::sync::atomic::AtomicUsize;

        let config = test_config();
        let cache = Arc::new(RedisCache::new(config).await.unwrap());

        // Clean up
        let _ = cache.delete("concurrent_test").await;

        let computation_count = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        // Spawn multiple concurrent tasks
        for _ in 0..5 {
            let cache = Arc::clone(&cache);
            let count = Arc::clone(&computation_count);

            let handle = tokio::spawn(async move {
                cache
                    .get_or_set("concurrent_test", Duration::from_secs(60), || {
                        let count = Arc::clone(&count);
                        async move {
                            // Simulate expensive computation
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            count.fetch_add(1, Ordering::SeqCst);
                            Ok(b"computed".to_vec())
                        }
                    })
                    .await
            });

            handles.push(handle);
        }

        // Wait for all tasks
        for handle in handles {
            let result = handle.await.unwrap().unwrap();
            assert_eq!(result, b"computed".to_vec());
        }

        // Only one computation should have run
        let final_count = computation_count.load(Ordering::SeqCst);
        assert_eq!(
            final_count, 1,
            "Expected 1 computation, got {}",
            final_count
        );

        // Clean up
        cache.delete("concurrent_test").await.unwrap();
    }
}
