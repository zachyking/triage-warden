//! Cache abstraction for storing enrichment results and frequently accessed data.
//!
//! This module provides a `Cache` trait that supports TTL, atomic get-or-set operations,
//! and efficient batch operations for deduplicating concurrent enrichment requests.
//!
//! # Example
//!
//! ```ignore
//! use tw_core::cache::{Cache, MockCache, CacheError};
//! use std::time::Duration;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), CacheError> {
//!     let cache = MockCache::new();
//!
//!     // Basic set and get
//!     cache.set("key", b"value", Duration::from_secs(60)).await?;
//!     let value = cache.get("key").await?;
//!
//!     // Atomic get-or-set (prevents thundering herd)
//!     let value = cache.get_or_set("expensive_key", Duration::from_secs(300), || async {
//!         // This closure only runs if the key doesn't exist
//!         Ok(b"computed_value".to_vec())
//!     }).await?;
//!
//!     Ok(())
//! }
//! ```

mod error;
mod mock;
#[cfg(feature = "redis-cache")]
pub mod redis;
mod types;

pub use error::{CacheError, CacheResult};
pub use mock::MockCache;
#[cfg(feature = "redis-cache")]
pub use redis::{RedisCache, RedisCacheConfig};
pub use types::{CacheEntry, CacheStats};

use async_trait::async_trait;
use std::future::Future;
use std::time::Duration;

/// A dyn-safe cache trait for use in trait objects.
///
/// This trait includes only the methods that are dyn-compatible (no generic parameters).
/// Use this when you need `Arc<dyn DynCache>` for dependency injection.
///
/// For the full cache interface including `get_or_set`, use the [`Cache`] trait.
#[async_trait]
pub trait DynCache: Send + Sync + 'static {
    /// Gets a value from the cache by key.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError>;

    /// Sets a value in the cache with a TTL.
    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError>;

    /// Deletes a key from the cache.
    async fn delete(&self, key: &str) -> Result<bool, CacheError>;

    /// Checks if a key exists in the cache.
    async fn exists(&self, key: &str) -> Result<bool, CacheError>;

    /// Gets multiple values from the cache in a single operation.
    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, CacheError>;

    /// Sets multiple key-value pairs in a single operation.
    async fn mset(&self, entries: &[(&str, &[u8], Duration)]) -> Result<(), CacheError>;

    /// Returns current cache statistics.
    async fn stats(&self) -> CacheStats;
}

/// A trait for cache implementations supporting TTL, atomic operations, and batch access.
///
/// Implementations must be thread-safe (`Send + Sync`) and have a static lifetime.
/// The trait uses `async_trait` to support async methods in trait definitions.
///
/// # Key Features
///
/// - **TTL Support**: All entries can have a time-to-live. A TTL of `Duration::ZERO` means no expiration.
/// - **Atomic get-or-set**: The `get_or_set` method prevents thundering herd by ensuring only one
///   caller computes the value for a given key when multiple concurrent requests arrive.
/// - **Batch Operations**: `mget` and `mset` allow efficient bulk access to reduce round trips.
///
/// # Namespace Support
///
/// Implementations may support namespacing by prepending a prefix to all keys,
/// enabling tenant isolation in multi-tenant environments.
///
/// # Note on Trait Objects
///
/// This trait is NOT dyn-compatible due to the generic `get_or_set` method.
/// For trait objects, use [`DynCache`] instead.
#[async_trait]
pub trait Cache: DynCache {
    /// Atomically gets a value or computes and sets it if missing.
    ///
    /// This method prevents the "thundering herd" problem by ensuring that when multiple
    /// concurrent requests arrive for the same missing key, only one caller executes the
    /// computation function `f`. Other callers wait for the result.
    ///
    /// # Arguments
    ///
    /// * `key` - The cache key to look up or set
    /// * `ttl` - Time-to-live for the entry if it needs to be computed. `Duration::ZERO` means no expiration.
    /// * `f` - A function that computes the value if the key is missing
    ///
    /// # Example
    ///
    /// ```ignore
    /// let enrichment = cache.get_or_set("ip:192.168.1.1", Duration::from_secs(3600), || async {
    ///     // Expensive API call only happens once even with concurrent requests
    ///     let result = threat_intel_api.lookup("192.168.1.1").await?;
    ///     Ok(serde_json::to_vec(&result)?)
    /// }).await?;
    /// ```
    async fn get_or_set<F, Fut>(
        &self,
        key: &str,
        ttl: Duration,
        f: F,
    ) -> Result<Vec<u8>, CacheError>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<Vec<u8>, CacheError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_mock_basic_usage() {
        // Test that MockCache implements the Cache trait correctly
        let cache = MockCache::new();

        cache
            .set("test", b"value", Duration::from_secs(60))
            .await
            .unwrap();
        let result = cache.get("test").await.unwrap();
        assert_eq!(result, Some(b"value".to_vec()));
    }

    /// Helper function demonstrating how to use Cache trait with generics
    async fn use_cache<C: Cache>(cache: &C) -> Result<Vec<u8>, CacheError> {
        cache.set("key", b"value", Duration::from_secs(60)).await?;
        let result = cache.get("key").await?;
        Ok(result.unwrap_or_default())
    }

    #[tokio::test]
    async fn test_cache_trait_with_generics() {
        // The Cache trait is used with generics rather than trait objects
        // because `get_or_set` has generic type parameters.
        let cache = MockCache::new();
        let result = use_cache(&cache).await.unwrap();
        assert_eq!(result, b"value".to_vec());
    }
}
