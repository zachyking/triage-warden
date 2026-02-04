//! Mock cache implementation for testing.

use super::{Cache, CacheEntry, CacheError, CacheStats};
use async_trait::async_trait;
use chrono::{Duration as ChronoDuration, Utc};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

/// A mock cache implementation using an in-memory HashMap.
///
/// This implementation is intended for testing and development purposes.
/// It supports TTL, atomic get-or-set operations with thundering herd protection,
/// and maintains statistics for hits and misses.
///
/// # Thread Safety
///
/// Uses `tokio::sync::RwLock` for the cache data and `tokio::sync::Mutex` for
/// per-key locking during get_or_set operations to prevent thundering herd.
#[derive(Debug)]
pub struct MockCache {
    /// The cache data store.
    data: RwLock<HashMap<String, CacheEntry>>,
    /// Per-key locks for get_or_set operations.
    key_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Optional namespace prefix for all keys.
    namespace: Option<String>,
    /// Cache hit counter.
    hits: AtomicU64,
    /// Cache miss counter.
    misses: AtomicU64,
}

impl MockCache {
    /// Creates a new mock cache with no namespace.
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            key_locks: Mutex::new(HashMap::new()),
            namespace: None,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Creates a new mock cache with a namespace prefix.
    ///
    /// All keys will be prefixed with `{namespace}:` for tenant isolation.
    pub fn with_namespace(namespace: impl Into<String>) -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            key_locks: Mutex::new(HashMap::new()),
            namespace: Some(namespace.into()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Returns the full key including namespace prefix if set.
    fn full_key(&self, key: &str) -> String {
        match &self.namespace {
            Some(ns) => format!("{}:{}", ns, key),
            None => key.to_string(),
        }
    }

    /// Gets or creates a lock for a specific key.
    async fn get_key_lock(&self, key: &str) -> Arc<Mutex<()>> {
        let mut locks = self.key_locks.lock().await;
        locks
            .entry(key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Cleans up expired entries from the cache.
    ///
    /// This is called periodically during operations but can also be called manually.
    pub async fn cleanup_expired(&self) {
        let mut data = self.data.write().await;
        data.retain(|_, entry| !entry.is_expired());
    }

    /// Clears all entries from the cache.
    pub async fn clear(&self) {
        let mut data = self.data.write().await;
        data.clear();
    }

    /// Resets the statistics counters.
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::SeqCst);
        self.misses.store(0, Ordering::SeqCst);
    }

    /// Records a cache hit.
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::SeqCst);
    }

    /// Records a cache miss.
    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::SeqCst);
    }
}

impl Default for MockCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Cache for MockCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, CacheError> {
        let full_key = self.full_key(key);
        let data = self.data.read().await;

        match data.get(&full_key) {
            Some(entry) if !entry.is_expired() => {
                self.record_hit();
                Ok(Some(entry.value.clone()))
            }
            Some(_) => {
                // Entry exists but is expired - count as miss
                self.record_miss();
                Ok(None)
            }
            None => {
                self.record_miss();
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: &[u8], ttl: Duration) -> Result<(), CacheError> {
        let full_key = self.full_key(key);
        let expires_at = if ttl.is_zero() {
            None
        } else {
            Some(Utc::now() + ChronoDuration::milliseconds(ttl.as_millis() as i64))
        };

        let entry = CacheEntry::new(value.to_vec(), expires_at);

        let mut data = self.data.write().await;
        data.insert(full_key, entry);

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<bool, CacheError> {
        let full_key = self.full_key(key);
        let mut data = self.data.write().await;
        Ok(data.remove(&full_key).is_some())
    }

    async fn exists(&self, key: &str) -> Result<bool, CacheError> {
        let full_key = self.full_key(key);
        let data = self.data.read().await;

        match data.get(&full_key) {
            Some(entry) => Ok(!entry.is_expired()),
            None => Ok(false),
        }
    }

    async fn mget(&self, keys: &[&str]) -> Result<Vec<Option<Vec<u8>>>, CacheError> {
        let data = self.data.read().await;
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            let full_key = self.full_key(key);
            match data.get(&full_key) {
                Some(entry) if !entry.is_expired() => {
                    self.record_hit();
                    results.push(Some(entry.value.clone()));
                }
                _ => {
                    self.record_miss();
                    results.push(None);
                }
            }
        }

        Ok(results)
    }

    async fn mset(&self, entries: &[(&str, &[u8], Duration)]) -> Result<(), CacheError> {
        let mut data = self.data.write().await;

        for (key, value, ttl) in entries {
            let full_key = self.full_key(key);
            let expires_at = if ttl.is_zero() {
                None
            } else {
                Some(Utc::now() + ChronoDuration::milliseconds(ttl.as_millis() as i64))
            };

            let entry = CacheEntry::new(value.to_vec(), expires_at);
            data.insert(full_key, entry);
        }

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
        // First, try a quick read without locking
        if let Some(value) = self.get(key).await? {
            return Ok(value);
        }

        // Get or create a lock for this specific key
        let key_lock = self.get_key_lock(key).await;

        // Acquire the key-specific lock
        let _guard = key_lock.lock().await;

        // Double-check after acquiring lock (another thread may have set it)
        if let Some(value) = self.get(key).await? {
            return Ok(value);
        }

        // Compute the value
        let value = f().await?;

        // Store it in the cache
        self.set(key, &value, ttl).await?;

        Ok(value)
    }

    fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::SeqCst);
        let misses = self.misses.load(Ordering::SeqCst);

        // Get size synchronously - this is a best-effort count
        // In a real implementation, this might be tracked atomically
        let size = {
            // We can't await in a non-async fn, so we use try_read
            // If we can't get the lock, return 0 as a reasonable default
            match self.data.try_read() {
                Ok(data) => data.len() as u64,
                Err(_) => 0,
            }
        };

        CacheStats::new(hits, misses, size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_basic_set_get() {
        let cache = MockCache::new();

        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("key1").await.unwrap();
        assert_eq!(result, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_get_missing_key() {
        let cache = MockCache::new();
        let result = cache.get("nonexistent").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete() {
        let cache = MockCache::new();

        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();

        let deleted = cache.delete("key1").await.unwrap();
        assert!(deleted);

        let result = cache.get("key1").await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_delete_missing_key() {
        let cache = MockCache::new();
        let deleted = cache.delete("nonexistent").await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_exists() {
        let cache = MockCache::new();

        assert!(!cache.exists("key1").await.unwrap());

        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();

        assert!(cache.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let cache = MockCache::new();

        // Set with very short TTL
        cache
            .set("key1", b"value1", Duration::from_millis(50))
            .await
            .unwrap();

        // Should exist immediately
        assert!(cache.exists("key1").await.unwrap());

        // Wait for expiration
        sleep(Duration::from_millis(100)).await;

        // Should be expired now
        let result = cache.get("key1").await.unwrap();
        assert_eq!(result, None);
        assert!(!cache.exists("key1").await.unwrap());
    }

    #[tokio::test]
    async fn test_zero_ttl_never_expires() {
        let cache = MockCache::new();

        cache
            .set("permanent", b"value", Duration::ZERO)
            .await
            .unwrap();

        // Wait a bit
        sleep(Duration::from_millis(50)).await;

        // Should still exist
        let result = cache.get("permanent").await.unwrap();
        assert_eq!(result, Some(b"value".to_vec()));
    }

    #[tokio::test]
    async fn test_mget() {
        let cache = MockCache::new();

        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("key2", b"value2", Duration::from_secs(60))
            .await
            .unwrap();

        let results = cache.mget(&["key1", "key2", "key3"]).await.unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0], Some(b"value1".to_vec()));
        assert_eq!(results[1], Some(b"value2".to_vec()));
        assert_eq!(results[2], None);
    }

    #[tokio::test]
    async fn test_mset() {
        let cache = MockCache::new();

        let entries: Vec<(&str, &[u8], Duration)> = vec![
            ("key1", b"value1", Duration::from_secs(60)),
            ("key2", b"value2", Duration::from_secs(60)),
            ("key3", b"value3", Duration::ZERO),
        ];

        cache.mset(&entries).await.unwrap();

        assert_eq!(cache.get("key1").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(cache.get("key2").await.unwrap(), Some(b"value2".to_vec()));
        assert_eq!(cache.get("key3").await.unwrap(), Some(b"value3".to_vec()));
    }

    #[tokio::test]
    async fn test_get_or_set_existing() {
        let cache = MockCache::new();

        cache
            .set("key1", b"existing", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache
            .get_or_set("key1", Duration::from_secs(60), || async {
                Ok(b"computed".to_vec())
            })
            .await
            .unwrap();

        // Should return existing value, not computed one
        assert_eq!(result, b"existing".to_vec());
    }

    #[tokio::test]
    async fn test_get_or_set_missing() {
        let cache = MockCache::new();

        let result = cache
            .get_or_set("key1", Duration::from_secs(60), || async {
                Ok(b"computed".to_vec())
            })
            .await
            .unwrap();

        assert_eq!(result, b"computed".to_vec());

        // Value should now be in cache
        let cached = cache.get("key1").await.unwrap();
        assert_eq!(cached, Some(b"computed".to_vec()));
    }

    #[tokio::test]
    async fn test_get_or_set_concurrent() {
        let cache = Arc::new(MockCache::new());
        let computation_count = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];

        // Spawn 10 concurrent tasks all trying to get_or_set the same key
        for _ in 0..10 {
            let cache = Arc::clone(&cache);
            let count = Arc::clone(&computation_count);

            let handle = tokio::spawn(async move {
                cache
                    .get_or_set("shared_key", Duration::from_secs(60), || {
                        let count = Arc::clone(&count);
                        async move {
                            // Simulate expensive computation
                            sleep(Duration::from_millis(50)).await;
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

        // The computation should have run only once due to thundering herd protection
        let final_count = computation_count.load(Ordering::SeqCst);
        assert_eq!(
            final_count, 1,
            "Expected computation to run exactly once, but ran {} times",
            final_count
        );
    }

    #[tokio::test]
    async fn test_stats() {
        let cache = MockCache::new();

        // Initial stats should be zero
        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.hit_rate, 0.0);

        // Miss
        cache.get("nonexistent").await.unwrap();

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);

        // Set and hit
        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache.get("key1").await.unwrap();

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.5).abs() < f64::EPSILON);
        assert_eq!(stats.size, 1);
    }

    #[tokio::test]
    async fn test_namespace() {
        let cache1 = MockCache::with_namespace("tenant1");
        let cache2 = MockCache::with_namespace("tenant2");

        cache1
            .set("key", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache2
            .set("key", b"value2", Duration::from_secs(60))
            .await
            .unwrap();

        // Each namespace has its own key
        assert_eq!(cache1.get("key").await.unwrap(), Some(b"value1".to_vec()));
        assert_eq!(cache2.get("key").await.unwrap(), Some(b"value2".to_vec()));
    }

    #[tokio::test]
    async fn test_clear() {
        let cache = MockCache::new();

        cache
            .set("key1", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("key2", b"value2", Duration::from_secs(60))
            .await
            .unwrap();

        cache.clear().await;

        assert_eq!(cache.get("key1").await.unwrap(), None);
        assert_eq!(cache.get("key2").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_cleanup_expired() {
        let cache = MockCache::new();

        cache
            .set("short", b"value", Duration::from_millis(10))
            .await
            .unwrap();
        cache
            .set("long", b"value", Duration::from_secs(60))
            .await
            .unwrap();

        // Wait for short TTL to expire
        sleep(Duration::from_millis(50)).await;

        cache.cleanup_expired().await;

        let stats = cache.stats();
        assert_eq!(stats.size, 1); // Only "long" key should remain
    }

    #[tokio::test]
    async fn test_reset_stats() {
        let cache = MockCache::new();

        cache.get("miss1").await.unwrap();
        cache.get("miss2").await.unwrap();

        let stats = cache.stats();
        assert_eq!(stats.misses, 2);

        cache.reset_stats();

        let stats = cache.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[tokio::test]
    async fn test_overwrite_existing() {
        let cache = MockCache::new();

        cache
            .set("key", b"value1", Duration::from_secs(60))
            .await
            .unwrap();
        cache
            .set("key", b"value2", Duration::from_secs(60))
            .await
            .unwrap();

        let result = cache.get("key").await.unwrap();
        assert_eq!(result, Some(b"value2".to_vec()));
    }
}
