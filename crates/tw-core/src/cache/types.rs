//! Cache types and structures.

use chrono::{DateTime, Utc};

/// Statistics for cache operations.
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Current number of entries in the cache.
    pub size: u64,
    /// Cache hit rate (hits / (hits + misses)), 0.0 if no operations.
    pub hit_rate: f64,
}

impl CacheStats {
    /// Creates a new CacheStats instance with the given values.
    pub fn new(hits: u64, misses: u64, size: u64) -> Self {
        let hit_rate = if hits + misses > 0 {
            hits as f64 / (hits + misses) as f64
        } else {
            0.0
        };

        Self {
            hits,
            misses,
            size,
            hit_rate,
        }
    }

    /// Returns the total number of cache operations (hits + misses).
    pub fn total_operations(&self) -> u64 {
        self.hits + self.misses
    }
}

/// A single cache entry with value and expiration.
#[derive(Debug, Clone)]
pub struct CacheEntry {
    /// The cached value as bytes.
    pub value: Vec<u8>,
    /// When this entry expires, or None for no expiration.
    pub expires_at: Option<DateTime<Utc>>,
}

impl CacheEntry {
    /// Creates a new cache entry with the given value and expiration.
    pub fn new(value: Vec<u8>, expires_at: Option<DateTime<Utc>>) -> Self {
        Self { value, expires_at }
    }

    /// Creates a cache entry that never expires.
    pub fn permanent(value: Vec<u8>) -> Self {
        Self {
            value,
            expires_at: None,
        }
    }

    /// Returns true if this entry has expired.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(expires) => Utc::now() >= expires,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_cache_stats_new() {
        let stats = CacheStats::new(80, 20, 100);
        assert_eq!(stats.hits, 80);
        assert_eq!(stats.misses, 20);
        assert_eq!(stats.size, 100);
        assert!((stats.hit_rate - 0.8).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cache_stats_zero_operations() {
        let stats = CacheStats::new(0, 0, 0);
        assert_eq!(stats.hit_rate, 0.0);
    }

    #[test]
    fn test_cache_stats_total_operations() {
        let stats = CacheStats::new(50, 50, 100);
        assert_eq!(stats.total_operations(), 100);
    }

    #[test]
    fn test_cache_entry_not_expired() {
        let entry = CacheEntry::new(vec![1, 2, 3], Some(Utc::now() + Duration::hours(1)));
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expired() {
        let entry = CacheEntry::new(vec![1, 2, 3], Some(Utc::now() - Duration::hours(1)));
        assert!(entry.is_expired());
    }

    #[test]
    fn test_cache_entry_permanent() {
        let entry = CacheEntry::permanent(vec![1, 2, 3]);
        assert!(entry.expires_at.is_none());
        assert!(!entry.is_expired());
    }
}
