//! Types for enrichment caching.

use std::net::IpAddr;
use std::time::Duration;
use thiserror::Error;

/// Default TTL for threat intel lookups (5 minutes).
pub const DEFAULT_THREAT_INTEL_TTL_SECS: u64 = 300;

/// Default TTL for asset/host info lookups (1 hour).
pub const DEFAULT_ASSET_INFO_TTL_SECS: u64 = 3600;

/// Default TTL for user info lookups (30 minutes).
pub const DEFAULT_USER_INFO_TTL_SECS: u64 = 1800;

/// Default TTL for other enrichment types (15 minutes).
pub const DEFAULT_TTL_SECS: u64 = 900;

/// Errors that can occur during enrichment operations.
#[derive(Error, Debug, Clone)]
pub enum EnrichmentError {
    /// Cache operation failed.
    #[error("Cache error: {0}")]
    Cache(String),

    /// Connector operation failed.
    #[error("Connector error: {0}")]
    Connector(String),

    /// Serialization/deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Feature not enabled.
    #[error("Feature not enabled: {0}")]
    FeatureDisabled(String),

    /// Invalid request.
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

/// Result type for enrichment operations.
pub type EnrichmentResult<T> = Result<T, EnrichmentError>;

/// Configuration for enrichment caching.
#[derive(Debug, Clone)]
pub struct EnrichmentConfig {
    /// TTL for threat intel lookups.
    pub threat_intel_ttl: Duration,
    /// TTL for asset/host info lookups.
    pub asset_info_ttl: Duration,
    /// TTL for user info lookups.
    pub user_info_ttl: Duration,
    /// Default TTL for other enrichment types.
    pub default_ttl: Duration,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self {
            threat_intel_ttl: Duration::from_secs(DEFAULT_THREAT_INTEL_TTL_SECS),
            asset_info_ttl: Duration::from_secs(DEFAULT_ASSET_INFO_TTL_SECS),
            user_info_ttl: Duration::from_secs(DEFAULT_USER_INFO_TTL_SECS),
            default_ttl: Duration::from_secs(DEFAULT_TTL_SECS),
        }
    }
}

impl EnrichmentConfig {
    /// Creates a new enrichment config with custom TTLs.
    pub fn new(
        threat_intel_ttl: Duration,
        asset_info_ttl: Duration,
        user_info_ttl: Duration,
        default_ttl: Duration,
    ) -> Self {
        Self {
            threat_intel_ttl,
            asset_info_ttl,
            user_info_ttl,
            default_ttl,
        }
    }

    /// Creates a config with all TTLs set to the same value.
    pub fn uniform(ttl: Duration) -> Self {
        Self {
            threat_intel_ttl: ttl,
            asset_info_ttl: ttl,
            user_info_ttl: ttl,
            default_ttl: ttl,
        }
    }
}

/// Options for enrichment cache behavior.
#[derive(Debug, Clone, Default)]
pub struct EnrichmentCacheOptions {
    /// If true, bypass the cache and fetch fresh data.
    pub bypass_cache: bool,
}

impl EnrichmentCacheOptions {
    /// Creates options with cache bypass enabled.
    pub fn bypass() -> Self {
        Self { bypass_cache: true }
    }
}

/// Statistics for cached enrichment operations.
#[derive(Debug, Clone, Default)]
pub struct CachedEnrichmentStats {
    /// Number of cache hits.
    pub hits: u64,
    /// Number of cache misses.
    pub misses: u64,
    /// Cache hit rate (hits / (hits + misses)), 0.0 if no operations.
    pub hit_rate: f64,
}

impl CachedEnrichmentStats {
    /// Creates a new stats instance.
    pub fn new(hits: u64, misses: u64) -> Self {
        let hit_rate = if hits + misses > 0 {
            hits as f64 / (hits + misses) as f64
        } else {
            0.0
        };
        Self {
            hits,
            misses,
            hit_rate,
        }
    }

    /// Returns the total number of operations.
    pub fn total_operations(&self) -> u64 {
        self.hits + self.misses
    }
}

/// Types of threat intel requests that can be cached.
#[derive(Debug, Clone)]
pub enum ThreatIntelRequest {
    /// Look up a file hash (MD5, SHA1, SHA256).
    Hash(String),
    /// Look up an IP address.
    Ip(IpAddr),
    /// Look up a domain name.
    Domain(String),
    /// Look up a URL.
    Url(String),
}

impl ThreatIntelRequest {
    /// Returns a string representation for use in cache keys.
    pub fn cache_key_input(&self) -> String {
        match self {
            ThreatIntelRequest::Hash(h) => format!("hash:{}", h),
            ThreatIntelRequest::Ip(ip) => format!("ip:{}", ip),
            ThreatIntelRequest::Domain(d) => format!("domain:{}", d),
            ThreatIntelRequest::Url(u) => format!("url:{}", u),
        }
    }

    /// Returns the request type as a string.
    pub fn request_type(&self) -> &'static str {
        match self {
            ThreatIntelRequest::Hash(_) => "hash",
            ThreatIntelRequest::Ip(_) => "ip",
            ThreatIntelRequest::Domain(_) => "domain",
            ThreatIntelRequest::Url(_) => "url",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enrichment_config_default() {
        let config = EnrichmentConfig::default();
        assert_eq!(config.threat_intel_ttl, Duration::from_secs(300));
        assert_eq!(config.asset_info_ttl, Duration::from_secs(3600));
        assert_eq!(config.user_info_ttl, Duration::from_secs(1800));
        assert_eq!(config.default_ttl, Duration::from_secs(900));
    }

    #[test]
    fn test_enrichment_config_uniform() {
        let config = EnrichmentConfig::uniform(Duration::from_secs(600));
        assert_eq!(config.threat_intel_ttl, Duration::from_secs(600));
        assert_eq!(config.asset_info_ttl, Duration::from_secs(600));
        assert_eq!(config.user_info_ttl, Duration::from_secs(600));
        assert_eq!(config.default_ttl, Duration::from_secs(600));
    }

    #[test]
    fn test_cached_enrichment_stats_new() {
        let stats = CachedEnrichmentStats::new(80, 20);
        assert_eq!(stats.hits, 80);
        assert_eq!(stats.misses, 20);
        assert!((stats.hit_rate - 0.8).abs() < f64::EPSILON);
        assert_eq!(stats.total_operations(), 100);
    }

    #[test]
    fn test_cached_enrichment_stats_zero_operations() {
        let stats = CachedEnrichmentStats::new(0, 0);
        assert_eq!(stats.hit_rate, 0.0);
        assert_eq!(stats.total_operations(), 0);
    }

    #[test]
    fn test_threat_intel_request_cache_key_input() {
        let hash = ThreatIntelRequest::Hash("abc123def".to_string());
        assert_eq!(hash.cache_key_input(), "hash:abc123def");
        assert_eq!(hash.request_type(), "hash");

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_req = ThreatIntelRequest::Ip(ip);
        assert_eq!(ip_req.cache_key_input(), "ip:192.168.1.1");
        assert_eq!(ip_req.request_type(), "ip");

        let domain = ThreatIntelRequest::Domain("example.com".to_string());
        assert_eq!(domain.cache_key_input(), "domain:example.com");
        assert_eq!(domain.request_type(), "domain");

        let url = ThreatIntelRequest::Url("https://example.com/malware".to_string());
        assert_eq!(url.cache_key_input(), "url:https://example.com/malware");
        assert_eq!(url.request_type(), "url");
    }

    #[test]
    fn test_enrichment_cache_options_default() {
        let options = EnrichmentCacheOptions::default();
        assert!(!options.bypass_cache);
    }

    #[test]
    fn test_enrichment_cache_options_bypass() {
        let options = EnrichmentCacheOptions::bypass();
        assert!(options.bypass_cache);
    }

    #[test]
    fn test_enrichment_error_display() {
        let cache_err = EnrichmentError::Cache("connection failed".to_string());
        assert!(cache_err.to_string().contains("connection failed"));

        let connector_err = EnrichmentError::Connector("rate limited".to_string());
        assert!(connector_err.to_string().contains("rate limited"));

        let serial_err = EnrichmentError::Serialization("invalid json".to_string());
        assert!(serial_err.to_string().contains("invalid json"));

        let feature_err = EnrichmentError::FeatureDisabled("enrichment_cache".to_string());
        assert!(feature_err.to_string().contains("enrichment_cache"));

        let invalid_err = EnrichmentError::InvalidRequest("missing input".to_string());
        assert!(invalid_err.to_string().contains("missing input"));
    }
}
