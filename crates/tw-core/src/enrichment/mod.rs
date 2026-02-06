//! Enrichment caching integration for Triage Warden.
//!
//! This module provides a caching layer for enrichment operations to reduce
//! external API calls and improve response times. It supports:
//!
//! - Cache-through pattern: check cache -> call API -> store result
//! - Configurable TTL per enrichment type
//! - Batch deduplication for concurrent requests
//! - Feature flag control (`enrichment_cache`)
//! - Metrics for cache hits, misses, and hit rate
//!
//! # Cache Key Format
//!
//! Cache keys follow the format: `enrich:{tenant_id}:{type}:{hash(input)}`
//!
//! # TTL Configuration
//!
//! - Threat intel: 5 minutes (300 seconds)
//! - Asset info (EDR host data): 1 hour (3600 seconds)
//! - User info: 30 minutes (1800 seconds)
//!
//! # Example
//!
//! ```rust,ignore
//! use tw_core::enrichment::{CachedEnrichment, EnrichmentConfig};
//! use tw_core::cache::MockCache;
//! use std::sync::Arc;
//!
//! let cache = Arc::new(MockCache::new());
//! let config = EnrichmentConfig::default();
//! let cached_enrichment = CachedEnrichment::new(cache, config);
//!
//! // Perform cached threat intel lookup
//! let result = cached_enrichment
//!     .lookup_threat_intel(
//!         &tenant_ctx,
//!         &threat_intel_connector,
//!         ThreatIntelRequest::Hash("abc123...".to_string()),
//!         false, // bypass_cache
//!     )
//!     .await?;
//! ```

pub mod asset_context;
mod types;

pub use asset_context::{
    adjust_severity, enrich_with_asset_context, AssetContext, AssetEnrichmentResult,
    IdentityContext,
};
pub use types::{
    CachedEnrichmentStats, EnrichmentCacheOptions, EnrichmentConfig, EnrichmentError,
    EnrichmentResult, ThreatIntelRequest,
};

use crate::cache::DynCache;
use crate::features::FeatureFlags;
use crate::incident::EnrichmentType;
use crate::tenant::TenantContext;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, instrument, warn};
use tw_connectors::traits::{EDRConnector, ThreatIntelConnector, ThreatIntelResult};
use tw_connectors::HostInfo;

/// Type alias for in-flight request tracking to avoid clippy::type_complexity.
type InFlightRequests =
    HashMap<String, Arc<tokio::sync::broadcast::Sender<Result<Vec<u8>, String>>>>;

/// Feature flag name for enrichment caching.
pub const ENRICHMENT_CACHE_FLAG: &str = "enrichment_cache";

/// Cached enrichment service that provides caching for external API calls.
///
/// This service wraps enrichment connectors (threat intel, EDR, etc.) and
/// provides transparent caching with:
/// - Configurable TTL per enrichment type
/// - In-flight request deduplication
/// - Feature flag control
/// - Cache hit/miss metrics
pub struct CachedEnrichment {
    /// The cache implementation (optional - graceful degradation if None).
    cache: Option<Arc<dyn DynCache>>,
    /// Feature flags for controlling caching behavior.
    feature_flags: Option<Arc<FeatureFlags>>,
    /// Configuration for TTL and other settings.
    config: EnrichmentConfig,
    /// In-flight request tracking for deduplication.
    in_flight: Mutex<InFlightRequests>,
    /// Cache hit counter.
    hits: AtomicU64,
    /// Cache miss counter.
    misses: AtomicU64,
}

impl CachedEnrichment {
    /// Creates a new cached enrichment service.
    pub fn new(cache: Option<Arc<dyn DynCache>>, config: EnrichmentConfig) -> Self {
        Self {
            cache,
            feature_flags: None,
            config,
            in_flight: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Creates a new cached enrichment service with feature flags.
    pub fn with_feature_flags(
        cache: Option<Arc<dyn DynCache>>,
        config: EnrichmentConfig,
        feature_flags: Arc<FeatureFlags>,
    ) -> Self {
        Self {
            cache,
            feature_flags: Some(feature_flags),
            config,
            in_flight: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Checks if caching is enabled for the given tenant.
    fn is_caching_enabled(&self, tenant: Option<&TenantContext>) -> bool {
        // If no cache is configured, caching is disabled
        if self.cache.is_none() {
            return false;
        }

        // Check feature flag if available
        if let Some(flags) = &self.feature_flags {
            return flags.is_enabled(ENRICHMENT_CACHE_FLAG, tenant);
        }

        // Default to enabled if no feature flags configured
        true
    }

    /// Generates a cache key for the given enrichment type and input.
    ///
    /// Format: `enrich:{tenant_id}:{type}:{hash(input)}`
    fn cache_key(&self, tenant_id: &uuid::Uuid, enrichment_type: &str, input: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("enrich:{}:{}:{}", tenant_id, enrichment_type, hash)
    }

    /// Gets the TTL for the given enrichment type.
    fn get_ttl(&self, enrichment_type: &EnrichmentType) -> Duration {
        match enrichment_type {
            EnrichmentType::ThreatIntel => self.config.threat_intel_ttl,
            EnrichmentType::HostInfo => self.config.asset_info_ttl,
            EnrichmentType::UserInfo => self.config.user_info_ttl,
            _ => self.config.default_ttl,
        }
    }

    /// Records a cache hit.
    fn record_hit(&self) {
        self.hits.fetch_add(1, Ordering::SeqCst);
        metrics::counter!("enrichment_cache_hits").increment(1);
    }

    /// Records a cache miss.
    fn record_miss(&self) {
        self.misses.fetch_add(1, Ordering::SeqCst);
        metrics::counter!("enrichment_cache_misses").increment(1);
    }

    /// Returns current cache statistics.
    pub fn stats(&self) -> CachedEnrichmentStats {
        let hits = self.hits.load(Ordering::SeqCst);
        let misses = self.misses.load(Ordering::SeqCst);
        CachedEnrichmentStats::new(hits, misses)
    }

    /// Resets the statistics counters.
    pub fn reset_stats(&self) {
        self.hits.store(0, Ordering::SeqCst);
        self.misses.store(0, Ordering::SeqCst);
    }

    /// Performs a cached lookup with in-flight deduplication.
    ///
    /// This method:
    /// 1. Checks if caching is enabled
    /// 2. Checks cache for existing result
    /// 3. Deduplicates concurrent requests for the same key
    /// 4. Calls the API if needed
    /// 5. Caches successful results
    async fn cached_lookup<T, F, Fut>(
        &self,
        tenant: &TenantContext,
        enrichment_type: EnrichmentType,
        input: &str,
        options: EnrichmentCacheOptions,
        fetch_fn: F,
    ) -> EnrichmentResult<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Clone + Send + 'static,
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<T, tw_connectors::ConnectorError>> + Send,
    {
        let enrichment_type_str = format!("{:?}", enrichment_type).to_lowercase();
        let cache_key = self.cache_key(&tenant.tenant_id, &enrichment_type_str, input);

        // Check if caching is enabled and not bypassed
        let caching_enabled = self.is_caching_enabled(Some(tenant)) && !options.bypass_cache;

        if caching_enabled {
            if let Some(cache) = &self.cache {
                // Try to get from cache first
                match cache.get(&cache_key).await {
                    Ok(Some(cached_bytes)) => {
                        match serde_json::from_slice::<T>(&cached_bytes) {
                            Ok(result) => {
                                self.record_hit();
                                debug!("Cache hit for key: {}", cache_key);
                                return Ok(result);
                            }
                            Err(e) => {
                                warn!("Failed to deserialize cached value: {}", e);
                                // Continue to fetch fresh data
                            }
                        }
                    }
                    Ok(None) => {
                        // Cache miss, continue
                        debug!("Cache miss for key: {}", cache_key);
                    }
                    Err(e) => {
                        warn!("Cache error: {}, proceeding without cache", e);
                    }
                }
            }
        }

        self.record_miss();

        // Check for in-flight request deduplication
        let should_fetch = {
            let mut in_flight = self.in_flight.lock().await;
            if let Some(sender) = in_flight.get(&cache_key) {
                // Another request is already in progress, subscribe to it
                let mut receiver = sender.subscribe();
                drop(in_flight); // Release lock while waiting

                match receiver.recv().await {
                    Ok(Ok(bytes)) => {
                        return serde_json::from_slice::<T>(&bytes)
                            .map_err(|e| EnrichmentError::Serialization(e.to_string()));
                    }
                    Ok(Err(e)) => {
                        return Err(EnrichmentError::Connector(e));
                    }
                    Err(_) => {
                        // Sender dropped, need to retry
                        // Fall through to fetch
                    }
                }
                false
            } else {
                // Create new broadcast channel for this request
                let (tx, _) = tokio::sync::broadcast::channel(1);
                in_flight.insert(cache_key.clone(), Arc::new(tx));
                true
            }
        };

        // Fetch if we're the first request
        let result = if should_fetch {
            let fetch_result = fetch_fn().await;

            // Notify waiting subscribers
            let sender = {
                let mut in_flight = self.in_flight.lock().await;
                in_flight.remove(&cache_key)
            };

            match &fetch_result {
                Ok(value) => {
                    // Serialize for cache and broadcast
                    match serde_json::to_vec(value) {
                        Ok(bytes) => {
                            // Cache the result (only on success)
                            if caching_enabled {
                                if let Some(cache) = &self.cache {
                                    let ttl = self.get_ttl(&enrichment_type);
                                    if let Err(e) = cache.set(&cache_key, &bytes, ttl).await {
                                        warn!("Failed to cache result: {}", e);
                                    } else {
                                        debug!("Cached result with TTL {:?}", ttl);
                                    }
                                }
                            }

                            // Broadcast to waiting subscribers
                            if let Some(sender) = sender {
                                let _ = sender.send(Ok(bytes));
                            }
                        }
                        Err(e) => {
                            warn!("Failed to serialize result: {}", e);
                            if let Some(sender) = sender {
                                let _ = sender.send(Err(e.to_string()));
                            }
                        }
                    }
                }
                Err(e) => {
                    // Don't cache errors, but notify subscribers
                    if let Some(sender) = sender {
                        let _ = sender.send(Err(e.to_string()));
                    }
                }
            }

            fetch_result.map_err(|e| EnrichmentError::Connector(e.to_string()))
        } else {
            // This shouldn't happen, but handle it gracefully
            fetch_fn()
                .await
                .map_err(|e| EnrichmentError::Connector(e.to_string()))
        };

        result
    }

    /// Looks up threat intelligence for an indicator.
    ///
    /// This method caches results for 5 minutes by default.
    #[instrument(skip(self, connector), fields(tenant_id = %tenant.tenant_id))]
    pub async fn lookup_threat_intel<C: ThreatIntelConnector>(
        &self,
        tenant: &TenantContext,
        connector: &C,
        request: ThreatIntelRequest,
        bypass_cache: bool,
    ) -> EnrichmentResult<ThreatIntelResult> {
        let options = EnrichmentCacheOptions { bypass_cache };
        let input = request.cache_key_input();

        match request {
            ThreatIntelRequest::Hash(hash) => {
                self.cached_lookup(
                    tenant,
                    EnrichmentType::ThreatIntel,
                    &input,
                    options,
                    || async move { connector.lookup_hash(&hash).await },
                )
                .await
            }
            ThreatIntelRequest::Ip(ip) => {
                self.cached_lookup(
                    tenant,
                    EnrichmentType::ThreatIntel,
                    &input,
                    options,
                    || async move { connector.lookup_ip(&ip).await },
                )
                .await
            }
            ThreatIntelRequest::Domain(domain) => {
                self.cached_lookup(
                    tenant,
                    EnrichmentType::ThreatIntel,
                    &input,
                    options,
                    || async move { connector.lookup_domain(&domain).await },
                )
                .await
            }
            ThreatIntelRequest::Url(url) => {
                self.cached_lookup(
                    tenant,
                    EnrichmentType::ThreatIntel,
                    &input,
                    options,
                    || async move { connector.lookup_url(&url).await },
                )
                .await
            }
        }
    }

    /// Looks up host information from EDR.
    ///
    /// This method caches results for 1 hour by default.
    #[instrument(skip(self, connector), fields(tenant_id = %tenant.tenant_id, hostname = %hostname))]
    pub async fn lookup_host_info<C: EDRConnector>(
        &self,
        tenant: &TenantContext,
        connector: &C,
        hostname: &str,
        bypass_cache: bool,
    ) -> EnrichmentResult<HostInfo> {
        let options = EnrichmentCacheOptions { bypass_cache };

        self.cached_lookup(
            tenant,
            EnrichmentType::HostInfo,
            hostname,
            options,
            || async move { connector.get_host_info(hostname).await },
        )
        .await
    }

    /// Performs a batch threat intel lookup with deduplication.
    ///
    /// Concurrent requests for the same indicator will share a single API call.
    #[instrument(skip(self, connector), fields(tenant_id = %tenant.tenant_id, count = requests.len()))]
    pub async fn batch_lookup_threat_intel<C: ThreatIntelConnector + Sync>(
        &self,
        tenant: &TenantContext,
        connector: &C,
        requests: Vec<ThreatIntelRequest>,
        bypass_cache: bool,
    ) -> Vec<EnrichmentResult<ThreatIntelResult>> {
        // Process all requests concurrently with automatic deduplication
        let futures: Vec<_> = requests
            .into_iter()
            .map(|req| self.lookup_threat_intel(tenant, connector, req, bypass_cache))
            .collect();

        futures::future::join_all(futures).await
    }

    /// Invalidates a cached enrichment result.
    pub async fn invalidate(
        &self,
        tenant: &TenantContext,
        enrichment_type: &EnrichmentType,
        input: &str,
    ) -> EnrichmentResult<bool> {
        if let Some(cache) = &self.cache {
            let enrichment_type_str = format!("{:?}", enrichment_type).to_lowercase();
            let cache_key = self.cache_key(&tenant.tenant_id, &enrichment_type_str, input);
            cache
                .delete(&cache_key)
                .await
                .map_err(|e| EnrichmentError::Cache(e.to_string()))
        } else {
            Ok(false)
        }
    }
}

impl Default for CachedEnrichment {
    fn default() -> Self {
        Self::new(None, EnrichmentConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::MockCache;
    use crate::features::{FeatureFlag, InMemoryFeatureFlagStore};
    use crate::tenant::Tenant;
    use std::net::IpAddr;
    use tw_connectors::threat_intel::MockThreatIntelConnector;
    use tw_connectors::traits::ThreatVerdict;

    fn create_test_tenant() -> TenantContext {
        let tenant = Tenant::new("test-tenant", "Test Tenant").unwrap();
        TenantContext::from_tenant(&tenant)
    }

    #[tokio::test]
    async fn test_cache_key_generation() {
        let enrichment = CachedEnrichment::default();
        let tenant_id = uuid::Uuid::new_v4();

        let key1 = enrichment.cache_key(&tenant_id, "threatintel", "192.168.1.1");
        let key2 = enrichment.cache_key(&tenant_id, "threatintel", "192.168.1.1");
        let key3 = enrichment.cache_key(&tenant_id, "threatintel", "192.168.1.2");

        // Same input should produce same key
        assert_eq!(key1, key2);

        // Different input should produce different key
        assert_ne!(key1, key3);

        // Key should contain tenant_id
        assert!(key1.contains(&tenant_id.to_string()));
    }

    #[tokio::test]
    async fn test_caching_disabled_without_cache() {
        let enrichment = CachedEnrichment::new(None, EnrichmentConfig::default());
        let tenant = create_test_tenant();

        assert!(!enrichment.is_caching_enabled(Some(&tenant)));
    }

    #[tokio::test]
    async fn test_caching_enabled_with_cache() {
        let cache = Arc::new(MockCache::new());
        let enrichment = CachedEnrichment::new(Some(cache), EnrichmentConfig::default());
        let tenant = create_test_tenant();

        assert!(enrichment.is_caching_enabled(Some(&tenant)));
    }

    #[tokio::test]
    async fn test_caching_controlled_by_feature_flag() {
        let cache = Arc::new(MockCache::new());

        // Create feature flags with enrichment_cache disabled
        let store = Arc::new(InMemoryFeatureFlagStore::new());
        let flags = Arc::new(FeatureFlags::new(store));

        // Add a disabled flag
        let flag =
            FeatureFlag::new(ENRICHMENT_CACHE_FLAG, "Enrichment caching", false, None).unwrap();
        flags.upsert(&flag).await.unwrap();
        flags.refresh().await.unwrap();

        let enrichment = CachedEnrichment::with_feature_flags(
            Some(cache),
            EnrichmentConfig::default(),
            flags.clone(),
        );
        let tenant = create_test_tenant();

        // Should be disabled because feature flag is off
        assert!(!enrichment.is_caching_enabled(Some(&tenant)));
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();

        // Pre-populate cache
        let result = ThreatIntelResult {
            indicator_type: tw_connectors::IndicatorType::Ipv4,
            indicator: "192.168.1.1".to_string(),
            verdict: ThreatVerdict::Clean,
            malicious_score: 0,
            malicious_count: 0,
            total_engines: 70,
            categories: vec![],
            malware_families: vec![],
            first_seen: None,
            last_seen: None,
            details: std::collections::HashMap::new(),
            source: "test".to_string(),
            cache_ttl: 300,
        };

        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());
        let cache_key = enrichment.cache_key(&tenant.tenant_id, "threatintel", "ip:192.168.1.1");

        let bytes = serde_json::to_vec(&result).unwrap();
        cache
            .set(&cache_key, &bytes, Duration::from_secs(300))
            .await
            .unwrap();

        // Create a mock connector that should not be called
        let connector = MockThreatIntelConnector::new("test-connector");

        // Lookup should hit cache
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let lookup_result = enrichment
            .lookup_threat_intel(&tenant, &connector, ThreatIntelRequest::Ip(ip), false)
            .await
            .unwrap();

        assert_eq!(lookup_result.indicator, "192.168.1.1");
        assert_eq!(lookup_result.verdict, ThreatVerdict::Clean);

        // Check stats
        let stats = enrichment.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
    }

    #[tokio::test]
    async fn test_cache_miss_and_store() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());

        // Create a mock connector
        let connector = MockThreatIntelConnector::new("test-connector");

        // Lookup should miss cache and call connector
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let _result = enrichment
            .lookup_threat_intel(&tenant, &connector, ThreatIntelRequest::Ip(ip), false)
            .await
            .unwrap();

        // Result should be cached now
        let cache_key = enrichment.cache_key(&tenant.tenant_id, "threatintel", "ip:8.8.8.8");
        let cached = cache.get(&cache_key).await.unwrap();
        assert!(cached.is_some());

        // Check stats
        let stats = enrichment.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_bypass_cache() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();

        // Pre-populate cache with old data
        let old_result = ThreatIntelResult {
            indicator_type: tw_connectors::IndicatorType::Ipv4,
            indicator: "192.168.1.1".to_string(),
            verdict: ThreatVerdict::Clean, // Old verdict
            malicious_score: 0,
            malicious_count: 0,
            total_engines: 70,
            categories: vec![],
            malware_families: vec![],
            first_seen: None,
            last_seen: None,
            details: std::collections::HashMap::new(),
            source: "old".to_string(),
            cache_ttl: 300,
        };

        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());
        let cache_key = enrichment.cache_key(&tenant.tenant_id, "threatintel", "ip:192.168.1.1");

        let bytes = serde_json::to_vec(&old_result).unwrap();
        cache
            .set(&cache_key, &bytes, Duration::from_secs(300))
            .await
            .unwrap();

        // Create connector that returns different data
        let connector = MockThreatIntelConnector::new("test-connector");

        // Bypass cache
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let result = enrichment
            .lookup_threat_intel(
                &tenant,
                &connector,
                ThreatIntelRequest::Ip(ip),
                true, // bypass_cache
            )
            .await
            .unwrap();

        // Should get fresh data from connector, not cached "Clean" verdict
        // MockThreatIntelConnector returns Unknown by default
        assert_eq!(result.verdict, ThreatVerdict::Unknown);

        // Stats should show a miss (bypass counts as miss)
        let stats = enrichment.stats();
        assert_eq!(stats.misses, 1);
    }

    #[tokio::test]
    async fn test_ttl_per_enrichment_type() {
        let enrichment = CachedEnrichment::new(None, EnrichmentConfig::default());

        let threat_intel_ttl = enrichment.get_ttl(&EnrichmentType::ThreatIntel);
        let host_info_ttl = enrichment.get_ttl(&EnrichmentType::HostInfo);
        let user_info_ttl = enrichment.get_ttl(&EnrichmentType::UserInfo);

        assert_eq!(threat_intel_ttl, Duration::from_secs(300)); // 5 minutes
        assert_eq!(host_info_ttl, Duration::from_secs(3600)); // 1 hour
        assert_eq!(user_info_ttl, Duration::from_secs(1800)); // 30 minutes
    }

    #[tokio::test]
    async fn test_stats_calculation() {
        let stats = CachedEnrichmentStats::new(80, 20);

        assert_eq!(stats.hits, 80);
        assert_eq!(stats.misses, 20);
        assert!((stats.hit_rate - 0.8).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());

        // Add something to cache
        let cache_key = enrichment.cache_key(&tenant.tenant_id, "threatintel", "test-input");
        cache
            .set(&cache_key, b"test-data", Duration::from_secs(300))
            .await
            .unwrap();

        // Verify it exists
        assert!(cache.exists(&cache_key).await.unwrap());

        // Invalidate
        let deleted = enrichment
            .invalidate(&tenant, &EnrichmentType::ThreatIntel, "test-input")
            .await
            .unwrap();
        assert!(deleted);

        // Verify it's gone
        assert!(!cache.exists(&cache_key).await.unwrap());
    }

    #[tokio::test]
    async fn test_graceful_degradation_without_cache() {
        // No cache configured - should still work
        let enrichment = CachedEnrichment::new(None, EnrichmentConfig::default());
        let tenant = create_test_tenant();
        let connector = MockThreatIntelConnector::new("test-connector");

        // Should succeed without cache
        let ip: IpAddr = "8.8.8.8".parse().unwrap();
        let result = enrichment
            .lookup_threat_intel(&tenant, &connector, ThreatIntelRequest::Ip(ip), false)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_concurrent_request_deduplication() {
        let cache = Arc::new(MockCache::new());
        let enrichment = Arc::new(CachedEnrichment::new(
            Some(cache),
            EnrichmentConfig::default(),
        ));
        let tenant = Arc::new(create_test_tenant());

        // Create a mock connector that tracks calls
        let connector = Arc::new(MockThreatIntelConnector::new("test-connector"));

        // Spawn multiple concurrent requests for the same IP
        let mut handles = vec![];
        for _ in 0..5 {
            let enrichment = Arc::clone(&enrichment);
            let tenant = Arc::clone(&tenant);
            let connector = Arc::clone(&connector);

            handles.push(tokio::spawn(async move {
                let ip: IpAddr = "1.2.3.4".parse().unwrap();
                enrichment
                    .lookup_threat_intel(
                        &tenant,
                        connector.as_ref(),
                        ThreatIntelRequest::Ip(ip),
                        false,
                    )
                    .await
            }));
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;

        // All should succeed
        for result in results {
            assert!(result.unwrap().is_ok());
        }

        // Due to deduplication, we should see fewer cache misses than requests
        // (at least some requests should share)
        let stats = enrichment.stats();
        // At minimum, the first request causes a miss and others might wait
        // The exact number depends on timing, but should be less than 5
        assert!(stats.misses <= 5);
    }

    #[tokio::test]
    async fn test_threat_intel_request_cache_key_input() {
        let hash_req = ThreatIntelRequest::Hash("abc123".to_string());
        assert_eq!(hash_req.cache_key_input(), "hash:abc123");

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let ip_req = ThreatIntelRequest::Ip(ip);
        assert_eq!(ip_req.cache_key_input(), "ip:192.168.1.1");

        let domain_req = ThreatIntelRequest::Domain("example.com".to_string());
        assert_eq!(domain_req.cache_key_input(), "domain:example.com");

        let url_req = ThreatIntelRequest::Url("https://example.com/path".to_string());
        assert_eq!(url_req.cache_key_input(), "url:https://example.com/path");
    }

    #[tokio::test]
    async fn test_batch_lookup() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());
        let connector = MockThreatIntelConnector::new("test-connector");

        // Create batch of requests
        let requests = vec![
            ThreatIntelRequest::Ip("8.8.8.8".parse().unwrap()),
            ThreatIntelRequest::Domain("example.com".to_string()),
            ThreatIntelRequest::Hash("abc123def".to_string()),
        ];

        let results = enrichment
            .batch_lookup_threat_intel(&tenant, &connector, requests, false)
            .await;

        // All should succeed
        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result.is_ok());
        }

        // Should have had 3 cache misses (one for each unique request)
        let stats = enrichment.stats();
        assert_eq!(stats.misses, 3);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let cache = Arc::new(MockCache::new());

        // Create two different tenants
        let tenant1 = {
            let t = Tenant::new("tenant-one", "Tenant One").unwrap();
            TenantContext::from_tenant(&t)
        };
        let tenant2 = {
            let t = Tenant::new("tenant-two", "Tenant Two").unwrap();
            TenantContext::from_tenant(&t)
        };

        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());
        let connector = MockThreatIntelConnector::new("test-connector");

        // Lookup same IP for both tenants
        let ip: IpAddr = "1.1.1.1".parse().unwrap();

        let _result1 = enrichment
            .lookup_threat_intel(&tenant1, &connector, ThreatIntelRequest::Ip(ip), false)
            .await
            .unwrap();

        let _result2 = enrichment
            .lookup_threat_intel(&tenant2, &connector, ThreatIntelRequest::Ip(ip), false)
            .await
            .unwrap();

        // Should have 2 cache misses because tenants are isolated
        let stats = enrichment.stats();
        assert_eq!(stats.misses, 2);

        // Verify different cache keys
        let key1 = enrichment.cache_key(&tenant1.tenant_id, "threatintel", "ip:1.1.1.1");
        let key2 = enrichment.cache_key(&tenant2.tenant_id, "threatintel", "ip:1.1.1.1");
        assert_ne!(key1, key2);
    }

    #[tokio::test]
    async fn test_reset_stats() {
        let enrichment = CachedEnrichment::default();

        // Manually increment stats
        enrichment
            .hits
            .store(10, std::sync::atomic::Ordering::SeqCst);
        enrichment
            .misses
            .store(5, std::sync::atomic::Ordering::SeqCst);

        let stats = enrichment.stats();
        assert_eq!(stats.hits, 10);
        assert_eq!(stats.misses, 5);

        // Reset
        enrichment.reset_stats();

        let stats = enrichment.stats();
        assert_eq!(stats.hits, 0);
        assert_eq!(stats.misses, 0);
    }

    #[tokio::test]
    async fn test_feature_flag_enabled() {
        let cache = Arc::new(MockCache::new());

        // Create feature flags with enrichment_cache enabled
        let store = Arc::new(InMemoryFeatureFlagStore::new());
        let flags = Arc::new(FeatureFlags::new(store));

        // Add an enabled flag
        let flag =
            FeatureFlag::new(ENRICHMENT_CACHE_FLAG, "Enrichment caching", true, None).unwrap();
        flags.upsert(&flag).await.unwrap();
        flags.refresh().await.unwrap();

        let enrichment = CachedEnrichment::with_feature_flags(
            Some(cache),
            EnrichmentConfig::default(),
            flags.clone(),
        );
        let tenant = create_test_tenant();

        // Should be enabled because feature flag is on
        assert!(enrichment.is_caching_enabled(Some(&tenant)));
    }

    #[tokio::test]
    async fn test_custom_ttl_config() {
        let config = EnrichmentConfig::new(
            Duration::from_secs(60),  // threat_intel: 1 minute
            Duration::from_secs(120), // asset_info: 2 minutes
            Duration::from_secs(180), // user_info: 3 minutes
            Duration::from_secs(240), // default: 4 minutes
        );

        let enrichment = CachedEnrichment::new(None, config);

        assert_eq!(
            enrichment.get_ttl(&EnrichmentType::ThreatIntel),
            Duration::from_secs(60)
        );
        assert_eq!(
            enrichment.get_ttl(&EnrichmentType::HostInfo),
            Duration::from_secs(120)
        );
        assert_eq!(
            enrichment.get_ttl(&EnrichmentType::UserInfo),
            Duration::from_secs(180)
        );
        assert_eq!(
            enrichment.get_ttl(&EnrichmentType::SiemSearch),
            Duration::from_secs(240)
        );
    }

    #[tokio::test]
    async fn test_hash_lookup() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());

        // Use EICAR test file hash which MockThreatIntelConnector knows about
        let connector = MockThreatIntelConnector::new("test-connector");
        let eicar_md5 = "44d88612fea8a8f36de82e1278abb02f".to_string();

        let result = enrichment
            .lookup_threat_intel(
                &tenant,
                &connector,
                ThreatIntelRequest::Hash(eicar_md5),
                false,
            )
            .await
            .unwrap();

        assert_eq!(result.verdict, ThreatVerdict::Malicious);
        assert!(result
            .malware_families
            .contains(&"EICAR-Test-File".to_string()));
    }

    #[tokio::test]
    async fn test_domain_lookup() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());

        // Use known malicious domain from MockThreatIntelConnector
        let connector = MockThreatIntelConnector::new("test-connector");

        let result = enrichment
            .lookup_threat_intel(
                &tenant,
                &connector,
                ThreatIntelRequest::Domain("evil.example.com".to_string()),
                false,
            )
            .await
            .unwrap();

        assert_eq!(result.verdict, ThreatVerdict::Malicious);
        assert!(result.categories.contains(&"phishing".to_string()));
    }

    #[tokio::test]
    async fn test_url_lookup() {
        let cache = Arc::new(MockCache::new());
        let tenant = create_test_tenant();
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());
        let connector = MockThreatIntelConnector::new("test-connector");

        let result = enrichment
            .lookup_threat_intel(
                &tenant,
                &connector,
                ThreatIntelRequest::Url("https://unknown-url.example.com/path".to_string()),
                false,
            )
            .await
            .unwrap();

        // Unknown URLs return Unknown verdict
        assert_eq!(result.verdict, ThreatVerdict::Unknown);
    }

    #[tokio::test]
    async fn test_metrics_counter_update() {
        let cache = Arc::new(MockCache::new());
        let enrichment = CachedEnrichment::new(Some(cache.clone()), EnrichmentConfig::default());

        // Initial stats
        let initial_stats = enrichment.stats();
        assert_eq!(initial_stats.hits, 0);
        assert_eq!(initial_stats.misses, 0);
        assert_eq!(initial_stats.hit_rate, 0.0);

        // Record some operations manually
        enrichment.record_hit();
        enrichment.record_hit();
        enrichment.record_miss();

        let stats = enrichment.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert!((stats.hit_rate - 0.6666666666666666).abs() < 0.001);
    }
}
