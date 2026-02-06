//! Threat intelligence aggregation layer.
//!
//! Aggregates results from multiple threat intel providers with
//! weighted scoring, parallel lookups, and TTL-based caching.

use crate::http::ResponseCache;
use crate::traits::{
    ConnectorError, ConnectorResult, IndicatorType, ThreatIntelConnector, ThreatIntelResult,
    ThreatVerdict,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Configuration for the threat intel aggregator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorConfig {
    /// Cache TTL for aggregated results.
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: Duration,
    /// Timeout per provider lookup.
    #[serde(default = "default_timeout")]
    pub timeout_per_provider: Duration,
    /// Minimum providers that must agree for a consensus verdict.
    #[serde(default = "default_min_consensus")]
    pub min_providers_for_consensus: usize,
    /// Maximum cache entries.
    #[serde(default = "default_max_cache")]
    pub max_cache_entries: u64,
}

fn default_cache_ttl() -> Duration {
    Duration::from_secs(3600)
}

fn default_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_min_consensus() -> usize {
    2
}

fn default_max_cache() -> u64 {
    50000
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            cache_ttl: default_cache_ttl(),
            timeout_per_provider: default_timeout(),
            min_providers_for_consensus: default_min_consensus(),
            max_cache_entries: default_max_cache(),
        }
    }
}

/// Result from a single provider lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderResult {
    /// Name of the provider.
    pub provider: String,
    /// The result from this provider.
    pub result: ThreatIntelResult,
    /// How long the lookup took.
    pub latency_ms: u64,
}

/// Aggregated result from multiple threat intel providers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedIntelResult {
    /// Weighted overall score (0.0 - 100.0).
    pub overall_score: f32,
    /// Whether the indicator is considered malicious by consensus.
    pub is_malicious: bool,
    /// Consensus verdict from providers.
    pub consensus_verdict: ThreatVerdict,
    /// Combined categories from all providers.
    pub categories: Vec<String>,
    /// Combined malware families from all providers.
    pub malware_families: Vec<String>,
    /// Earliest first_seen across all providers.
    pub first_seen: Option<DateTime<Utc>>,
    /// Latest last_seen across all providers.
    pub last_seen: Option<DateTime<Utc>>,
    /// Names of providers that contributed results.
    pub sources: Vec<String>,
    /// Individual results from each provider.
    pub provider_results: Vec<ProviderResult>,
    /// The indicator that was looked up.
    pub indicator: String,
    /// Type of the indicator.
    pub indicator_type: IndicatorType,
}

/// Provider registration with optional weight.
struct RegisteredProvider {
    connector: Arc<dyn ThreatIntelConnector>,
    weight: f32,
}

/// Aggregates threat intelligence from multiple providers.
pub struct ThreatIntelAggregator {
    providers: Vec<RegisteredProvider>,
    cache: ResponseCache<AggregatedIntelResult>,
    config: AggregatorConfig,
}

impl ThreatIntelAggregator {
    /// Creates a new aggregator with the given configuration.
    pub fn new(config: AggregatorConfig) -> Self {
        let cache = ResponseCache::new(config.cache_ttl, config.max_cache_entries);
        Self {
            providers: Vec::new(),
            cache,
            config,
        }
    }

    /// Adds a provider with the default weight of 1.0.
    pub fn add_provider(&mut self, connector: Arc<dyn ThreatIntelConnector>) {
        self.add_provider_with_weight(connector, 1.0);
    }

    /// Adds a provider with a custom weight for scoring.
    pub fn add_provider_with_weight(
        &mut self,
        connector: Arc<dyn ThreatIntelConnector>,
        weight: f32,
    ) {
        self.providers
            .push(RegisteredProvider { connector, weight });
    }

    /// Returns the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Looks up a hash across all providers.
    pub async fn lookup_hash(&self, hash: &str) -> ConnectorResult<AggregatedIntelResult> {
        let cache_key = format!("agg:hash:{}", hash.to_lowercase());
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Aggregator cache hit for hash {}", hash);
            return Ok(cached);
        }

        let results = self
            .parallel_lookup(|provider| {
                let hash = hash.to_string();
                Box::pin(async move { provider.lookup_hash(&hash).await })
            })
            .await;

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };

        let aggregated = self.aggregate_results(results, hash, indicator_type);
        self.cache.insert(cache_key, aggregated.clone()).await;
        Ok(aggregated)
    }

    /// Looks up an IP address across all providers.
    pub async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<AggregatedIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("agg:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Aggregator cache hit for IP {}", ip_str);
            return Ok(cached);
        }

        let ip_clone = *ip;
        let results = self
            .parallel_lookup(|provider| {
                Box::pin(async move { provider.lookup_ip(&ip_clone).await })
            })
            .await;

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let aggregated = self.aggregate_results(results, &ip_str, indicator_type);
        self.cache.insert(cache_key, aggregated.clone()).await;
        Ok(aggregated)
    }

    /// Looks up a domain across all providers.
    pub async fn lookup_domain(&self, domain: &str) -> ConnectorResult<AggregatedIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("agg:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Aggregator cache hit for domain {}", domain);
            return Ok(cached);
        }

        let results = self
            .parallel_lookup(|provider| {
                let domain = domain.clone();
                Box::pin(async move { provider.lookup_domain(&domain).await })
            })
            .await;

        let aggregated = self.aggregate_results(results, &domain, IndicatorType::Domain);
        self.cache.insert(cache_key, aggregated.clone()).await;
        Ok(aggregated)
    }

    /// Looks up a URL across all providers.
    pub async fn lookup_url(&self, url: &str) -> ConnectorResult<AggregatedIntelResult> {
        let cache_key = format!("agg:url:{}", url);
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Aggregator cache hit for URL");
            return Ok(cached);
        }

        let results = self
            .parallel_lookup(|provider| {
                let url = url.to_string();
                Box::pin(async move { provider.lookup_url(&url).await })
            })
            .await;

        let aggregated = self.aggregate_results(results, url, IndicatorType::Url);
        self.cache.insert(cache_key, aggregated.clone()).await;
        Ok(aggregated)
    }

    /// Queries all providers in parallel with timeout.
    async fn parallel_lookup<F, Fut>(
        &self,
        make_future: F,
    ) -> Vec<(usize, Result<ThreatIntelResult, ConnectorError>)>
    where
        F: Fn(Arc<dyn ThreatIntelConnector>) -> Fut,
        Fut: std::future::Future<Output = ConnectorResult<ThreatIntelResult>> + Send + 'static,
    {
        let timeout = self.config.timeout_per_provider;
        let mut handles = Vec::with_capacity(self.providers.len());

        for (idx, provider) in self.providers.iter().enumerate() {
            let connector = provider.connector.clone();
            let fut = make_future(connector);
            let handle = tokio::spawn(async move {
                let start = std::time::Instant::now();
                let result = tokio::time::timeout(timeout, fut).await;
                let elapsed = start.elapsed().as_millis() as u64;
                match result {
                    Ok(Ok(mut r)) => {
                        // Inject latency into details
                        r.details
                            .insert("lookup_latency_ms".to_string(), serde_json::json!(elapsed));
                        (idx, Ok(r))
                    }
                    Ok(Err(e)) => (idx, Err(e)),
                    Err(_) => (
                        idx,
                        Err(ConnectorError::Timeout(
                            "Provider lookup timed out".to_string(),
                        )),
                    ),
                }
            });
            handles.push(handle);
        }

        let mut results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(result) => results.push(result),
                Err(e) => {
                    warn!("Provider task panicked: {}", e);
                }
            }
        }
        results
    }

    /// Aggregates results from multiple providers into a single verdict.
    fn aggregate_results(
        &self,
        results: Vec<(usize, Result<ThreatIntelResult, ConnectorError>)>,
        indicator: &str,
        indicator_type: IndicatorType,
    ) -> AggregatedIntelResult {
        let mut provider_results = Vec::new();
        let mut total_weight = 0.0f32;
        let mut weighted_score = 0.0f32;
        let mut categories = Vec::new();
        let mut malware_families = Vec::new();
        let mut first_seen: Option<DateTime<Utc>> = None;
        let mut last_seen: Option<DateTime<Utc>> = None;
        let mut sources = Vec::new();
        let mut verdict_counts: HashMap<ThreatVerdict, f32> = HashMap::new();

        for (idx, result) in results {
            match result {
                Ok(intel) => {
                    let weight = self.providers.get(idx).map(|p| p.weight).unwrap_or(1.0);
                    let latency = intel
                        .details
                        .get("lookup_latency_ms")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    sources.push(intel.source.clone());

                    // Accumulate weighted score
                    weighted_score += intel.malicious_score as f32 * weight;
                    total_weight += weight;

                    // Accumulate verdict votes
                    *verdict_counts.entry(intel.verdict.clone()).or_insert(0.0) += weight;

                    // Merge categories
                    for cat in &intel.categories {
                        if !categories.contains(cat) {
                            categories.push(cat.clone());
                        }
                    }

                    // Merge malware families
                    for family in &intel.malware_families {
                        if !malware_families.contains(family) {
                            malware_families.push(family.clone());
                        }
                    }

                    // Track earliest first_seen
                    if let Some(fs) = intel.first_seen {
                        first_seen = Some(match first_seen {
                            Some(existing) if fs < existing => fs,
                            Some(existing) => existing,
                            None => fs,
                        });
                    }

                    // Track latest last_seen
                    if let Some(ls) = intel.last_seen {
                        last_seen = Some(match last_seen {
                            Some(existing) if ls > existing => ls,
                            Some(existing) => existing,
                            None => ls,
                        });
                    }

                    provider_results.push(ProviderResult {
                        provider: intel.source.clone(),
                        result: intel,
                        latency_ms: latency,
                    });
                }
                Err(e) => {
                    if let Some(provider) = self.providers.get(idx) {
                        warn!("Provider {} failed: {}", provider.connector.name(), e);
                    }
                }
            }
        }

        let overall_score = if total_weight > 0.0 {
            weighted_score / total_weight
        } else {
            0.0
        };

        // Determine consensus verdict
        let consensus_verdict = self.determine_consensus(&verdict_counts, provider_results.len());
        let is_malicious = consensus_verdict == ThreatVerdict::Malicious;

        info!(
            indicator = indicator,
            sources = provider_results.len(),
            overall_score = overall_score,
            verdict = ?consensus_verdict,
            "Aggregated threat intel"
        );

        AggregatedIntelResult {
            overall_score,
            is_malicious,
            consensus_verdict,
            categories,
            malware_families,
            first_seen,
            last_seen,
            sources,
            provider_results,
            indicator: indicator.to_string(),
            indicator_type,
        }
    }

    /// Determines consensus verdict from weighted votes.
    fn determine_consensus(
        &self,
        votes: &HashMap<ThreatVerdict, f32>,
        total_providers: usize,
    ) -> ThreatVerdict {
        if votes.is_empty() {
            return ThreatVerdict::Unknown;
        }

        // If not enough providers responded, be cautious
        if total_providers < self.config.min_providers_for_consensus {
            // With fewer providers than needed for consensus, take the most severe verdict
            if votes.contains_key(&ThreatVerdict::Malicious) {
                return ThreatVerdict::Malicious;
            }
            if votes.contains_key(&ThreatVerdict::Suspicious) {
                return ThreatVerdict::Suspicious;
            }
        }

        // Find the verdict with the highest weighted votes
        let mut best_verdict = ThreatVerdict::Unknown;
        let mut best_weight = 0.0f32;
        for (verdict, weight) in votes {
            if *weight > best_weight {
                best_weight = *weight;
                best_verdict = verdict.clone();
            }
        }

        best_verdict
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat_intel::mock::MockThreatIntelConnector;

    fn create_aggregator_with_mocks() -> ThreatIntelAggregator {
        let mut aggregator = ThreatIntelAggregator::new(AggregatorConfig::default());

        let mock1 = Arc::new(MockThreatIntelConnector::new("mock-provider-1"));
        let mock2 = Arc::new(MockThreatIntelConnector::new("mock-provider-2"));

        aggregator.add_provider(mock1);
        aggregator.add_provider_with_weight(mock2, 2.0);

        aggregator
    }

    #[test]
    fn test_aggregator_config_defaults() {
        let config = AggregatorConfig::default();
        assert_eq!(config.cache_ttl, Duration::from_secs(3600));
        assert_eq!(config.timeout_per_provider, Duration::from_secs(30));
        assert_eq!(config.min_providers_for_consensus, 2);
    }

    #[test]
    fn test_add_providers() {
        let aggregator = create_aggregator_with_mocks();
        assert_eq!(aggregator.provider_count(), 2);
    }

    #[test]
    fn test_determine_consensus_empty() {
        let aggregator = ThreatIntelAggregator::new(AggregatorConfig::default());
        let votes = HashMap::new();
        assert_eq!(
            aggregator.determine_consensus(&votes, 0),
            ThreatVerdict::Unknown
        );
    }

    #[test]
    fn test_determine_consensus_malicious() {
        let aggregator = ThreatIntelAggregator::new(AggregatorConfig::default());
        let mut votes = HashMap::new();
        votes.insert(ThreatVerdict::Malicious, 3.0);
        votes.insert(ThreatVerdict::Clean, 1.0);
        assert_eq!(
            aggregator.determine_consensus(&votes, 4),
            ThreatVerdict::Malicious
        );
    }

    #[test]
    fn test_determine_consensus_clean() {
        let aggregator = ThreatIntelAggregator::new(AggregatorConfig::default());
        let mut votes = HashMap::new();
        votes.insert(ThreatVerdict::Clean, 5.0);
        votes.insert(ThreatVerdict::Suspicious, 1.0);
        assert_eq!(
            aggregator.determine_consensus(&votes, 3),
            ThreatVerdict::Clean
        );
    }

    #[test]
    fn test_determine_consensus_below_min_providers() {
        let mut config = AggregatorConfig::default();
        config.min_providers_for_consensus = 3;
        let aggregator = ThreatIntelAggregator::new(config);
        let mut votes = HashMap::new();
        votes.insert(ThreatVerdict::Malicious, 1.0);
        // Only 1 provider responded, need 3 for consensus - should escalate to malicious
        assert_eq!(
            aggregator.determine_consensus(&votes, 1),
            ThreatVerdict::Malicious
        );
    }

    #[tokio::test]
    async fn test_lookup_domain_aggregated() {
        let aggregator = create_aggregator_with_mocks();
        let result = aggregator.lookup_domain("evil.example.com").await.unwrap();

        assert!(result.is_malicious);
        assert_eq!(result.sources.len(), 2);
        assert!(result.overall_score > 50.0);
    }

    #[tokio::test]
    async fn test_lookup_hash_aggregated() {
        let aggregator = create_aggregator_with_mocks();
        let result = aggregator
            .lookup_hash("44d88612fea8a8f36de82e1278abb02f")
            .await
            .unwrap();

        assert!(result.is_malicious);
        assert!(!result.provider_results.is_empty());
    }

    #[tokio::test]
    async fn test_lookup_ip_aggregated() {
        let aggregator = create_aggregator_with_mocks();
        let ip: IpAddr = "203.0.113.100".parse().unwrap();
        let result = aggregator.lookup_ip(&ip).await.unwrap();

        assert!(result.is_malicious);
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let aggregator = create_aggregator_with_mocks();

        // First lookup
        let result1 = aggregator.lookup_domain("evil.example.com").await.unwrap();
        // Second lookup should hit cache
        let result2 = aggregator.lookup_domain("evil.example.com").await.unwrap();

        assert_eq!(result1.overall_score, result2.overall_score);
        assert_eq!(result1.sources.len(), result2.sources.len());
    }

    #[tokio::test]
    async fn test_unknown_indicator() {
        let aggregator = create_aggregator_with_mocks();
        let result = aggregator
            .lookup_domain("unknown-domain-xyz.example")
            .await
            .unwrap();

        assert!(!result.is_malicious);
        assert_eq!(result.consensus_verdict, ThreatVerdict::Unknown);
    }
}
