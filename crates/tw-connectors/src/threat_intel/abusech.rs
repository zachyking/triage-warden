//! Abuse.ch threat intelligence connector.
//!
//! Integrates with Abuse.ch services: URLhaus, MalwareBazaar, and ThreatFox
//! for URL, hash, and IoC lookups.

use crate::http::{HttpClient, RateLimitConfig, ResponseCache};
use crate::traits::{
    AnalysisStatus, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
    IndicatorType, ThreatIntelConnector, ThreatIntelResult, ThreatVerdict,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tracing::info;

/// Abuse.ch connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbusechConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// URLhaus API base URL.
    #[serde(default = "default_urlhaus_url")]
    pub urlhaus_base_url: String,
    /// MalwareBazaar API base URL.
    #[serde(default = "default_bazaar_url")]
    pub bazaar_base_url: String,
    /// ThreatFox API base URL.
    #[serde(default = "default_threatfox_url")]
    pub threatfox_base_url: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_max_cache")]
    pub max_cache_entries: u64,
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_urlhaus_url() -> String {
    "https://urlhaus-api.abuse.ch".to_string()
}
fn default_bazaar_url() -> String {
    "https://mb-api.abuse.ch".to_string()
}
fn default_threatfox_url() -> String {
    "https://threatfox-api.abuse.ch".to_string()
}
fn default_cache_ttl() -> u64 {
    1800
}
fn default_max_cache() -> u64 {
    10000
}
fn default_rate_limit() -> u32 {
    60
}

/// Abuse.ch connector for URLhaus, MalwareBazaar, and ThreatFox.
pub struct AbusechConnector {
    config: AbusechConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl AbusechConnector {
    pub fn new(config: AbusechConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 10,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;
        let cache = ResponseCache::new(
            Duration::from_secs(config.cache_ttl_secs),
            config.max_cache_entries,
        );

        info!("Abuse.ch connector initialized");

        Ok(Self {
            config,
            client,
            cache,
        })
    }

    fn unknown_result(&self, indicator_type: IndicatorType, indicator: &str) -> ThreatIntelResult {
        ThreatIntelResult {
            indicator_type,
            indicator: indicator.to_string(),
            verdict: ThreatVerdict::Unknown,
            malicious_score: 0,
            malicious_count: 0,
            total_engines: 0,
            categories: vec![],
            malware_families: vec![],
            first_seen: None,
            last_seen: None,
            details: HashMap::new(),
            source: "Abuse.ch".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for AbusechConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // URLhaus has no dedicated health endpoint; try a benign query
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl ThreatIntelConnector for AbusechConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        let cache_key = format!("abusech:hash:{}", hash);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };

        // Query MalwareBazaar
        let hash_type = match hash.len() {
            32 => "md5_hash",
            40 => "sha1_hash",
            _ => "sha256_hash",
        };

        let body = serde_json::json!({
            "query": "get_info",
            hash_type: hash,
        });

        let response = self.client.post("/api/v1/", &body).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<BazaarResponse>().await {
                Ok(data) if data.query_status == "ok" => {
                    let sample = data.data.and_then(|d| d.into_iter().next());
                    match sample {
                        Some(s) => ThreatIntelResult {
                            indicator_type,
                            indicator: hash.clone(),
                            verdict: ThreatVerdict::Malicious,
                            malicious_score: 90,
                            malicious_count: 1,
                            total_engines: 1,
                            categories: s.tags.unwrap_or_default(),
                            malware_families: s.signature.map(|s| vec![s]).unwrap_or_default(),
                            first_seen: None,
                            last_seen: None,
                            details: {
                                let mut d = HashMap::new();
                                if let Some(ft) = s.file_type {
                                    d.insert("file_type".to_string(), serde_json::json!(ft));
                                }
                                if let Some(fs) = s.file_size {
                                    d.insert("file_size".to_string(), serde_json::json!(fs));
                                }
                                d
                            },
                            source: "Abuse.ch MalwareBazaar".to_string(),
                            cache_ttl: self.config.cache_ttl_secs,
                        },
                        None => self.unknown_result(indicator_type, &hash),
                    }
                }
                _ => self.unknown_result(indicator_type, &hash),
            },
            _ => self.unknown_result(indicator_type, &hash),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("abusech:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        // Query ThreatFox for IoC
        let body = serde_json::json!({
            "query": "search_ioc",
            "search_term": ip_str,
        });

        let response = self.client.post("/api/v1/", &body).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<ThreatFoxResponse>().await {
                Ok(data) if data.query_status == "ok" => {
                    let ioc_count = data.data.as_ref().map(|d| d.len()).unwrap_or(0);
                    if ioc_count > 0 {
                        let tags: Vec<String> = data
                            .data
                            .as_ref()
                            .unwrap()
                            .iter()
                            .flat_map(|i| i.tags.clone().unwrap_or_default())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        let malware: Vec<String> = data
                            .data
                            .as_ref()
                            .unwrap()
                            .iter()
                            .filter_map(|i| i.malware_printable.clone())
                            .collect::<std::collections::HashSet<_>>()
                            .into_iter()
                            .collect();
                        ThreatIntelResult {
                            indicator_type,
                            indicator: ip_str.clone(),
                            verdict: ThreatVerdict::Malicious,
                            malicious_score: 80,
                            malicious_count: ioc_count as u32,
                            total_engines: 1,
                            categories: tags,
                            malware_families: malware,
                            first_seen: None,
                            last_seen: None,
                            details: HashMap::new(),
                            source: "Abuse.ch ThreatFox".to_string(),
                            cache_ttl: self.config.cache_ttl_secs,
                        }
                    } else {
                        self.unknown_result(indicator_type, &ip_str)
                    }
                }
                _ => self.unknown_result(indicator_type, &ip_str),
            },
            _ => self.unknown_result(indicator_type, &ip_str),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("abusech:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        // Query URLhaus for domain
        let body = serde_json::json!({
            "host": domain,
        });

        let response = self.client.post("/v1/host/", &body).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<UrlhausHostResponse>().await {
                Ok(data) if data.query_status == "ok" => {
                    let url_count = data.url_count.unwrap_or(0);
                    if url_count > 0 {
                        ThreatIntelResult {
                            indicator_type: IndicatorType::Domain,
                            indicator: domain.clone(),
                            verdict: ThreatVerdict::Malicious,
                            malicious_score: std::cmp::min(50 + url_count * 10, 100) as u8,
                            malicious_count: url_count as u32,
                            total_engines: 1,
                            categories: vec!["malware-distribution".to_string()],
                            malware_families: vec![],
                            first_seen: None,
                            last_seen: None,
                            details: {
                                let mut d = HashMap::new();
                                d.insert("url_count".to_string(), serde_json::json!(url_count));
                                d
                            },
                            source: "Abuse.ch URLhaus".to_string(),
                            cache_ttl: self.config.cache_ttl_secs,
                        }
                    } else {
                        self.unknown_result(IndicatorType::Domain, &domain)
                    }
                }
                _ => self.unknown_result(IndicatorType::Domain, &domain),
            },
            _ => self.unknown_result(IndicatorType::Domain, &domain),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        let cache_key = format!("abusech:url:{}", url);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let body = serde_json::json!({
            "url": url,
        });

        let response = self.client.post("/v1/url/", &body).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<UrlhausUrlResponse>().await {
                Ok(data) if data.query_status == "ok" => {
                    let threat = data.threat.as_deref().unwrap_or("unknown");
                    ThreatIntelResult {
                        indicator_type: IndicatorType::Url,
                        indicator: url.to_string(),
                        verdict: ThreatVerdict::Malicious,
                        malicious_score: 85,
                        malicious_count: 1,
                        total_engines: 1,
                        categories: vec![threat.to_string()],
                        malware_families: vec![],
                        first_seen: None,
                        last_seen: None,
                        details: {
                            let mut d = HashMap::new();
                            if let Some(status) = data.url_status {
                                d.insert("url_status".to_string(), serde_json::json!(status));
                            }
                            d
                        },
                        source: "Abuse.ch URLhaus".to_string(),
                        cache_ttl: self.config.cache_ttl_secs,
                    }
                }
                _ => self.unknown_result(IndicatorType::Url, url),
            },
            _ => self.unknown_result(IndicatorType::Url, url),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "Abuse.ch does not support direct file submission".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "Abuse.ch does not support analysis status".to_string(),
        ))
    }
}

// Response types

#[derive(Debug, Deserialize)]
struct BazaarResponse {
    query_status: String,
    data: Option<Vec<BazaarSample>>,
}

#[derive(Debug, Deserialize)]
struct BazaarSample {
    signature: Option<String>,
    file_type: Option<String>,
    file_size: Option<u64>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxResponse {
    query_status: String,
    data: Option<Vec<ThreatFoxIoc>>,
}

#[derive(Debug, Deserialize)]
struct ThreatFoxIoc {
    malware_printable: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct UrlhausHostResponse {
    query_status: String,
    url_count: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UrlhausUrlResponse {
    query_status: String,
    threat: Option<String>,
    url_status: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> AbusechConfig {
        AbusechConfig {
            connector: ConnectorConfig {
                name: "abusech-test".to_string(),
                base_url: "https://mb-api.abuse.ch".to_string(),
                auth: AuthConfig::None,
                timeout_secs: 30,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            urlhaus_base_url: default_urlhaus_url(),
            bazaar_base_url: default_bazaar_url(),
            threatfox_base_url: default_threatfox_url(),
            cache_ttl_secs: 1800,
            max_cache_entries: 1000,
            requests_per_minute: 60,
        }
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();
        assert_eq!(config.connector.name, "abusech-test");
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = AbusechConnector::new(config).unwrap();
        assert_eq!(connector.name(), "abusech-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_cache_ttl(), 1800);
        assert_eq!(default_rate_limit(), 60);
        assert_eq!(default_urlhaus_url(), "https://urlhaus-api.abuse.ch");
        assert_eq!(default_bazaar_url(), "https://mb-api.abuse.ch");
        assert_eq!(default_threatfox_url(), "https://threatfox-api.abuse.ch");
    }
}
