//! VirusTotal threat intelligence connector.
//!
//! This module provides integration with VirusTotal API v3 for threat intelligence lookups.
//! It includes proper rate limiting (4 requests/minute for free tier) and caching.

use crate::http::{HttpClient, RateLimitConfig, ResponseCache};
use crate::traits::{
    AnalysisStatus, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
    IndicatorType, ThreatIntelConnector, ThreatIntelResult, ThreatVerdict,
};
use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use tracing::{debug, info, instrument, warn};

/// VirusTotal connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirusTotalConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Cache TTL in seconds (default: 3600 = 1 hour).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Maximum cache entries (default: 10000).
    #[serde(default = "default_max_cache_entries")]
    pub max_cache_entries: u64,
    /// Requests per minute rate limit (default: 4 for free tier).
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_max_cache_entries() -> u64 {
    10000
}

fn default_rate_limit() -> u32 {
    4 // Free tier limit
}

/// VirusTotal connector for threat intelligence lookups.
pub struct VirusTotalConnector {
    config: VirusTotalConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl VirusTotalConnector {
    /// Creates a new VirusTotal connector.
    pub fn new(config: VirusTotalConfig) -> ConnectorResult<Self> {
        // Configure rate limiting
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 1, // No bursting for VT
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;
        let cache = ResponseCache::new(
            Duration::from_secs(config.cache_ttl_secs),
            config.max_cache_entries,
        );

        info!(
            "VirusTotal connector initialized (rate limit: {} req/min, cache TTL: {}s)",
            config.requests_per_minute, config.cache_ttl_secs
        );

        Ok(Self {
            config,
            client,
            cache,
        })
    }

    /// Creates a connector with custom rate limit (e.g., for premium API).
    pub fn with_rate_limit(
        mut config: VirusTotalConfig,
        requests_per_minute: u32,
    ) -> ConnectorResult<Self> {
        config.requests_per_minute = requests_per_minute;
        Self::new(config)
    }

    /// Parses a VirusTotal file report into our format.
    fn parse_file_report(&self, data: VTFileData, hash: &str) -> ThreatIntelResult {
        let attributes = data.attributes;

        let malicious_count = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious)
            .unwrap_or(0);

        let total_engines = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious + s.undetected + s.suspicious + s.harmless)
            .unwrap_or(0);

        let verdict = self.calculate_verdict(malicious_count, total_engines);
        let malicious_score = if total_engines > 0 {
            ((malicious_count as f64 / total_engines as f64) * 100.0) as u8
        } else {
            0
        };

        ThreatIntelResult {
            indicator_type: self.detect_hash_type(hash),
            indicator: hash.to_string(),
            verdict,
            malicious_score,
            malicious_count,
            total_engines,
            categories: attributes.tags.unwrap_or_default(),
            malware_families: attributes
                .popular_threat_classification
                .map(|c| {
                    c.suggested_threat_label
                        .map(|l| vec![l])
                        .unwrap_or_default()
                })
                .unwrap_or_default(),
            first_seen: attributes
                .first_submission_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            last_seen: attributes
                .last_analysis_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            details: {
                let mut details = HashMap::new();
                if let Some(names) = attributes.names {
                    details.insert("names".to_string(), serde_json::json!(names));
                }
                if let Some(size) = attributes.size {
                    details.insert("size".to_string(), serde_json::json!(size));
                }
                if let Some(type_description) = attributes.type_description {
                    details.insert(
                        "type_description".to_string(),
                        serde_json::json!(type_description),
                    );
                }
                details
            },
            source: "VirusTotal".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    /// Parses a VirusTotal IP report into our format.
    fn parse_ip_report(&self, data: VTIPData, ip: &str) -> ThreatIntelResult {
        let attributes = data.attributes;

        let malicious_count = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious)
            .unwrap_or(0);

        let total_engines = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious + s.undetected + s.suspicious + s.harmless)
            .unwrap_or(0);

        let verdict = self.calculate_verdict(malicious_count, total_engines);
        let malicious_score = if total_engines > 0 {
            ((malicious_count as f64 / total_engines as f64) * 100.0) as u8
        } else {
            0
        };

        ThreatIntelResult {
            indicator_type: if ip.contains(':') {
                IndicatorType::Ipv6
            } else {
                IndicatorType::Ipv4
            },
            indicator: ip.to_string(),
            verdict,
            malicious_score,
            malicious_count,
            total_engines,
            categories: attributes.tags.unwrap_or_default(),
            malware_families: vec![],
            first_seen: None,
            last_seen: attributes
                .last_analysis_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            details: {
                let mut details = HashMap::new();
                if let Some(country) = attributes.country {
                    details.insert("country".to_string(), serde_json::json!(country));
                }
                if let Some(asn) = attributes.asn {
                    details.insert("asn".to_string(), serde_json::json!(asn));
                }
                if let Some(owner) = attributes.as_owner {
                    details.insert("as_owner".to_string(), serde_json::json!(owner));
                }
                if let Some(network) = attributes.network {
                    details.insert("network".to_string(), serde_json::json!(network));
                }
                if let Some(continent) = attributes.continent {
                    details.insert("continent".to_string(), serde_json::json!(continent));
                }
                details
            },
            source: "VirusTotal".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    /// Parses a VirusTotal domain report into our format.
    fn parse_domain_report(&self, data: VTDomainData, domain: &str) -> ThreatIntelResult {
        let attributes = data.attributes;

        let malicious_count = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious)
            .unwrap_or(0);

        let total_engines = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious + s.undetected + s.suspicious + s.harmless)
            .unwrap_or(0);

        let verdict = self.calculate_verdict(malicious_count, total_engines);
        let malicious_score = if total_engines > 0 {
            ((malicious_count as f64 / total_engines as f64) * 100.0) as u8
        } else {
            0
        };

        ThreatIntelResult {
            indicator_type: IndicatorType::Domain,
            indicator: domain.to_string(),
            verdict,
            malicious_score,
            malicious_count,
            total_engines,
            categories: attributes
                .categories
                .map(|c| c.into_values().collect())
                .unwrap_or_default(),
            malware_families: vec![],
            first_seen: attributes
                .creation_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            last_seen: attributes
                .last_analysis_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            details: {
                let mut details = HashMap::new();
                if let Some(registrar) = attributes.registrar {
                    details.insert("registrar".to_string(), serde_json::json!(registrar));
                }
                if let Some(whois) = attributes.whois {
                    details.insert("whois".to_string(), serde_json::json!(whois));
                }
                if let Some(tld) = attributes.tld {
                    details.insert("tld".to_string(), serde_json::json!(tld));
                }
                details
            },
            source: "VirusTotal".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    /// Parses a VirusTotal URL report into our format.
    fn parse_url_report(&self, data: VTUrlData, url: &str) -> ThreatIntelResult {
        let attributes = data.attributes;

        let malicious_count = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious)
            .unwrap_or(0);

        let total_engines = attributes
            .last_analysis_stats
            .as_ref()
            .map(|s| s.malicious + s.undetected + s.suspicious + s.harmless)
            .unwrap_or(0);

        let verdict = self.calculate_verdict(malicious_count, total_engines);
        let malicious_score = if total_engines > 0 {
            ((malicious_count as f64 / total_engines as f64) * 100.0) as u8
        } else {
            0
        };

        ThreatIntelResult {
            indicator_type: IndicatorType::Url,
            indicator: url.to_string(),
            verdict,
            malicious_score,
            malicious_count,
            total_engines,
            categories: attributes
                .categories
                .map(|c| c.into_values().collect())
                .unwrap_or_default(),
            malware_families: vec![],
            first_seen: attributes
                .first_submission_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            last_seen: attributes
                .last_analysis_date
                .and_then(|ts| Utc.timestamp_opt(ts, 0).single()),
            details: {
                let mut details = HashMap::new();
                if let Some(final_url) = attributes.last_final_url {
                    details.insert("final_url".to_string(), serde_json::json!(final_url));
                }
                if let Some(title) = attributes.title {
                    details.insert("title".to_string(), serde_json::json!(title));
                }
                details
            },
            source: "VirusTotal".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    /// Calculates the threat verdict based on detection ratio.
    fn calculate_verdict(&self, malicious: u32, total: u32) -> ThreatVerdict {
        if total == 0 {
            return ThreatVerdict::Unknown;
        }

        let ratio = malicious as f64 / total as f64;

        if ratio > 0.5 {
            ThreatVerdict::Malicious
        } else if ratio > 0.1 || malicious > 0 {
            // Suspicious if more than 10% flagged it, or any vendor flagged it as malicious
            ThreatVerdict::Suspicious
        } else {
            ThreatVerdict::Clean
        }
    }

    /// Detects the hash type from the hash string.
    fn detect_hash_type(&self, hash: &str) -> IndicatorType {
        match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            64 => IndicatorType::Sha256,
            _ => IndicatorType::Sha256,
        }
    }

    /// Creates an unknown result for not found indicators.
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
            source: "VirusTotal".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for VirusTotalConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        // Check API status by getting quota info
        match self.client.get("/api/v3/users/current").await {
            Ok(response) if response.status().is_success() => {
                // Parse quota information
                if let Ok(quota) = response.json::<VTQuotaResponse>().await {
                    let remaining = quota
                        .data
                        .attributes
                        .quotas
                        .api_requests_monthly
                        .user
                        .allowed
                        .saturating_sub(
                            quota.data.attributes.quotas.api_requests_monthly.user.used,
                        );

                    if remaining < 100 {
                        return Ok(ConnectorHealth::Degraded(format!(
                            "Low API quota: {} remaining",
                            remaining
                        )));
                    }
                }
                Ok(ConnectorHealth::Healthy)
            }
            Ok(response) if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS => {
                Ok(ConnectorHealth::Degraded("Rate limited".to_string()))
            }
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Unexpected status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/v3/users/current").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for VirusTotalConnector {
    #[instrument(skip(self), fields(hash = %hash))]
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        let cache_key = format!("vt:hash:{}", hash);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for hash {}", hash);
            return Ok(cached);
        }

        debug!("Cache miss, fetching from VirusTotal API");
        let path = format!("/api/v3/files/{}", hash);
        let response = self.client.get(&path).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let result = self.unknown_result(self.detect_hash_type(&hash), &hash);
            self.cache.insert(cache_key, result.clone()).await;
            return Ok(result);
        }

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to lookup hash: {}",
                response.status()
            )));
        }

        let vt_response: VTResponse<VTFileData> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let result = self.parse_file_report(vt_response.data, &hash);
        self.cache.insert(cache_key, result.clone()).await;

        Ok(result)
    }

    #[instrument(skip(self), fields(ip = %ip))]
    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("vt:ip:{}", ip_str);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for IP {}", ip_str);
            return Ok(cached);
        }

        debug!("Cache miss, fetching from VirusTotal API");
        let path = format!("/api/v3/ip_addresses/{}", ip_str);
        let response = self.client.get(&path).await?;

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let result = self.unknown_result(indicator_type, &ip_str);
            self.cache.insert(cache_key, result.clone()).await;
            return Ok(result);
        }

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to lookup IP: {}",
                response.status()
            )));
        }

        let vt_response: VTResponse<VTIPData> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let result = self.parse_ip_report(vt_response.data, &ip_str);
        self.cache.insert(cache_key, result.clone()).await;

        Ok(result)
    }

    #[instrument(skip(self), fields(domain = %domain))]
    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("vt:domain:{}", domain);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for domain {}", domain);
            return Ok(cached);
        }

        debug!("Cache miss, fetching from VirusTotal API");
        let path = format!("/api/v3/domains/{}", domain);
        let response = self.client.get(&path).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let result = self.unknown_result(IndicatorType::Domain, &domain);
            self.cache.insert(cache_key, result.clone()).await;
            return Ok(result);
        }

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to lookup domain: {}",
                response.status()
            )));
        }

        let vt_response: VTResponse<VTDomainData> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let result = self.parse_domain_report(vt_response.data, &domain);
        self.cache.insert(cache_key, result.clone()).await;

        Ok(result)
    }

    #[instrument(skip(self))]
    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        // URL lookups require base64 encoding the URL (URL-safe, no padding)
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        let encoded = URL_SAFE_NO_PAD.encode(url);
        let cache_key = format!("vt:url:{}", encoded);

        // Check cache first
        if let Some(cached) = self.cache.get(&cache_key).await {
            debug!("Cache hit for URL");
            return Ok(cached);
        }

        debug!("Cache miss, fetching from VirusTotal API");
        let path = format!("/api/v3/urls/{}", encoded);
        let response = self.client.get(&path).await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            let result = self.unknown_result(IndicatorType::Url, url);
            self.cache.insert(cache_key, result.clone()).await;
            return Ok(result);
        }

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to lookup URL: {}",
                response.status()
            )));
        }

        let vt_response: VTResponse<VTUrlData> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let result = self.parse_url_report(vt_response.data, url);
        self.cache.insert(cache_key, result.clone()).await;

        Ok(result)
    }

    #[instrument(skip(self))]
    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        // File submission requires multipart upload
        // This would require additional implementation with reqwest multipart
        warn!("File submission not yet implemented");
        Err(ConnectorError::Internal(
            "File submission not yet implemented".to_string(),
        ))
    }

    #[instrument(skip(self), fields(analysis_id = %analysis_id))]
    async fn get_analysis_status(&self, analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        let path = format!("/api/v3/analyses/{}", analysis_id);
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get analysis: {}",
                response.status()
            )));
        }

        let vt_response: VTResponse<VTAnalysisData> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(e.to_string()))?;

        let status = &vt_response.data.attributes.status;
        let progress = match status.as_str() {
            "completed" => 100,
            "queued" => 0,
            _ => 50,
        };

        Ok(AnalysisStatus {
            id: analysis_id.to_string(),
            status: status.clone(),
            progress,
            result: None, // Would need to parse full result
        })
    }
}

// VirusTotal API response types

#[derive(Debug, Deserialize)]
struct VTResponse<T> {
    data: T,
}

#[derive(Debug, Deserialize)]
struct VTFileData {
    attributes: VTFileAttributes,
}

#[derive(Debug, Deserialize)]
struct VTFileAttributes {
    last_analysis_stats: Option<VTAnalysisStats>,
    first_submission_date: Option<i64>,
    last_analysis_date: Option<i64>,
    tags: Option<Vec<String>>,
    popular_threat_classification: Option<VTThreatClassification>,
    names: Option<Vec<String>>,
    size: Option<u64>,
    type_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTAnalysisStats {
    malicious: u32,
    suspicious: u32,
    undetected: u32,
    harmless: u32,
}

#[derive(Debug, Deserialize)]
struct VTThreatClassification {
    suggested_threat_label: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTIPData {
    attributes: VTIPAttributes,
}

#[derive(Debug, Deserialize)]
struct VTIPAttributes {
    last_analysis_stats: Option<VTAnalysisStats>,
    last_analysis_date: Option<i64>,
    tags: Option<Vec<String>>,
    country: Option<String>,
    asn: Option<u32>,
    as_owner: Option<String>,
    network: Option<String>,
    continent: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTDomainData {
    attributes: VTDomainAttributes,
}

#[derive(Debug, Deserialize)]
struct VTDomainAttributes {
    last_analysis_stats: Option<VTAnalysisStats>,
    last_analysis_date: Option<i64>,
    creation_date: Option<i64>,
    categories: Option<HashMap<String, String>>,
    registrar: Option<String>,
    whois: Option<String>,
    tld: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTUrlData {
    attributes: VTUrlAttributes,
}

#[derive(Debug, Deserialize)]
struct VTUrlAttributes {
    last_analysis_stats: Option<VTAnalysisStats>,
    last_analysis_date: Option<i64>,
    first_submission_date: Option<i64>,
    categories: Option<HashMap<String, String>>,
    last_final_url: Option<String>,
    title: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VTAnalysisData {
    attributes: VTAnalysisAttributes,
}

#[derive(Debug, Deserialize)]
struct VTAnalysisAttributes {
    status: String,
}

// Quota response for health check
#[derive(Debug, Deserialize)]
struct VTQuotaResponse {
    data: VTQuotaData,
}

#[derive(Debug, Deserialize)]
struct VTQuotaData {
    attributes: VTQuotaAttributes,
}

#[derive(Debug, Deserialize)]
struct VTQuotaAttributes {
    quotas: VTQuotas,
}

#[derive(Debug, Deserialize)]
struct VTQuotas {
    api_requests_monthly: VTQuotaLimit,
}

#[derive(Debug, Deserialize)]
struct VTQuotaLimit {
    user: VTQuotaUser,
}

#[derive(Debug, Deserialize)]
struct VTQuotaUser {
    allowed: u64,
    used: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::AuthConfig;
    use std::collections::HashMap;

    fn create_test_config() -> VirusTotalConfig {
        VirusTotalConfig {
            connector: ConnectorConfig {
                name: "virustotal-test".to_string(),
                base_url: "https://www.virustotal.com".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-api-key".to_string()),
                    header_name: "x-apikey".to_string(),
                },
                timeout_secs: 30,
                max_retries: 3,
                verify_tls: true,
                headers: HashMap::new(),
            },
            cache_ttl_secs: 3600,
            max_cache_entries: 1000,
            requests_per_minute: 4,
        }
    }

    #[test]
    fn test_detect_hash_type() {
        let config = create_test_config();
        let connector = VirusTotalConnector::new(config).unwrap();

        assert_eq!(
            connector.detect_hash_type("d41d8cd98f00b204e9800998ecf8427e"),
            IndicatorType::Md5
        );
        assert_eq!(
            connector.detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            IndicatorType::Sha1
        );
        assert_eq!(
            connector.detect_hash_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            IndicatorType::Sha256
        );
    }

    #[test]
    fn test_calculate_verdict() {
        let config = create_test_config();
        let connector = VirusTotalConnector::new(config).unwrap();

        assert_eq!(connector.calculate_verdict(0, 0), ThreatVerdict::Unknown);
        assert_eq!(connector.calculate_verdict(0, 70), ThreatVerdict::Clean);
        assert_eq!(
            connector.calculate_verdict(5, 70),
            ThreatVerdict::Suspicious
        );
        assert_eq!(
            connector.calculate_verdict(40, 70),
            ThreatVerdict::Malicious
        );
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_cache_ttl(), 3600);
        assert_eq!(default_max_cache_entries(), 10000);
        assert_eq!(default_rate_limit(), 4);
    }
}
