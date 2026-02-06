//! AlienVault OTX threat intelligence connector.
//!
//! Integrates with the AlienVault Open Threat Exchange (OTX) API for
//! IP, domain, hash, and URL lookups with pulse (threat report) context.

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

/// AlienVault OTX connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlienVaultConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Cache TTL in seconds (default: 3600).
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    /// Max cache entries (default: 10000).
    #[serde(default = "default_max_cache")]
    pub max_cache_entries: u64,
    /// Requests per minute rate limit (default: 50).
    #[serde(default = "default_rate_limit")]
    pub requests_per_minute: u32,
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_max_cache() -> u64 {
    10000
}

fn default_rate_limit() -> u32 {
    50
}

/// AlienVault OTX connector.
pub struct AlienVaultConnector {
    config: AlienVaultConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl AlienVaultConnector {
    /// Creates a new AlienVault OTX connector.
    pub fn new(config: AlienVaultConfig) -> ConnectorResult<Self> {
        let rate_limit = RateLimitConfig {
            max_requests: config.requests_per_minute,
            period: Duration::from_secs(60),
            burst_size: 5,
        };

        let client = HttpClient::with_rate_limit(config.connector.clone(), Some(rate_limit))?;
        let cache = ResponseCache::new(
            Duration::from_secs(config.cache_ttl_secs),
            config.max_cache_entries,
        );

        info!(
            "AlienVault OTX connector initialized (rate limit: {} req/min)",
            config.requests_per_minute
        );

        Ok(Self {
            config,
            client,
            cache,
        })
    }

    /// Builds a ThreatIntelResult from OTX general data.
    fn build_result(
        &self,
        indicator: &str,
        indicator_type: IndicatorType,
        general: &OtxGeneralResponse,
    ) -> ThreatIntelResult {
        let pulse_count = general.pulse_info.count;
        let (verdict, score) = self.calculate_verdict(pulse_count);

        let categories: Vec<String> = general
            .pulse_info
            .pulses
            .iter()
            .flat_map(|p| p.tags.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let malware_families: Vec<String> = general
            .pulse_info
            .pulses
            .iter()
            .filter_map(|p| p.malware_families.clone())
            .flatten()
            .flat_map(|f| f.display_name)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        ThreatIntelResult {
            indicator_type,
            indicator: indicator.to_string(),
            verdict,
            malicious_score: score,
            malicious_count: pulse_count,
            total_engines: pulse_count,
            categories,
            malware_families,
            first_seen: None,
            last_seen: None,
            details: {
                let mut d = HashMap::new();
                d.insert("pulse_count".to_string(), serde_json::json!(pulse_count));
                if !general.pulse_info.pulses.is_empty() {
                    let pulse_names: Vec<&str> = general
                        .pulse_info
                        .pulses
                        .iter()
                        .take(5)
                        .map(|p| p.name.as_str())
                        .collect();
                    d.insert("top_pulses".to_string(), serde_json::json!(pulse_names));
                }
                d
            },
            source: "AlienVault OTX".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    /// Calculates verdict based on the number of pulses referencing the indicator.
    fn calculate_verdict(&self, pulse_count: u32) -> (ThreatVerdict, u8) {
        if pulse_count == 0 {
            (ThreatVerdict::Unknown, 0)
        } else if pulse_count >= 10 {
            (
                ThreatVerdict::Malicious,
                std::cmp::min(90 + pulse_count / 5, 100) as u8,
            )
        } else if pulse_count >= 3 {
            (ThreatVerdict::Suspicious, (30 + pulse_count * 6) as u8)
        } else {
            (ThreatVerdict::Suspicious, (pulse_count * 15) as u8)
        }
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
            source: "AlienVault OTX".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for AlienVaultConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/v1/user/me").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/v1/user/me").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for AlienVaultConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        let cache_key = format!("otx:hash:{}", hash);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            64 => IndicatorType::Sha256,
            _ => IndicatorType::Sha256,
        };

        let path = format!("/api/v1/indicators/file/{}/general", hash);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<OtxGeneralResponse>().await {
                Ok(data) => self.build_result(&hash, indicator_type, &data),
                Err(_) => self.unknown_result(indicator_type, &hash),
            },
            _ => self.unknown_result(indicator_type, &hash),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("otx:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let ip_section = if ip.is_ipv6() { "IPv6" } else { "IPv4" };
        let path = format!("/api/v1/indicators/{}/{}/general", ip_section, ip_str);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<OtxGeneralResponse>().await {
                Ok(data) => self.build_result(&ip_str, indicator_type, &data),
                Err(_) => self.unknown_result(indicator_type, &ip_str),
            },
            _ => self.unknown_result(indicator_type, &ip_str),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("otx:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let path = format!("/api/v1/indicators/domain/{}/general", domain);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<OtxGeneralResponse>().await {
                Ok(data) => self.build_result(&domain, IndicatorType::Domain, &data),
                Err(_) => self.unknown_result(IndicatorType::Domain, &domain),
            },
            _ => self.unknown_result(IndicatorType::Domain, &domain),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        let cache_key = format!("otx:url:{}", url);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let path = format!(
            "/api/v1/indicators/url/{}/general",
            urlencoding::encode(url)
        );
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<OtxGeneralResponse>().await {
                Ok(data) => self.build_result(url, IndicatorType::Url, &data),
                Err(_) => self.unknown_result(IndicatorType::Url, url),
            },
            _ => self.unknown_result(IndicatorType::Url, url),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "AlienVault OTX does not support file submission".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "AlienVault OTX does not support analysis status".to_string(),
        ))
    }
}

// OTX API response types

#[derive(Debug, Deserialize)]
struct OtxGeneralResponse {
    pulse_info: OtxPulseInfo,
}

#[derive(Debug, Deserialize)]
struct OtxPulseInfo {
    count: u32,
    #[serde(default)]
    pulses: Vec<OtxPulse>,
}

#[derive(Debug, Deserialize)]
struct OtxPulse {
    name: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    malware_families: Option<Vec<OtxMalwareFamily>>,
}

#[derive(Debug, Clone, Deserialize)]
struct OtxMalwareFamily {
    display_name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> AlienVaultConfig {
        AlienVaultConfig {
            connector: ConnectorConfig {
                name: "alienvault-test".to_string(),
                base_url: "https://otx.alienvault.com".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "X-OTX-API-KEY".to_string(),
                },
                timeout_secs: 30,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            cache_ttl_secs: 3600,
            max_cache_entries: 1000,
            requests_per_minute: 50,
        }
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();
        assert_eq!(config.connector.name, "alienvault-test");
        assert_eq!(config.requests_per_minute, 50);
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = AlienVaultConnector::new(config).unwrap();
        assert_eq!(connector.name(), "alienvault-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_calculate_verdict_no_pulses() {
        let config = create_test_config();
        let connector = AlienVaultConnector::new(config).unwrap();
        let (verdict, score) = connector.calculate_verdict(0);
        assert_eq!(verdict, ThreatVerdict::Unknown);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_calculate_verdict_many_pulses() {
        let config = create_test_config();
        let connector = AlienVaultConnector::new(config).unwrap();
        let (verdict, _score) = connector.calculate_verdict(15);
        assert_eq!(verdict, ThreatVerdict::Malicious);
    }

    #[test]
    fn test_config_defaults() {
        assert_eq!(default_cache_ttl(), 3600);
        assert_eq!(default_max_cache(), 10000);
        assert_eq!(default_rate_limit(), 50);
    }
}
