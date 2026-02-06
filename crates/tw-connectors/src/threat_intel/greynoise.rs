//! GreyNoise threat intelligence connector.
//!
//! Integrates with GreyNoise API for IP reputation and noise classification,
//! distinguishing between targeted activity and internet-wide scanning.

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

/// GreyNoise connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GreyNoiseConfig {
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_secs: u64,
    #[serde(default = "default_max_cache")]
    pub max_cache_entries: u64,
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
    100
}

/// GreyNoise IP classification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NoiseClassification {
    /// IP is known to scan the internet.
    Noise,
    /// IP shows characteristics of a RIOT (Rule It OuT) - known benign service.
    Riot,
    /// Unknown classification.
    Unknown,
}

/// GreyNoise connector.
pub struct GreyNoiseConnector {
    config: GreyNoiseConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl GreyNoiseConnector {
    pub fn new(config: GreyNoiseConfig) -> ConnectorResult<Self> {
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

        info!("GreyNoise connector initialized");

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
            source: "GreyNoise".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    fn classify_verdict(&self, classification: &str, seen: bool) -> (ThreatVerdict, u8) {
        match classification {
            "malicious" => (ThreatVerdict::Malicious, 80),
            "benign" => (ThreatVerdict::Clean, 0),
            _ if seen => (ThreatVerdict::Suspicious, 40),
            _ => (ThreatVerdict::Unknown, 0),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for GreyNoiseConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/ping").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/ping").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for GreyNoiseConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        // GreyNoise only supports IP lookups
        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };
        Ok(self.unknown_result(indicator_type, hash))
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("greynoise:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let path = format!("/v3/community/{}", ip_str);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => {
                match r.json::<GreyNoiseCommunityResponse>().await {
                    Ok(data) => {
                        let (verdict, score) = self
                            .classify_verdict(&data.classification.unwrap_or_default(), data.noise);
                        let mut categories = Vec::new();
                        if data.noise {
                            categories.push("internet-scanner".to_string());
                        }
                        if data.riot {
                            categories.push("known-benign".to_string());
                        }

                        ThreatIntelResult {
                            indicator_type,
                            indicator: ip_str.clone(),
                            verdict,
                            malicious_score: score,
                            malicious_count: if score >= 80 { 1 } else { 0 },
                            total_engines: 1,
                            categories,
                            malware_families: vec![],
                            first_seen: None,
                            last_seen: None,
                            details: {
                                let mut d = HashMap::new();
                                d.insert("noise".to_string(), serde_json::json!(data.noise));
                                d.insert("riot".to_string(), serde_json::json!(data.riot));
                                if let Some(name) = data.name {
                                    d.insert("name".to_string(), serde_json::json!(name));
                                }
                                if let Some(link) = data.link {
                                    d.insert("link".to_string(), serde_json::json!(link));
                                }
                                d
                            },
                            source: "GreyNoise".to_string(),
                            cache_ttl: self.config.cache_ttl_secs,
                        }
                    }
                    Err(_) => self.unknown_result(indicator_type, &ip_str),
                }
            }
            _ => self.unknown_result(indicator_type, &ip_str),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        // GreyNoise only supports IP lookups
        Ok(self.unknown_result(IndicatorType::Domain, domain))
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        Ok(self.unknown_result(IndicatorType::Url, url))
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "GreyNoise does not support file submission".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "GreyNoise does not support analysis status".to_string(),
        ))
    }
}

// Response types

#[derive(Debug, Deserialize)]
struct GreyNoiseCommunityResponse {
    noise: bool,
    riot: bool,
    classification: Option<String>,
    name: Option<String>,
    link: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> GreyNoiseConfig {
        GreyNoiseConfig {
            connector: ConnectorConfig {
                name: "greynoise-test".to_string(),
                base_url: "https://api.greynoise.io".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "key".to_string(),
                },
                timeout_secs: 30,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            cache_ttl_secs: 3600,
            max_cache_entries: 1000,
            requests_per_minute: 100,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = GreyNoiseConnector::new(config).unwrap();
        assert_eq!(connector.name(), "greynoise-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_classify_verdict() {
        let config = create_test_config();
        let connector = GreyNoiseConnector::new(config).unwrap();
        assert_eq!(
            connector.classify_verdict("malicious", true),
            (ThreatVerdict::Malicious, 80)
        );
        assert_eq!(
            connector.classify_verdict("benign", false),
            (ThreatVerdict::Clean, 0)
        );
        assert_eq!(
            connector.classify_verdict("unknown", true),
            (ThreatVerdict::Suspicious, 40)
        );
        assert_eq!(
            connector.classify_verdict("unknown", false),
            (ThreatVerdict::Unknown, 0)
        );
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_cache_ttl(), 3600);
        assert_eq!(default_rate_limit(), 100);
    }
}
