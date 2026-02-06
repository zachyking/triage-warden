//! MISP (Malware Information Sharing Platform) threat intelligence connector.
//!
//! Integrates with MISP instances for IoC queries and attribute searches.

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

/// MISP connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MispConfig {
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

/// MISP connector.
pub struct MispConnector {
    config: MispConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl MispConnector {
    pub fn new(config: MispConfig) -> ConnectorResult<Self> {
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

        info!("MISP connector initialized");

        Ok(Self {
            config,
            client,
            cache,
        })
    }

    /// Searches MISP attributes for a value of a given type.
    async fn search_attribute(
        &self,
        value: &str,
        attr_type: &str,
    ) -> ConnectorResult<Option<Vec<MispAttribute>>> {
        let body = serde_json::json!({
            "returnFormat": "json",
            "value": value,
            "type": attr_type,
            "limit": 50,
        });

        let response = self.client.post("/attributes/restSearch", &body).await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        match response.json::<MispSearchResponse>().await {
            Ok(data) => Ok(Some(data.response.attribute.unwrap_or_default())),
            Err(_) => Ok(None),
        }
    }

    fn build_result_from_attributes(
        &self,
        indicator: &str,
        indicator_type: IndicatorType,
        attributes: &[MispAttribute],
    ) -> ThreatIntelResult {
        if attributes.is_empty() {
            return self.unknown_result(indicator_type, indicator);
        }

        let event_count = attributes
            .iter()
            .filter_map(|a| a.event_id.as_deref())
            .collect::<std::collections::HashSet<_>>()
            .len();

        let categories: Vec<String> = attributes
            .iter()
            .filter_map(|a| a.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        let score = std::cmp::min(40 + event_count * 15, 100) as u8;
        let verdict = if event_count >= 3 {
            ThreatVerdict::Malicious
        } else if event_count >= 1 {
            ThreatVerdict::Suspicious
        } else {
            ThreatVerdict::Unknown
        };

        ThreatIntelResult {
            indicator_type,
            indicator: indicator.to_string(),
            verdict,
            malicious_score: score,
            malicious_count: event_count as u32,
            total_engines: 1,
            categories,
            malware_families: vec![],
            first_seen: None,
            last_seen: None,
            details: {
                let mut d = HashMap::new();
                d.insert(
                    "misp_event_count".to_string(),
                    serde_json::json!(event_count),
                );
                d.insert(
                    "misp_attribute_count".to_string(),
                    serde_json::json!(attributes.len()),
                );
                d
            },
            source: "MISP".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
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
            source: "MISP".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for MispConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/servers/getVersion.json").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/servers/getVersion.json").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for MispConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        let cache_key = format!("misp:hash:{}", hash);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };

        let attr_type = match hash.len() {
            32 => "md5",
            40 => "sha1",
            _ => "sha256",
        };

        let result = match self.search_attribute(&hash, attr_type).await {
            Ok(Some(attrs)) => self.build_result_from_attributes(&hash, indicator_type, &attrs),
            _ => self.unknown_result(indicator_type, &hash),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("misp:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let result = match self.search_attribute(&ip_str, "ip-dst").await {
            Ok(Some(attrs)) => self.build_result_from_attributes(&ip_str, indicator_type, &attrs),
            _ => self.unknown_result(indicator_type, &ip_str),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("misp:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let result = match self.search_attribute(&domain, "domain").await {
            Ok(Some(attrs)) => {
                self.build_result_from_attributes(&domain, IndicatorType::Domain, &attrs)
            }
            _ => self.unknown_result(IndicatorType::Domain, &domain),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        let cache_key = format!("misp:url:{}", url);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let result = match self.search_attribute(url, "url").await {
            Ok(Some(attrs)) => self.build_result_from_attributes(url, IndicatorType::Url, &attrs),
            _ => self.unknown_result(IndicatorType::Url, url),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "MISP does not support file submission via this connector".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "MISP does not support analysis status".to_string(),
        ))
    }
}

// Response types

#[derive(Debug, Deserialize)]
struct MispSearchResponse {
    response: MispAttributeResponse,
}

#[derive(Debug, Deserialize)]
struct MispAttributeResponse {
    #[serde(rename = "Attribute")]
    attribute: Option<Vec<MispAttribute>>,
}

#[derive(Debug, Deserialize)]
struct MispAttribute {
    #[serde(rename = "event_id")]
    event_id: Option<String>,
    category: Option<String>,
    #[serde(rename = "type")]
    #[allow(dead_code)]
    attr_type: Option<String>,
    #[allow(dead_code)]
    value: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> MispConfig {
        MispConfig {
            connector: ConnectorConfig {
                name: "misp-test".to_string(),
                base_url: "https://misp.example.com".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "Authorization".to_string(),
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
        let connector = MispConnector::new(config).unwrap();
        assert_eq!(connector.name(), "misp-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_build_result_empty_attributes() {
        let config = create_test_config();
        let connector = MispConnector::new(config).unwrap();
        let result = connector.build_result_from_attributes("test", IndicatorType::Domain, &[]);
        assert_eq!(result.verdict, ThreatVerdict::Unknown);
    }

    #[test]
    fn test_build_result_with_attributes() {
        let config = create_test_config();
        let connector = MispConnector::new(config).unwrap();
        let attrs = vec![
            MispAttribute {
                event_id: Some("1".to_string()),
                category: Some("Network activity".to_string()),
                attr_type: Some("domain".to_string()),
                value: Some("evil.com".to_string()),
            },
            MispAttribute {
                event_id: Some("2".to_string()),
                category: Some("Payload delivery".to_string()),
                attr_type: Some("domain".to_string()),
                value: Some("evil.com".to_string()),
            },
            MispAttribute {
                event_id: Some("3".to_string()),
                category: Some("Network activity".to_string()),
                attr_type: Some("domain".to_string()),
                value: Some("evil.com".to_string()),
            },
        ];
        let result =
            connector.build_result_from_attributes("evil.com", IndicatorType::Domain, &attrs);
        assert_eq!(result.verdict, ThreatVerdict::Malicious);
        assert!(result.malicious_score >= 40);
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_cache_ttl(), 3600);
        assert_eq!(default_rate_limit(), 100);
    }
}
