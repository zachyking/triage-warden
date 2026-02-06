//! IBM X-Force Exchange threat intelligence connector.
//!
//! Integrates with IBM X-Force Exchange API for IP, domain, hash, and URL
//! lookups with malware family information.

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

/// IBM X-Force Exchange connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XForceConfig {
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
    30
}

/// IBM X-Force Exchange connector.
pub struct XForceConnector {
    config: XForceConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl XForceConnector {
    pub fn new(config: XForceConfig) -> ConnectorResult<Self> {
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
            "IBM X-Force connector initialized (rate limit: {} req/min)",
            config.requests_per_minute
        );

        Ok(Self {
            config,
            client,
            cache,
        })
    }

    fn calculate_verdict(&self, score: f64) -> ThreatVerdict {
        if score >= 7.0 {
            ThreatVerdict::Malicious
        } else if score >= 3.0 {
            ThreatVerdict::Suspicious
        } else if score > 0.0 {
            ThreatVerdict::Clean
        } else {
            ThreatVerdict::Unknown
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
            source: "IBM X-Force".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for XForceConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api/").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api/").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for XForceConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        let cache_key = format!("xforce:hash:{}", hash);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };

        let path = format!("/api/malware/{}", hash);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<XForceMalwareResponse>().await {
                Ok(data) => {
                    let risk_score = data.malware.risk.unwrap_or(0.0);
                    let verdict = self.calculate_verdict(risk_score);
                    ThreatIntelResult {
                        indicator_type,
                        indicator: hash.clone(),
                        verdict,
                        malicious_score: (risk_score * 10.0).min(100.0) as u8,
                        malicious_count: if risk_score >= 7.0 { 1 } else { 0 },
                        total_engines: 1,
                        categories: data
                            .malware
                            .family
                            .as_ref()
                            .map(|f| vec![f.clone()])
                            .unwrap_or_default(),
                        malware_families: data.malware.family.into_iter().collect(),
                        first_seen: None,
                        last_seen: None,
                        details: {
                            let mut d = HashMap::new();
                            d.insert("risk_score".to_string(), serde_json::json!(risk_score));
                            if let Some(mime) = data.malware.mime_type {
                                d.insert("mime_type".to_string(), serde_json::json!(mime));
                            }
                            d
                        },
                        source: "IBM X-Force".to_string(),
                        cache_ttl: self.config.cache_ttl_secs,
                    }
                }
                Err(_) => self.unknown_result(indicator_type, &hash),
            },
            _ => self.unknown_result(indicator_type, &hash),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("xforce:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let path = format!("/api/ipr/{}", ip_str);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<XForceIPResponse>().await {
                Ok(data) => {
                    let score = data.score.unwrap_or(0.0);
                    let verdict = self.calculate_verdict(score);
                    ThreatIntelResult {
                        indicator_type,
                        indicator: ip_str.clone(),
                        verdict,
                        malicious_score: (score * 10.0).min(100.0) as u8,
                        malicious_count: data.cats.as_ref().map(|c| c.len() as u32).unwrap_or(0),
                        total_engines: 1,
                        categories: data
                            .cats
                            .map(|c| c.into_keys().collect())
                            .unwrap_or_default(),
                        malware_families: vec![],
                        first_seen: None,
                        last_seen: None,
                        details: {
                            let mut d = HashMap::new();
                            d.insert("risk_score".to_string(), serde_json::json!(score));
                            if let Some(geo) = data.geo {
                                d.insert("country".to_string(), serde_json::json!(geo.country));
                            }
                            d
                        },
                        source: "IBM X-Force".to_string(),
                        cache_ttl: self.config.cache_ttl_secs,
                    }
                }
                Err(_) => self.unknown_result(indicator_type, &ip_str),
            },
            _ => self.unknown_result(indicator_type, &ip_str),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        let cache_key = format!("xforce:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let path = format!("/api/url/{}", domain);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<XForceUrlResponse>().await {
                Ok(data) => {
                    let score = data.result.score.unwrap_or(0.0);
                    let verdict = self.calculate_verdict(score);
                    ThreatIntelResult {
                        indicator_type: IndicatorType::Domain,
                        indicator: domain.clone(),
                        verdict,
                        malicious_score: (score * 10.0).min(100.0) as u8,
                        malicious_count: if score >= 7.0 { 1 } else { 0 },
                        total_engines: 1,
                        categories: data
                            .result
                            .cats
                            .map(|c| c.into_keys().collect())
                            .unwrap_or_default(),
                        malware_families: vec![],
                        first_seen: None,
                        last_seen: None,
                        details: {
                            let mut d = HashMap::new();
                            d.insert("risk_score".to_string(), serde_json::json!(score));
                            d
                        },
                        source: "IBM X-Force".to_string(),
                        cache_ttl: self.config.cache_ttl_secs,
                    }
                }
                Err(_) => self.unknown_result(IndicatorType::Domain, &domain),
            },
            _ => self.unknown_result(IndicatorType::Domain, &domain),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        let cache_key = format!("xforce:url:{}", url);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let path = format!("/api/url/{}", urlencoding::encode(url));
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<XForceUrlResponse>().await {
                Ok(data) => {
                    let score = data.result.score.unwrap_or(0.0);
                    let verdict = self.calculate_verdict(score);
                    ThreatIntelResult {
                        indicator_type: IndicatorType::Url,
                        indicator: url.to_string(),
                        verdict,
                        malicious_score: (score * 10.0).min(100.0) as u8,
                        malicious_count: if score >= 7.0 { 1 } else { 0 },
                        total_engines: 1,
                        categories: data
                            .result
                            .cats
                            .map(|c| c.into_keys().collect())
                            .unwrap_or_default(),
                        malware_families: vec![],
                        first_seen: None,
                        last_seen: None,
                        details: HashMap::new(),
                        source: "IBM X-Force".to_string(),
                        cache_ttl: self.config.cache_ttl_secs,
                    }
                }
                Err(_) => self.unknown_result(IndicatorType::Url, url),
            },
            _ => self.unknown_result(IndicatorType::Url, url),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "X-Force Exchange does not support file submission".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "X-Force Exchange does not support analysis status".to_string(),
        ))
    }
}

// X-Force API response types

#[derive(Debug, Deserialize)]
struct XForceMalwareResponse {
    malware: XForceMalware,
}

#[derive(Debug, Deserialize)]
struct XForceMalware {
    risk: Option<f64>,
    family: Option<String>,
    mime_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XForceIPResponse {
    score: Option<f64>,
    cats: Option<HashMap<String, u32>>,
    geo: Option<XForceGeo>,
}

#[derive(Debug, Deserialize)]
struct XForceGeo {
    country: Option<String>,
}

#[derive(Debug, Deserialize)]
struct XForceUrlResponse {
    result: XForceUrlResult,
}

#[derive(Debug, Deserialize)]
struct XForceUrlResult {
    score: Option<f64>,
    cats: Option<HashMap<String, bool>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> XForceConfig {
        XForceConfig {
            connector: ConnectorConfig {
                name: "xforce-test".to_string(),
                base_url: "https://api.xforce.ibmcloud.com".to_string(),
                auth: AuthConfig::Basic {
                    username: "test-key".to_string(),
                    password: SecureString::new("test-password".to_string()),
                },
                timeout_secs: 30,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            cache_ttl_secs: 3600,
            max_cache_entries: 1000,
            requests_per_minute: 30,
        }
    }

    #[test]
    fn test_config_creation() {
        let config = create_test_config();
        assert_eq!(config.connector.name, "xforce-test");
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = XForceConnector::new(config).unwrap();
        assert_eq!(connector.name(), "xforce-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_calculate_verdict() {
        let config = create_test_config();
        let connector = XForceConnector::new(config).unwrap();
        assert_eq!(connector.calculate_verdict(0.0), ThreatVerdict::Unknown);
        assert_eq!(connector.calculate_verdict(2.0), ThreatVerdict::Clean);
        assert_eq!(connector.calculate_verdict(5.0), ThreatVerdict::Suspicious);
        assert_eq!(connector.calculate_verdict(8.0), ThreatVerdict::Malicious);
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_cache_ttl(), 3600);
        assert_eq!(default_rate_limit(), 30);
    }
}
