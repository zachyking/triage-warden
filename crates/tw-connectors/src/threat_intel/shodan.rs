//! Shodan threat intelligence connector.
//!
//! Integrates with the Shodan API for IP enrichment including open ports,
//! services, vulnerabilities, and historical data.

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

/// Shodan connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShodanConfig {
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
    7200
}
fn default_max_cache() -> u64 {
    10000
}
fn default_rate_limit() -> u32 {
    60
}

/// Shodan connector.
pub struct ShodanConnector {
    config: ShodanConfig,
    client: HttpClient,
    cache: ResponseCache<ThreatIntelResult>,
}

impl ShodanConnector {
    pub fn new(config: ShodanConfig) -> ConnectorResult<Self> {
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

        info!("Shodan connector initialized");

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
            source: "Shodan".to_string(),
            cache_ttl: self.config.cache_ttl_secs,
        }
    }

    fn calculate_risk_score(&self, vulns_count: usize, open_ports: usize) -> (ThreatVerdict, u8) {
        let vuln_score = std::cmp::min(vulns_count * 15, 60) as u8;
        let port_score = std::cmp::min(open_ports * 2, 40) as u8;
        let total = vuln_score.saturating_add(port_score);

        let verdict = if total >= 70 {
            ThreatVerdict::Malicious
        } else if total >= 30 {
            ThreatVerdict::Suspicious
        } else if open_ports > 0 {
            ThreatVerdict::Clean
        } else {
            ThreatVerdict::Unknown
        };

        (verdict, total)
    }
}

#[async_trait]
impl crate::traits::Connector for ShodanConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/api-info").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) => Ok(ConnectorHealth::Unhealthy(format!(
                "Status: {}",
                response.status()
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/api-info").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl ThreatIntelConnector for ShodanConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            _ => IndicatorType::Sha256,
        };
        Ok(self.unknown_result(indicator_type, hash))
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        let cache_key = format!("shodan:ip:{}", ip_str);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let path = format!("/shodan/host/{}", ip_str);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => match r.json::<ShodanHostResponse>().await {
                Ok(data) => {
                    let vulns = data.vulns.as_ref().map(|v| v.len()).unwrap_or(0);
                    let ports_count = data.ports.as_ref().map(|p| p.len()).unwrap_or(0);
                    let (verdict, score) = self.calculate_risk_score(vulns, ports_count);

                    let mut categories = Vec::new();
                    if let Some(tags) = &data.tags {
                        categories.extend(tags.clone());
                    }

                    ThreatIntelResult {
                        indicator_type,
                        indicator: ip_str.clone(),
                        verdict,
                        malicious_score: score,
                        malicious_count: vulns as u32,
                        total_engines: 1,
                        categories,
                        malware_families: vec![],
                        first_seen: None,
                        last_seen: None,
                        details: {
                            let mut d = HashMap::new();
                            if let Some(ports) = &data.ports {
                                d.insert("open_ports".to_string(), serde_json::json!(ports));
                            }
                            if let Some(vulns) = &data.vulns {
                                d.insert("vulnerabilities".to_string(), serde_json::json!(vulns));
                            }
                            if let Some(os) = &data.os {
                                d.insert("os".to_string(), serde_json::json!(os));
                            }
                            if let Some(org) = &data.org {
                                d.insert("org".to_string(), serde_json::json!(org));
                            }
                            if let Some(isp) = &data.isp {
                                d.insert("isp".to_string(), serde_json::json!(isp));
                            }
                            if let Some(country) = &data.country_code {
                                d.insert("country".to_string(), serde_json::json!(country));
                            }
                            d
                        },
                        source: "Shodan".to_string(),
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
        let cache_key = format!("shodan:domain:{}", domain);
        if let Some(cached) = self.cache.get(&cache_key).await {
            return Ok(cached);
        }

        let path = format!("/dns/resolve?hostnames={}", domain);
        let response = self.client.get(&path).await;

        let result = match response {
            Ok(r) if r.status().is_success() => {
                match r.json::<HashMap<String, Option<String>>>().await {
                    Ok(data) => {
                        if let Some(Some(ip_str)) = data.get(&domain) {
                            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                                // Recursively look up the resolved IP
                                return self.lookup_ip(&ip).await;
                            }
                        }
                        self.unknown_result(IndicatorType::Domain, &domain)
                    }
                    Err(_) => self.unknown_result(IndicatorType::Domain, &domain),
                }
            }
            _ => self.unknown_result(IndicatorType::Domain, &domain),
        };

        self.cache.insert(cache_key, result.clone()).await;
        Ok(result)
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        Ok(self.unknown_result(IndicatorType::Url, url))
    }

    async fn submit_file(&self, _file_path: &str) -> ConnectorResult<String> {
        Err(ConnectorError::Internal(
            "Shodan does not support file submission".to_string(),
        ))
    }

    async fn get_analysis_status(&self, _analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        Err(ConnectorError::Internal(
            "Shodan does not support analysis status".to_string(),
        ))
    }
}

// Response types

#[derive(Debug, Deserialize)]
struct ShodanHostResponse {
    ports: Option<Vec<u16>>,
    vulns: Option<Vec<String>>,
    os: Option<String>,
    org: Option<String>,
    isp: Option<String>,
    country_code: Option<String>,
    tags: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secure_string::SecureString;
    use crate::traits::{AuthConfig, Connector};

    fn create_test_config() -> ShodanConfig {
        ShodanConfig {
            connector: ConnectorConfig {
                name: "shodan-test".to_string(),
                base_url: "https://api.shodan.io".to_string(),
                auth: AuthConfig::ApiKey {
                    key: SecureString::new("test-key".to_string()),
                    header_name: "key".to_string(),
                },
                timeout_secs: 30,
                max_retries: 2,
                verify_tls: true,
                headers: HashMap::new(),
            },
            cache_ttl_secs: 7200,
            max_cache_entries: 1000,
            requests_per_minute: 60,
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = ShodanConnector::new(config).unwrap();
        assert_eq!(connector.name(), "shodan-test");
        assert_eq!(connector.connector_type(), "threat_intel");
    }

    #[test]
    fn test_calculate_risk_score() {
        let config = create_test_config();
        let connector = ShodanConnector::new(config).unwrap();

        let (verdict, _) = connector.calculate_risk_score(0, 0);
        assert_eq!(verdict, ThreatVerdict::Unknown);

        let (verdict, _) = connector.calculate_risk_score(0, 5);
        assert_eq!(verdict, ThreatVerdict::Clean);

        let (verdict, score) = connector.calculate_risk_score(3, 10);
        assert_eq!(verdict, ThreatVerdict::Suspicious);
        assert!(score >= 30);

        let (verdict, score) = connector.calculate_risk_score(5, 20);
        assert_eq!(verdict, ThreatVerdict::Malicious);
        assert!(score >= 70);
    }

    #[test]
    fn test_defaults() {
        assert_eq!(default_cache_ttl(), 7200);
        assert_eq!(default_rate_limit(), 60);
    }
}
