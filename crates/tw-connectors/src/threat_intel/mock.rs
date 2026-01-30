//! Mock threat intelligence connector for testing.
//!
//! This module provides a configurable mock connector for testing threat intel
//! lookups without making real API calls. Supports preconfigured results,
//! failure injection, and latency simulation.

use crate::traits::{
    AnalysisStatus, ConnectorError, ConnectorHealth, ConnectorResult, IndicatorType,
    ThreatIntelConnector, ThreatIntelResult, ThreatVerdict,
};
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Behavior configuration for failure injection.
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Return results normally.
    Normal,
    /// Fail with a specific error after N calls.
    FailAfter { calls: u64, error: ConnectorError },
    /// Return error for specific indicators.
    FailOn {
        indicators: Vec<String>,
        error: ConnectorError,
    },
    /// Simulate latency.
    WithLatency(Duration),
    /// Always fail.
    AlwaysFail(ConnectorError),
    /// Simulate being unhealthy.
    Unhealthy(String),
}

impl Default for MockBehavior {
    fn default() -> Self {
        Self::Normal
    }
}

/// Mock threat intelligence connector for testing.
pub struct MockThreatIntelConnector {
    name: String,
    /// Preconfigured results for specific indicators.
    results: Arc<RwLock<HashMap<String, ThreatIntelResult>>>,
    /// Default verdict for unknown indicators.
    default_verdict: ThreatVerdict,
    /// Call counter for failure injection.
    call_count: AtomicU64,
    /// Current behavior.
    behavior: Arc<RwLock<MockBehavior>>,
    /// Track all lookups for verification.
    lookup_history: Arc<RwLock<Vec<LookupRecord>>>,
}

/// Record of a lookup for test verification.
#[derive(Debug, Clone)]
pub struct LookupRecord {
    pub indicator_type: String,
    pub indicator: String,
    pub timestamp: chrono::DateTime<Utc>,
}

impl MockThreatIntelConnector {
    /// Creates a new mock threat intel connector.
    pub fn new(name: &str) -> Self {
        let mut results = HashMap::new();

        // Add some default malicious indicators for testing
        results.insert(
            "44d88612fea8a8f36de82e1278abb02f".to_string(), // EICAR test file MD5
            ThreatIntelResult {
                indicator_type: IndicatorType::Md5,
                indicator: "44d88612fea8a8f36de82e1278abb02f".to_string(),
                verdict: ThreatVerdict::Malicious,
                malicious_score: 95,
                malicious_count: 65,
                total_engines: 70,
                categories: vec!["test-file".to_string()],
                malware_families: vec!["EICAR-Test-File".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: HashMap::new(),
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        // EICAR SHA-256
        results.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            ThreatIntelResult {
                indicator_type: IndicatorType::Sha256,
                indicator: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
                    .to_string(),
                verdict: ThreatVerdict::Malicious,
                malicious_score: 95,
                malicious_count: 68,
                total_engines: 72,
                categories: vec!["test-file".to_string()],
                malware_families: vec!["EICAR-Test-File".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: HashMap::new(),
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        results.insert(
            "192.0.2.1".to_string(), // TEST-NET-1 (documentation)
            ThreatIntelResult {
                indicator_type: IndicatorType::Ipv4,
                indicator: "192.0.2.1".to_string(),
                verdict: ThreatVerdict::Suspicious,
                malicious_score: 30,
                malicious_count: 5,
                total_engines: 50,
                categories: vec!["suspicious".to_string()],
                malware_families: vec![],
                first_seen: None,
                last_seen: Some(Utc::now()),
                details: {
                    let mut d = HashMap::new();
                    d.insert("country".to_string(), serde_json::json!("XX"));
                    d.insert("asn".to_string(), serde_json::json!(12345));
                    d
                },
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        // Known malicious IP (commonly used in tests)
        results.insert(
            "203.0.113.100".to_string(),
            ThreatIntelResult {
                indicator_type: IndicatorType::Ipv4,
                indicator: "203.0.113.100".to_string(),
                verdict: ThreatVerdict::Malicious,
                malicious_score: 90,
                malicious_count: 45,
                total_engines: 50,
                categories: vec!["botnet".to_string(), "c2".to_string()],
                malware_families: vec!["Mirai".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: {
                    let mut d = HashMap::new();
                    d.insert("country".to_string(), serde_json::json!("RU"));
                    d.insert("asn".to_string(), serde_json::json!(54321));
                    d
                },
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        results.insert(
            "evil.example.com".to_string(),
            ThreatIntelResult {
                indicator_type: IndicatorType::Domain,
                indicator: "evil.example.com".to_string(),
                verdict: ThreatVerdict::Malicious,
                malicious_score: 85,
                malicious_count: 42,
                total_engines: 50,
                categories: vec!["malware".to_string(), "phishing".to_string()],
                malware_families: vec!["Emotet".to_string()],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: HashMap::new(),
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        results.insert(
            "phishing-site.example.org".to_string(),
            ThreatIntelResult {
                indicator_type: IndicatorType::Domain,
                indicator: "phishing-site.example.org".to_string(),
                verdict: ThreatVerdict::Malicious,
                malicious_score: 92,
                malicious_count: 55,
                total_engines: 60,
                categories: vec!["phishing".to_string(), "credential-theft".to_string()],
                malware_families: vec![],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: HashMap::new(),
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        // Clean domain
        results.insert(
            "google.com".to_string(),
            ThreatIntelResult {
                indicator_type: IndicatorType::Domain,
                indicator: "google.com".to_string(),
                verdict: ThreatVerdict::Clean,
                malicious_score: 0,
                malicious_count: 0,
                total_engines: 70,
                categories: vec!["search-engine".to_string()],
                malware_families: vec![],
                first_seen: Some(Utc::now()),
                last_seen: Some(Utc::now()),
                details: HashMap::new(),
                source: "Mock".to_string(),
                cache_ttl: 3600,
            },
        );

        Self {
            name: name.to_string(),
            results: Arc::new(RwLock::new(results)),
            default_verdict: ThreatVerdict::Unknown,
            call_count: AtomicU64::new(0),
            behavior: Arc::new(RwLock::new(MockBehavior::Normal)),
            lookup_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Creates a mock connector with a specific default verdict.
    pub fn with_default_verdict(name: &str, verdict: ThreatVerdict) -> Self {
        let mut connector = Self::new(name);
        connector.default_verdict = verdict;
        connector
    }

    /// Adds a preconfigured result for an indicator.
    pub async fn add_result(&self, indicator: &str, result: ThreatIntelResult) {
        let mut results = self.results.write().await;
        results.insert(indicator.to_lowercase(), result);
    }

    /// Sets the behavior for failure injection.
    pub async fn set_behavior(&self, behavior: MockBehavior) {
        let mut b = self.behavior.write().await;
        *b = behavior;
    }

    /// Gets the lookup history for test verification.
    pub async fn get_lookup_history(&self) -> Vec<LookupRecord> {
        let history = self.lookup_history.read().await;
        history.clone()
    }

    /// Clears the lookup history.
    pub async fn clear_history(&self) {
        let mut history = self.lookup_history.write().await;
        history.clear();
    }

    /// Resets the call counter.
    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }

    /// Gets the current call count.
    pub fn get_call_count(&self) -> u64 {
        self.call_count.load(Ordering::SeqCst)
    }

    /// Records a lookup and applies behavior.
    async fn record_and_check(&self, indicator_type: &str, indicator: &str) -> ConnectorResult<()> {
        // Record the lookup
        {
            let mut history = self.lookup_history.write().await;
            history.push(LookupRecord {
                indicator_type: indicator_type.to_string(),
                indicator: indicator.to_string(),
                timestamp: Utc::now(),
            });
        }

        // Increment call count
        let count = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;

        // Check behavior
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::Normal => Ok(()),
            MockBehavior::FailAfter { calls, error } => {
                if count > *calls {
                    Err(error.clone())
                } else {
                    Ok(())
                }
            }
            MockBehavior::FailOn { indicators, error } => {
                if indicators.contains(&indicator.to_string()) {
                    Err(error.clone())
                } else {
                    Ok(())
                }
            }
            MockBehavior::WithLatency(duration) => {
                tokio::time::sleep(*duration).await;
                Ok(())
            }
            MockBehavior::AlwaysFail(error) => Err(error.clone()),
            MockBehavior::Unhealthy(_) => Ok(()), // Only affects health check
        }
    }

    /// Creates an unknown result for an indicator.
    fn unknown_result(&self, indicator_type: IndicatorType, indicator: &str) -> ThreatIntelResult {
        ThreatIntelResult {
            indicator_type,
            indicator: indicator.to_string(),
            verdict: self.default_verdict.clone(),
            malicious_score: 0,
            malicious_count: 0,
            total_engines: 0,
            categories: vec![],
            malware_families: vec![],
            first_seen: None,
            last_seen: None,
            details: HashMap::new(),
            source: "Mock".to_string(),
            cache_ttl: 3600,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for MockThreatIntelConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "threat_intel"
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::Unhealthy(reason) => Ok(ConnectorHealth::Unhealthy(reason.clone())),
            MockBehavior::AlwaysFail(_) => {
                Ok(ConnectorHealth::Unhealthy("Always failing".to_string()))
            }
            _ => Ok(ConnectorHealth::Healthy),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let behavior = self.behavior.read().await;
        match &*behavior {
            MockBehavior::AlwaysFail(e) => Err(e.clone()),
            MockBehavior::Unhealthy(_) => Ok(false),
            _ => Ok(true),
        }
    }
}

#[async_trait]
impl ThreatIntelConnector for MockThreatIntelConnector {
    async fn lookup_hash(&self, hash: &str) -> ConnectorResult<ThreatIntelResult> {
        let hash = hash.to_lowercase();
        self.record_and_check("hash", &hash).await?;

        let indicator_type = match hash.len() {
            32 => IndicatorType::Md5,
            40 => IndicatorType::Sha1,
            64 => IndicatorType::Sha256,
            _ => IndicatorType::Sha256,
        };

        let results = self.results.read().await;
        Ok(results
            .get(&hash)
            .cloned()
            .unwrap_or_else(|| self.unknown_result(indicator_type, &hash)))
    }

    async fn lookup_ip(&self, ip: &IpAddr) -> ConnectorResult<ThreatIntelResult> {
        let ip_str = ip.to_string();
        self.record_and_check("ip", &ip_str).await?;

        let indicator_type = if ip.is_ipv6() {
            IndicatorType::Ipv6
        } else {
            IndicatorType::Ipv4
        };

        let results = self.results.read().await;
        Ok(results
            .get(&ip_str)
            .cloned()
            .unwrap_or_else(|| self.unknown_result(indicator_type, &ip_str)))
    }

    async fn lookup_domain(&self, domain: &str) -> ConnectorResult<ThreatIntelResult> {
        let domain = domain.to_lowercase();
        self.record_and_check("domain", &domain).await?;

        let results = self.results.read().await;
        Ok(results
            .get(&domain)
            .cloned()
            .unwrap_or_else(|| self.unknown_result(IndicatorType::Domain, &domain)))
    }

    async fn lookup_url(&self, url: &str) -> ConnectorResult<ThreatIntelResult> {
        let url = url.to_lowercase();
        self.record_and_check("url", &url).await?;

        let results = self.results.read().await;
        Ok(results
            .get(&url)
            .cloned()
            .unwrap_or_else(|| self.unknown_result(IndicatorType::Url, &url)))
    }

    async fn submit_file(&self, file_path: &str) -> ConnectorResult<String> {
        self.record_and_check("file_submit", file_path).await?;
        Ok(format!("mock-analysis-{}", uuid::Uuid::new_v4()))
    }

    async fn get_analysis_status(&self, analysis_id: &str) -> ConnectorResult<AnalysisStatus> {
        self.record_and_check("analysis_status", analysis_id)
            .await?;
        Ok(AnalysisStatus {
            id: analysis_id.to_string(),
            status: "completed".to_string(),
            progress: 100,
            result: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lookup_known_hash() {
        let connector = MockThreatIntelConnector::new("test");
        let result = connector
            .lookup_hash("44d88612fea8a8f36de82e1278abb02f")
            .await
            .unwrap();

        assert_eq!(result.verdict, ThreatVerdict::Malicious);
        assert_eq!(result.malicious_score, 95);
    }

    #[tokio::test]
    async fn test_lookup_unknown_hash() {
        let connector = MockThreatIntelConnector::new("test");
        let result = connector
            .lookup_hash("0000000000000000000000000000000000000000000000000000000000000000")
            .await
            .unwrap();

        assert_eq!(result.verdict, ThreatVerdict::Unknown);
        assert_eq!(result.indicator_type, IndicatorType::Sha256);
    }

    #[tokio::test]
    async fn test_lookup_known_domain() {
        let connector = MockThreatIntelConnector::new("test");
        let result = connector.lookup_domain("evil.example.com").await.unwrap();

        assert_eq!(result.verdict, ThreatVerdict::Malicious);
        assert!(result.categories.contains(&"phishing".to_string()));
    }

    #[tokio::test]
    async fn test_custom_result() {
        let connector = MockThreatIntelConnector::new("test");

        connector
            .add_result(
                "custom-indicator",
                ThreatIntelResult {
                    indicator_type: IndicatorType::Domain,
                    indicator: "custom-indicator".to_string(),
                    verdict: ThreatVerdict::Clean,
                    malicious_score: 0,
                    malicious_count: 0,
                    total_engines: 50,
                    categories: vec!["business".to_string()],
                    malware_families: vec![],
                    first_seen: None,
                    last_seen: None,
                    details: HashMap::new(),
                    source: "Mock".to_string(),
                    cache_ttl: 3600,
                },
            )
            .await;

        let result = connector.lookup_domain("custom-indicator").await.unwrap();
        assert_eq!(result.verdict, ThreatVerdict::Clean);
    }

    #[tokio::test]
    async fn test_fail_after_behavior() {
        let connector = MockThreatIntelConnector::new("test");
        connector
            .set_behavior(MockBehavior::FailAfter {
                calls: 2,
                error: ConnectorError::RateLimited(60),
            })
            .await;

        // First two calls succeed
        assert!(connector.lookup_domain("test1.com").await.is_ok());
        assert!(connector.lookup_domain("test2.com").await.is_ok());

        // Third call fails
        let result = connector.lookup_domain("test3.com").await;
        assert!(matches!(result, Err(ConnectorError::RateLimited(_))));
    }

    #[tokio::test]
    async fn test_lookup_history() {
        let connector = MockThreatIntelConnector::new("test");

        connector.lookup_hash("abc123").await.ok();
        connector.lookup_domain("example.com").await.ok();
        connector
            .lookup_ip(&"192.168.1.1".parse().unwrap())
            .await
            .ok();

        let history = connector.get_lookup_history().await;
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].indicator_type, "hash");
        assert_eq!(history[1].indicator_type, "domain");
        assert_eq!(history[2].indicator_type, "ip");
    }

    #[tokio::test]
    async fn test_default_verdict() {
        let connector =
            MockThreatIntelConnector::with_default_verdict("test", ThreatVerdict::Suspicious);

        let result = connector.lookup_domain("unknown-domain.com").await.unwrap();
        assert_eq!(result.verdict, ThreatVerdict::Suspicious);
    }
}
