//! Mock attack surface monitor for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

use crate::traits::{ConnectorHealth, ConnectorResult};
use crate::Connector;

use super::{AttackSurfaceMonitor, ExposureType, ExternalExposure};

/// Mock ASM provider with configurable responses.
pub struct MockAsmProvider {
    name: String,
    exposures: Arc<Mutex<HashMap<String, Vec<ExternalExposure>>>>,
    risk_scores: Arc<Mutex<HashMap<String, f32>>>,
    healthy: Arc<Mutex<bool>>,
}

impl MockAsmProvider {
    /// Creates a new mock ASM provider.
    pub fn new() -> Self {
        Self {
            name: "mock-asm".to_string(),
            exposures: Arc::new(Mutex::new(HashMap::new())),
            risk_scores: Arc::new(Mutex::new(HashMap::new())),
            healthy: Arc::new(Mutex::new(true)),
        }
    }

    /// Creates a mock ASM provider with a custom name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::new()
        }
    }

    /// Adds exposures for a domain.
    pub fn add_exposures(&self, domain: &str, exposures: Vec<ExternalExposure>) {
        self.exposures
            .lock()
            .unwrap()
            .insert(domain.to_string(), exposures);
    }

    /// Sets a risk score for a domain.
    pub fn set_risk_score(&self, domain: &str, score: f32) {
        self.risk_scores
            .lock()
            .unwrap()
            .insert(domain.to_string(), score);
    }

    /// Sets whether the mock reports as healthy.
    pub fn set_healthy(&self, healthy: bool) {
        *self.healthy.lock().unwrap() = healthy;
    }

    /// Creates a sample open port exposure for testing.
    pub fn sample_open_port(asset: &str, port: u16, service: &str) -> ExternalExposure {
        let now = Utc::now();
        ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: asset.to_string(),
            exposure_type: ExposureType::OpenPort {
                port,
                service: service.to_string(),
            },
            risk_score: if port == 22 { 40.0 } else { 20.0 },
            details: serde_json::json!({"scanner": "mock"}),
            first_seen: now,
            last_seen: now,
        }
    }

    /// Creates a sample expired certificate exposure for testing.
    pub fn sample_expired_cert(domain: &str) -> ExternalExposure {
        let now = Utc::now();
        ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: domain.to_string(),
            exposure_type: ExposureType::ExpiredCertificate {
                domain: domain.to_string(),
                expiry: now - chrono::Duration::days(30),
            },
            risk_score: 75.0,
            details: serde_json::json!({"days_expired": 30}),
            first_seen: now,
            last_seen: now,
        }
    }
}

impl Default for MockAsmProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Connector for MockAsmProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "asm"
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check".to_string(),
            "test_connection".to_string(),
            "get_exposures".to_string(),
            "get_risk_score".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        if *self.healthy.lock().unwrap() {
            Ok(ConnectorHealth::Healthy)
        } else {
            Ok(ConnectorHealth::Unhealthy("Mock unhealthy".to_string()))
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(*self.healthy.lock().unwrap())
    }
}

#[async_trait]
impl AttackSurfaceMonitor for MockAsmProvider {
    async fn get_exposures(&self, domain: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let exposures = self.exposures.lock().unwrap();
        Ok(exposures.get(domain).cloned().unwrap_or_default())
    }

    async fn get_asset_exposure(&self, asset_id: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let exposures = self.exposures.lock().unwrap();
        let mut result = Vec::new();
        for exps in exposures.values() {
            for exp in exps {
                if exp.asset_identifier == asset_id {
                    result.push(exp.clone());
                }
            }
        }
        Ok(result)
    }

    async fn get_risk_score(&self, domain: &str) -> ConnectorResult<Option<f32>> {
        let scores = self.risk_scores.lock().unwrap();
        Ok(scores.get(domain).copied())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_health_check() {
        let provider = MockAsmProvider::new();
        let health = provider.health_check().await.unwrap();
        assert_eq!(health, ConnectorHealth::Healthy);

        provider.set_healthy(false);
        let health = provider.health_check().await.unwrap();
        assert!(matches!(health, ConnectorHealth::Unhealthy(_)));
    }

    #[tokio::test]
    async fn test_mock_get_exposures() {
        let provider = MockAsmProvider::new();
        let exposure = MockAsmProvider::sample_open_port("192.168.1.1", 443, "https");
        provider.add_exposures("example.com", vec![exposure]);

        let results = provider.get_exposures("example.com").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = provider.get_exposures("other.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_mock_get_asset_exposure() {
        let provider = MockAsmProvider::new();
        let exposure = MockAsmProvider::sample_open_port("192.168.1.1", 22, "ssh");
        provider.add_exposures("example.com", vec![exposure]);

        let results = provider.get_asset_exposure("192.168.1.1").await.unwrap();
        assert_eq!(results.len(), 1);

        let results = provider.get_asset_exposure("10.0.0.1").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_mock_get_risk_score() {
        let provider = MockAsmProvider::new();
        provider.set_risk_score("example.com", 72.5);

        let score = provider.get_risk_score("example.com").await.unwrap();
        assert_eq!(score, Some(72.5));

        let score = provider.get_risk_score("other.com").await.unwrap();
        assert!(score.is_none());
    }

    #[test]
    fn test_mock_default() {
        let provider = MockAsmProvider::default();
        assert_eq!(provider.name(), "mock-asm");
    }

    #[test]
    fn test_mock_with_name() {
        let provider = MockAsmProvider::with_name("custom-asm");
        assert_eq!(provider.name(), "custom-asm");
    }

    #[test]
    fn test_sample_open_port() {
        let exposure = MockAsmProvider::sample_open_port("10.0.0.1", 22, "ssh");
        assert_eq!(exposure.asset_identifier, "10.0.0.1");
        assert_eq!(exposure.risk_score, 40.0); // SSH gets higher risk
        assert!(matches!(
            exposure.exposure_type,
            ExposureType::OpenPort { port: 22, .. }
        ));
    }

    #[test]
    fn test_sample_expired_cert() {
        let exposure = MockAsmProvider::sample_expired_cert("example.com");
        assert_eq!(exposure.asset_identifier, "example.com");
        assert_eq!(exposure.risk_score, 75.0);
        assert!(matches!(
            exposure.exposure_type,
            ExposureType::ExpiredCertificate { .. }
        ));
    }

    #[tokio::test]
    async fn test_mock_multiple_exposures() {
        let provider = MockAsmProvider::new();
        let exposures = vec![
            MockAsmProvider::sample_open_port("192.168.1.1", 22, "ssh"),
            MockAsmProvider::sample_open_port("192.168.1.1", 443, "https"),
            MockAsmProvider::sample_expired_cert("example.com"),
        ];
        provider.add_exposures("example.com", exposures);

        let results = provider.get_exposures("example.com").await.unwrap();
        assert_eq!(results.len(), 3);
    }
}
