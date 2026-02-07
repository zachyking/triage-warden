//! Censys attack surface management connector.

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::http::HttpClient;
use crate::traits::{
    AuthConfig, ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult,
};
use crate::Connector;

use super::{AttackSurfaceMonitor, ExposureType, ExternalExposure};

/// Configuration for the Censys connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CensysConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
    /// Censys API ID.
    pub api_id: Option<String>,
    /// Censys API secret.
    pub api_secret: Option<String>,
}

/// Censys attack surface management connector.
pub struct CensysConnector {
    config: CensysConfig,
    client: HttpClient,
}

impl CensysConnector {
    /// Creates a new Censys connector.
    pub fn new(mut config: CensysConfig) -> ConnectorResult<Self> {
        if matches!(config.connector.auth, AuthConfig::None) {
            if let (Some(api_id), Some(api_secret)) =
                (config.api_id.clone(), config.api_secret.clone())
            {
                config.connector.auth = AuthConfig::Basic {
                    username: api_id,
                    password: crate::SecureString::new(api_secret),
                };
            }
        }

        let client = HttpClient::new(config.connector.clone())?;
        info!("Censys ASM connector initialized");
        Ok(Self { config, client })
    }

    async fn get_json(&self, path: &str) -> ConnectorResult<Value> {
        let response = self.client.get(path).await?;
        response.json::<Value>().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse Censys JSON response: {}", e))
        })
    }

    async fn post_json(&self, path: &str, body: &Value) -> ConnectorResult<Value> {
        let response = self.client.post(path, body).await?;
        response.json::<Value>().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse Censys JSON response: {}", e))
        })
    }

    fn find_value<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
        let mut cursor = root;
        for part in path.split('.') {
            cursor = cursor.get(part)?;
        }
        Some(cursor)
    }

    fn as_string(root: &Value, paths: &[&str]) -> Option<String> {
        for path in paths {
            if let Some(value) = Self::find_value(root, path) {
                if let Some(s) = value.as_str() {
                    if !s.is_empty() {
                        return Some(s.to_string());
                    }
                }
                if let Some(i) = value.as_i64() {
                    return Some(i.to_string());
                }
                if let Some(u) = value.as_u64() {
                    return Some(u.to_string());
                }
            }
        }
        None
    }

    fn as_u16(root: &Value, paths: &[&str]) -> Option<u16> {
        for path in paths {
            if let Some(value) = Self::find_value(root, path) {
                if let Some(v) = value.as_u64() {
                    return u16::try_from(v).ok();
                }
                if let Some(v) = value.as_i64() {
                    if v >= 0 {
                        return u16::try_from(v as u64).ok();
                    }
                }
                if let Some(v) = value.as_str().and_then(|v| v.parse::<u16>().ok()) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn as_f32(root: &Value, paths: &[&str]) -> Option<f32> {
        for path in paths {
            if let Some(value) = Self::find_value(root, path) {
                if let Some(v) = value.as_f64() {
                    return Some(v as f32);
                }
                if let Some(v) = value.as_i64() {
                    return Some(v as f32);
                }
                if let Some(v) = value.as_u64() {
                    return Some(v as f32);
                }
                if let Some(v) = value.as_str().and_then(|v| v.parse::<f32>().ok()) {
                    return Some(v);
                }
            }
        }
        None
    }

    fn as_datetime(root: &Value, paths: &[&str]) -> Option<DateTime<Utc>> {
        for path in paths {
            if let Some(value) = Self::find_value(root, path) {
                if let Some(s) = value.as_str() {
                    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
                        return Some(dt.with_timezone(&Utc));
                    }
                    if let Ok(ts) = s.parse::<i64>() {
                        if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
                            return Some(dt);
                        }
                    }
                }
                if let Some(ts) = value.as_i64() {
                    if ts > 2_000_000_000 {
                        if let Some(dt) = Utc.timestamp_millis_opt(ts).single() {
                            return Some(dt);
                        }
                    }
                    if let Some(dt) = Utc.timestamp_opt(ts, 0).single() {
                        return Some(dt);
                    }
                }
            }
        }
        None
    }

    fn host_hits(payload: &Value) -> Vec<&Value> {
        let paths = ["result.hits", "hits", "results", "data"];
        for path in paths {
            if let Some(hits) = Self::find_value(payload, path).and_then(|v| v.as_array()) {
                return hits.iter().collect();
            }
        }
        if let Some(arr) = payload.as_array() {
            return arr.iter().collect();
        }
        Vec::new()
    }

    fn service_rows(host: &Value) -> Vec<&Value> {
        let paths = ["services", "result.services", "data.services"];
        for path in paths {
            if let Some(services) = Self::find_value(host, path).and_then(|v| v.as_array()) {
                return services.iter().collect();
            }
        }
        Vec::new()
    }

    fn open_port_risk(port: u16) -> f32 {
        match port {
            22 => 60.0,
            23 => 85.0,
            3389 => 80.0,
            445 => 90.0,
            5432 | 3306 | 27017 => 75.0,
            80 | 8080 => 45.0,
            443 => 30.0,
            _ => 35.0,
        }
    }

    fn parse_exposures_from_host(
        host: &Value,
        default_asset: Option<&str>,
    ) -> Vec<ExternalExposure> {
        let asset_identifier = Self::as_string(host, &["ip", "name", "host", "asset"])
            .or_else(|| default_asset.map(|v| v.to_string()))
            .unwrap_or_else(|| "unknown-asset".to_string());

        let now = Utc::now();
        let host_observed =
            Self::as_datetime(host, &["last_updated_at", "observed_at"]).unwrap_or(now);

        let mut exposures = Vec::new();

        for service in Self::service_rows(host) {
            if let Some(port) = Self::as_u16(service, &["port", "service.port"]) {
                let service_name = Self::as_string(
                    service,
                    &["service_name", "extended_service_name", "service.name"],
                )
                .unwrap_or_else(|| "unknown".to_string());

                exposures.push(ExternalExposure {
                    id: Uuid::new_v4(),
                    asset_identifier: asset_identifier.clone(),
                    exposure_type: ExposureType::OpenPort {
                        port,
                        service: service_name,
                    },
                    risk_score: Self::open_port_risk(port),
                    details: serde_json::json!({
                        "source": "censys",
                        "service": service,
                    }),
                    first_seen: Self::as_datetime(service, &["first_observed_at"])
                        .unwrap_or(host_observed),
                    last_seen: Self::as_datetime(service, &["last_observed_at"])
                        .unwrap_or(host_observed),
                });
            }

            if let Some(days_to_expiry) = Self::as_f32(
                service,
                &[
                    "tls.certificates.leaf_data.validity.length",
                    "tls.certificates.leaf_data.days_to_expiry",
                ],
            ) {
                if days_to_expiry < 0.0 {
                    exposures.push(ExternalExposure {
                        id: Uuid::new_v4(),
                        asset_identifier: asset_identifier.clone(),
                        exposure_type: ExposureType::ExpiredCertificate {
                            domain: asset_identifier.clone(),
                            expiry: now,
                        },
                        risk_score: 70.0,
                        details: serde_json::json!({
                            "source": "censys",
                            "days_to_expiry": days_to_expiry,
                            "service": service,
                        }),
                        first_seen: host_observed,
                        last_seen: host_observed,
                    });
                }
            }
        }

        exposures
    }

    fn calculate_risk_score(exposures: &[ExternalExposure]) -> Option<f32> {
        if exposures.is_empty() {
            return None;
        }

        let max = exposures
            .iter()
            .map(|exp| exp.risk_score)
            .fold(0.0_f32, f32::max);
        let avg = exposures.iter().map(|exp| exp.risk_score).sum::<f32>() / exposures.len() as f32;

        Some(((max * 0.6) + (avg * 0.4)).clamp(0.0, 100.0))
    }
}

#[async_trait]
impl Connector for CensysConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
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
        match self.client.get("/v2/account").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(response) => Ok(ConnectorHealth::Degraded(format!(
                "Unexpected status code {}",
                response.status()
            ))),
            Err(ConnectorError::ConnectionFailed(err)) => Ok(ConnectorHealth::Unhealthy(err)),
            Err(err) => Ok(ConnectorHealth::Unhealthy(err.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/v2/account").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AttackSurfaceMonitor for CensysConnector {
    async fn get_exposures(&self, domain: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let query = format!("services.tls.certificates.leaf_data.names: {}", domain);
        let body = serde_json::json!({
            "q": query,
            "per_page": 100,
            "virtual_hosts": "EXCLUDE",
        });

        let payload = self.post_json("/v2/hosts/search", &body).await?;
        let mut exposures = Vec::new();

        for hit in Self::host_hits(&payload) {
            exposures.extend(Self::parse_exposures_from_host(hit, None));
        }

        Ok(exposures)
    }

    async fn get_asset_exposure(&self, asset_id: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let path = format!("/v2/hosts/{}", urlencoding::encode(asset_id));
        let payload = self.get_json(&path).await?;

        let host = Self::find_value(&payload, "result").unwrap_or(&payload);
        Ok(Self::parse_exposures_from_host(host, Some(asset_id)))
    }

    async fn get_risk_score(&self, domain: &str) -> ConnectorResult<Option<f32>> {
        let exposures = self.get_exposures(domain).await?;
        Ok(Self::calculate_risk_score(&exposures))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_config() -> CensysConfig {
        CensysConfig {
            connector: ConnectorConfig {
                name: "censys-test".to_string(),
                base_url: "https://search.censys.io/api".to_string(),
                auth: AuthConfig::None,
                timeout_secs: 30,
                max_retries: 0,
                verify_tls: true,
                headers: HashMap::new(),
            },
            api_id: None,
            api_secret: None,
        }
    }

    #[test]
    fn test_connector_name() {
        let connector = CensysConnector::new(test_config()).unwrap();
        assert_eq!(connector.name(), "censys-test");
        assert_eq!(connector.connector_type(), "asm");
    }

    #[test]
    fn test_connector_capabilities() {
        let connector = CensysConnector::new(test_config()).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"get_exposures".to_string()));
        assert!(caps.contains(&"get_risk_score".to_string()));
    }

    #[test]
    fn test_parse_exposures_from_host() {
        let host = serde_json::json!({
            "ip": "203.0.113.10",
            "last_updated_at": "2025-01-01T00:00:00Z",
            "services": [
                {"port": 22, "service_name": "SSH"},
                {"port": 443, "service_name": "HTTPS"}
            ]
        });

        let exposures = CensysConnector::parse_exposures_from_host(&host, None);
        assert_eq!(exposures.len(), 2);
        assert!(matches!(
            exposures[0].exposure_type,
            ExposureType::OpenPort { .. }
        ));
    }

    #[test]
    fn test_calculate_risk_score() {
        let now = Utc::now();
        let exposures = vec![
            ExternalExposure {
                id: Uuid::new_v4(),
                asset_identifier: "asset-1".to_string(),
                exposure_type: ExposureType::OpenPort {
                    port: 22,
                    service: "ssh".to_string(),
                },
                risk_score: 60.0,
                details: serde_json::Value::Null,
                first_seen: now,
                last_seen: now,
            },
            ExternalExposure {
                id: Uuid::new_v4(),
                asset_identifier: "asset-2".to_string(),
                exposure_type: ExposureType::OpenPort {
                    port: 445,
                    service: "smb".to_string(),
                },
                risk_score: 90.0,
                details: serde_json::Value::Null,
                first_seen: now,
                last_seen: now,
            },
        ];

        let risk = CensysConnector::calculate_risk_score(&exposures).unwrap();
        assert!(risk > 70.0);
        assert!(risk <= 100.0);
    }

    #[test]
    fn test_auth_from_api_id_secret() {
        let mut config = test_config();
        config.api_id = Some("id".to_string());
        config.api_secret = Some("secret".to_string());

        let connector = CensysConnector::new(config).unwrap();
        assert!(matches!(
            connector.config.connector.auth,
            AuthConfig::Basic { .. }
        ));
    }
}
