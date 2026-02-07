//! SecurityScorecard attack surface management connector.

use async_trait::async_trait;
use chrono::{DateTime, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;
use uuid::Uuid;

use crate::http::HttpClient;
use crate::traits::{ConnectorConfig, ConnectorError, ConnectorHealth, ConnectorResult};
use crate::Connector;

use super::{AttackSurfaceMonitor, ExposureType, ExternalExposure};

/// Configuration for the SecurityScorecard connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScorecardConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: ConnectorConfig,
}

/// SecurityScorecard attack surface management connector.
pub struct ScorecardConnector {
    config: ScorecardConfig,
    client: HttpClient,
}

impl ScorecardConnector {
    /// Creates a new SecurityScorecard connector.
    pub fn new(config: ScorecardConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("SecurityScorecard ASM connector initialized");
        Ok(Self { config, client })
    }

    async fn get_json(&self, path: &str) -> ConnectorResult<Value> {
        let response = self.client.get(path).await?;
        response.json::<Value>().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!(
                "Failed to parse SecurityScorecard JSON response: {}",
                e
            ))
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

    fn as_usize(root: &Value, paths: &[&str]) -> Option<usize> {
        for path in paths {
            if let Some(value) = Self::find_value(root, path) {
                if let Some(v) = value.as_u64() {
                    return Some(v as usize);
                }
                if let Some(v) = value.as_i64() {
                    if v >= 0 {
                        return Some(v as usize);
                    }
                }
                if let Some(v) = value.as_str().and_then(|v| v.parse::<usize>().ok()) {
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

    fn score_to_risk(score: f32) -> f32 {
        (100.0 - score).clamp(0.0, 100.0)
    }

    fn grade_to_score(grade: &str) -> Option<f32> {
        match grade.to_ascii_uppercase().as_str() {
            "A" => Some(95.0),
            "B" => Some(80.0),
            "C" => Some(65.0),
            "D" => Some(45.0),
            "E" => Some(25.0),
            "F" => Some(10.0),
            _ => None,
        }
    }

    fn factor_rows(payload: &Value) -> Vec<&Value> {
        let paths = ["factors", "data.factors", "results", "entries"];
        for path in paths {
            if let Some(rows) = Self::find_value(payload, path).and_then(|v| v.as_array()) {
                return rows.iter().collect();
            }
        }
        if let Some(rows) = payload.as_array() {
            return rows.iter().collect();
        }
        Vec::new()
    }

    fn issue_rows(payload: &Value) -> Vec<&Value> {
        let paths = ["issues", "data.issues", "results", "findings"];
        for path in paths {
            if let Some(rows) = Self::find_value(payload, path).and_then(|v| v.as_array()) {
                return rows.iter().collect();
            }
        }
        if let Some(rows) = payload.as_array() {
            return rows.iter().collect();
        }
        Vec::new()
    }

    fn factor_to_exposure(domain: &str, factor: &Value) -> Option<ExternalExposure> {
        let factor_name = Self::as_string(factor, &["name", "factor", "identifier"])?;
        let issue_count =
            Self::as_usize(factor, &["issue_count", "issues", "failed_checks"]).unwrap_or(0);

        if issue_count == 0 {
            return None;
        }

        let normalized = factor_name.to_ascii_lowercase();
        let exposure_type = if normalized.contains("dns") {
            ExposureType::DnsIssue {
                issue_type: factor_name.clone(),
            }
        } else if normalized.contains("header") || normalized.contains("http") {
            ExposureType::MisconfiguredHeader {
                header: factor_name.clone(),
                issue: "Security posture degraded".to_string(),
            }
        } else {
            ExposureType::ExposedService {
                service: factor_name.clone(),
                version: "unknown".to_string(),
            }
        };

        let quality_score = Self::as_f32(factor, &["score", "grade_score"]).unwrap_or(50.0);

        Some(ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: domain.to_string(),
            exposure_type,
            risk_score: Self::score_to_risk(quality_score),
            details: serde_json::json!({
                "source": "securityscorecard",
                "factor": factor,
            }),
            first_seen: Self::as_datetime(factor, &["first_observed", "created_at"])
                .unwrap_or_else(Utc::now),
            last_seen: Self::as_datetime(factor, &["updated_at", "last_observed"])
                .unwrap_or_else(Utc::now),
        })
    }

    fn issue_to_exposure(asset_id: &str, issue: &Value) -> ExternalExposure {
        let port = Self::as_u16(issue, &["port", "service.port"]);
        let service = Self::as_string(issue, &["service", "service_name", "protocol"])
            .unwrap_or_else(|| "unknown".to_string());

        let exposure_type = if let Some(port) = port {
            ExposureType::OpenPort {
                port,
                service: service.clone(),
            }
        } else if service.to_ascii_lowercase().contains("tls") {
            ExposureType::WeakCipher {
                domain: asset_id.to_string(),
                cipher: Self::as_string(issue, &["cipher", "issue_type"]).unwrap_or(service),
            }
        } else {
            ExposureType::ExposedService {
                service,
                version: Self::as_string(issue, &["version", "service_version"])
                    .unwrap_or_else(|| "unknown".to_string()),
            }
        };

        let risk_score = Self::as_f32(issue, &["risk_score", "severity_score", "score"])
            .unwrap_or(65.0)
            .clamp(0.0, 100.0);

        ExternalExposure {
            id: Uuid::new_v4(),
            asset_identifier: asset_id.to_string(),
            exposure_type,
            risk_score,
            details: serde_json::json!({
                "source": "securityscorecard",
                "issue": issue,
            }),
            first_seen: Self::as_datetime(issue, &["first_seen", "created_at"])
                .unwrap_or_else(Utc::now),
            last_seen: Self::as_datetime(issue, &["last_seen", "updated_at"])
                .unwrap_or_else(Utc::now),
        }
    }

    fn calculate_aggregate_risk(exposures: &[ExternalExposure]) -> Option<f32> {
        if exposures.is_empty() {
            return None;
        }

        let weighted_sum = exposures
            .iter()
            .map(|exp| {
                let weight = match exp.exposure_type {
                    ExposureType::ExpiredCertificate { .. } => 1.2,
                    ExposureType::WeakCipher { .. } => 1.1,
                    ExposureType::OpenPort { port, .. } if [22, 23, 3389, 445].contains(&port) => {
                        1.2
                    }
                    _ => 1.0,
                };
                exp.risk_score * weight
            })
            .sum::<f32>();

        let normalization = exposures
            .iter()
            .map(|exp| match exp.exposure_type {
                ExposureType::ExpiredCertificate { .. } => 1.2,
                ExposureType::WeakCipher { .. } => 1.1,
                ExposureType::OpenPort { port, .. } if [22, 23, 3389, 445].contains(&port) => 1.2,
                _ => 1.0,
            })
            .sum::<f32>();

        Some((weighted_sum / normalization).clamp(0.0, 100.0))
    }
}

#[async_trait]
impl Connector for ScorecardConnector {
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
        match self.client.get("/companies?limit=1").await {
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
        let response = self.client.get("/companies?limit=1").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AttackSurfaceMonitor for ScorecardConnector {
    async fn get_exposures(&self, domain: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let path = format!("/companies/{}/factors", urlencoding::encode(domain));
        let payload = self.get_json(&path).await?;

        let exposures = Self::factor_rows(&payload)
            .into_iter()
            .filter_map(|factor| Self::factor_to_exposure(domain, factor))
            .collect();

        Ok(exposures)
    }

    async fn get_asset_exposure(&self, asset_id: &str) -> ConnectorResult<Vec<ExternalExposure>> {
        let path = format!("/assets/{}/issues", urlencoding::encode(asset_id));
        let payload = self.get_json(&path).await?;

        Ok(Self::issue_rows(&payload)
            .into_iter()
            .map(|issue| Self::issue_to_exposure(asset_id, issue))
            .collect())
    }

    async fn get_risk_score(&self, domain: &str) -> ConnectorResult<Option<f32>> {
        let company_path = format!("/companies/{}", urlencoding::encode(domain));
        match self.get_json(&company_path).await {
            Ok(payload) => {
                let direct_score =
                    Self::as_f32(&payload, &["score", "security_score"]).or_else(|| {
                        Self::as_string(&payload, &["grade", "rating"])
                            .and_then(|grade| Self::grade_to_score(&grade))
                    });

                if let Some(score) = direct_score {
                    return Ok(Some(Self::score_to_risk(score)));
                }
            }
            Err(ConnectorError::NotFound(_)) => return Ok(None),
            Err(err) => return Err(err),
        }

        let exposures = self.get_exposures(domain).await?;
        Ok(Self::calculate_aggregate_risk(&exposures))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::AuthConfig;
    use std::collections::HashMap;

    fn test_config() -> ScorecardConfig {
        ScorecardConfig {
            connector: ConnectorConfig {
                name: "scorecard-test".to_string(),
                base_url: "https://api.securityscorecard.io".to_string(),
                auth: AuthConfig::None,
                timeout_secs: 30,
                max_retries: 0,
                verify_tls: true,
                headers: HashMap::new(),
            },
        }
    }

    #[test]
    fn test_connector_name() {
        let connector = ScorecardConnector::new(test_config()).unwrap();
        assert_eq!(connector.name(), "scorecard-test");
        assert_eq!(connector.connector_type(), "asm");
    }

    #[test]
    fn test_connector_capabilities() {
        let connector = ScorecardConnector::new(test_config()).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"get_exposures".to_string()));
        assert!(caps.contains(&"get_risk_score".to_string()));
    }

    #[test]
    fn test_factor_to_exposure() {
        let factor = serde_json::json!({
            "name": "DNS Health",
            "issue_count": 3,
            "score": 40,
            "updated_at": "2025-01-01T00:00:00Z"
        });

        let exposure = ScorecardConnector::factor_to_exposure("example.com", &factor).unwrap();
        assert_eq!(exposure.asset_identifier, "example.com");
        assert!(matches!(
            exposure.exposure_type,
            ExposureType::DnsIssue { .. }
        ));
        assert!(exposure.risk_score >= 50.0);
    }

    #[test]
    fn test_issue_to_exposure() {
        let issue = serde_json::json!({
            "port": 3389,
            "service": "rdp",
            "risk_score": 82,
            "updated_at": "2025-01-02T00:00:00Z"
        });

        let exposure = ScorecardConnector::issue_to_exposure("asset-1", &issue);
        assert_eq!(exposure.asset_identifier, "asset-1");
        assert!(matches!(
            exposure.exposure_type,
            ExposureType::OpenPort { .. }
        ));
        assert_eq!(exposure.risk_score, 82.0);
    }

    #[test]
    fn test_grade_and_score_conversion() {
        assert_eq!(ScorecardConnector::grade_to_score("A"), Some(95.0));
        assert_eq!(ScorecardConnector::grade_to_score("F"), Some(10.0));
        assert_eq!(ScorecardConnector::score_to_risk(80.0), 20.0);
    }

    #[test]
    fn test_calculate_aggregate_risk() {
        let now = Utc::now();
        let exposures = vec![
            ExternalExposure {
                id: Uuid::new_v4(),
                asset_identifier: "asset-1".to_string(),
                exposure_type: ExposureType::OpenPort {
                    port: 22,
                    service: "ssh".to_string(),
                },
                risk_score: 70.0,
                details: serde_json::Value::Null,
                first_seen: now,
                last_seen: now,
            },
            ExternalExposure {
                id: Uuid::new_v4(),
                asset_identifier: "asset-2".to_string(),
                exposure_type: ExposureType::MisconfiguredHeader {
                    header: "CSP".to_string(),
                    issue: "missing".to_string(),
                },
                risk_score: 50.0,
                details: serde_json::Value::Null,
                first_seen: now,
                last_seen: now,
            },
        ];

        let risk = ScorecardConnector::calculate_aggregate_risk(&exposures).unwrap();
        assert!(risk > 50.0);
        assert!(risk <= 100.0);
    }
}
