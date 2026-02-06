//! Microsoft Entra ID (Azure AD) connector.
//!
//! Provides integration with Microsoft Entra ID for identity-related
//! security signals and risky user/sign-in detection.

use crate::http::HttpClient;
use crate::traits::{
    AlertSource, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, Enricher,
    EnrichmentResult, Ioc, IocType, RawAlert,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Entra ID connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntraIdConfig {
    /// Base connector configuration.
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Azure tenant ID.
    pub tenant_id: String,
}

/// Microsoft Entra ID connector.
pub struct EntraIdConnector {
    config: EntraIdConfig,
    client: HttpClient,
}

impl EntraIdConnector {
    /// Creates a new Entra ID connector.
    pub fn new(config: EntraIdConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "Entra ID connector initialized for tenant '{}'",
            config.tenant_id
        );
        Ok(Self { config, client })
    }

    /// Parses a risky detection into a RawAlert.
    fn parse_risk_detection(detection: &RiskDetection) -> RawAlert {
        let severity = match detection.risk_level.as_deref() {
            Some("high") => "high",
            Some("medium") => "medium",
            Some("low") => "low",
            _ => "medium",
        };

        let mut raw_data = HashMap::new();
        raw_data.insert(
            "user_principal_name".to_string(),
            serde_json::json!(detection.user_principal_name),
        );
        raw_data.insert(
            "risk_type".to_string(),
            serde_json::json!(detection.risk_event_type),
        );
        raw_data.insert(
            "ip_address".to_string(),
            serde_json::json!(detection.ip_address),
        );
        raw_data.insert(
            "location".to_string(),
            serde_json::json!(detection.location),
        );
        raw_data.insert(
            "risk_state".to_string(),
            serde_json::json!(detection.risk_state),
        );
        raw_data.insert(
            "risk_detail".to_string(),
            serde_json::json!(detection.risk_detail),
        );

        RawAlert {
            id: detection.id.clone(),
            title: format!(
                "Identity Risk: {}",
                detection.risk_event_type.as_deref().unwrap_or("Unknown")
            ),
            description: format!(
                "Risk detection for user {} from IP {}",
                detection
                    .user_principal_name
                    .as_deref()
                    .unwrap_or("unknown"),
                detection.ip_address.as_deref().unwrap_or("unknown")
            ),
            severity: severity.to_string(),
            timestamp: detection
                .detected_date_time
                .as_ref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            source: "azure_entra_id".to_string(),
            raw_data,
        }
    }
}

#[async_trait]
impl crate::traits::Connector for EntraIdConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "cloud"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Identity
    }

    fn capabilities(&self) -> Vec<String> {
        vec![
            "health_check".to_string(),
            "test_connection".to_string(),
            "fetch_alerts".to_string(),
            "enrich".to_string(),
        ]
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/v1.0/organization").await {
            Ok(response) if response.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(response) if response.status().as_u16() == 401 => Ok(ConnectorHealth::Unhealthy(
                "Authentication failed".to_string(),
            )),
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".to_string())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let response = self.client.get("/v1.0/organization").await?;
        Ok(response.status().is_success())
    }
}

#[async_trait]
impl AlertSource for EntraIdConnector {
    #[instrument(skip(self))]
    async fn fetch_alerts(
        &self,
        since: DateTime<Utc>,
        limit: Option<usize>,
    ) -> ConnectorResult<Vec<RawAlert>> {
        let top = limit.unwrap_or(100).min(500);
        let filter = format!("detectedDateTime ge {}", since.format("%Y-%m-%dT%H:%M:%SZ"));
        let path = format!(
            "/v1.0/identityProtection/riskDetections?$top={}&$filter={}&$orderby=detectedDateTime desc",
            top,
            urlencoding::encode(&filter)
        );

        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to list risk detections: {}",
                body
            )));
        }

        let result: GraphListResponse<RiskDetection> = response.json().await.map_err(|e| {
            ConnectorError::InvalidResponse(format!("Failed to parse risk detections: {}", e))
        })?;

        Ok(result
            .value
            .iter()
            .map(Self::parse_risk_detection)
            .collect())
    }

    async fn acknowledge_alert(&self, _alert_id: &str) -> ConnectorResult<()> {
        // Risk detections in Entra ID are read-only; acknowledgement
        // is done via the risky user dismiss/confirm API.
        Ok(())
    }
}

#[async_trait]
impl Enricher for EntraIdConnector {
    fn supported_ioc_types(&self) -> Vec<IocType> {
        vec![IocType::Email]
    }

    #[instrument(skip(self))]
    async fn enrich(&self, ioc: &Ioc) -> ConnectorResult<EnrichmentResult> {
        if ioc.ioc_type != IocType::Email {
            return Ok(EnrichmentResult {
                ioc: ioc.clone(),
                found: false,
                risk_score: None,
                data: HashMap::new(),
                source: "azure_entra_id".to_string(),
                enriched_at: Utc::now(),
            });
        }

        let path = format!(
            "/v1.0/users/{}?$select=id,displayName,userPrincipalName,accountEnabled,riskLevel,riskState",
            urlencoding::encode(&ioc.value)
        );

        let response = self.client.get(&path).await?;

        if response.status().as_u16() == 404 {
            return Ok(EnrichmentResult {
                ioc: ioc.clone(),
                found: false,
                risk_score: None,
                data: HashMap::new(),
                source: "azure_entra_id".to_string(),
                enriched_at: Utc::now(),
            });
        }

        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to get user: {}",
                body
            )));
        }

        let user: EntraUser = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Failed to parse user: {}", e)))?;

        let mut data = HashMap::new();
        data.insert(
            "display_name".to_string(),
            serde_json::json!(user.display_name),
        );
        data.insert(
            "account_enabled".to_string(),
            serde_json::json!(user.account_enabled),
        );
        data.insert("risk_level".to_string(), serde_json::json!(user.risk_level));
        data.insert("risk_state".to_string(), serde_json::json!(user.risk_state));

        let risk_score = match user.risk_level.as_deref() {
            Some("high") => Some(80),
            Some("medium") => Some(50),
            Some("low") => Some(20),
            _ => Some(0),
        };

        Ok(EnrichmentResult {
            ioc: ioc.clone(),
            found: true,
            risk_score,
            data,
            source: "azure_entra_id".to_string(),
            enriched_at: Utc::now(),
        })
    }
}

// Graph API response types

#[derive(Debug, Deserialize)]
struct GraphListResponse<T> {
    #[serde(default)]
    value: Vec<T>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RiskDetection {
    id: String,
    user_principal_name: Option<String>,
    risk_event_type: Option<String>,
    risk_level: Option<String>,
    risk_state: Option<String>,
    risk_detail: Option<String>,
    ip_address: Option<String>,
    location: Option<serde_json::Value>,
    detected_date_time: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntraUser {
    display_name: Option<String>,
    account_enabled: Option<bool>,
    risk_level: Option<String>,
    risk_state: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> EntraIdConfig {
        EntraIdConfig {
            connector: test_connector_config("entraid-test", "https://graph.microsoft.com"),
            tenant_id: "tenant-12345".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        let config = create_test_config();
        let connector = EntraIdConnector::new(config);
        assert!(connector.is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let config = create_test_config();
        let connector = EntraIdConnector::new(config).unwrap();
        assert_eq!(connector.name(), "entraid-test");
        assert_eq!(connector.category(), ConnectorCategory::Identity);
    }

    #[test]
    fn test_parse_risk_detection() {
        let detection = RiskDetection {
            id: "risk-001".to_string(),
            user_principal_name: Some("user@company.com".to_string()),
            risk_event_type: Some("unfamiliarFeatures".to_string()),
            risk_level: Some("high".to_string()),
            risk_state: Some("atRisk".to_string()),
            risk_detail: Some("Unfamiliar sign-in properties".to_string()),
            ip_address: Some("203.0.113.50".to_string()),
            location: None,
            detected_date_time: Some("2024-01-15T10:30:00Z".to_string()),
        };

        let alert = EntraIdConnector::parse_risk_detection(&detection);
        assert_eq!(alert.id, "risk-001");
        assert_eq!(alert.severity, "high");
        assert_eq!(alert.source, "azure_entra_id");
        assert!(alert.title.contains("unfamiliarFeatures"));
    }

    #[test]
    fn test_supported_ioc_types() {
        let config = create_test_config();
        let connector = EntraIdConnector::new(config).unwrap();
        let types = connector.supported_ioc_types();
        assert_eq!(types, vec![IocType::Email]);
    }

    #[test]
    fn test_capabilities() {
        let config = create_test_config();
        let connector = EntraIdConnector::new(config).unwrap();
        let caps = connector.capabilities();
        assert!(caps.contains(&"fetch_alerts".to_string()));
        assert!(caps.contains(&"enrich".to_string()));
    }
}
