//! Opsgenie connector.
//!
//! Provides integration with Atlassian Opsgenie for alert/incident management
//! and on-call schedule retrieval.

use crate::http::HttpClient;
use crate::traits::{
    CMDBAsset, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, ITSMConnector,
    ITSMIncident, OnCallInfo,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, instrument};

/// Opsgenie connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpsgenieConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Default team ID.
    pub team_id: Option<String>,
}

/// Opsgenie connector.
pub struct OpsgenieConnector {
    config: OpsgenieConfig,
    client: HttpClient,
}

impl OpsgenieConnector {
    pub fn new(config: OpsgenieConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("Opsgenie connector initialized");
        Ok(Self { config, client })
    }

    fn parse_incident(incident: &OgIncident) -> ITSMIncident {
        let created_at = incident
            .created_at
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = incident
            .priority
            .as_deref()
            .map(|p| match p {
                "P1" => "critical",
                "P2" => "high",
                "P3" => "medium",
                "P4" | "P5" => "low",
                _ => "medium",
            })
            .unwrap_or("medium")
            .to_string();

        ITSMIncident {
            id: incident.id.clone().unwrap_or_default(),
            title: incident.message.clone().unwrap_or_default(),
            description: incident.description.clone().unwrap_or_default(),
            severity,
            state: incident.status.clone().unwrap_or_else(|| "open".into()),
            assigned_to: incident.owner.clone(),
            assignment_group: None,
            created_at,
            updated_at: created_at,
            url: None,
            fields: HashMap::new(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for OpsgenieConnector {
    fn name(&self) -> &str {
        &self.config.connector.name
    }

    fn connector_type(&self) -> &str {
        "itsm"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Itsm
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        match self.client.get("/v2/heartbeats").await {
            Ok(r) if r.status().is_success() => Ok(ConnectorHealth::Healthy),
            Ok(r) if r.status().as_u16() == 401 => {
                Ok(ConnectorHealth::Unhealthy("Auth failed".into()))
            }
            Ok(_) => Ok(ConnectorHealth::Degraded("Unexpected response".into())),
            Err(ConnectorError::ConnectionFailed(e)) => Ok(ConnectorHealth::Unhealthy(format!(
                "Connection failed: {}",
                e
            ))),
            Err(e) => Ok(ConnectorHealth::Unhealthy(e.to_string())),
        }
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        let r = self.client.get("/v2/heartbeats").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl ITSMConnector for OpsgenieConnector {
    #[instrument(skip(self))]
    async fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
    ) -> ConnectorResult<ITSMIncident> {
        let priority = match severity {
            "critical" => "P1",
            "high" => "P2",
            "medium" => "P3",
            "low" => "P4",
            _ => "P3",
        };

        let body = serde_json::json!({
            "message": title,
            "description": description,
            "priority": priority
        });

        let response = self.client.post("/v1/incidents/create", &body).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to create incident: {}",
                err
            )));
        }

        let result: OgDataResponse<OgIncident> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.data))
    }

    #[instrument(skip(self))]
    async fn get_incident(&self, incident_id: &str) -> ConnectorResult<ITSMIncident> {
        let path = format!("/v1/incidents/{}", urlencoding::encode(incident_id));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Incident not found: {}",
                incident_id
            )));
        }

        let result: OgDataResponse<OgIncident> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.data))
    }

    #[instrument(skip(self))]
    async fn update_incident(
        &self,
        incident_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConnectorResult<ITSMIncident> {
        let path = format!("/v1/incidents/{}", urlencoding::encode(incident_id));
        let response = self.client.put(&path, &serde_json::json!(updates)).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to update incident: {}",
                err
            )));
        }

        let result: OgDataResponse<OgIncident> = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.data))
    }

    #[instrument(skip(self))]
    async fn get_on_call(&self, schedule: &str) -> ConnectorResult<Vec<OnCallInfo>> {
        let path = format!("/v2/schedules/{}/on-calls", urlencoding::encode(schedule));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: OgDataResponse<OgOnCallData> = response.json().await.unwrap_or_default();
        Ok(result
            .data
            .on_call_participants
            .into_iter()
            .map(|p| OnCallInfo {
                user: p.name.unwrap_or_default(),
                schedule: schedule.to_string(),
                start: Utc::now(),
                end: Utc::now() + chrono::Duration::hours(8),
            })
            .collect())
    }

    async fn get_asset_from_cmdb(&self, _identifier: &str) -> ConnectorResult<Option<CMDBAsset>> {
        // Opsgenie doesn't have CMDB
        Ok(None)
    }
}

// Opsgenie API response types

#[derive(Debug, Default, Deserialize)]
struct OgDataResponse<T: Default> {
    #[serde(default)]
    data: T,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OgIncident {
    id: Option<String>,
    message: Option<String>,
    description: Option<String>,
    status: Option<String>,
    priority: Option<String>,
    owner: Option<String>,
    created_at: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OgOnCallData {
    #[serde(default)]
    on_call_participants: Vec<OgParticipant>,
}

#[derive(Debug, Default, Deserialize)]
struct OgParticipant {
    name: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> OpsgenieConfig {
        OpsgenieConfig {
            connector: test_connector_config("og-test", "https://api.opsgenie.com"),
            team_id: Some("team-001".to_string()),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(OpsgenieConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = OpsgenieConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "og-test");
        assert_eq!(c.connector_type(), "itsm");
        assert_eq!(c.category(), ConnectorCategory::Itsm);
    }

    #[test]
    fn test_parse_incident() {
        let incident = OgIncident {
            id: Some("inc-001".to_string()),
            message: Some("Security Alert".to_string()),
            description: Some("Suspicious activity detected".to_string()),
            status: Some("open".to_string()),
            priority: Some("P1".to_string()),
            owner: Some("analyst@company.com".to_string()),
            created_at: Some("2024-01-15T10:30:00Z".to_string()),
        };

        let parsed = OpsgenieConnector::parse_incident(&incident);
        assert_eq!(parsed.id, "inc-001");
        assert_eq!(parsed.severity, "critical");
        assert_eq!(parsed.state, "open");
    }
}
