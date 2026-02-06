//! PagerDuty connector.
//!
//! Provides integration with PagerDuty for incident management,
//! on-call schedule retrieval, and escalation.

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

/// PagerDuty connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PagerDutyConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// Default escalation policy ID.
    pub escalation_policy_id: Option<String>,
    /// Default service ID.
    pub service_id: Option<String>,
}

/// PagerDuty connector.
pub struct PagerDutyConnector {
    config: PagerDutyConfig,
    client: HttpClient,
}

impl PagerDutyConnector {
    pub fn new(config: PagerDutyConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!("PagerDuty connector initialized");
        Ok(Self { config, client })
    }

    fn parse_incident(incident: &PdIncident) -> ITSMIncident {
        let created_at = incident
            .created_at
            .as_ref()
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let urgency = incident.urgency.as_deref().unwrap_or("low");
        let severity = match urgency {
            "high" => "high",
            "low" => "medium",
            _ => "low",
        }
        .to_string();

        ITSMIncident {
            id: incident.id.clone().unwrap_or_default(),
            title: incident.title.clone().unwrap_or_default(),
            description: incident.description.clone().unwrap_or_default(),
            severity,
            state: incident
                .status
                .clone()
                .unwrap_or_else(|| "triggered".into()),
            assigned_to: incident
                .assignments
                .as_ref()
                .and_then(|a| a.first())
                .and_then(|a| a.assignee.as_ref())
                .and_then(|u| u.summary.clone()),
            assignment_group: incident
                .escalation_policy
                .as_ref()
                .and_then(|p| p.summary.clone()),
            created_at,
            updated_at: created_at,
            url: incident.html_url.clone(),
            fields: HashMap::new(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for PagerDutyConnector {
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
        match self.client.get("/abilities").await {
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
        let r = self.client.get("/abilities").await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl ITSMConnector for PagerDutyConnector {
    #[instrument(skip(self))]
    async fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
    ) -> ConnectorResult<ITSMIncident> {
        let urgency = match severity {
            "critical" | "high" => "high",
            _ => "low",
        };

        let mut body = serde_json::json!({
            "incident": {
                "type": "incident",
                "title": title,
                "body": {
                    "type": "incident_body",
                    "details": description
                },
                "urgency": urgency
            }
        });

        if let Some(ref service_id) = self.config.service_id {
            body["incident"]["service"] = serde_json::json!({
                "id": service_id,
                "type": "service_reference"
            });
        }

        if let Some(ref policy_id) = self.config.escalation_policy_id {
            body["incident"]["escalation_policy"] = serde_json::json!({
                "id": policy_id,
                "type": "escalation_policy_reference"
            });
        }

        let response = self.client.post("/incidents", &body).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to create incident: {}",
                err
            )));
        }

        let result: PdIncidentResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.incident))
    }

    #[instrument(skip(self))]
    async fn get_incident(&self, incident_id: &str) -> ConnectorResult<ITSMIncident> {
        let path = format!("/incidents/{}", urlencoding::encode(incident_id));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Incident not found: {}",
                incident_id
            )));
        }

        let result: PdIncidentResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.incident))
    }

    #[instrument(skip(self))]
    async fn update_incident(
        &self,
        incident_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConnectorResult<ITSMIncident> {
        let path = format!("/incidents/{}", urlencoding::encode(incident_id));
        let body = serde_json::json!({ "incident": updates });
        let response = self.client.put(&path, &body).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to update incident: {}",
                err
            )));
        }

        let result: PdIncidentResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.incident))
    }

    #[instrument(skip(self))]
    async fn get_on_call(&self, schedule: &str) -> ConnectorResult<Vec<OnCallInfo>> {
        let path = format!("/oncalls?schedule_ids[]={}", urlencoding::encode(schedule));
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: PdOnCallResponse = response.json().await.unwrap_or_default();
        Ok(result
            .oncalls
            .into_iter()
            .map(|o| {
                let start = o
                    .start
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now);
                let end = o
                    .end
                    .as_ref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|| Utc::now() + chrono::Duration::hours(8));

                OnCallInfo {
                    user: o
                        .user
                        .as_ref()
                        .and_then(|u| u.summary.clone())
                        .unwrap_or_default(),
                    schedule: schedule.to_string(),
                    start,
                    end,
                }
            })
            .collect())
    }

    async fn get_asset_from_cmdb(&self, _identifier: &str) -> ConnectorResult<Option<CMDBAsset>> {
        // PagerDuty doesn't have CMDB
        Ok(None)
    }
}

// PagerDuty API response types

#[derive(Debug, Default, Deserialize)]
struct PdIncidentResponse {
    #[serde(default)]
    incident: PdIncident,
}

#[derive(Debug, Default, Deserialize)]
struct PdIncident {
    id: Option<String>,
    title: Option<String>,
    description: Option<String>,
    status: Option<String>,
    urgency: Option<String>,
    created_at: Option<String>,
    html_url: Option<String>,
    assignments: Option<Vec<PdAssignment>>,
    escalation_policy: Option<PdReference>,
}

#[derive(Debug, Default, Deserialize)]
struct PdAssignment {
    assignee: Option<PdReference>,
}

#[derive(Debug, Default, Deserialize)]
struct PdReference {
    summary: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct PdOnCallResponse {
    #[serde(default)]
    oncalls: Vec<PdOnCall>,
}

#[derive(Debug, Default, Deserialize)]
struct PdOnCall {
    user: Option<PdReference>,
    start: Option<String>,
    end: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> PagerDutyConfig {
        PagerDutyConfig {
            connector: test_connector_config("pd-test", "https://api.pagerduty.com"),
            escalation_policy_id: Some("POLICY001".to_string()),
            service_id: Some("SERVICE001".to_string()),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(PagerDutyConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = PagerDutyConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "pd-test");
        assert_eq!(c.connector_type(), "itsm");
        assert_eq!(c.category(), ConnectorCategory::Itsm);
    }

    #[test]
    fn test_parse_incident() {
        let incident = PdIncident {
            id: Some("P123456".to_string()),
            title: Some("Security Alert".to_string()),
            description: Some("Suspicious activity detected".to_string()),
            status: Some("triggered".to_string()),
            urgency: Some("high".to_string()),
            created_at: Some("2024-01-15T10:30:00Z".to_string()),
            html_url: Some("https://pd.com/incidents/P123456".to_string()),
            assignments: None,
            escalation_policy: None,
        };

        let parsed = PagerDutyConnector::parse_incident(&incident);
        assert_eq!(parsed.id, "P123456");
        assert_eq!(parsed.severity, "high");
        assert_eq!(parsed.state, "triggered");
    }
}
