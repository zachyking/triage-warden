//! ServiceNow ITSM connector.
//!
//! Provides integration with ServiceNow for incident management, on-call
//! schedules, and CMDB asset lookups.

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

/// ServiceNow connector configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceNowConfig {
    #[serde(flatten)]
    pub connector: crate::traits::ConnectorConfig,
    /// ServiceNow instance name (e.g., "mycompany" for mycompany.service-now.com).
    pub instance: String,
}

/// ServiceNow connector.
pub struct ServiceNowConnector {
    config: ServiceNowConfig,
    client: HttpClient,
}

impl ServiceNowConnector {
    pub fn new(config: ServiceNowConfig) -> ConnectorResult<Self> {
        let client = HttpClient::new(config.connector.clone())?;
        info!(
            "ServiceNow connector initialized for instance '{}'",
            config.instance
        );
        Ok(Self { config, client })
    }

    fn parse_incident(record: &SnowRecord) -> ITSMIncident {
        let created_at = record
            .get("sys_created_on")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let updated_at = record
            .get("sys_updated_on")
            .and_then(|v| v.as_str())
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(Utc::now);

        let severity = record
            .get("severity")
            .or_else(|| record.get("priority"))
            .and_then(|v| v.as_str())
            .unwrap_or("3")
            .to_string();

        ITSMIncident {
            id: record
                .get("sys_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            title: record
                .get("short_description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            description: record
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            severity,
            state: record
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or("1")
                .to_string(),
            assigned_to: record
                .get("assigned_to")
                .and_then(|v| v.as_str())
                .map(String::from),
            assignment_group: record
                .get("assignment_group")
                .and_then(|v| v.as_str())
                .map(String::from),
            created_at,
            updated_at,
            url: None,
            fields: record.clone(),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for ServiceNowConnector {
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
        match self
            .client
            .get("/api/now/table/sys_user?sysparm_limit=1")
            .await
        {
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
        let r = self
            .client
            .get("/api/now/table/sys_user?sysparm_limit=1")
            .await?;
        Ok(r.status().is_success())
    }
}

#[async_trait]
impl ITSMConnector for ServiceNowConnector {
    #[instrument(skip(self))]
    async fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
    ) -> ConnectorResult<ITSMIncident> {
        let body = serde_json::json!({
            "short_description": title,
            "description": description,
            "severity": severity,
            "category": "Security",
            "subcategory": "Security Incident"
        });

        let response = self.client.post("/api/now/table/incident", &body).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to create incident: {}",
                err
            )));
        }

        let result: SnowResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.result))
    }

    #[instrument(skip(self))]
    async fn get_incident(&self, incident_id: &str) -> ConnectorResult<ITSMIncident> {
        let path = format!(
            "/api/now/table/incident/{}",
            urlencoding::encode(incident_id)
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Err(ConnectorError::NotFound(format!(
                "Incident not found: {}",
                incident_id
            )));
        }

        let result: SnowResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.result))
    }

    #[instrument(skip(self))]
    async fn update_incident(
        &self,
        incident_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConnectorResult<ITSMIncident> {
        let path = format!(
            "/api/now/table/incident/{}",
            urlencoding::encode(incident_id)
        );
        let response = self.client.put(&path, &serde_json::json!(updates)).await?;

        if !response.status().is_success() {
            let err = response.text().await.unwrap_or_default();
            return Err(ConnectorError::RequestFailed(format!(
                "Failed to update incident: {}",
                err
            )));
        }

        let result: SnowResponse = response
            .json()
            .await
            .map_err(|e| ConnectorError::InvalidResponse(format!("Parse error: {}", e)))?;

        Ok(Self::parse_incident(&result.result))
    }

    #[instrument(skip(self))]
    async fn get_on_call(&self, schedule: &str) -> ConnectorResult<Vec<OnCallInfo>> {
        let path = format!(
            "/api/now/on_call_rota/whoisoncall?group_name={}",
            urlencoding::encode(schedule)
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        let result: SnowListResponse = response.json().await.unwrap_or_default();
        Ok(result
            .result
            .into_iter()
            .map(|r| OnCallInfo {
                user: r
                    .get("userId")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
                schedule: schedule.to_string(),
                start: Utc::now(),
                end: Utc::now() + chrono::Duration::hours(8),
            })
            .collect())
    }

    #[instrument(skip(self))]
    async fn get_asset_from_cmdb(&self, identifier: &str) -> ConnectorResult<Option<CMDBAsset>> {
        let path = format!(
            "/api/now/cmdb/instance/cmdb_ci?sysparm_query=name={}",
            urlencoding::encode(identifier)
        );
        let response = self.client.get(&path).await?;

        if !response.status().is_success() {
            return Ok(None);
        }

        let result: SnowListResponse = response.json().await.unwrap_or_default();
        Ok(result.result.into_iter().next().map(|r| CMDBAsset {
            id: r
                .get("sys_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            name: r
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string(),
            asset_class: r
                .get("sys_class_name")
                .and_then(|v| v.as_str())
                .unwrap_or("cmdb_ci")
                .to_string(),
            owner: r.get("owned_by").and_then(|v| v.as_str()).map(String::from),
            environment: r
                .get("environment")
                .and_then(|v| v.as_str())
                .map(String::from),
            criticality: r
                .get("business_criticality")
                .and_then(|v| v.as_str())
                .map(String::from),
            attributes: r,
        }))
    }
}

// ServiceNow API response types

type SnowRecord = HashMap<String, serde_json::Value>;

#[derive(Debug, Default, Deserialize)]
struct SnowResponse {
    #[serde(default)]
    result: SnowRecord,
}

#[derive(Debug, Default, Deserialize)]
struct SnowListResponse {
    #[serde(default)]
    result: Vec<SnowRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::test_connector_config;
    use crate::traits::Connector;

    fn create_test_config() -> ServiceNowConfig {
        ServiceNowConfig {
            connector: test_connector_config("snow-test", "https://mycompany.service-now.com"),
            instance: "mycompany".to_string(),
        }
    }

    #[test]
    fn test_connector_creation() {
        assert!(ServiceNowConnector::new(create_test_config()).is_ok());
    }

    #[test]
    fn test_connector_name_and_category() {
        let c = ServiceNowConnector::new(create_test_config()).unwrap();
        assert_eq!(c.name(), "snow-test");
        assert_eq!(c.connector_type(), "itsm");
        assert_eq!(c.category(), ConnectorCategory::Itsm);
    }

    #[test]
    fn test_parse_incident() {
        let mut record = HashMap::new();
        record.insert("sys_id".to_string(), serde_json::json!("INC001"));
        record.insert(
            "short_description".to_string(),
            serde_json::json!("Security Incident"),
        );
        record.insert("severity".to_string(), serde_json::json!("2"));
        record.insert("state".to_string(), serde_json::json!("1"));

        let incident = ServiceNowConnector::parse_incident(&record);
        assert_eq!(incident.id, "INC001");
        assert_eq!(incident.title, "Security Incident");
        assert_eq!(incident.severity, "2");
    }
}
