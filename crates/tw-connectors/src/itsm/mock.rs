//! Mock ITSM connector for testing.

use crate::traits::{
    CMDBAsset, ConnectorCategory, ConnectorError, ConnectorHealth, ConnectorResult, ITSMConnector,
    ITSMIncident, OnCallInfo,
};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mock ITSM connector for testing.
pub struct MockITSMConnector {
    name: String,
    incidents: Arc<RwLock<HashMap<String, ITSMIncident>>>,
    next_id: Arc<RwLock<u32>>,
}

impl MockITSMConnector {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            incidents: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub fn with_sample_data(name: &str) -> Self {
        let now = Utc::now();
        let mut incidents = HashMap::new();
        incidents.insert(
            "INC-001".to_string(),
            ITSMIncident {
                id: "INC-001".to_string(),
                title: "Suspicious Login Activity".to_string(),
                description: "Multiple failed logins from unusual location".to_string(),
                severity: "high".to_string(),
                state: "open".to_string(),
                assigned_to: Some("analyst@company.com".to_string()),
                assignment_group: Some("SOC".to_string()),
                created_at: now - Duration::hours(2),
                updated_at: now - Duration::minutes(30),
                url: Some("https://itsm.example.com/INC-001".to_string()),
                fields: HashMap::new(),
            },
        );

        Self {
            name: name.to_string(),
            incidents: Arc::new(RwLock::new(incidents)),
            next_id: Arc::new(RwLock::new(2)),
        }
    }
}

#[async_trait]
impl crate::traits::Connector for MockITSMConnector {
    fn name(&self) -> &str {
        &self.name
    }

    fn connector_type(&self) -> &str {
        "itsm"
    }

    fn category(&self) -> ConnectorCategory {
        ConnectorCategory::Itsm
    }

    async fn health_check(&self) -> ConnectorResult<ConnectorHealth> {
        Ok(ConnectorHealth::Healthy)
    }

    async fn test_connection(&self) -> ConnectorResult<bool> {
        Ok(true)
    }
}

#[async_trait]
impl ITSMConnector for MockITSMConnector {
    async fn create_incident(
        &self,
        title: &str,
        description: &str,
        severity: &str,
    ) -> ConnectorResult<ITSMIncident> {
        let mut next_id = self.next_id.write().await;
        let id = format!("INC-{:03}", *next_id);
        *next_id += 1;

        let now = Utc::now();
        let incident = ITSMIncident {
            id: id.clone(),
            title: title.to_string(),
            description: description.to_string(),
            severity: severity.to_string(),
            state: "open".to_string(),
            assigned_to: None,
            assignment_group: None,
            created_at: now,
            updated_at: now,
            url: Some(format!("https://itsm.example.com/{}", id)),
            fields: HashMap::new(),
        };

        self.incidents.write().await.insert(id, incident.clone());
        Ok(incident)
    }

    async fn get_incident(&self, incident_id: &str) -> ConnectorResult<ITSMIncident> {
        self.incidents
            .read()
            .await
            .get(incident_id)
            .cloned()
            .ok_or_else(|| ConnectorError::NotFound(format!("Incident not found: {}", incident_id)))
    }

    async fn update_incident(
        &self,
        incident_id: &str,
        updates: HashMap<String, serde_json::Value>,
    ) -> ConnectorResult<ITSMIncident> {
        let mut incidents = self.incidents.write().await;
        let incident = incidents.get_mut(incident_id).ok_or_else(|| {
            ConnectorError::NotFound(format!("Incident not found: {}", incident_id))
        })?;

        if let Some(state) = updates.get("state").and_then(|v| v.as_str()) {
            incident.state = state.to_string();
        }
        if let Some(assigned_to) = updates.get("assigned_to").and_then(|v| v.as_str()) {
            incident.assigned_to = Some(assigned_to.to_string());
        }
        incident.updated_at = Utc::now();

        Ok(incident.clone())
    }

    async fn get_on_call(&self, schedule: &str) -> ConnectorResult<Vec<OnCallInfo>> {
        let now = Utc::now();
        Ok(vec![OnCallInfo {
            user: "on-call-analyst@company.com".to_string(),
            schedule: schedule.to_string(),
            start: now,
            end: now + Duration::hours(8),
        }])
    }

    async fn get_asset_from_cmdb(&self, identifier: &str) -> ConnectorResult<Option<CMDBAsset>> {
        if identifier == "server-001" {
            Ok(Some(CMDBAsset {
                id: "asset-001".to_string(),
                name: "server-001".to_string(),
                asset_class: "Server".to_string(),
                owner: Some("infra-team".to_string()),
                environment: Some("production".to_string()),
                criticality: Some("high".to_string()),
                attributes: HashMap::new(),
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::Connector;

    #[tokio::test]
    async fn test_create_and_get_incident() {
        let c = MockITSMConnector::new("test");
        let incident = c
            .create_incident("Test Incident", "Description", "high")
            .await
            .unwrap();
        assert_eq!(incident.id, "INC-001");
        assert_eq!(incident.state, "open");

        let fetched = c.get_incident("INC-001").await.unwrap();
        assert_eq!(fetched.title, "Test Incident");
    }

    #[tokio::test]
    async fn test_update_incident() {
        let c = MockITSMConnector::with_sample_data("test");
        let mut updates = HashMap::new();
        updates.insert("state".to_string(), serde_json::json!("resolved"));

        let updated = c.update_incident("INC-001", updates).await.unwrap();
        assert_eq!(updated.state, "resolved");
    }

    #[tokio::test]
    async fn test_get_on_call() {
        let c = MockITSMConnector::new("test");
        let on_call = c.get_on_call("soc-schedule").await.unwrap();
        assert_eq!(on_call.len(), 1);
        assert_eq!(on_call[0].schedule, "soc-schedule");
    }

    #[tokio::test]
    async fn test_cmdb_lookup() {
        let c = MockITSMConnector::new("test");
        let asset = c.get_asset_from_cmdb("server-001").await.unwrap();
        assert!(asset.is_some());
        assert_eq!(asset.unwrap().name, "server-001");

        let missing = c.get_asset_from_cmdb("nonexistent").await.unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn test_name_and_category() {
        let c = MockITSMConnector::new("test");
        assert_eq!(c.name(), "test");
        assert_eq!(c.connector_type(), "itsm");
        assert_eq!(c.category(), ConnectorCategory::Itsm);
    }
}
