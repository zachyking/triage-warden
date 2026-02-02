//! Mock implementation of ConnectorRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
use crate::db::{ConnectorRepository, ConnectorUpdate, DbError};

/// Mock implementation of ConnectorRepository using in-memory storage.
pub struct MockConnectorRepository {
    connectors: Arc<RwLock<HashMap<Uuid, ConnectorConfig>>>,
}

impl Default for MockConnectorRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockConnectorRepository {
    /// Creates a new mock repository.
    pub fn new() -> Self {
        Self {
            connectors: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a mock repository pre-populated with connectors.
    pub fn with_connectors(connectors: Vec<ConnectorConfig>) -> Self {
        let map: HashMap<Uuid, ConnectorConfig> =
            connectors.into_iter().map(|c| (c.id, c)).collect();
        Self {
            connectors: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all connectors in the mock.
    pub async fn snapshot(&self) -> Vec<ConnectorConfig> {
        self.connectors.read().await.values().cloned().collect()
    }

    /// Clears all connectors from the mock.
    pub async fn clear(&self) {
        self.connectors.write().await.clear();
    }
}

#[async_trait]
impl ConnectorRepository for MockConnectorRepository {
    async fn create(&self, connector: &ConnectorConfig) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        if connectors.contains_key(&connector.id) {
            return Err(DbError::Constraint(format!(
                "Connector with id '{}' already exists",
                connector.id
            )));
        }

        // Check for duplicate names
        for existing in connectors.values() {
            if existing.name == connector.name {
                return Err(DbError::Constraint(format!(
                    "Connector with name '{}' already exists",
                    connector.name
                )));
            }
        }

        connectors.insert(connector.id, connector.clone());
        Ok(connector.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        Ok(connectors.get(&id).cloned())
    }

    async fn list(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors.values().cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_by_type(
        &self,
        connector_type: ConnectorType,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter(|c| c.connector_type == connector_type)
            .cloned()
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_enabled(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> =
            connectors.values().filter(|c| c.enabled).cloned().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn update(&self, id: Uuid, update: &ConnectorUpdate) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        // First, check if connector exists
        if !connectors.contains_key(&id) {
            return Err(DbError::NotFound {
                entity: "Connector".to_string(),
                id: id.to_string(),
            });
        }

        // Check for duplicate name if name is being updated
        if let Some(name) = &update.name {
            for (other_id, other) in connectors.iter() {
                if *other_id != id && other.name == *name {
                    return Err(DbError::Constraint(format!(
                        "Connector with name '{}' already exists",
                        name
                    )));
                }
            }
        }

        // Now perform the update
        let connector = connectors.get_mut(&id).unwrap();

        if let Some(name) = &update.name {
            connector.name = name.clone();
        }

        if let Some(config) = &update.config {
            connector.config = config.clone();
        }

        if let Some(enabled) = update.enabled {
            connector.enabled = enabled;
        }

        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let mut connectors = self.connectors.write().await;
        Ok(connectors.remove(&id).is_some())
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        let connector = connectors.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })?;

        connector.status = status;
        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }

    async fn update_health_check(&self, id: Uuid) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        let connector = connectors.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })?;

        connector.last_health_check = Some(Utc::now());
        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connector(id: Uuid, name: &str, connector_type: ConnectorType) -> ConnectorConfig {
        ConnectorConfig {
            id,
            name: name.to_string(),
            connector_type,
            config: serde_json::json!({}),
            status: ConnectorStatus::Unknown,
            enabled: true,
            last_health_check: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let repo = MockConnectorRepository::new();
        let connector = test_connector(Uuid::new_v4(), "Test Splunk", ConnectorType::Splunk);

        repo.create(&connector).await.unwrap();

        let retrieved = repo.get(connector.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Splunk");
    }

    #[tokio::test]
    async fn test_list_by_type() {
        let repo = MockConnectorRepository::new();

        repo.create(&test_connector(
            Uuid::new_v4(),
            "Splunk 1",
            ConnectorType::Splunk,
        ))
        .await
        .unwrap();
        repo.create(&test_connector(
            Uuid::new_v4(),
            "Jira 1",
            ConnectorType::Jira,
        ))
        .await
        .unwrap();
        repo.create(&test_connector(
            Uuid::new_v4(),
            "Splunk 2",
            ConnectorType::Splunk,
        ))
        .await
        .unwrap();

        let splunk_connectors = repo.list_by_type(ConnectorType::Splunk).await.unwrap();
        assert_eq!(splunk_connectors.len(), 2);

        let jira_connectors = repo.list_by_type(ConnectorType::Jira).await.unwrap();
        assert_eq!(jira_connectors.len(), 1);
    }

    #[tokio::test]
    async fn test_list_enabled() {
        let repo = MockConnectorRepository::new();

        let enabled = test_connector(Uuid::new_v4(), "Enabled", ConnectorType::Splunk);
        let mut disabled = test_connector(Uuid::new_v4(), "Disabled", ConnectorType::Splunk);
        disabled.enabled = false;

        repo.create(&enabled).await.unwrap();
        repo.create(&disabled).await.unwrap();

        let enabled_list = repo.list_enabled().await.unwrap();
        assert_eq!(enabled_list.len(), 1);
        assert_eq!(enabled_list[0].name, "Enabled");
    }

    #[tokio::test]
    async fn test_update_status() {
        let repo = MockConnectorRepository::new();
        let connector = test_connector(Uuid::new_v4(), "Test", ConnectorType::Splunk);
        repo.create(&connector).await.unwrap();

        let updated = repo
            .update_status(connector.id, ConnectorStatus::Connected)
            .await
            .unwrap();
        assert_eq!(updated.status, ConnectorStatus::Connected);
    }

    #[tokio::test]
    async fn test_duplicate_name_rejected() {
        let repo = MockConnectorRepository::new();
        let c1 = test_connector(Uuid::new_v4(), "Same Name", ConnectorType::Splunk);
        let c2 = test_connector(Uuid::new_v4(), "Same Name", ConnectorType::Jira);

        repo.create(&c1).await.unwrap();
        let result = repo.create(&c2).await;

        assert!(matches!(result, Err(DbError::Constraint(_))));
    }
}
