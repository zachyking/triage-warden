//! Mock implementation of ConnectorRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::connector::{ConnectorConfig, ConnectorStatus, ConnectorType};
use crate::db::{ConnectorFilter, ConnectorRepository, ConnectorUpdate, DbError};

/// Storage type for connectors with tenant association.
type ConnectorStorage = HashMap<Uuid, (Option<Uuid>, ConnectorConfig)>;

/// Mock implementation of ConnectorRepository using in-memory storage.
/// Stores connectors with optional tenant_id association.
pub struct MockConnectorRepository {
    connectors: Arc<RwLock<ConnectorStorage>>,
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

    /// Creates a mock repository pre-populated with connectors (no tenant association).
    pub fn with_connectors(connectors: Vec<ConnectorConfig>) -> Self {
        let map: HashMap<Uuid, (Option<Uuid>, ConnectorConfig)> =
            connectors.into_iter().map(|c| (c.id, (None, c))).collect();
        Self {
            connectors: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all connectors in the mock.
    pub async fn snapshot(&self) -> Vec<ConnectorConfig> {
        self.connectors
            .read()
            .await
            .values()
            .map(|(_, c)| c.clone())
            .collect()
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

        // Check for duplicate names (across all tenants for backward compatibility)
        for (_, (_, existing)) in connectors.iter() {
            if existing.name == connector.name {
                return Err(DbError::Constraint(format!(
                    "Connector with name '{}' already exists",
                    connector.name
                )));
            }
        }

        connectors.insert(connector.id, (None, connector.clone()));
        Ok(connector.clone())
    }

    async fn create_for_tenant(
        &self,
        tenant_id: Uuid,
        connector: &ConnectorConfig,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        if connectors.contains_key(&connector.id) {
            return Err(DbError::Constraint(format!(
                "Connector with id '{}' already exists",
                connector.id
            )));
        }

        // Check for duplicate names within the same tenant
        for (_, (tid, existing)) in connectors.iter() {
            if *tid == Some(tenant_id) && existing.name == connector.name {
                return Err(DbError::Constraint(format!(
                    "Connector with name '{}' already exists for tenant",
                    connector.name
                )));
            }
        }

        connectors.insert(connector.id, (Some(tenant_id), connector.clone()));
        Ok(connector.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        Ok(connectors.get(&id).map(|(_, c)| c.clone()))
    }

    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        Ok(connectors.get(&id).and_then(|(tid, c)| {
            if *tid == Some(tenant_id) {
                Some(c.clone())
            } else {
                None
            }
        }))
    }

    async fn list(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> =
            connectors.values().map(|(_, c)| c.clone()).collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_for_tenant(&self, tenant_id: Uuid) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter_map(|(tid, c)| {
                if *tid == Some(tenant_id) {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect();
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
            .filter(|(_, c)| c.connector_type == connector_type)
            .map(|(_, c)| c.clone())
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_by_type_for_tenant(
        &self,
        connector_type: ConnectorType,
        tenant_id: Uuid,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter_map(|(tid, c)| {
                if *tid == Some(tenant_id) && c.connector_type == connector_type {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_enabled(&self) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter(|(_, c)| c.enabled)
            .map(|(_, c)| c.clone())
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_enabled_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter_map(|(tid, c)| {
                if *tid == Some(tenant_id) && c.enabled {
                    Some(c.clone())
                } else {
                    None
                }
            })
            .collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn list_filtered(
        &self,
        filter: &ConnectorFilter,
    ) -> Result<Vec<ConnectorConfig>, DbError> {
        let connectors = self.connectors.read().await;
        let mut result: Vec<ConnectorConfig> = connectors
            .values()
            .filter_map(|(tid, c)| {
                // Filter by tenant_id if specified
                if let Some(filter_tenant) = filter.tenant_id {
                    if *tid != Some(filter_tenant) {
                        return None;
                    }
                }

                // Filter by connector_type if specified
                if let Some(filter_type) = &filter.connector_type {
                    if c.connector_type != *filter_type {
                        return None;
                    }
                }

                // Filter by enabled if specified
                if let Some(filter_enabled) = filter.enabled {
                    if c.enabled != filter_enabled {
                        return None;
                    }
                }

                Some(c.clone())
            })
            .collect();
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
            for (other_id, (_, other)) in connectors.iter() {
                if *other_id != id && other.name == *name {
                    return Err(DbError::Constraint(format!(
                        "Connector with name '{}' already exists",
                        name
                    )));
                }
            }
        }

        // Now perform the update
        let (_, connector) = connectors.get_mut(&id).unwrap();

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

    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &ConnectorUpdate,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        // First, check if connector exists for this tenant
        let exists_for_tenant = connectors
            .get(&id)
            .map(|(tid, _)| *tid == Some(tenant_id))
            .unwrap_or(false);

        if !exists_for_tenant {
            return Err(DbError::NotFound {
                entity: "Connector".to_string(),
                id: id.to_string(),
            });
        }

        // Check for duplicate name if name is being updated (within same tenant)
        if let Some(name) = &update.name {
            for (other_id, (tid, other)) in connectors.iter() {
                if *other_id != id && *tid == Some(tenant_id) && other.name == *name {
                    return Err(DbError::Constraint(format!(
                        "Connector with name '{}' already exists for tenant",
                        name
                    )));
                }
            }
        }

        // Now perform the update
        let (_, connector) = connectors.get_mut(&id).unwrap();

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

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let mut connectors = self.connectors.write().await;

        // Check if the connector exists for this tenant
        let exists_for_tenant = connectors
            .get(&id)
            .map(|(tid, _)| *tid == Some(tenant_id))
            .unwrap_or(false);

        if exists_for_tenant {
            connectors.remove(&id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn update_status(
        &self,
        id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        let (_, connector) = connectors.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })?;

        connector.status = status;
        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }

    async fn update_status_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        status: ConnectorStatus,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        // Check if the connector exists for this tenant
        let exists_for_tenant = connectors
            .get(&id)
            .map(|(tid, _)| *tid == Some(tenant_id))
            .unwrap_or(false);

        if !exists_for_tenant {
            return Err(DbError::NotFound {
                entity: "Connector".to_string(),
                id: id.to_string(),
            });
        }

        let (_, connector) = connectors.get_mut(&id).unwrap();
        connector.status = status;
        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }

    async fn update_health_check(&self, id: Uuid) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        let (_, connector) = connectors.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Connector".to_string(),
            id: id.to_string(),
        })?;

        connector.last_health_check = Some(Utc::now());
        connector.updated_at = Utc::now();
        Ok(connector.clone())
    }

    async fn update_health_check_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<ConnectorConfig, DbError> {
        let mut connectors = self.connectors.write().await;

        // Check if the connector exists for this tenant
        let exists_for_tenant = connectors
            .get(&id)
            .map(|(tid, _)| *tid == Some(tenant_id))
            .unwrap_or(false);

        if !exists_for_tenant {
            return Err(DbError::NotFound {
                entity: "Connector".to_string(),
                id: id.to_string(),
            });
        }

        let (_, connector) = connectors.get_mut(&id).unwrap();
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
    async fn test_create_for_tenant_and_get() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();
        let connector = test_connector(Uuid::new_v4(), "Test Splunk", ConnectorType::Splunk);

        repo.create_for_tenant(tenant_id, &connector).await.unwrap();

        // Should be visible via get_for_tenant
        let retrieved = repo.get_for_tenant(connector.id, tenant_id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Splunk");

        // Should NOT be visible for a different tenant
        let other_tenant = Uuid::new_v4();
        let retrieved = repo
            .get_for_tenant(connector.id, other_tenant)
            .await
            .unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_list_for_tenant() {
        let repo = MockConnectorRepository::new();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();

        repo.create_for_tenant(
            tenant1,
            &test_connector(Uuid::new_v4(), "T1 Splunk", ConnectorType::Splunk),
        )
        .await
        .unwrap();
        repo.create_for_tenant(
            tenant2,
            &test_connector(Uuid::new_v4(), "T2 Jira", ConnectorType::Jira),
        )
        .await
        .unwrap();

        let tenant1_connectors = repo.list_for_tenant(tenant1).await.unwrap();
        assert_eq!(tenant1_connectors.len(), 1);
        assert_eq!(tenant1_connectors[0].name, "T1 Splunk");

        let tenant2_connectors = repo.list_for_tenant(tenant2).await.unwrap();
        assert_eq!(tenant2_connectors.len(), 1);
        assert_eq!(tenant2_connectors[0].name, "T2 Jira");
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
    async fn test_list_by_type_for_tenant() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();

        repo.create_for_tenant(
            tenant_id,
            &test_connector(Uuid::new_v4(), "T Splunk 1", ConnectorType::Splunk),
        )
        .await
        .unwrap();
        repo.create_for_tenant(
            tenant_id,
            &test_connector(Uuid::new_v4(), "T Jira", ConnectorType::Jira),
        )
        .await
        .unwrap();

        // Create one for another tenant
        let other_tenant = Uuid::new_v4();
        repo.create_for_tenant(
            other_tenant,
            &test_connector(Uuid::new_v4(), "Other Splunk", ConnectorType::Splunk),
        )
        .await
        .unwrap();

        let splunk = repo
            .list_by_type_for_tenant(ConnectorType::Splunk, tenant_id)
            .await
            .unwrap();
        assert_eq!(splunk.len(), 1);
        assert_eq!(splunk[0].name, "T Splunk 1");
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
    async fn test_list_enabled_for_tenant() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();

        let enabled = test_connector(Uuid::new_v4(), "Enabled", ConnectorType::Splunk);
        let mut disabled = test_connector(Uuid::new_v4(), "Disabled", ConnectorType::Splunk);
        disabled.enabled = false;

        repo.create_for_tenant(tenant_id, &enabled).await.unwrap();
        repo.create_for_tenant(tenant_id, &disabled).await.unwrap();

        let enabled_list = repo.list_enabled_for_tenant(tenant_id).await.unwrap();
        assert_eq!(enabled_list.len(), 1);
        assert_eq!(enabled_list[0].name, "Enabled");
    }

    #[tokio::test]
    async fn test_list_filtered() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();

        let mut connector = test_connector(Uuid::new_v4(), "Test", ConnectorType::Splunk);
        connector.enabled = true;
        repo.create_for_tenant(tenant_id, &connector).await.unwrap();

        // Filter by tenant and type
        let filter = ConnectorFilter {
            tenant_id: Some(tenant_id),
            connector_type: Some(ConnectorType::Splunk),
            enabled: Some(true),
        };
        let result = repo.list_filtered(&filter).await.unwrap();
        assert_eq!(result.len(), 1);

        // Filter by wrong type
        let filter = ConnectorFilter {
            tenant_id: Some(tenant_id),
            connector_type: Some(ConnectorType::Jira),
            enabled: None,
        };
        let result = repo.list_filtered(&filter).await.unwrap();
        assert_eq!(result.len(), 0);
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
    async fn test_update_status_for_tenant() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();
        let connector = test_connector(Uuid::new_v4(), "Test", ConnectorType::Splunk);
        repo.create_for_tenant(tenant_id, &connector).await.unwrap();

        let updated = repo
            .update_status_for_tenant(connector.id, tenant_id, ConnectorStatus::Connected)
            .await
            .unwrap();
        assert_eq!(updated.status, ConnectorStatus::Connected);

        // Should fail for wrong tenant
        let other_tenant = Uuid::new_v4();
        let result = repo
            .update_status_for_tenant(connector.id, other_tenant, ConnectorStatus::Error)
            .await;
        assert!(matches!(result, Err(DbError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_delete_for_tenant() {
        let repo = MockConnectorRepository::new();
        let tenant_id = Uuid::new_v4();
        let connector = test_connector(Uuid::new_v4(), "Test", ConnectorType::Splunk);
        repo.create_for_tenant(tenant_id, &connector).await.unwrap();

        // Should fail for wrong tenant
        let other_tenant = Uuid::new_v4();
        let deleted = repo
            .delete_for_tenant(connector.id, other_tenant)
            .await
            .unwrap();
        assert!(!deleted);

        // Should succeed for correct tenant
        let deleted = repo
            .delete_for_tenant(connector.id, tenant_id)
            .await
            .unwrap();
        assert!(deleted);

        // Verify it's gone
        let retrieved = repo.get(connector.id).await.unwrap();
        assert!(retrieved.is_none());
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
