//! Asset & Identity Context Store.
//!
//! Provides storage traits and in-memory implementations for managing
//! assets, identities, and their relationships.

pub mod sync;

use crate::models::{
    Asset, Criticality, EntityRef, EntityRelationship, Environment, IdentifierType, Identity,
    IdentityStatus, RelationshipType,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Errors that can occur in the asset store.
#[derive(Error, Debug)]
pub enum AssetStoreError {
    /// Entity not found.
    #[error("Not found: {0}")]
    NotFound(String),
    /// Duplicate entity.
    #[error("Duplicate: {0}")]
    Duplicate(String),
    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for asset store operations.
pub type AssetStoreResult<T> = Result<T, AssetStoreError>;

/// Search parameters for querying assets.
#[derive(Debug, Default)]
pub struct AssetSearchParams {
    /// Filter by name (substring match).
    pub name: Option<String>,
    /// Filter by asset type.
    pub asset_type: Option<crate::models::AssetType>,
    /// Filter by criticality.
    pub criticality: Option<Criticality>,
    /// Filter by environment.
    pub environment: Option<Environment>,
    /// Filter by tag key-value pair.
    pub tag: Option<(String, String)>,
    /// Maximum results to return.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

/// Search parameters for querying identities.
#[derive(Debug, Default)]
pub struct IdentitySearchParams {
    /// Filter by display name (substring match).
    pub display_name: Option<String>,
    /// Filter by identity type.
    pub identity_type: Option<crate::models::IdentityType>,
    /// Filter by status.
    pub status: Option<IdentityStatus>,
    /// Filter by department.
    pub department: Option<String>,
    /// Filter by minimum risk score.
    pub min_risk_score: Option<f32>,
    /// Maximum results to return.
    pub limit: Option<usize>,
    /// Offset for pagination.
    pub offset: Option<usize>,
}

/// Trait for storing and retrieving assets.
#[async_trait]
pub trait AssetStore: Send + Sync {
    /// Find an asset by its unique ID.
    async fn find_by_id(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<Option<Asset>>;

    /// Find an asset by an identifier (hostname, IP, etc.).
    async fn find_by_identifier(
        &self,
        tenant_id: Uuid,
        identifier_type: &IdentifierType,
        value: &str,
    ) -> AssetStoreResult<Option<Asset>>;

    /// Search for assets matching the given parameters.
    async fn search(
        &self,
        tenant_id: Uuid,
        params: &AssetSearchParams,
    ) -> AssetStoreResult<Vec<Asset>>;

    /// Create a new asset.
    async fn create(&self, asset: &Asset) -> AssetStoreResult<()>;

    /// Update an existing asset.
    async fn update(&self, asset: &Asset) -> AssetStoreResult<()>;

    /// Delete an asset by ID.
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<bool>;

    /// List all assets for a tenant.
    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        limit: usize,
        offset: usize,
    ) -> AssetStoreResult<Vec<Asset>>;

    /// Count assets for a tenant.
    async fn count(&self, tenant_id: Uuid) -> AssetStoreResult<u64>;
}

/// Trait for storing and retrieving identities.
#[async_trait]
pub trait IdentityStore: Send + Sync {
    /// Find an identity by its unique ID.
    async fn find_by_id(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<Option<Identity>>;

    /// Find an identity by its primary identifier (username, email).
    async fn find_by_identifier(
        &self,
        tenant_id: Uuid,
        identifier: &str,
    ) -> AssetStoreResult<Option<Identity>>;

    /// Search for identities matching the given parameters.
    async fn search(
        &self,
        tenant_id: Uuid,
        params: &IdentitySearchParams,
    ) -> AssetStoreResult<Vec<Identity>>;

    /// Create a new identity.
    async fn create(&self, identity: &Identity) -> AssetStoreResult<()>;

    /// Update an existing identity.
    async fn update(&self, identity: &Identity) -> AssetStoreResult<()>;

    /// Count identities for a tenant.
    async fn count(&self, tenant_id: Uuid) -> AssetStoreResult<u64>;
}

/// Trait for storing and querying entity relationships.
#[async_trait]
pub trait RelationshipStore: Send + Sync {
    /// Find all relationships for a given entity.
    async fn find_relationships(
        &self,
        tenant_id: Uuid,
        entity: &EntityRef,
        relationship_type: Option<&RelationshipType>,
    ) -> AssetStoreResult<Vec<EntityRelationship>>;

    /// Add a new relationship.
    async fn add_relationship(&self, relationship: &EntityRelationship) -> AssetStoreResult<()>;

    /// Remove a relationship by ID.
    async fn remove_relationship(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<bool>;
}

// ============================================================================
// In-Memory Implementations (for testing)
// ============================================================================

/// In-memory implementation of AssetStore for testing.
pub struct InMemoryAssetStore {
    assets: Arc<RwLock<HashMap<Uuid, Asset>>>,
}

impl InMemoryAssetStore {
    /// Creates a new empty in-memory asset store.
    pub fn new() -> Self {
        Self {
            assets: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryAssetStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AssetStore for InMemoryAssetStore {
    async fn find_by_id(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<Option<Asset>> {
        let assets = self.assets.read().await;
        Ok(assets
            .get(&id)
            .filter(|a| a.tenant_id == tenant_id)
            .cloned())
    }

    async fn find_by_identifier(
        &self,
        tenant_id: Uuid,
        identifier_type: &IdentifierType,
        value: &str,
    ) -> AssetStoreResult<Option<Asset>> {
        let assets = self.assets.read().await;
        Ok(assets
            .values()
            .find(|a| a.tenant_id == tenant_id && a.matches_identifier(identifier_type, value))
            .cloned())
    }

    async fn search(
        &self,
        tenant_id: Uuid,
        params: &AssetSearchParams,
    ) -> AssetStoreResult<Vec<Asset>> {
        let assets = self.assets.read().await;
        let mut results: Vec<Asset> = assets
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .filter(|a| {
                if let Some(ref name) = params.name {
                    a.name.to_lowercase().contains(&name.to_lowercase())
                } else {
                    true
                }
            })
            .filter(|a| {
                if let Some(ref at) = params.asset_type {
                    &a.asset_type == at
                } else {
                    true
                }
            })
            .filter(|a| {
                if let Some(ref c) = params.criticality {
                    &a.criticality == c
                } else {
                    true
                }
            })
            .filter(|a| {
                if let Some(ref e) = params.environment {
                    &a.environment == e
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn create(&self, asset: &Asset) -> AssetStoreResult<()> {
        let mut assets = self.assets.write().await;
        if assets.contains_key(&asset.id) {
            return Err(AssetStoreError::Duplicate(format!(
                "Asset {} already exists",
                asset.id
            )));
        }
        assets.insert(asset.id, asset.clone());
        Ok(())
    }

    async fn update(&self, asset: &Asset) -> AssetStoreResult<()> {
        let mut assets = self.assets.write().await;
        if !assets.contains_key(&asset.id) {
            return Err(AssetStoreError::NotFound(format!(
                "Asset {} not found",
                asset.id
            )));
        }
        assets.insert(asset.id, asset.clone());
        Ok(())
    }

    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<bool> {
        let mut assets = self.assets.write().await;
        if let Some(asset) = assets.get(&id) {
            if asset.tenant_id == tenant_id {
                assets.remove(&id);
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn list_by_tenant(
        &self,
        tenant_id: Uuid,
        limit: usize,
        offset: usize,
    ) -> AssetStoreResult<Vec<Asset>> {
        let assets = self.assets.read().await;
        let mut results: Vec<Asset> = assets
            .values()
            .filter(|a| a.tenant_id == tenant_id)
            .cloned()
            .collect();
        results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn count(&self, tenant_id: Uuid) -> AssetStoreResult<u64> {
        let assets = self.assets.read().await;
        Ok(assets.values().filter(|a| a.tenant_id == tenant_id).count() as u64)
    }
}

/// In-memory implementation of IdentityStore for testing.
pub struct InMemoryIdentityStore {
    identities: Arc<RwLock<HashMap<Uuid, Identity>>>,
}

impl InMemoryIdentityStore {
    /// Creates a new empty in-memory identity store.
    pub fn new() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryIdentityStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl IdentityStore for InMemoryIdentityStore {
    async fn find_by_id(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<Option<Identity>> {
        let identities = self.identities.read().await;
        Ok(identities
            .get(&id)
            .filter(|i| i.tenant_id == tenant_id)
            .cloned())
    }

    async fn find_by_identifier(
        &self,
        tenant_id: Uuid,
        identifier: &str,
    ) -> AssetStoreResult<Option<Identity>> {
        let identities = self.identities.read().await;
        Ok(identities
            .values()
            .find(|i| i.tenant_id == tenant_id && i.primary_identifier == identifier)
            .cloned())
    }

    async fn search(
        &self,
        tenant_id: Uuid,
        params: &IdentitySearchParams,
    ) -> AssetStoreResult<Vec<Identity>> {
        let identities = self.identities.read().await;
        let mut results: Vec<Identity> = identities
            .values()
            .filter(|i| i.tenant_id == tenant_id)
            .filter(|i| {
                if let Some(ref name) = params.display_name {
                    i.display_name.to_lowercase().contains(&name.to_lowercase())
                } else {
                    true
                }
            })
            .filter(|i| {
                if let Some(ref it) = params.identity_type {
                    &i.identity_type == it
                } else {
                    true
                }
            })
            .filter(|i| {
                if let Some(ref s) = params.status {
                    &i.status == s
                } else {
                    true
                }
            })
            .filter(|i| {
                if let Some(ref dept) = params.department {
                    i.department.as_deref() == Some(dept.as_str())
                } else {
                    true
                }
            })
            .filter(|i| {
                if let Some(min) = params.min_risk_score {
                    i.risk_score >= min
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        results.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

        let offset = params.offset.unwrap_or(0);
        let limit = params.limit.unwrap_or(100);

        Ok(results.into_iter().skip(offset).take(limit).collect())
    }

    async fn create(&self, identity: &Identity) -> AssetStoreResult<()> {
        let mut identities = self.identities.write().await;
        if identities.contains_key(&identity.id) {
            return Err(AssetStoreError::Duplicate(format!(
                "Identity {} already exists",
                identity.id
            )));
        }
        identities.insert(identity.id, identity.clone());
        Ok(())
    }

    async fn update(&self, identity: &Identity) -> AssetStoreResult<()> {
        let mut identities = self.identities.write().await;
        if !identities.contains_key(&identity.id) {
            return Err(AssetStoreError::NotFound(format!(
                "Identity {} not found",
                identity.id
            )));
        }
        identities.insert(identity.id, identity.clone());
        Ok(())
    }

    async fn count(&self, tenant_id: Uuid) -> AssetStoreResult<u64> {
        let identities = self.identities.read().await;
        Ok(identities
            .values()
            .filter(|i| i.tenant_id == tenant_id)
            .count() as u64)
    }
}

/// In-memory implementation of RelationshipStore for testing.
pub struct InMemoryRelationshipStore {
    relationships: Arc<RwLock<HashMap<Uuid, EntityRelationship>>>,
}

impl InMemoryRelationshipStore {
    /// Creates a new empty in-memory relationship store.
    pub fn new() -> Self {
        Self {
            relationships: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemoryRelationshipStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RelationshipStore for InMemoryRelationshipStore {
    async fn find_relationships(
        &self,
        tenant_id: Uuid,
        entity: &EntityRef,
        relationship_type: Option<&RelationshipType>,
    ) -> AssetStoreResult<Vec<EntityRelationship>> {
        let relationships = self.relationships.read().await;
        Ok(relationships
            .values()
            .filter(|r| r.tenant_id == tenant_id && r.involves(&entity.entity_type, &entity.id))
            .filter(|r| {
                if let Some(rt) = relationship_type {
                    &r.relationship_type == rt
                } else {
                    true
                }
            })
            .cloned()
            .collect())
    }

    async fn add_relationship(&self, relationship: &EntityRelationship) -> AssetStoreResult<()> {
        let mut relationships = self.relationships.write().await;
        if relationships.contains_key(&relationship.id) {
            return Err(AssetStoreError::Duplicate(format!(
                "Relationship {} already exists",
                relationship.id
            )));
        }
        relationships.insert(relationship.id, relationship.clone());
        Ok(())
    }

    async fn remove_relationship(&self, tenant_id: Uuid, id: Uuid) -> AssetStoreResult<bool> {
        let mut relationships = self.relationships.write().await;
        if let Some(rel) = relationships.get(&id) {
            if rel.tenant_id == tenant_id {
                relationships.remove(&id);
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AssetIdentifier, AssetType, IdentityType};

    fn test_tenant() -> Uuid {
        Uuid::from_u128(0x12345678_1234_1234_1234_123456789012)
    }

    #[tokio::test]
    async fn test_asset_store_crud() {
        let store = InMemoryAssetStore::new();
        let tenant = test_tenant();

        let mut asset = Asset::new(
            tenant,
            "server-01".to_string(),
            AssetType::Server,
            Criticality::High,
            Environment::Production,
        );
        asset.add_identifier(AssetIdentifier::new(
            IdentifierType::Hostname,
            "server-01.corp.local".to_string(),
            "edr".to_string(),
        ));

        // Create
        store.create(&asset).await.unwrap();

        // Find by ID
        let found = store.find_by_id(tenant, asset.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "server-01");

        // Find by identifier
        let found = store
            .find_by_identifier(tenant, &IdentifierType::Hostname, "server-01.corp.local")
            .await
            .unwrap();
        assert!(found.is_some());

        // Update
        asset.criticality = Criticality::Critical;
        store.update(&asset).await.unwrap();
        let updated = store.find_by_id(tenant, asset.id).await.unwrap().unwrap();
        assert_eq!(updated.criticality, Criticality::Critical);

        // Count
        let count = store.count(tenant).await.unwrap();
        assert_eq!(count, 1);

        // Delete
        let deleted = store.delete(tenant, asset.id).await.unwrap();
        assert!(deleted);
        assert!(store.find_by_id(tenant, asset.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_asset_store_search() {
        let store = InMemoryAssetStore::new();
        let tenant = test_tenant();

        for i in 0..5 {
            let asset = Asset::new(
                tenant,
                format!("server-{:02}", i),
                AssetType::Server,
                if i < 3 {
                    Criticality::High
                } else {
                    Criticality::Low
                },
                Environment::Production,
            );
            store.create(&asset).await.unwrap();
        }

        // Search by criticality
        let params = AssetSearchParams {
            criticality: Some(Criticality::High),
            ..Default::default()
        };
        let results = store.search(tenant, &params).await.unwrap();
        assert_eq!(results.len(), 3);

        // Search by name
        let params = AssetSearchParams {
            name: Some("server-0".to_string()),
            ..Default::default()
        };
        let results = store.search(tenant, &params).await.unwrap();
        assert_eq!(results.len(), 5); // all match "server-0"

        // Pagination
        let params = AssetSearchParams {
            limit: Some(2),
            offset: Some(0),
            ..Default::default()
        };
        let results = store.search(tenant, &params).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_asset_store_tenant_isolation() {
        let store = InMemoryAssetStore::new();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();

        let asset1 = Asset::new(
            tenant1,
            "asset-1".to_string(),
            AssetType::Server,
            Criticality::High,
            Environment::Production,
        );
        let asset2 = Asset::new(
            tenant2,
            "asset-2".to_string(),
            AssetType::Server,
            Criticality::High,
            Environment::Production,
        );

        store.create(&asset1).await.unwrap();
        store.create(&asset2).await.unwrap();

        assert_eq!(store.count(tenant1).await.unwrap(), 1);
        assert_eq!(store.count(tenant2).await.unwrap(), 1);

        // Cannot see other tenant's assets
        assert!(store
            .find_by_id(tenant1, asset2.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn test_asset_store_duplicate() {
        let store = InMemoryAssetStore::new();
        let asset = Asset::new(
            test_tenant(),
            "dup".to_string(),
            AssetType::Server,
            Criticality::Low,
            Environment::Testing,
        );
        store.create(&asset).await.unwrap();
        assert!(store.create(&asset).await.is_err());
    }

    #[tokio::test]
    async fn test_identity_store_crud() {
        let store = InMemoryIdentityStore::new();
        let tenant = test_tenant();

        let mut identity = Identity::new(
            tenant,
            IdentityType::User,
            "jdoe@corp.com".to_string(),
            "John Doe".to_string(),
        );
        identity.department = Some("Engineering".to_string());

        // Create
        store.create(&identity).await.unwrap();

        // Find by ID
        let found = store.find_by_id(tenant, identity.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().display_name, "John Doe");

        // Find by identifier
        let found = store
            .find_by_identifier(tenant, "jdoe@corp.com")
            .await
            .unwrap();
        assert!(found.is_some());

        // Update
        identity.set_risk_score(75.0);
        store.update(&identity).await.unwrap();
        let updated = store
            .find_by_id(tenant, identity.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.risk_score, 75.0);

        // Count
        assert_eq!(store.count(tenant).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn test_identity_store_search() {
        let store = InMemoryIdentityStore::new();
        let tenant = test_tenant();

        for i in 0..5 {
            let mut identity = Identity::new(
                tenant,
                IdentityType::User,
                format!("user{}@corp.com", i),
                format!("User {}", i),
            );
            identity.department = Some("Engineering".to_string());
            if i >= 3 {
                identity.set_risk_score(80.0);
            }
            store.create(&identity).await.unwrap();
        }

        // Search by department
        let params = IdentitySearchParams {
            department: Some("Engineering".to_string()),
            ..Default::default()
        };
        let results = store.search(tenant, &params).await.unwrap();
        assert_eq!(results.len(), 5);

        // Search by min risk score
        let params = IdentitySearchParams {
            min_risk_score: Some(50.0),
            ..Default::default()
        };
        let results = store.search(tenant, &params).await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_relationship_store() {
        let store = InMemoryRelationshipStore::new();
        let tenant = test_tenant();
        let asset_id = Uuid::new_v4();
        let identity_id = Uuid::new_v4();

        let rel = EntityRelationship::new(
            tenant,
            EntityRef::identity(identity_id),
            EntityRef::asset(asset_id),
            RelationshipType::OwnerOf,
        );

        // Add
        store.add_relationship(&rel).await.unwrap();

        // Find by entity
        let results = store
            .find_relationships(tenant, &EntityRef::asset(asset_id), None)
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // Find by entity and type
        let results = store
            .find_relationships(
                tenant,
                &EntityRef::identity(identity_id),
                Some(&RelationshipType::OwnerOf),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 1);

        // Find with non-matching type
        let results = store
            .find_relationships(
                tenant,
                &EntityRef::identity(identity_id),
                Some(&RelationshipType::UsesAsset),
            )
            .await
            .unwrap();
        assert_eq!(results.len(), 0);

        // Remove
        let removed = store.remove_relationship(tenant, rel.id).await.unwrap();
        assert!(removed);
        let results = store
            .find_relationships(tenant, &EntityRef::asset(asset_id), None)
            .await
            .unwrap();
        assert_eq!(results.len(), 0);
    }
}
