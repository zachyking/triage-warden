//! Mock implementation of TenantRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::db::tenant_repo::{TenantFilter, TenantRepository, TenantUpdate};
use crate::db::DbError;
use crate::tenant::Tenant;

/// Mock implementation of TenantRepository using in-memory storage.
pub struct MockTenantRepository {
    tenants: Arc<RwLock<HashMap<Uuid, Tenant>>>,
}

impl Default for MockTenantRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTenantRepository {
    /// Creates a new mock repository.
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a mock repository pre-populated with tenants.
    pub fn with_tenants(tenants: Vec<Tenant>) -> Self {
        let map: HashMap<Uuid, Tenant> = tenants.into_iter().map(|t| (t.id, t)).collect();
        Self {
            tenants: Arc::new(RwLock::new(map)),
        }
    }

    /// Creates a mock repository with a default tenant already inserted.
    pub fn with_default_tenant() -> Self {
        let default_tenant = Tenant::with_id(
            Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            "default",
            "Default Organization",
        )
        .expect("Default tenant should be valid");
        Self::with_tenants(vec![default_tenant])
    }

    /// Gets a snapshot of all tenants in the mock.
    pub async fn snapshot(&self) -> Vec<Tenant> {
        self.tenants.read().await.values().cloned().collect()
    }

    /// Clears all tenants from the mock.
    pub async fn clear(&self) {
        self.tenants.write().await.clear();
    }
}

#[async_trait]
impl TenantRepository for MockTenantRepository {
    async fn create(&self, tenant: &Tenant) -> Result<Tenant, DbError> {
        let mut tenants = self.tenants.write().await;

        // Check for duplicate slug
        for existing in tenants.values() {
            if existing.slug == tenant.slug {
                return Err(DbError::Constraint(format!(
                    "Tenant with slug '{}' already exists",
                    tenant.slug
                )));
            }
        }

        tenants.insert(tenant.id, tenant.clone());
        Ok(tenant.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Tenant>, DbError> {
        let tenants = self.tenants.read().await;
        Ok(tenants.get(&id).cloned())
    }

    async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>, DbError> {
        let tenants = self.tenants.read().await;
        Ok(tenants.values().find(|t| t.slug == slug).cloned())
    }

    async fn list(&self, filter: &TenantFilter) -> Result<Vec<Tenant>, DbError> {
        let tenants = self.tenants.read().await;
        let mut result: Vec<Tenant> = tenants
            .values()
            .filter(|t| {
                if let Some(status) = &filter.status {
                    if t.status != *status {
                        return false;
                    }
                }
                if let Some(search) = &filter.search {
                    let search_lower = search.to_lowercase();
                    if !t.name.to_lowercase().contains(&search_lower)
                        && !t.slug.to_lowercase().contains(&search_lower)
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    async fn update(&self, id: Uuid, update: &TenantUpdate) -> Result<Tenant, DbError> {
        let mut tenants = self.tenants.write().await;

        let tenant = tenants.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "Tenant".to_string(),
            id: id.to_string(),
        })?;

        if let Some(name) = &update.name {
            tenant.name = name.clone();
        }

        if let Some(status) = update.status {
            tenant.status = status;
        }

        if let Some(settings) = &update.settings {
            tenant.settings = settings.clone();
        }

        tenant.updated_at = Utc::now();
        Ok(tenant.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let mut tenants = self.tenants.write().await;
        Ok(tenants.remove(&id).is_some())
    }

    async fn count(&self, filter: &TenantFilter) -> Result<u64, DbError> {
        let list = self.list(filter).await?;
        Ok(list.len() as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let tenants = self.tenants.read().await;
        Ok(!tenants.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::{TenantSettings, TenantStatus};

    fn test_tenant(slug: &str, name: &str) -> Tenant {
        Tenant::new(slug, name).expect("Valid tenant")
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let repo = MockTenantRepository::new();
        let tenant = test_tenant("acme-corp", "Acme Corporation");

        repo.create(&tenant).await.unwrap();

        let retrieved = repo.get(tenant.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().slug, "acme-corp");
    }

    #[tokio::test]
    async fn test_get_by_slug() {
        let repo = MockTenantRepository::new();
        let tenant = test_tenant("test-org", "Test Organization");
        repo.create(&tenant).await.unwrap();

        let found = repo.get_by_slug("test-org").await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "Test Organization");

        let not_found = repo.get_by_slug("nonexistent").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_duplicate_slug_rejected() {
        let repo = MockTenantRepository::new();
        let tenant1 = test_tenant("same-slug", "Organization One");
        let tenant2 = test_tenant("same-slug", "Organization Two");

        repo.create(&tenant1).await.unwrap();
        let result = repo.create(&tenant2).await;

        assert!(matches!(result, Err(DbError::Constraint(_))));
    }

    #[tokio::test]
    async fn test_list_with_status_filter() {
        let repo = MockTenantRepository::new();

        let active = test_tenant("active-org", "Active Organization");
        let mut suspended = test_tenant("suspended-org", "Suspended Organization");
        suspended.status = TenantStatus::Suspended;

        repo.create(&active).await.unwrap();
        repo.create(&suspended).await.unwrap();

        let filter = TenantFilter {
            status: Some(TenantStatus::Active),
            ..Default::default()
        };

        let result = repo.list(&filter).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].slug, "active-org");
    }

    #[tokio::test]
    async fn test_list_with_search_filter() {
        let repo = MockTenantRepository::new();

        repo.create(&test_tenant("acme-corp", "Acme Corporation"))
            .await
            .unwrap();
        repo.create(&test_tenant("globex-inc", "Globex Industries"))
            .await
            .unwrap();
        repo.create(&test_tenant("initech", "Initech"))
            .await
            .unwrap();

        let filter = TenantFilter {
            search: Some("corp".to_string()),
            ..Default::default()
        };

        let result = repo.list(&filter).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].slug, "acme-corp");
    }

    #[tokio::test]
    async fn test_update_tenant() {
        let repo = MockTenantRepository::new();
        let tenant = test_tenant("original-org", "Original Name");
        repo.create(&tenant).await.unwrap();

        let update = TenantUpdate {
            name: Some("Updated Name".to_string()),
            status: Some(TenantStatus::Suspended),
            settings: None,
        };

        let updated = repo.update(tenant.id, &update).await.unwrap();
        assert_eq!(updated.name, "Updated Name");
        assert_eq!(updated.status, TenantStatus::Suspended);
    }

    #[tokio::test]
    async fn test_update_tenant_settings() {
        let repo = MockTenantRepository::new();
        let tenant = test_tenant("settings-org", "Settings Organization");
        repo.create(&tenant).await.unwrap();

        let new_settings = TenantSettings {
            concurrency_limit: 50,
            ..TenantSettings::default()
        };

        let update = TenantUpdate {
            name: None,
            status: None,
            settings: Some(new_settings),
        };

        let updated = repo.update(tenant.id, &update).await.unwrap();
        assert_eq!(updated.settings.concurrency_limit, 50);
    }

    #[tokio::test]
    async fn test_update_nonexistent_tenant() {
        let repo = MockTenantRepository::new();
        let update = TenantUpdate::default();

        let result = repo.update(Uuid::new_v4(), &update).await;
        assert!(matches!(result, Err(DbError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_delete_tenant() {
        let repo = MockTenantRepository::new();
        let tenant = test_tenant("delete-me", "To Be Deleted");
        repo.create(&tenant).await.unwrap();

        let deleted = repo.delete(tenant.id).await.unwrap();
        assert!(deleted);

        let not_found = repo.get(tenant.id).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_tenant() {
        let repo = MockTenantRepository::new();
        let deleted = repo.delete(Uuid::new_v4()).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_count() {
        let repo = MockTenantRepository::new();

        repo.create(&test_tenant("org-one", "Organization One"))
            .await
            .unwrap();
        repo.create(&test_tenant("org-two", "Organization Two"))
            .await
            .unwrap();

        let count = repo.count(&TenantFilter::default()).await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_any_exist() {
        let repo = MockTenantRepository::new();

        assert!(!repo.any_exist().await.unwrap());

        repo.create(&test_tenant("first-org", "First Organization"))
            .await
            .unwrap();

        assert!(repo.any_exist().await.unwrap());
    }

    #[tokio::test]
    async fn test_get_default() {
        let repo = MockTenantRepository::with_default_tenant();

        let default = repo.get_default().await.unwrap();
        assert!(default.is_some());
        assert_eq!(default.unwrap().slug, "default");
    }

    #[tokio::test]
    async fn test_snapshot_and_clear() {
        let repo = MockTenantRepository::new();

        repo.create(&test_tenant("org-one", "Organization One"))
            .await
            .unwrap();
        repo.create(&test_tenant("org-two", "Organization Two"))
            .await
            .unwrap();

        let snapshot = repo.snapshot().await;
        assert_eq!(snapshot.len(), 2);

        repo.clear().await;
        assert!(!repo.any_exist().await.unwrap());
    }

    #[tokio::test]
    async fn test_with_tenants() {
        let tenants = vec![
            test_tenant("org-one", "Organization One"),
            test_tenant("org-two", "Organization Two"),
        ];

        let repo = MockTenantRepository::with_tenants(tenants);

        let count = repo.count(&TenantFilter::default()).await.unwrap();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_list_sorted_by_name() {
        let repo = MockTenantRepository::new();

        repo.create(&test_tenant("zzz-org", "Zzz Organization"))
            .await
            .unwrap();
        repo.create(&test_tenant("aaa-org", "Aaa Organization"))
            .await
            .unwrap();
        repo.create(&test_tenant("mmm-org", "Mmm Organization"))
            .await
            .unwrap();

        let result = repo.list(&TenantFilter::default()).await.unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].name, "Aaa Organization");
        assert_eq!(result[1].name, "Mmm Organization");
        assert_eq!(result[2].name, "Zzz Organization");
    }
}
