//! Mock implementation of ApiKeyRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::ApiKey;
use crate::db::{ApiKeyFilter, ApiKeyRepository, DbError};

/// Storage type for API keys with tenant association.
type ApiKeyStorage = HashMap<Uuid, (Option<Uuid>, ApiKey)>;

/// Mock implementation of ApiKeyRepository using in-memory storage.
/// Stores API keys with optional tenant_id association.
pub struct MockApiKeyRepository {
    keys: Arc<RwLock<ApiKeyStorage>>,
}

impl Default for MockApiKeyRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockApiKeyRepository {
    /// Creates a new mock repository.
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a mock repository pre-populated with API keys (no tenant association).
    pub fn with_keys(keys: Vec<ApiKey>) -> Self {
        let map: HashMap<Uuid, (Option<Uuid>, ApiKey)> =
            keys.into_iter().map(|k| (k.id, (None, k))).collect();
        Self {
            keys: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all keys in the mock.
    pub async fn snapshot(&self) -> Vec<ApiKey> {
        self.keys
            .read()
            .await
            .values()
            .map(|(_, k)| k.clone())
            .collect()
    }

    /// Clears all keys from the mock.
    pub async fn clear(&self) {
        self.keys.write().await.clear();
    }
}

#[async_trait]
impl ApiKeyRepository for MockApiKeyRepository {
    async fn create(&self, tenant_id: Uuid, api_key: &ApiKey) -> Result<ApiKey, DbError> {
        let mut keys = self.keys.write().await;

        // Check for duplicate prefix (within the same tenant)
        for (tid, existing) in keys.values() {
            if *tid == Some(tenant_id) && existing.key_prefix == api_key.key_prefix {
                return Err(DbError::Constraint(format!(
                    "API key with prefix '{}' already exists for tenant",
                    api_key.key_prefix
                )));
            }
        }

        keys.insert(api_key.id, (Some(tenant_id), api_key.clone()));
        Ok(api_key.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        Ok(keys.get(&id).map(|(_, k)| k.clone()))
    }

    async fn get_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<Option<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        Ok(keys.get(&id).and_then(|(tid, k)| {
            if *tid == Some(tenant_id) {
                Some(k.clone())
            } else {
                None
            }
        }))
    }

    async fn get_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        Ok(keys
            .values()
            .find(|(_, k)| k.key_prefix == prefix)
            .map(|(_, k)| k.clone()))
    }

    async fn list(&self, filter: &ApiKeyFilter) -> Result<Vec<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        let now = Utc::now();

        let mut result: Vec<ApiKey> = keys
            .values()
            .filter_map(|(tid, k)| {
                // Filter by tenant_id if specified
                if let Some(filter_tenant) = filter.tenant_id {
                    if *tid != Some(filter_tenant) {
                        return None;
                    }
                }
                // Filter by user_id if specified
                if let Some(user_id) = &filter.user_id {
                    if k.user_id != *user_id {
                        return None;
                    }
                }
                // Filter by active_only if specified
                if let Some(true) = filter.active_only {
                    if k.expires_at.map(|exp| exp < now).unwrap_or(false) {
                        return None;
                    }
                }
                Some(k.clone())
            })
            .collect();

        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>, DbError> {
        self.list(&ApiKeyFilter {
            tenant_id: None,
            user_id: Some(user_id),
            active_only: None,
        })
        .await
    }

    async fn list_by_user_for_tenant(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<ApiKey>, DbError> {
        self.list(&ApiKeyFilter {
            tenant_id: Some(tenant_id),
            user_id: Some(user_id),
            active_only: None,
        })
        .await
    }

    async fn update_last_used(&self, id: Uuid) -> Result<(), DbError> {
        let mut keys = self.keys.write().await;

        let (_, key) = keys.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "ApiKey".to_string(),
            id: id.to_string(),
        })?;

        key.last_used_at = Some(Utc::now());
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let mut keys = self.keys.write().await;
        Ok(keys.remove(&id).is_some())
    }

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let mut keys = self.keys.write().await;

        // Check if the key exists for this tenant
        let exists_for_tenant = keys
            .get(&id)
            .map(|(tid, _)| *tid == Some(tenant_id))
            .unwrap_or(false);

        if exists_for_tenant {
            keys.remove(&id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let mut keys = self.keys.write().await;
        let original_len = keys.len();
        keys.retain(|_, (_, k)| k.user_id != user_id);
        Ok((original_len - keys.len()) as u64)
    }

    async fn delete_by_user_for_tenant(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<u64, DbError> {
        let mut keys = self.keys.write().await;
        let original_len = keys.len();
        keys.retain(|_, (tid, k)| !(*tid == Some(tenant_id) && k.user_id == user_id));
        Ok((original_len - keys.len()) as u64)
    }

    async fn count(&self, filter: &ApiKeyFilter) -> Result<u64, DbError> {
        let list = self.list(filter).await?;
        Ok(list.len() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn test_api_key(id: Uuid, user_id: Uuid, prefix: &str) -> ApiKey {
        ApiKey {
            id,
            user_id,
            name: format!("Test Key {}", prefix),
            key_hash: "hashed_key".to_string(),
            key_prefix: prefix.to_string(),
            scopes: vec!["read".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_abc123");

        repo.create(tenant_id, &key).await.unwrap();

        let retrieved = repo.get(key.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().key_prefix, "tw_abc123");
    }

    #[tokio::test]
    async fn test_get_for_tenant() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_abc123");

        repo.create(tenant_id, &key).await.unwrap();

        // Should be visible for correct tenant
        let retrieved = repo.get_for_tenant(key.id, tenant_id).await.unwrap();
        assert!(retrieved.is_some());

        // Should NOT be visible for different tenant
        let retrieved = repo.get_for_tenant(key.id, other_tenant).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_get_by_prefix() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_xyz789");
        repo.create(tenant_id, &key).await.unwrap();

        let found = repo.get_by_prefix("tw_xyz789").await.unwrap();
        assert!(found.is_some());

        let not_found = repo.get_by_prefix("tw_notfound").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_list_by_user() {
        let repo = MockApiKeyRepository::new();
        let tenant_id = Uuid::new_v4();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user1, "tw_key1"))
            .await
            .unwrap();
        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user1, "tw_key2"))
            .await
            .unwrap();
        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user2, "tw_key3"))
            .await
            .unwrap();

        let user1_keys = repo.list_by_user(user1).await.unwrap();
        assert_eq!(user1_keys.len(), 2);

        let user2_keys = repo.list_by_user(user2).await.unwrap();
        assert_eq!(user2_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_list_by_user_for_tenant() {
        let repo = MockApiKeyRepository::new();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        repo.create(tenant1, &test_api_key(Uuid::new_v4(), user_id, "tw_t1k1"))
            .await
            .unwrap();
        repo.create(tenant2, &test_api_key(Uuid::new_v4(), user_id, "tw_t2k1"))
            .await
            .unwrap();

        let tenant1_keys = repo
            .list_by_user_for_tenant(user_id, tenant1)
            .await
            .unwrap();
        assert_eq!(tenant1_keys.len(), 1);
        assert_eq!(tenant1_keys[0].key_prefix, "tw_t1k1");

        let tenant2_keys = repo
            .list_by_user_for_tenant(user_id, tenant2)
            .await
            .unwrap();
        assert_eq!(tenant2_keys.len(), 1);
        assert_eq!(tenant2_keys[0].key_prefix, "tw_t2k1");
    }

    #[tokio::test]
    async fn test_active_only_filter() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        // Create an expired key
        let expired_key = ApiKey {
            expires_at: Some(Utc::now() - Duration::hours(1)),
            ..test_api_key(Uuid::new_v4(), user_id, "tw_expired")
        };

        // Create a valid key
        let valid_key = ApiKey {
            expires_at: Some(Utc::now() + Duration::hours(1)),
            ..test_api_key(Uuid::new_v4(), user_id, "tw_valid")
        };

        repo.create(tenant_id, &expired_key).await.unwrap();
        repo.create(tenant_id, &valid_key).await.unwrap();

        let filter = ApiKeyFilter {
            tenant_id: Some(tenant_id),
            user_id: Some(user_id),
            active_only: Some(true),
        };

        let active_keys = repo.list(&filter).await.unwrap();
        assert_eq!(active_keys.len(), 1);
        assert_eq!(active_keys[0].key_prefix, "tw_valid");
    }

    #[tokio::test]
    async fn test_delete_by_user() {
        let repo = MockApiKeyRepository::new();
        let tenant_id = Uuid::new_v4();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user1, "tw_key1"))
            .await
            .unwrap();
        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user1, "tw_key2"))
            .await
            .unwrap();
        repo.create(tenant_id, &test_api_key(Uuid::new_v4(), user2, "tw_key3"))
            .await
            .unwrap();

        let deleted = repo.delete_by_user(user1).await.unwrap();
        assert_eq!(deleted, 2);

        let remaining = repo.list(&ApiKeyFilter::default()).await.unwrap();
        assert_eq!(remaining.len(), 1);
    }

    #[tokio::test]
    async fn test_delete_by_user_for_tenant() {
        let repo = MockApiKeyRepository::new();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let user_id = Uuid::new_v4();

        repo.create(tenant1, &test_api_key(Uuid::new_v4(), user_id, "tw_t1k1"))
            .await
            .unwrap();
        repo.create(tenant1, &test_api_key(Uuid::new_v4(), user_id, "tw_t1k2"))
            .await
            .unwrap();
        repo.create(tenant2, &test_api_key(Uuid::new_v4(), user_id, "tw_t2k1"))
            .await
            .unwrap();

        let deleted = repo
            .delete_by_user_for_tenant(user_id, tenant1)
            .await
            .unwrap();
        assert_eq!(deleted, 2);

        // Tenant2 key should still exist
        let remaining = repo.list(&ApiKeyFilter::default()).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].key_prefix, "tw_t2k1");
    }

    #[tokio::test]
    async fn test_delete_for_tenant() {
        let repo = MockApiKeyRepository::new();
        let tenant_id = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_todelete");

        repo.create(tenant_id, &key).await.unwrap();

        // Should fail for wrong tenant
        let deleted = repo.delete_for_tenant(key.id, other_tenant).await.unwrap();
        assert!(!deleted);

        // Should succeed for correct tenant
        let deleted = repo.delete_for_tenant(key.id, tenant_id).await.unwrap();
        assert!(deleted);

        let not_found = repo.get(key.id).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_single_key() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_todelete");
        repo.create(tenant_id, &key).await.unwrap();

        let deleted = repo.delete(key.id).await.unwrap();
        assert!(deleted);

        let not_found = repo.get(key.id).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let repo = MockApiKeyRepository::new();
        let deleted = repo.delete(Uuid::new_v4()).await.unwrap();
        assert!(!deleted);
    }

    #[tokio::test]
    async fn test_update_last_used() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_used");
        repo.create(tenant_id, &key).await.unwrap();

        assert!(repo
            .get(key.id)
            .await
            .unwrap()
            .unwrap()
            .last_used_at
            .is_none());

        repo.update_last_used(key.id).await.unwrap();

        let updated = repo.get(key.id).await.unwrap().unwrap();
        assert!(updated.last_used_at.is_some());
    }

    #[tokio::test]
    async fn test_duplicate_prefix_rejected_same_tenant() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let key1 = test_api_key(Uuid::new_v4(), user_id, "tw_same");
        let key2 = test_api_key(Uuid::new_v4(), user_id, "tw_same");

        repo.create(tenant_id, &key1).await.unwrap();
        let result = repo.create(tenant_id, &key2).await;

        assert!(matches!(result, Err(DbError::Constraint(_))));
    }

    #[tokio::test]
    async fn test_same_prefix_allowed_different_tenants() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant1 = Uuid::new_v4();
        let tenant2 = Uuid::new_v4();
        let key1 = test_api_key(Uuid::new_v4(), user_id, "tw_same");
        let key2 = test_api_key(Uuid::new_v4(), user_id, "tw_same");

        repo.create(tenant1, &key1).await.unwrap();
        // Should succeed for different tenant
        let result = repo.create(tenant2, &key2).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_key_without_expiry_always_active() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        // Key with no expiry
        let key = ApiKey {
            expires_at: None,
            ..test_api_key(Uuid::new_v4(), user_id, "tw_noexpiry")
        };

        repo.create(tenant_id, &key).await.unwrap();

        let filter = ApiKeyFilter {
            tenant_id: None,
            active_only: Some(true),
            user_id: None,
        };

        let active_keys = repo.list(&filter).await.unwrap();
        assert_eq!(active_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_count_keys() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();

        for i in 0..5 {
            repo.create(
                tenant_id,
                &test_api_key(Uuid::new_v4(), user_id, &format!("tw_key{}", i)),
            )
            .await
            .unwrap();
        }

        let count = repo.count(&ApiKeyFilter::default()).await.unwrap();
        assert_eq!(count, 5);
    }

    #[tokio::test]
    async fn test_with_keys_constructor() {
        let user_id = Uuid::new_v4();
        let keys = vec![
            test_api_key(Uuid::new_v4(), user_id, "tw_pre1"),
            test_api_key(Uuid::new_v4(), user_id, "tw_pre2"),
        ];

        let repo = MockApiKeyRepository::with_keys(keys);

        let all_keys = repo.list(&ApiKeyFilter::default()).await.unwrap();
        assert_eq!(all_keys.len(), 2);
    }
}
