//! Mock implementation of ApiKeyRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::ApiKey;
use crate::db::{ApiKeyFilter, ApiKeyRepository, DbError};

/// Mock implementation of ApiKeyRepository using in-memory storage.
pub struct MockApiKeyRepository {
    keys: Arc<RwLock<HashMap<Uuid, ApiKey>>>,
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

    /// Creates a mock repository pre-populated with API keys.
    pub fn with_keys(keys: Vec<ApiKey>) -> Self {
        let map: HashMap<Uuid, ApiKey> = keys.into_iter().map(|k| (k.id, k)).collect();
        Self {
            keys: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all keys in the mock.
    pub async fn snapshot(&self) -> Vec<ApiKey> {
        self.keys.read().await.values().cloned().collect()
    }

    /// Clears all keys from the mock.
    pub async fn clear(&self) {
        self.keys.write().await.clear();
    }
}

#[async_trait]
impl ApiKeyRepository for MockApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey, DbError> {
        let mut keys = self.keys.write().await;

        // Check for duplicate prefix
        for existing in keys.values() {
            if existing.key_prefix == api_key.key_prefix {
                return Err(DbError::Constraint(format!(
                    "API key with prefix '{}' already exists",
                    api_key.key_prefix
                )));
            }
        }

        keys.insert(api_key.id, api_key.clone());
        Ok(api_key.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        Ok(keys.get(&id).cloned())
    }

    async fn get_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        Ok(keys.values().find(|k| k.key_prefix == prefix).cloned())
    }

    async fn list(&self, filter: &ApiKeyFilter) -> Result<Vec<ApiKey>, DbError> {
        let keys = self.keys.read().await;
        let now = Utc::now();

        let mut result: Vec<ApiKey> = keys
            .values()
            .filter(|k| {
                if let Some(user_id) = &filter.user_id {
                    if k.user_id != *user_id {
                        return false;
                    }
                }
                if let Some(true) = filter.active_only {
                    if k.expires_at.map(|exp| exp < now).unwrap_or(false) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>, DbError> {
        self.list(&ApiKeyFilter {
            user_id: Some(user_id),
            active_only: None,
        })
        .await
    }

    async fn update_last_used(&self, id: Uuid) -> Result<(), DbError> {
        let mut keys = self.keys.write().await;

        let key = keys.get_mut(&id).ok_or_else(|| DbError::NotFound {
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

    async fn delete_by_user(&self, user_id: Uuid) -> Result<u64, DbError> {
        let mut keys = self.keys.write().await;
        let original_len = keys.len();
        keys.retain(|_, k| k.user_id != user_id);
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
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_abc123");

        repo.create(&key).await.unwrap();

        let retrieved = repo.get(key.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().key_prefix, "tw_abc123");
    }

    #[tokio::test]
    async fn test_get_by_prefix() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();
        let key = test_api_key(Uuid::new_v4(), user_id, "tw_xyz789");
        repo.create(&key).await.unwrap();

        let found = repo.get_by_prefix("tw_xyz789").await.unwrap();
        assert!(found.is_some());

        let not_found = repo.get_by_prefix("tw_notfound").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_list_by_user() {
        let repo = MockApiKeyRepository::new();
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        repo.create(&test_api_key(Uuid::new_v4(), user1, "tw_key1"))
            .await
            .unwrap();
        repo.create(&test_api_key(Uuid::new_v4(), user1, "tw_key2"))
            .await
            .unwrap();
        repo.create(&test_api_key(Uuid::new_v4(), user2, "tw_key3"))
            .await
            .unwrap();

        let user1_keys = repo.list_by_user(user1).await.unwrap();
        assert_eq!(user1_keys.len(), 2);

        let user2_keys = repo.list_by_user(user2).await.unwrap();
        assert_eq!(user2_keys.len(), 1);
    }

    #[tokio::test]
    async fn test_active_only_filter() {
        let repo = MockApiKeyRepository::new();
        let user_id = Uuid::new_v4();

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

        repo.create(&expired_key).await.unwrap();
        repo.create(&valid_key).await.unwrap();

        let filter = ApiKeyFilter {
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
        let user1 = Uuid::new_v4();
        let user2 = Uuid::new_v4();

        repo.create(&test_api_key(Uuid::new_v4(), user1, "tw_key1"))
            .await
            .unwrap();
        repo.create(&test_api_key(Uuid::new_v4(), user1, "tw_key2"))
            .await
            .unwrap();
        repo.create(&test_api_key(Uuid::new_v4(), user2, "tw_key3"))
            .await
            .unwrap();

        let deleted = repo.delete_by_user(user1).await.unwrap();
        assert_eq!(deleted, 2);

        let remaining = repo.list(&ApiKeyFilter::default()).await.unwrap();
        assert_eq!(remaining.len(), 1);
    }
}
