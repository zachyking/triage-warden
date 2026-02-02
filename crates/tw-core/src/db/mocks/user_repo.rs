//! Mock implementation of UserRepository for testing.

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::auth::{User, UserFilter, UserUpdate};
use crate::db::{DbError, UserRepository};

/// Mock implementation of UserRepository using in-memory storage.
pub struct MockUserRepository {
    users: Arc<RwLock<HashMap<Uuid, User>>>,
}

impl Default for MockUserRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl MockUserRepository {
    /// Creates a new mock repository.
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates a mock repository pre-populated with users.
    pub fn with_users(users: Vec<User>) -> Self {
        let map: HashMap<Uuid, User> = users.into_iter().map(|u| (u.id, u)).collect();
        Self {
            users: Arc::new(RwLock::new(map)),
        }
    }

    /// Gets a snapshot of all users in the mock.
    pub async fn snapshot(&self) -> Vec<User> {
        self.users.read().await.values().cloned().collect()
    }

    /// Clears all users from the mock.
    pub async fn clear(&self) {
        self.users.write().await.clear();
    }
}

#[async_trait]
impl UserRepository for MockUserRepository {
    async fn create(&self, user: &User) -> Result<User, DbError> {
        let mut users = self.users.write().await;

        // Check for duplicate email or username
        for existing in users.values() {
            if existing.email == user.email {
                return Err(DbError::Constraint(format!(
                    "User with email '{}' already exists",
                    user.email
                )));
            }
            if existing.username == user.username {
                return Err(DbError::Constraint(format!(
                    "User with username '{}' already exists",
                    user.username
                )));
            }
        }

        users.insert(user.id, user.clone());
        Ok(user.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<User>, DbError> {
        let users = self.users.read().await;
        Ok(users.get(&id).cloned())
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let users = self.users.read().await;
        Ok(users.values().find(|u| u.email == email).cloned())
    }

    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let users = self.users.read().await;
        Ok(users.values().find(|u| u.username == username).cloned())
    }

    async fn list(&self, filter: &UserFilter) -> Result<Vec<User>, DbError> {
        let users = self.users.read().await;
        let mut result: Vec<User> = users
            .values()
            .filter(|u| {
                if let Some(role) = &filter.role {
                    if u.role != *role {
                        return false;
                    }
                }
                if let Some(enabled) = filter.enabled {
                    if u.enabled != enabled {
                        return false;
                    }
                }
                if let Some(search) = &filter.search {
                    let search_lower = search.to_lowercase();
                    if !u.username.to_lowercase().contains(&search_lower)
                        && !u.email.to_lowercase().contains(&search_lower)
                        && !u
                            .display_name
                            .as_ref()
                            .map(|d| d.to_lowercase().contains(&search_lower))
                            .unwrap_or(false)
                    {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        result.sort_by(|a, b| a.username.cmp(&b.username));
        Ok(result)
    }

    async fn update(&self, id: Uuid, update: &UserUpdate) -> Result<User, DbError> {
        let mut users = self.users.write().await;

        // First, check if user exists
        if !users.contains_key(&id) {
            return Err(DbError::NotFound {
                entity: "User".to_string(),
                id: id.to_string(),
            });
        }

        // Check for duplicate email if email is being updated
        if let Some(email) = &update.email {
            for (other_id, other) in users.iter() {
                if *other_id != id && other.email == *email {
                    return Err(DbError::Constraint(format!(
                        "User with email '{}' already exists",
                        email
                    )));
                }
            }
        }

        // Check for duplicate username if username is being updated
        if let Some(username) = &update.username {
            for (other_id, other) in users.iter() {
                if *other_id != id && other.username == *username {
                    return Err(DbError::Constraint(format!(
                        "User with username '{}' already exists",
                        username
                    )));
                }
            }
        }

        // Now perform the update
        let user = users.get_mut(&id).unwrap();

        if let Some(email) = &update.email {
            user.email = email.clone();
        }

        if let Some(username) = &update.username {
            user.username = username.clone();
        }

        if let Some(role) = update.role {
            user.role = role;
        }

        if let Some(display_name) = &update.display_name {
            user.display_name = display_name.clone();
        }

        if let Some(enabled) = update.enabled {
            user.enabled = enabled;
        }

        user.updated_at = Utc::now();
        Ok(user.clone())
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), DbError> {
        let mut users = self.users.write().await;

        let user = users.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })?;

        user.password_hash = password_hash.to_string();
        user.updated_at = Utc::now();
        Ok(())
    }

    async fn update_last_login(&self, id: Uuid) -> Result<(), DbError> {
        let mut users = self.users.write().await;

        let user = users.get_mut(&id).ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })?;

        user.last_login_at = Some(Utc::now());
        user.updated_at = Utc::now();
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let mut users = self.users.write().await;
        Ok(users.remove(&id).is_some())
    }

    async fn count(&self, filter: &UserFilter) -> Result<u64, DbError> {
        let list = self.list(filter).await?;
        Ok(list.len() as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let users = self.users.read().await;
        Ok(!users.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Role;

    fn test_user(id: Uuid, username: &str, email: &str) -> User {
        User {
            id,
            email: email.to_string(),
            username: username.to_string(),
            password_hash: "hashed".to_string(),
            role: Role::Analyst,
            display_name: None,
            enabled: true,
            last_login_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get() {
        let repo = MockUserRepository::new();
        let user = test_user(Uuid::new_v4(), "testuser", "test@example.com");

        repo.create(&user).await.unwrap();

        let retrieved = repo.get(user.id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().username, "testuser");
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let repo = MockUserRepository::new();
        let user = test_user(Uuid::new_v4(), "testuser", "test@example.com");
        repo.create(&user).await.unwrap();

        let found = repo.get_by_email("test@example.com").await.unwrap();
        assert!(found.is_some());

        let not_found = repo.get_by_email("other@example.com").await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_duplicate_email_rejected() {
        let repo = MockUserRepository::new();
        let user1 = test_user(Uuid::new_v4(), "user1", "test@example.com");
        let user2 = test_user(Uuid::new_v4(), "user2", "test@example.com");

        repo.create(&user1).await.unwrap();
        let result = repo.create(&user2).await;

        assert!(matches!(result, Err(DbError::Constraint(_))));
    }

    #[tokio::test]
    async fn test_list_with_filter() {
        let repo = MockUserRepository::new();

        let admin = User {
            role: Role::Admin,
            ..test_user(Uuid::new_v4(), "admin", "admin@example.com")
        };
        let analyst = User {
            role: Role::Analyst,
            ..test_user(Uuid::new_v4(), "analyst", "analyst@example.com")
        };

        repo.create(&admin).await.unwrap();
        repo.create(&analyst).await.unwrap();

        let filter = UserFilter {
            role: Some(Role::Admin),
            ..Default::default()
        };

        let result = repo.list(&filter).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].username, "admin");
    }
}
