//! User repository for database operations.

use super::{DbError, DbPool};
use crate::auth::{Role, User, UserFilter, UserUpdate};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for user persistence.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Creates a new user.
    async fn create(&self, user: &User) -> Result<User, DbError>;

    /// Gets a user by ID.
    async fn get(&self, id: Uuid) -> Result<Option<User>, DbError>;

    /// Gets a user by email.
    async fn get_by_email(&self, email: &str) -> Result<Option<User>, DbError>;

    /// Gets a user by username.
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DbError>;

    /// Lists users with optional filtering.
    async fn list(&self, filter: &UserFilter) -> Result<Vec<User>, DbError>;

    /// Updates a user.
    async fn update(&self, id: Uuid, update: &UserUpdate) -> Result<User, DbError>;

    /// Updates a user's password hash.
    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), DbError>;

    /// Updates a user's last login timestamp.
    async fn update_last_login(&self, id: Uuid) -> Result<(), DbError>;

    /// Deletes a user.
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Counts users matching a filter.
    async fn count(&self, filter: &UserFilter) -> Result<u64, DbError>;

    /// Checks if any users exist (for initial setup).
    async fn any_exist(&self) -> Result<bool, DbError>;
}

/// SQLite implementation of UserRepository.
#[cfg(feature = "database")]
pub struct SqliteUserRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteUserRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl UserRepository for SqliteUserRepository {
    async fn create(&self, user: &User) -> Result<User, DbError> {
        let id = user.id.to_string();
        let role = user.role.as_str();
        let created_at = user.created_at.to_rfc3339();
        let updated_at = user.updated_at.to_rfc3339();
        let last_login_at = user.last_login_at.map(|t| t.to_rfc3339());

        sqlx::query(
            r#"
            INSERT INTO users (id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(role)
        .bind(&user.display_name)
        .bind(user.enabled)
        .bind(&last_login_at)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(user.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<User>, DbError> {
        let id_str = id.to_string();
        let row: Option<SqliteUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let row: Option<SqliteUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE email = ?",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let row: Option<SqliteUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &UserFilter) -> Result<Vec<User>, DbError> {
        let mut query = String::from(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE 1=1",
        );
        let mut params: Vec<String> = Vec::new();

        if let Some(role) = &filter.role {
            query.push_str(" AND role = ?");
            params.push(role.as_str().to_string());
        }

        if let Some(enabled) = filter.enabled {
            query.push_str(" AND enabled = ?");
            params.push(if enabled {
                "1".to_string()
            } else {
                "0".to_string()
            });
        }

        if let Some(search) = &filter.search {
            query.push_str(" AND (username LIKE ? OR email LIKE ? OR display_name LIKE ?)");
            let pattern = format!("%{}%", search);
            params.push(pattern.clone());
            params.push(pattern.clone());
            params.push(pattern);
        }

        query.push_str(" ORDER BY username ASC");

        let mut sqlx_query = sqlx::query_as::<_, SqliteUserRow>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let rows: Vec<SqliteUserRow> = sqlx_query.fetch_all(&self.pool).await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update(&self, id: Uuid, update: &UserUpdate) -> Result<User, DbError> {
        let existing = self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })?;

        let email = update.email.as_ref().unwrap_or(&existing.email);
        let username = update.username.as_ref().unwrap_or(&existing.username);
        let role = update.role.unwrap_or(existing.role);
        let display_name = match &update.display_name {
            Some(dn) => dn.clone(),
            None => existing.display_name.clone(),
        };
        let enabled = update.enabled.unwrap_or(existing.enabled);
        let updated_at = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE users SET email = ?, username = ?, role = ?, display_name = ?, enabled = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(email)
        .bind(username)
        .bind(role.as_str())
        .bind(&display_name)
        .bind(enabled)
        .bind(&updated_at)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), DbError> {
        let updated_at = Utc::now().to_rfc3339();

        let result = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(&updated_at)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "User".to_string(),
                id: id.to_string(),
            });
        }

        Ok(())
    }

    async fn update_last_login(&self, id: Uuid) -> Result<(), DbError> {
        let now = Utc::now().to_rfc3339();

        sqlx::query("UPDATE users SET last_login_at = ?, updated_at = ? WHERE id = ?")
            .bind(&now)
            .bind(&now)
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self, filter: &UserFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) as count FROM users WHERE 1=1");
        let mut params: Vec<String> = Vec::new();

        if let Some(role) = &filter.role {
            query.push_str(" AND role = ?");
            params.push(role.as_str().to_string());
        }

        if let Some(enabled) = filter.enabled {
            query.push_str(" AND enabled = ?");
            params.push(if enabled {
                "1".to_string()
            } else {
                "0".to_string()
            });
        }

        if let Some(search) = &filter.search {
            query.push_str(" AND (username LIKE ? OR email LIKE ? OR display_name LIKE ?)");
            let pattern = format!("%{}%", search);
            params.push(pattern.clone());
            params.push(pattern.clone());
            params.push(pattern);
        }

        let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let count: i64 = sqlx_query.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }
}

/// PostgreSQL implementation of UserRepository.
#[cfg(feature = "database")]
pub struct PgUserRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgUserRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl UserRepository for PgUserRepository {
    async fn create(&self, user: &User) -> Result<User, DbError> {
        let role = user.role.as_str();

        sqlx::query(
            r#"
            INSERT INTO users (id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(role)
        .bind(&user.display_name)
        .bind(user.enabled)
        .bind(user.last_login_at)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(user.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<User>, DbError> {
        let row: Option<PgUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_email(&self, email: &str) -> Result<Option<User>, DbError> {
        let row: Option<PgUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DbError> {
        let row: Option<PgUserRow> = sqlx::query_as(
            "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    async fn list(&self, filter: &UserFilter) -> Result<Vec<User>, DbError> {
        // For PostgreSQL, we need to handle parameter binding differently
        let rows: Vec<PgUserRow> = if filter.role.is_some()
            || filter.enabled.is_some()
            || filter.search.is_some()
        {
            // Build dynamic query with conditions
            let mut conditions = vec!["1=1".to_string()];
            let mut param_idx = 1;

            if filter.role.is_some() {
                conditions.push(format!("role = ${}", param_idx));
                param_idx += 1;
            }

            if filter.enabled.is_some() {
                conditions.push(format!("enabled = ${}", param_idx));
                param_idx += 1;
            }

            if filter.search.is_some() {
                conditions.push(format!(
                    "(username ILIKE ${} OR email ILIKE ${} OR display_name ILIKE ${})",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2
                ));
            }

            let query = format!(
                "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users WHERE {} ORDER BY username ASC",
                conditions.join(" AND ")
            );

            let mut sqlx_query = sqlx::query_as::<_, PgUserRow>(&query);

            if let Some(role) = &filter.role {
                sqlx_query = sqlx_query.bind(role.as_str());
            }

            if let Some(enabled) = filter.enabled {
                sqlx_query = sqlx_query.bind(enabled);
            }

            if let Some(search) = &filter.search {
                let pattern = format!("%{}%", search);
                sqlx_query = sqlx_query.bind(pattern.clone());
                sqlx_query = sqlx_query.bind(pattern.clone());
                sqlx_query = sqlx_query.bind(pattern);
            }

            sqlx_query.fetch_all(&self.pool).await?
        } else {
            sqlx::query_as(
                "SELECT id, email, username, password_hash, role, display_name, enabled, last_login_at, created_at, updated_at FROM users ORDER BY username ASC",
            )
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update(&self, id: Uuid, update: &UserUpdate) -> Result<User, DbError> {
        let existing = self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })?;

        let email = update.email.as_ref().unwrap_or(&existing.email);
        let username = update.username.as_ref().unwrap_or(&existing.username);
        let role = update.role.unwrap_or(existing.role);
        let display_name = match &update.display_name {
            Some(dn) => dn.clone(),
            None => existing.display_name.clone(),
        };
        let enabled = update.enabled.unwrap_or(existing.enabled);

        sqlx::query(
            r#"
            UPDATE users SET email = $1, username = $2, role = $3, display_name = $4, enabled = $5, updated_at = NOW()
            WHERE id = $6
            "#,
        )
        .bind(email)
        .bind(username)
        .bind(role.as_str())
        .bind(&display_name)
        .bind(enabled)
        .bind(id)
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "User".to_string(),
            id: id.to_string(),
        })
    }

    async fn update_password(&self, id: Uuid, password_hash: &str) -> Result<(), DbError> {
        let result =
            sqlx::query("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2")
                .bind(password_hash)
                .bind(id)
                .execute(&self.pool)
                .await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "User".to_string(),
                id: id.to_string(),
            });
        }

        Ok(())
    }

    async fn update_last_login(&self, id: Uuid) -> Result<(), DbError> {
        sqlx::query("UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn count(&self, filter: &UserFilter) -> Result<u64, DbError> {
        let count: i64 =
            if filter.role.is_some() || filter.enabled.is_some() || filter.search.is_some() {
                let mut conditions = vec!["1=1".to_string()];
                let mut param_idx = 1;

                if filter.role.is_some() {
                    conditions.push(format!("role = ${}", param_idx));
                    param_idx += 1;
                }

                if filter.enabled.is_some() {
                    conditions.push(format!("enabled = ${}", param_idx));
                    param_idx += 1;
                }

                if filter.search.is_some() {
                    conditions.push(format!(
                        "(username ILIKE ${} OR email ILIKE ${} OR display_name ILIKE ${})",
                        param_idx,
                        param_idx + 1,
                        param_idx + 2
                    ));
                }

                let query = format!(
                    "SELECT COUNT(*) FROM users WHERE {}",
                    conditions.join(" AND ")
                );

                let mut sqlx_query = sqlx::query_scalar::<_, i64>(&query);

                if let Some(role) = &filter.role {
                    sqlx_query = sqlx_query.bind(role.as_str());
                }

                if let Some(enabled) = filter.enabled {
                    sqlx_query = sqlx_query.bind(enabled);
                }

                if let Some(search) = &filter.search {
                    let pattern = format!("%{}%", search);
                    sqlx_query = sqlx_query.bind(pattern.clone());
                    sqlx_query = sqlx_query.bind(pattern.clone());
                    sqlx_query = sqlx_query.bind(pattern);
                }

                sqlx_query.fetch_one(&self.pool).await?
            } else {
                sqlx::query_scalar("SELECT COUNT(*) FROM users")
                    .fetch_one(&self.pool)
                    .await?
            };

        Ok(count as u64)
    }

    async fn any_exist(&self) -> Result<bool, DbError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&self.pool)
            .await?;
        Ok(count > 0)
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_user_repository(pool: &DbPool) -> Box<dyn UserRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteUserRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgUserRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteUserRow {
    id: String,
    email: String,
    username: String,
    password_hash: String,
    role: String,
    display_name: Option<String>,
    enabled: bool,
    last_login_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteUserRow> for User {
    type Error = DbError;

    fn try_from(row: SqliteUserRow) -> Result<Self, Self::Error> {
        let id = Uuid::parse_str(&row.id)
            .map_err(|e| DbError::Serialization(format!("Invalid UUID: {}", e)))?;

        let role = row
            .role
            .parse::<Role>()
            .map_err(|_| DbError::Serialization(format!("Invalid role: {}", row.role)))?;

        let last_login_at = row
            .last_login_at
            .map(|s| DateTime::parse_from_rfc3339(&s))
            .transpose()
            .map_err(|e| DbError::Serialization(format!("Invalid timestamp: {}", e)))?
            .map(|dt| dt.with_timezone(&Utc));

        let created_at = DateTime::parse_from_rfc3339(&row.created_at)
            .map_err(|e| DbError::Serialization(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        let updated_at = DateTime::parse_from_rfc3339(&row.updated_at)
            .map_err(|e| DbError::Serialization(format!("Invalid timestamp: {}", e)))?
            .with_timezone(&Utc);

        Ok(User {
            id,
            email: row.email,
            username: row.username,
            password_hash: row.password_hash,
            role,
            display_name: row.display_name,
            enabled: row.enabled,
            last_login_at,
            created_at,
            updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgUserRow {
    id: Uuid,
    email: String,
    username: String,
    password_hash: String,
    role: String,
    display_name: Option<String>,
    enabled: bool,
    last_login_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgUserRow> for User {
    type Error = DbError;

    fn try_from(row: PgUserRow) -> Result<Self, Self::Error> {
        let role = row
            .role
            .parse::<Role>()
            .map_err(|_| DbError::Serialization(format!("Invalid role: {}", row.role)))?;

        Ok(User {
            id: row.id,
            email: row.email,
            username: row.username,
            password_hash: row.password_hash,
            role,
            display_name: row.display_name,
            enabled: row.enabled,
            last_login_at: row.last_login_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_filter_default() {
        let filter = UserFilter::default();
        assert!(filter.role.is_none());
        assert!(filter.enabled.is_none());
        assert!(filter.search.is_none());
    }
}
