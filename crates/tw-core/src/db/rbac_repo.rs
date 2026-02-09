//! RBAC repository for role and permission persistence.

use super::{DbError, DbPool};
use crate::rbac::{builtin_roles, Permission, RbacRole, RoleAssignment};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Repository trait for RBAC persistence.
#[async_trait]
pub trait RbacRepository: Send + Sync {
    /// Ensures builtin roles exist for the tenant.
    async fn ensure_builtin_roles(&self, tenant_id: Uuid) -> Result<(), DbError>;

    /// Creates a custom role.
    async fn create_role(&self, role: &RbacRole) -> Result<RbacRole, DbError>;

    /// Gets a role by id.
    async fn get_role(&self, id: Uuid) -> Result<Option<RbacRole>, DbError>;

    /// Lists roles available to a tenant.
    async fn list_roles(
        &self,
        tenant_id: Uuid,
        include_system: bool,
    ) -> Result<Vec<RbacRole>, DbError>;

    /// Updates a role.
    async fn update_role(&self, id: Uuid, role: &RbacRole) -> Result<RbacRole, DbError>;

    /// Deletes a role. Returns true if deleted.
    async fn delete_role(&self, id: Uuid) -> Result<bool, DbError>;

    /// Assigns a role to a user.
    async fn assign_role(&self, assignment: &RoleAssignment) -> Result<RoleAssignment, DbError>;

    /// Removes a role assignment.
    async fn unassign_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, DbError>;

    /// Lists role assignments for a user.
    async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<RoleAssignment>, DbError>;

    /// Returns effective custom permissions from assigned RBAC roles.
    async fn get_user_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Permission>, DbError>;
}

#[cfg(feature = "database")]
pub struct SqliteRbacRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteRbacRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl RbacRepository for SqliteRbacRepository {
    async fn ensure_builtin_roles(&self, tenant_id: Uuid) -> Result<(), DbError> {
        for role in builtin_roles(Some(tenant_id)) {
            let permissions = serde_json::to_string(&role.permissions)?;
            sqlx::query(
                r#"
                INSERT INTO rbac_roles (id, tenant_id, name, description, permissions, is_system, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, name) DO UPDATE SET
                    description = excluded.description,
                    permissions = excluded.permissions,
                    is_system = excluded.is_system,
                    updated_at = excluded.updated_at
                "#,
            )
            .bind(role.id.to_string())
            .bind(role.tenant_id.map(|v| v.to_string()))
            .bind(&role.name)
            .bind(&role.description)
            .bind(permissions)
            .bind(role.is_system)
            .bind(role.created_at.to_rfc3339())
            .bind(role.updated_at.to_rfc3339())
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn create_role(&self, role: &RbacRole) -> Result<RbacRole, DbError> {
        let permissions = serde_json::to_string(&role.permissions)?;
        sqlx::query(
            r#"
            INSERT INTO rbac_roles (id, tenant_id, name, description, permissions, is_system, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(role.id.to_string())
        .bind(role.tenant_id.map(|v| v.to_string()))
        .bind(&role.name)
        .bind(&role.description)
        .bind(permissions)
        .bind(role.is_system)
        .bind(role.created_at.to_rfc3339())
        .bind(role.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(role.clone())
    }

    async fn get_role(&self, id: Uuid) -> Result<Option<RbacRole>, DbError> {
        let row: Option<SqliteRoleRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
            FROM rbac_roles
            WHERE id = ?
            "#,
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_roles(
        &self,
        tenant_id: Uuid,
        include_system: bool,
    ) -> Result<Vec<RbacRole>, DbError> {
        let rows: Vec<SqliteRoleRow> = if include_system {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
                FROM rbac_roles
                WHERE tenant_id = ?
                ORDER BY is_system DESC, name ASC
                "#,
            )
            .bind(tenant_id.to_string())
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
                FROM rbac_roles
                WHERE tenant_id = ? AND is_system = 0
                ORDER BY name ASC
                "#,
            )
            .bind(tenant_id.to_string())
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update_role(&self, id: Uuid, role: &RbacRole) -> Result<RbacRole, DbError> {
        let permissions = serde_json::to_string(&role.permissions)?;
        let updated_at = Utc::now().to_rfc3339();
        let affected = sqlx::query(
            r#"
            UPDATE rbac_roles
            SET description = ?, permissions = ?, updated_at = ?
            WHERE id = ? AND is_system = 0
            "#,
        )
        .bind(&role.description)
        .bind(permissions)
        .bind(updated_at)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?
        .rows_affected();

        if affected == 0 {
            return Err(DbError::NotFound {
                entity: "rbac_role".to_string(),
                id: id.to_string(),
            });
        }

        self.get_role(id).await?.ok_or(DbError::NotFound {
            entity: "rbac_role".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete_role(&self, id: Uuid) -> Result<bool, DbError> {
        let affected = sqlx::query("DELETE FROM rbac_roles WHERE id = ? AND is_system = 0")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> Result<RoleAssignment, DbError> {
        sqlx::query(
            r#"
            INSERT INTO rbac_user_roles (id, tenant_id, user_id, role_id, assigned_by, assigned_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, role_id) DO NOTHING
            "#,
        )
        .bind(assignment.id.to_string())
        .bind(assignment.tenant_id.to_string())
        .bind(assignment.user_id.to_string())
        .bind(assignment.role_id.to_string())
        .bind(assignment.assigned_by.map(|v| v.to_string()))
        .bind(assignment.assigned_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        Ok(assignment.clone())
    }

    async fn unassign_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, DbError> {
        let affected = sqlx::query(
            r#"
            DELETE FROM rbac_user_roles
            WHERE tenant_id = ? AND user_id = ? AND role_id = ?
            "#,
        )
        .bind(tenant_id.to_string())
        .bind(user_id.to_string())
        .bind(role_id.to_string())
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<RoleAssignment>, DbError> {
        let rows: Vec<SqliteAssignmentRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, user_id, role_id, assigned_by, assigned_at
            FROM rbac_user_roles
            WHERE tenant_id = ? AND user_id = ?
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id.to_string())
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn get_user_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Permission>, DbError> {
        let rows: Vec<SqliteRolePermissionsRow> = sqlx::query_as(
            r#"
            SELECT r.permissions
            FROM rbac_user_roles ur
            INNER JOIN rbac_roles r ON r.id = ur.role_id
            WHERE ur.tenant_id = ? AND ur.user_id = ?
            "#,
        )
        .bind(tenant_id.to_string())
        .bind(user_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        let mut permissions = Vec::new();
        for row in rows {
            let parsed: Vec<Permission> = serde_json::from_str(&row.permissions)?;
            permissions.extend(parsed);
        }
        Ok(permissions)
    }
}

#[cfg(feature = "database")]
pub struct PostgresRbacRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PostgresRbacRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl RbacRepository for PostgresRbacRepository {
    async fn ensure_builtin_roles(&self, tenant_id: Uuid) -> Result<(), DbError> {
        for role in builtin_roles(Some(tenant_id)) {
            let permissions = serde_json::to_value(&role.permissions)?;
            sqlx::query(
                r#"
                INSERT INTO rbac_roles (id, tenant_id, name, description, permissions, is_system, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (tenant_id, name)
                DO UPDATE SET
                    description = EXCLUDED.description,
                    permissions = EXCLUDED.permissions,
                    is_system = EXCLUDED.is_system,
                    updated_at = EXCLUDED.updated_at
                "#,
            )
            .bind(role.id)
            .bind(role.tenant_id)
            .bind(&role.name)
            .bind(&role.description)
            .bind(permissions)
            .bind(role.is_system)
            .bind(role.created_at)
            .bind(role.updated_at)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn create_role(&self, role: &RbacRole) -> Result<RbacRole, DbError> {
        let permissions = serde_json::to_value(&role.permissions)?;
        sqlx::query(
            r#"
            INSERT INTO rbac_roles (id, tenant_id, name, description, permissions, is_system, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(role.id)
        .bind(role.tenant_id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(permissions)
        .bind(role.is_system)
        .bind(role.created_at)
        .bind(role.updated_at)
        .execute(&self.pool)
        .await?;
        Ok(role.clone())
    }

    async fn get_role(&self, id: Uuid) -> Result<Option<RbacRole>, DbError> {
        let row: Option<PostgresRoleRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
            FROM rbac_roles
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.map(TryInto::try_into).transpose()
    }

    async fn list_roles(
        &self,
        tenant_id: Uuid,
        include_system: bool,
    ) -> Result<Vec<RbacRole>, DbError> {
        let rows: Vec<PostgresRoleRow> = if include_system {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
                FROM rbac_roles
                WHERE tenant_id = $1
                ORDER BY is_system DESC, name ASC
                "#,
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                r#"
                SELECT id, tenant_id, name, description, permissions, is_system, created_at, updated_at
                FROM rbac_roles
                WHERE tenant_id = $1 AND is_system = FALSE
                ORDER BY name ASC
                "#,
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?
        };
        rows.into_iter().map(TryInto::try_into).collect()
    }

    async fn update_role(&self, id: Uuid, role: &RbacRole) -> Result<RbacRole, DbError> {
        let permissions = serde_json::to_value(&role.permissions)?;
        let affected = sqlx::query(
            r#"
            UPDATE rbac_roles
            SET description = $1, permissions = $2, updated_at = NOW()
            WHERE id = $3 AND is_system = FALSE
            "#,
        )
        .bind(&role.description)
        .bind(permissions)
        .bind(id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if affected == 0 {
            return Err(DbError::NotFound {
                entity: "rbac_role".to_string(),
                id: id.to_string(),
            });
        }
        self.get_role(id).await?.ok_or(DbError::NotFound {
            entity: "rbac_role".to_string(),
            id: id.to_string(),
        })
    }

    async fn delete_role(&self, id: Uuid) -> Result<bool, DbError> {
        let affected = sqlx::query("DELETE FROM rbac_roles WHERE id = $1 AND is_system = FALSE")
            .bind(id)
            .execute(&self.pool)
            .await?
            .rows_affected();
        Ok(affected > 0)
    }

    async fn assign_role(&self, assignment: &RoleAssignment) -> Result<RoleAssignment, DbError> {
        sqlx::query(
            r#"
            INSERT INTO rbac_user_roles (id, tenant_id, user_id, role_id, assigned_by, assigned_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT(user_id, role_id) DO NOTHING
            "#,
        )
        .bind(assignment.id)
        .bind(assignment.tenant_id)
        .bind(assignment.user_id)
        .bind(assignment.role_id)
        .bind(assignment.assigned_by)
        .bind(assignment.assigned_at)
        .execute(&self.pool)
        .await?;
        Ok(assignment.clone())
    }

    async fn unassign_role(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        role_id: Uuid,
    ) -> Result<bool, DbError> {
        let affected = sqlx::query(
            r#"
            DELETE FROM rbac_user_roles
            WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(role_id)
        .execute(&self.pool)
        .await?
        .rows_affected();
        Ok(affected > 0)
    }

    async fn list_user_assignments(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<RoleAssignment>, DbError> {
        let rows: Vec<PostgresAssignmentRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, user_id, role_id, assigned_by, assigned_at
            FROM rbac_user_roles
            WHERE tenant_id = $1 AND user_id = $2
            ORDER BY assigned_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(RoleAssignment::from).collect())
    }

    async fn get_user_permissions(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<Vec<Permission>, DbError> {
        let rows: Vec<PostgresRolePermissionsRow> = sqlx::query_as(
            r#"
            SELECT r.permissions
            FROM rbac_user_roles ur
            INNER JOIN rbac_roles r ON r.id = ur.role_id
            WHERE ur.tenant_id = $1 AND ur.user_id = $2
            "#,
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        let mut permissions = Vec::new();
        for row in rows {
            let parsed: Vec<Permission> = serde_json::from_value(row.permissions)?;
            permissions.extend(parsed);
        }
        Ok(permissions)
    }
}

/// Creates an RBAC repository based on pool type.
pub fn create_rbac_repository(pool: &DbPool) -> Box<dyn RbacRepository> {
    match pool {
        DbPool::Sqlite(p) => Box::new(SqliteRbacRepository::new(p.clone())),
        DbPool::Postgres(p) => Box::new(PostgresRbacRepository::new(p.clone())),
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteRoleRow {
    id: String,
    tenant_id: Option<String>,
    name: String,
    description: String,
    permissions: String,
    is_system: bool,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteRoleRow> for RbacRole {
    type Error = DbError;

    fn try_from(value: SqliteRoleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&value.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: value
                .tenant_id
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            name: value.name,
            description: value.description,
            permissions: serde_json::from_str(&value.permissions)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            is_system: value.is_system,
            created_at: DateTime::parse_from_rfc3339(&value.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&value.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteAssignmentRow {
    id: String,
    tenant_id: String,
    user_id: String,
    role_id: String,
    assigned_by: Option<String>,
    assigned_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<SqliteAssignmentRow> for RoleAssignment {
    type Error = DbError;

    fn try_from(value: SqliteAssignmentRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Uuid::parse_str(&value.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: Uuid::parse_str(&value.tenant_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            user_id: Uuid::parse_str(&value.user_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            role_id: Uuid::parse_str(&value.role_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            assigned_by: value
                .assigned_by
                .as_deref()
                .map(Uuid::parse_str)
                .transpose()
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            assigned_at: DateTime::parse_from_rfc3339(&value.assigned_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct SqliteRolePermissionsRow {
    permissions: String,
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PostgresRoleRow {
    id: Uuid,
    tenant_id: Option<Uuid>,
    name: String,
    description: String,
    permissions: serde_json::Value,
    is_system: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PostgresRoleRow> for RbacRole {
    type Error = DbError;

    fn try_from(value: PostgresRoleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            tenant_id: value.tenant_id,
            name: value.name,
            description: value.description,
            permissions: serde_json::from_value(value.permissions)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            is_system: value.is_system,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PostgresAssignmentRow {
    id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    role_id: Uuid,
    assigned_by: Option<Uuid>,
    assigned_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl From<PostgresAssignmentRow> for RoleAssignment {
    fn from(value: PostgresAssignmentRow) -> Self {
        Self {
            id: value.id,
            tenant_id: value.tenant_id,
            user_id: value.user_id,
            role_id: value.role_id,
            assigned_by: value.assigned_by,
            assigned_at: value.assigned_at,
        }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PostgresRolePermissionsRow {
    permissions: serde_json::Value,
}
