//! Incident repository for database operations.

use super::pagination::Pagination;
use super::{DbError, DbPool};
use crate::incident::{Incident, IncidentStatus, Severity};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter criteria for listing incidents.
#[derive(Debug, Clone, Default)]
pub struct IncidentFilter {
    /// Filter by tenant (required for multi-tenant queries).
    pub tenant_id: Option<Uuid>,
    /// Filter by status (multiple allowed).
    pub status: Option<Vec<IncidentStatus>>,
    /// Filter by severity (multiple allowed).
    pub severity: Option<Vec<Severity>>,
    /// Filter by minimum created_at timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Filter by maximum created_at timestamp.
    pub until: Option<DateTime<Utc>>,
    /// Filter by tag (any match).
    pub tags: Option<Vec<String>>,
    /// Filter by ticket ID existence.
    pub has_ticket: Option<bool>,
    /// Full-text search query (searches alert_data, ticket_id, tags).
    pub query: Option<String>,
}

/// Partial update for an incident.
#[derive(Debug, Clone, Default)]
pub struct IncidentUpdate {
    pub status: Option<IncidentStatus>,
    pub severity: Option<Severity>,
    pub analysis: Option<serde_json::Value>,
    pub ticket_id: Option<String>,
    pub tags: Option<Vec<String>>,
}

/// Repository trait for incident persistence.
///
/// All methods that query or modify incidents are tenant-scoped:
/// - `get` and `get_for_tenant` - retrieves an incident by ID (optionally scoped to tenant)
/// - `list` and `count` - use `IncidentFilter.tenant_id` to scope results
/// - `create`, `save`, `update` - use the incident's `tenant_id` field
/// - `delete` - deletes within the tenant scope
#[async_trait]
pub trait IncidentRepository: Send + Sync {
    /// Creates a new incident. The incident's tenant_id is used for tenant scoping.
    async fn create(&self, incident: &Incident) -> Result<Incident, DbError>;

    /// Gets an incident by ID without tenant scoping (admin use only).
    /// For tenant-scoped access, use `get_for_tenant`.
    async fn get(&self, id: Uuid) -> Result<Option<Incident>, DbError>;

    /// Gets an incident by ID, scoped to a specific tenant.
    /// Returns None if the incident doesn't exist or belongs to a different tenant.
    async fn get_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<Option<Incident>, DbError>;

    /// Lists incidents with optional filtering and pagination.
    /// Use `filter.tenant_id` to scope results to a specific tenant.
    async fn list(
        &self,
        filter: &IncidentFilter,
        pagination: &Pagination,
    ) -> Result<Vec<Incident>, DbError>;

    /// Counts incidents matching the filter.
    /// Use `filter.tenant_id` to scope results to a specific tenant.
    async fn count(&self, filter: &IncidentFilter) -> Result<u64, DbError>;

    /// Updates an incident. The update is scoped to the incident's tenant.
    async fn update(&self, id: Uuid, update: &IncidentUpdate) -> Result<Incident, DbError>;

    /// Updates an incident, scoped to a specific tenant.
    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &IncidentUpdate,
    ) -> Result<Incident, DbError>;

    /// Updates the full incident (replaces all fields).
    async fn save(&self, incident: &Incident) -> Result<Incident, DbError>;

    /// Deletes an incident without tenant scoping (admin use only).
    async fn delete(&self, id: Uuid) -> Result<bool, DbError>;

    /// Deletes an incident, scoped to a specific tenant.
    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;
}

/// SQLite implementation of IncidentRepository.
#[cfg(feature = "database")]
pub struct SqliteIncidentRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteIncidentRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl IncidentRepository for SqliteIncidentRepository {
    async fn create(&self, incident: &Incident) -> Result<Incident, DbError> {
        let id = incident.id.to_string();
        let tenant_id = incident.tenant_id.to_string();
        let source = serde_json::to_string(&incident.source)?;
        // Use plain strings for severity/status to match DB schema constraints
        let severity = incident.severity.as_db_str();
        let status = incident.status.as_db_str();
        let alert_data = serde_json::to_string(&incident.alert_data)?;
        let enrichments = serde_json::to_string(&incident.enrichments)?;
        let analysis = incident
            .analysis
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let proposed_actions = serde_json::to_string(&incident.proposed_actions)?;
        let tags = serde_json::to_string(&incident.tags)?;
        let metadata = serde_json::to_string(&incident.metadata)?;
        let created_at = incident.created_at.to_rfc3339();
        let updated_at = incident.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO incidents (id, tenant_id, source, severity, status, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&tenant_id)
        .bind(source)
        .bind(severity)
        .bind(status)
        .bind(&alert_data)
        .bind(&enrichments)
        .bind(&analysis)
        .bind(&proposed_actions)
        .bind(&incident.ticket_id)
        .bind(&tags)
        .bind(&metadata)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(incident.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Incident>, DbError> {
        let id_str = id.to_string();

        let row: Option<IncidentRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, source, severity, status, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at FROM incidents WHERE id = ?"#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<Option<Incident>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<IncidentRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, source, severity, status, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at FROM incidents WHERE id = ? AND tenant_id = ?"#,
        )
        .bind(&id_str)
        .bind(&tenant_id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        filter: &IncidentFilter,
        pagination: &Pagination,
    ) -> Result<Vec<Incident>, DbError> {
        use super::make_like_pattern;

        // Build dynamic query with filters
        let mut query = String::from(
            "SELECT id, tenant_id, source, severity, status, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at FROM incidents WHERE 1=1",
        );

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }

        if filter.status.is_some() {
            query.push_str(" AND status IN (SELECT value FROM json_each(?))");
        }

        if filter.severity.is_some() {
            query.push_str(" AND severity IN (SELECT value FROM json_each(?))");
        }

        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }

        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        if filter.query.is_some() {
            query.push_str(
                " AND (alert_data LIKE ? ESCAPE '\\' OR ticket_id LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')",
            );
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, IncidentRow>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }

        if let Some(statuses) = &filter.status {
            // Use plain strings (not JSON-quoted) for DB comparison
            let status_strs: Vec<&str> = statuses.iter().map(|s| s.as_db_str()).collect();
            query_builder = query_builder.bind(serde_json::to_string(&status_strs)?);
        }

        if let Some(severities) = &filter.severity {
            // Use plain strings (not JSON-quoted) for DB comparison
            let severity_strs: Vec<&str> = severities.iter().map(|s| s.as_db_str()).collect();
            query_builder = query_builder.bind(serde_json::to_string(&severity_strs)?);
        }

        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }

        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        if let Some(search) = &filter.query {
            let pattern = make_like_pattern(search);
            query_builder = query_builder
                .bind(pattern.clone())
                .bind(pattern.clone())
                .bind(pattern);
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<IncidentRow> = query_builder.fetch_all(&self.pool).await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn count(&self, filter: &IncidentFilter) -> Result<u64, DbError> {
        use super::make_like_pattern;

        let mut query = String::from("SELECT COUNT(*) as count FROM incidents WHERE 1=1");

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }

        if filter.status.is_some() {
            query.push_str(" AND status IN (SELECT value FROM json_each(?))");
        }

        if filter.severity.is_some() {
            query.push_str(" AND severity IN (SELECT value FROM json_each(?))");
        }

        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }

        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        if filter.query.is_some() {
            query.push_str(
                " AND (alert_data LIKE ? ESCAPE '\\' OR ticket_id LIKE ? ESCAPE '\\' OR tags LIKE ? ESCAPE '\\')",
            );
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }

        if let Some(statuses) = &filter.status {
            // Use plain strings (not JSON-quoted) for DB comparison
            let status_strs: Vec<&str> = statuses.iter().map(|s| s.as_db_str()).collect();
            query_builder = query_builder.bind(serde_json::to_string(&status_strs)?);
        }

        if let Some(severities) = &filter.severity {
            // Use plain strings (not JSON-quoted) for DB comparison
            let severity_strs: Vec<&str> = severities.iter().map(|s| s.as_db_str()).collect();
            query_builder = query_builder.bind(serde_json::to_string(&severity_strs)?);
        }

        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }

        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        if let Some(search) = &filter.query {
            let pattern = make_like_pattern(search);
            query_builder = query_builder
                .bind(pattern.clone())
                .bind(pattern.clone())
                .bind(pattern);
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;

        Ok(count as u64)
    }

    async fn update(&self, id: Uuid, update: &IncidentUpdate) -> Result<Incident, DbError> {
        let id_str = id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<String> = vec![now];

        if let Some(status) = &update.status {
            set_clauses.push("status = ?".to_string());
            values.push(status.as_db_str().to_string());
        }

        if let Some(severity) = &update.severity {
            set_clauses.push("severity = ?".to_string());
            values.push(severity.as_db_str().to_string());
        }

        if let Some(analysis) = &update.analysis {
            set_clauses.push("analysis = ?".to_string());
            values.push(serde_json::to_string(analysis)?);
        }

        if let Some(ticket_id) = &update.ticket_id {
            set_clauses.push("ticket_id = ?".to_string());
            values.push(ticket_id.clone());
        }

        if let Some(tags) = &update.tags {
            set_clauses.push("tags = ?".to_string());
            values.push(serde_json::to_string(tags)?);
        }

        let query = format!(
            "UPDATE incidents SET {} WHERE id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        query_builder = query_builder.bind(&id_str);
        query_builder.execute(&self.pool).await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Incident".to_string(),
            id: id.to_string(),
        })
    }

    async fn save(&self, incident: &Incident) -> Result<Incident, DbError> {
        let id = incident.id.to_string();
        let source = serde_json::to_string(&incident.source)?;
        // Use plain strings for severity/status to match DB schema constraints
        let severity = incident.severity.as_db_str();
        let status = incident.status.as_db_str();
        let alert_data = serde_json::to_string(&incident.alert_data)?;
        let enrichments = serde_json::to_string(&incident.enrichments)?;
        let analysis = incident
            .analysis
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let proposed_actions = serde_json::to_string(&incident.proposed_actions)?;
        let tags = serde_json::to_string(&incident.tags)?;
        let metadata = serde_json::to_string(&incident.metadata)?;
        let updated_at = Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            UPDATE incidents SET
                source = ?, severity = ?, status = ?, alert_data = ?,
                enrichments = ?, analysis = ?, proposed_actions = ?,
                ticket_id = ?, tags = ?, metadata = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(source)
        .bind(severity)
        .bind(status)
        .bind(&alert_data)
        .bind(&enrichments)
        .bind(&analysis)
        .bind(&proposed_actions)
        .bind(&incident.ticket_id)
        .bind(&tags)
        .bind(&metadata)
        .bind(&updated_at)
        .bind(&id)
        .execute(&self.pool)
        .await?;

        Ok(incident.clone())
    }

    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &IncidentUpdate,
    ) -> Result<Incident, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();

        // Build dynamic update query with tenant scoping
        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<String> = vec![now];

        if let Some(status) = &update.status {
            set_clauses.push("status = ?".to_string());
            values.push(status.as_db_str().to_string());
        }

        if let Some(severity) = &update.severity {
            set_clauses.push("severity = ?".to_string());
            values.push(severity.as_db_str().to_string());
        }

        if let Some(analysis) = &update.analysis {
            set_clauses.push("analysis = ?".to_string());
            values.push(serde_json::to_string(analysis)?);
        }

        if let Some(ticket_id) = &update.ticket_id {
            set_clauses.push("ticket_id = ?".to_string());
            values.push(ticket_id.clone());
        }

        if let Some(tags) = &update.tags {
            set_clauses.push("tags = ?".to_string());
            values.push(serde_json::to_string(tags)?);
        }

        let query = format!(
            "UPDATE incidents SET {} WHERE id = ? AND tenant_id = ?",
            set_clauses.join(", ")
        );

        let mut query_builder = sqlx::query(&query);

        for value in &values {
            query_builder = query_builder.bind(value);
        }

        query_builder = query_builder.bind(&id_str).bind(&tenant_id_str);
        let result = query_builder.execute(&self.pool).await?;

        if result.rows_affected() == 0 {
            return Err(DbError::NotFound {
                entity: "Incident".to_string(),
                id: id.to_string(),
            });
        }

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "Incident".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();

        let result = sqlx::query("DELETE FROM incidents WHERE id = ?")
            .bind(&id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM incidents WHERE id = ? AND tenant_id = ?")
            .bind(&id_str)
            .bind(&tenant_id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// PostgreSQL implementation of IncidentRepository.
#[cfg(feature = "database")]
pub struct PgIncidentRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgIncidentRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl IncidentRepository for PgIncidentRepository {
    async fn create(&self, incident: &Incident) -> Result<Incident, DbError> {
        let source = serde_json::to_string(&incident.source)?;
        let severity = format!("{:?}", incident.severity).to_lowercase();
        let status = format!("{:?}", incident.status).to_lowercase();

        sqlx::query(
            r#"
            INSERT INTO incidents (id, tenant_id, source, severity, status, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at)
            VALUES ($1, $2, $3, $4::severity, $5::incident_status, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            "#,
        )
        .bind(incident.id)
        .bind(incident.tenant_id)
        .bind(&source)
        .bind(&severity)
        .bind(&status)
        .bind(&incident.alert_data)
        .bind(serde_json::to_value(&incident.enrichments)?)
        .bind(incident.analysis.as_ref().map(serde_json::to_value).transpose()?)
        .bind(serde_json::to_value(&incident.proposed_actions)?)
        .bind(&incident.ticket_id)
        .bind(serde_json::to_value(&incident.tags)?)
        .bind(serde_json::to_value(&incident.metadata)?)
        .bind(incident.created_at)
        .bind(incident.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(incident.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<Incident>, DbError> {
        let row: Option<PgIncidentRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, source, severity::text, status::text, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at FROM incidents WHERE id = $1"#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<Option<Incident>, DbError> {
        let row: Option<PgIncidentRow> = sqlx::query_as(
            r#"SELECT id, tenant_id, source, severity::text, status::text, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at FROM incidents WHERE id = $1 AND tenant_id = $2"#,
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn list(
        &self,
        filter: &IncidentFilter,
        pagination: &Pagination,
    ) -> Result<Vec<Incident>, DbError> {
        use super::make_like_pattern;

        let search_pattern = filter.query.as_ref().map(|q| make_like_pattern(q));

        let rows: Vec<PgIncidentRow> = sqlx::query_as(
            r#"
            SELECT id, tenant_id, source, severity::text, status::text, alert_data, enrichments, analysis, proposed_actions, ticket_id, tags, metadata, created_at, updated_at
            FROM incidents
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::text[] IS NULL OR status::text = ANY($2))
              AND ($3::text[] IS NULL OR severity::text = ANY($3))
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
              AND ($6::text IS NULL OR alert_data::text ILIKE $6 OR ticket_id ILIKE $6 OR tags::text ILIKE $6)
            ORDER BY created_at DESC
            LIMIT $7 OFFSET $8
            "#,
        )
        .bind(filter.tenant_id)
        .bind(filter.status.as_ref().map(|s| {
            s.iter()
                .map(|st| format!("{:?}", st).to_lowercase())
                .collect::<Vec<_>>()
        }))
        .bind(filter.severity.as_ref().map(|s| {
            s.iter()
                .map(|sv| format!("{:?}", sv).to_lowercase())
                .collect::<Vec<_>>()
        }))
        .bind(filter.since)
        .bind(filter.until)
        .bind(&search_pattern)
        .bind(pagination.limit() as i64)
        .bind(pagination.offset() as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn count(&self, filter: &IncidentFilter) -> Result<u64, DbError> {
        use super::make_like_pattern;

        let search_pattern = filter.query.as_ref().map(|q| make_like_pattern(q));

        let count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM incidents
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::text[] IS NULL OR status::text = ANY($2))
              AND ($3::text[] IS NULL OR severity::text = ANY($3))
              AND ($4::timestamptz IS NULL OR created_at >= $4)
              AND ($5::timestamptz IS NULL OR created_at <= $5)
              AND ($6::text IS NULL OR alert_data::text ILIKE $6 OR ticket_id ILIKE $6 OR tags::text ILIKE $6)
            "#,
        )
        .bind(filter.tenant_id)
        .bind(filter.status.as_ref().map(|s| {
            s.iter()
                .map(|st| format!("{:?}", st).to_lowercase())
                .collect::<Vec<_>>()
        }))
        .bind(filter.severity.as_ref().map(|s| {
            s.iter()
                .map(|sv| format!("{:?}", sv).to_lowercase())
                .collect::<Vec<_>>()
        }))
        .bind(filter.since)
        .bind(filter.until)
        .bind(&search_pattern)
        .fetch_one(&self.pool)
        .await?;

        Ok(count as u64)
    }

    async fn update(&self, id: Uuid, update: &IncidentUpdate) -> Result<Incident, DbError> {
        sqlx::query(
            r#"
            UPDATE incidents SET
                status = COALESCE($2::incident_status, status),
                severity = COALESCE($3::severity, severity),
                analysis = COALESCE($4, analysis),
                ticket_id = COALESCE($5, ticket_id),
                tags = COALESCE($6, tags),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(
            update
                .status
                .as_ref()
                .map(|s| format!("{:?}", s).to_lowercase()),
        )
        .bind(
            update
                .severity
                .as_ref()
                .map(|s| format!("{:?}", s).to_lowercase()),
        )
        .bind(&update.analysis)
        .bind(&update.ticket_id)
        .bind(
            update
                .tags
                .as_ref()
                .and_then(|t| serde_json::to_value(t).ok()),
        )
        .execute(&self.pool)
        .await?;

        self.get(id).await?.ok_or_else(|| DbError::NotFound {
            entity: "Incident".to_string(),
            id: id.to_string(),
        })
    }

    async fn save(&self, incident: &Incident) -> Result<Incident, DbError> {
        let source = serde_json::to_string(&incident.source)?;
        let severity = format!("{:?}", incident.severity).to_lowercase();
        let status = format!("{:?}", incident.status).to_lowercase();

        sqlx::query(
            r#"
            UPDATE incidents SET
                source = $2, severity = $3::severity, status = $4::incident_status,
                alert_data = $5, enrichments = $6, analysis = $7, proposed_actions = $8,
                ticket_id = $9, tags = $10, metadata = $11, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(incident.id)
        .bind(&source)
        .bind(&severity)
        .bind(&status)
        .bind(&incident.alert_data)
        .bind(serde_json::to_value(&incident.enrichments)?)
        .bind(
            incident
                .analysis
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        )
        .bind(serde_json::to_value(&incident.proposed_actions)?)
        .bind(&incident.ticket_id)
        .bind(serde_json::to_value(&incident.tags)?)
        .bind(serde_json::to_value(&incident.metadata)?)
        .execute(&self.pool)
        .await?;

        Ok(incident.clone())
    }

    async fn update_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &IncidentUpdate,
    ) -> Result<Incident, DbError> {
        sqlx::query(
            r#"
            UPDATE incidents SET
                status = COALESCE($3::incident_status, status),
                severity = COALESCE($4::severity, severity),
                analysis = COALESCE($5, analysis),
                ticket_id = COALESCE($6, ticket_id),
                tags = COALESCE($7, tags),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(
            update
                .status
                .as_ref()
                .map(|s| format!("{:?}", s).to_lowercase()),
        )
        .bind(
            update
                .severity
                .as_ref()
                .map(|s| format!("{:?}", s).to_lowercase()),
        )
        .bind(&update.analysis)
        .bind(&update.ticket_id)
        .bind(
            update
                .tags
                .as_ref()
                .and_then(|t| serde_json::to_value(t).ok()),
        )
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "Incident".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM incidents WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn delete_for_tenant(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM incidents WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_incident_repository(pool: &DbPool) -> Box<dyn IncidentRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteIncidentRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgIncidentRepository::new(pool.clone())),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct IncidentRow {
    id: String,
    tenant_id: String,
    source: String,
    severity: String,
    status: String,
    alert_data: String,
    enrichments: String,
    analysis: Option<String>,
    proposed_actions: String,
    ticket_id: Option<String>,
    tags: String,
    metadata: String,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<IncidentRow> for Incident {
    type Error = DbError;

    fn try_from(row: IncidentRow) -> Result<Self, Self::Error> {
        // Severity and status are stored as plain strings, wrap in quotes for JSON parsing
        let severity_json = format!("\"{}\"", row.severity);
        let status_json = format!("\"{}\"", row.status);

        Ok(Incident {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: Uuid::parse_str(&row.tenant_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            source: serde_json::from_str(&row.source)?,
            severity: serde_json::from_str(&severity_json)?,
            status: serde_json::from_str(&status_json)?,
            alert_data: serde_json::from_str(&row.alert_data)?,
            enrichments: serde_json::from_str(&row.enrichments)?,
            analysis: row.analysis.map(|a| serde_json::from_str(&a)).transpose()?,
            proposed_actions: serde_json::from_str(&row.proposed_actions)?,
            audit_log: Vec::new(), // Loaded separately from audit_logs table
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            ticket_id: row.ticket_id,
            tags: serde_json::from_str(&row.tags)?,
            metadata: serde_json::from_str(&row.metadata)?,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgIncidentRow {
    id: Uuid,
    tenant_id: Uuid,
    source: String,
    severity: String,
    status: String,
    alert_data: serde_json::Value,
    enrichments: serde_json::Value,
    analysis: Option<serde_json::Value>,
    proposed_actions: serde_json::Value,
    ticket_id: Option<String>,
    tags: serde_json::Value,
    metadata: serde_json::Value,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgIncidentRow> for Incident {
    type Error = DbError;

    fn try_from(row: PgIncidentRow) -> Result<Self, Self::Error> {
        // Parse severity from string
        let severity = match row.severity.as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" => Severity::Medium,
            "high" => Severity::High,
            "critical" => Severity::Critical,
            _ => {
                return Err(DbError::Serialization(format!(
                    "Unknown severity: {}",
                    row.severity
                )))
            }
        };

        // Parse status from string
        let status = match row.status.as_str() {
            "new" => IncidentStatus::New,
            "enriching" => IncidentStatus::Enriching,
            "analyzing" => IncidentStatus::Analyzing,
            "pending_review" => IncidentStatus::PendingReview,
            "pending_approval" => IncidentStatus::PendingApproval,
            "executing" => IncidentStatus::Executing,
            "resolved" => IncidentStatus::Resolved,
            "false_positive" => IncidentStatus::FalsePositive,
            "escalated" => IncidentStatus::Escalated,
            "closed" => IncidentStatus::Closed,
            _ => {
                return Err(DbError::Serialization(format!(
                    "Unknown status: {}",
                    row.status
                )))
            }
        };

        Ok(Incident {
            id: row.id,
            tenant_id: row.tenant_id,
            source: serde_json::from_str(&row.source)?,
            severity,
            status,
            alert_data: row.alert_data,
            enrichments: serde_json::from_value(row.enrichments)?,
            analysis: row.analysis.map(serde_json::from_value).transpose()?,
            proposed_actions: serde_json::from_value(row.proposed_actions)?,
            audit_log: Vec::new(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            ticket_id: row.ticket_id,
            tags: serde_json::from_value(row.tags)?,
            metadata: serde_json::from_value(row.metadata)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::pagination::{DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE};

    #[test]
    fn test_pagination() {
        let p = Pagination::default();
        assert_eq!(p.page, 1);
        assert_eq!(p.per_page, DEFAULT_PAGE_SIZE);
        assert_eq!(p.offset(), 0);
        assert_eq!(p.limit(), DEFAULT_PAGE_SIZE);

        let p = Pagination::new(3, 10);
        assert_eq!(p.offset(), 20);
        assert_eq!(p.limit(), 10);
    }

    #[test]
    fn test_pagination_clamping() {
        // per_page should be clamped to MAX_PAGE_SIZE
        let p = Pagination::new(1, 500);
        assert_eq!(p.per_page, MAX_PAGE_SIZE);

        // page 0 should become 1
        let p = Pagination::new(0, 50);
        assert_eq!(p.page, 1);
    }

    #[test]
    fn test_filter_default() {
        let f = IncidentFilter::default();
        assert!(f.status.is_none());
        assert!(f.severity.is_none());
        assert!(f.since.is_none());
    }
}
