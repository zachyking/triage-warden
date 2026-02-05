//! Feedback repository for database operations.
//!
//! This module provides persistence for analyst feedback on AI-generated
//! triage analyses, supporting both SQLite and PostgreSQL backends.

use super::pagination::{PaginatedResult, Pagination};
use super::{DbError, DbPool};
use crate::feedback::{AnalystFeedback, FeedbackStats, FeedbackType};
use crate::incident::{Severity, TriageVerdict};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

/// Filter criteria for listing feedback.
#[derive(Debug, Clone, Default)]
pub struct FeedbackFilter {
    /// Filter by tenant (required for multi-tenant queries).
    pub tenant_id: Option<Uuid>,
    /// Filter by incident ID.
    pub incident_id: Option<Uuid>,
    /// Filter by analyst ID.
    pub analyst_id: Option<Uuid>,
    /// Filter by feedback type.
    pub feedback_type: Option<FeedbackType>,
    /// Filter by original verdict.
    pub original_verdict: Option<TriageVerdict>,
    /// Filter by whether a correction was made.
    pub has_correction: Option<bool>,
    /// Filter by minimum created_at timestamp.
    pub since: Option<DateTime<Utc>>,
    /// Filter by maximum created_at timestamp.
    pub until: Option<DateTime<Utc>>,
}

/// Partial update for feedback.
#[derive(Debug, Clone, Default)]
pub struct FeedbackUpdate {
    /// Updated corrected verdict.
    pub corrected_verdict: Option<Option<TriageVerdict>>,
    /// Updated corrected severity.
    pub corrected_severity: Option<Option<Severity>>,
    /// Updated feedback type.
    pub feedback_type: Option<FeedbackType>,
    /// Updated notes.
    pub notes: Option<Option<String>>,
    /// Updated corrected MITRE techniques.
    pub corrected_mitre_techniques: Option<Option<Vec<String>>>,
}

/// Repository trait for feedback persistence.
///
/// All methods that query or modify feedback are tenant-scoped for security.
#[async_trait]
pub trait FeedbackRepository: Send + Sync {
    /// Creates a new feedback entry.
    async fn create(&self, feedback: &AnalystFeedback) -> Result<AnalystFeedback, DbError>;

    /// Gets a feedback entry by ID without tenant scoping (admin use only).
    async fn get(&self, id: Uuid) -> Result<Option<AnalystFeedback>, DbError>;

    /// Gets a feedback entry by ID, scoped to a specific tenant.
    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<AnalystFeedback>, DbError>;

    /// Gets feedback for a specific incident within a tenant.
    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AnalystFeedback>, DbError>;

    /// Lists feedback with optional filtering and pagination.
    async fn list(
        &self,
        filter: &FeedbackFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<AnalystFeedback>, DbError>;

    /// Counts feedback entries matching the filter.
    async fn count(&self, filter: &FeedbackFilter) -> Result<u64, DbError>;

    /// Updates a feedback entry.
    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &FeedbackUpdate,
    ) -> Result<AnalystFeedback, DbError>;

    /// Deletes a feedback entry.
    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError>;

    /// Gets aggregate feedback statistics for a tenant.
    async fn get_stats(&self, tenant_id: Uuid) -> Result<FeedbackStats, DbError>;

    /// Gets aggregate feedback statistics for a specific time range.
    async fn get_stats_for_range(
        &self,
        tenant_id: Uuid,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<FeedbackStats, DbError>;

    /// Gets the latest feedback for each unique incident within a tenant.
    /// Useful for training data export.
    async fn get_latest_per_incident(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError>;

    /// Gets all corrected feedback (for training data export).
    async fn get_corrections(
        &self,
        tenant_id: Uuid,
        since: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError>;

    /// Gets feedback for training data export.
    ///
    /// This method retrieves feedback based on training data criteria:
    /// - If `corrections_only` is true, only returns feedback with corrections
    /// - Otherwise, returns all feedback for training
    async fn get_for_training(
        &self,
        tenant_id: Uuid,
        corrections_only: bool,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<AnalystFeedback>, DbError>;
}

/// SQLite implementation of FeedbackRepository.
#[cfg(feature = "database")]
pub struct SqliteFeedbackRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteFeedbackRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl FeedbackRepository for SqliteFeedbackRepository {
    async fn create(&self, feedback: &AnalystFeedback) -> Result<AnalystFeedback, DbError> {
        let id = feedback.id.to_string();
        let incident_id = feedback.incident_id.to_string();
        let tenant_id = feedback.tenant_id.to_string();
        let analyst_id = feedback.analyst_id.to_string();
        let original_verdict = verdict_to_db_str(&feedback.original_verdict);
        let corrected_verdict = feedback.corrected_verdict.as_ref().map(verdict_to_db_str);
        let original_severity = feedback.original_severity.as_db_str();
        let corrected_severity = feedback
            .corrected_severity
            .map(|s| s.as_db_str().to_string());
        let feedback_type = feedback.feedback_type.as_db_str();
        let original_mitre = serde_json::to_string(&feedback.original_mitre_techniques)?;
        let corrected_mitre = feedback
            .corrected_mitre_techniques
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;
        let created_at = feedback.created_at.to_rfc3339();
        let updated_at = feedback.updated_at.to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO analyst_feedback (
                id, incident_id, tenant_id, analyst_id,
                original_verdict, corrected_verdict,
                original_severity, corrected_severity,
                original_confidence, feedback_type, notes,
                original_mitre_techniques, corrected_mitre_techniques,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&incident_id)
        .bind(&tenant_id)
        .bind(&analyst_id)
        .bind(&original_verdict)
        .bind(&corrected_verdict)
        .bind(original_severity)
        .bind(&corrected_severity)
        .bind(feedback.original_confidence)
        .bind(feedback_type)
        .bind(&feedback.notes)
        .bind(&original_mitre)
        .bind(&corrected_mitre)
        .bind(&created_at)
        .bind(&updated_at)
        .execute(&self.pool)
        .await?;

        Ok(feedback.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<AnalystFeedback>, DbError> {
        let id_str = id.to_string();

        let row: Option<FeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE id = ?
            "#,
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<AnalystFeedback>, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let row: Option<FeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE id = ? AND tenant_id = ?
            "#,
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

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let incident_id_str = incident_id.to_string();

        let rows: Vec<FeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = ? AND incident_id = ?
            ORDER BY created_at DESC
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&incident_id_str)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list(
        &self,
        filter: &FeedbackFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<AnalystFeedback>, DbError> {
        let mut query = String::from(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback WHERE 1=1
            "#,
        );

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.analyst_id.is_some() {
            query.push_str(" AND analyst_id = ?");
        }
        if filter.feedback_type.is_some() {
            query.push_str(" AND feedback_type = ?");
        }
        if filter.original_verdict.is_some() {
            query.push_str(" AND original_verdict = ?");
        }
        if let Some(has_correction) = filter.has_correction {
            if has_correction {
                query.push_str(
                    " AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)",
                );
            } else {
                query.push_str(" AND corrected_verdict IS NULL AND corrected_severity IS NULL");
            }
        }
        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }
        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ? OFFSET ?");

        let mut query_builder = sqlx::query_as::<_, FeedbackRow>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(analyst_id) = filter.analyst_id {
            query_builder = query_builder.bind(analyst_id.to_string());
        }
        if let Some(feedback_type) = &filter.feedback_type {
            query_builder = query_builder.bind(feedback_type.as_db_str());
        }
        if let Some(original_verdict) = &filter.original_verdict {
            query_builder = query_builder.bind(verdict_to_db_str(original_verdict));
        }
        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }
        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        query_builder = query_builder
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64);

        let rows: Vec<FeedbackRow> = query_builder.fetch_all(&self.pool).await?;
        let items: Result<Vec<AnalystFeedback>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &FeedbackFilter) -> Result<u64, DbError> {
        let mut query = String::from("SELECT COUNT(*) FROM analyst_feedback WHERE 1=1");

        if filter.tenant_id.is_some() {
            query.push_str(" AND tenant_id = ?");
        }
        if filter.incident_id.is_some() {
            query.push_str(" AND incident_id = ?");
        }
        if filter.analyst_id.is_some() {
            query.push_str(" AND analyst_id = ?");
        }
        if filter.feedback_type.is_some() {
            query.push_str(" AND feedback_type = ?");
        }
        if filter.original_verdict.is_some() {
            query.push_str(" AND original_verdict = ?");
        }
        if let Some(has_correction) = filter.has_correction {
            if has_correction {
                query.push_str(
                    " AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)",
                );
            } else {
                query.push_str(" AND corrected_verdict IS NULL AND corrected_severity IS NULL");
            }
        }
        if filter.since.is_some() {
            query.push_str(" AND created_at >= ?");
        }
        if filter.until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        let mut query_builder = sqlx::query_scalar::<_, i64>(&query);

        if let Some(tenant_id) = filter.tenant_id {
            query_builder = query_builder.bind(tenant_id.to_string());
        }
        if let Some(incident_id) = filter.incident_id {
            query_builder = query_builder.bind(incident_id.to_string());
        }
        if let Some(analyst_id) = filter.analyst_id {
            query_builder = query_builder.bind(analyst_id.to_string());
        }
        if let Some(feedback_type) = &filter.feedback_type {
            query_builder = query_builder.bind(feedback_type.as_db_str());
        }
        if let Some(original_verdict) = &filter.original_verdict {
            query_builder = query_builder.bind(verdict_to_db_str(original_verdict));
        }
        if let Some(since) = &filter.since {
            query_builder = query_builder.bind(since.to_rfc3339());
        }
        if let Some(until) = &filter.until {
            query_builder = query_builder.bind(until.to_rfc3339());
        }

        let count: i64 = query_builder.fetch_one(&self.pool).await?;
        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &FeedbackUpdate,
    ) -> Result<AnalystFeedback, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();
        let now = Utc::now().to_rfc3339();

        let mut set_clauses = vec!["updated_at = ?".to_string()];
        let mut values: Vec<Option<String>> = vec![Some(now)];

        if let Some(corrected_verdict) = &update.corrected_verdict {
            set_clauses.push("corrected_verdict = ?".to_string());
            values.push(corrected_verdict.as_ref().map(verdict_to_db_str));
        }

        if let Some(corrected_severity) = &update.corrected_severity {
            set_clauses.push("corrected_severity = ?".to_string());
            values.push(corrected_severity.map(|s| s.as_db_str().to_string()));
        }

        if let Some(feedback_type) = &update.feedback_type {
            set_clauses.push("feedback_type = ?".to_string());
            values.push(Some(feedback_type.as_db_str().to_string()));
        }

        if let Some(notes) = &update.notes {
            set_clauses.push("notes = ?".to_string());
            values.push(notes.clone());
        }

        if let Some(corrected_mitre) = &update.corrected_mitre_techniques {
            set_clauses.push("corrected_mitre_techniques = ?".to_string());
            values.push(
                corrected_mitre
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()?,
            );
        }

        let query = format!(
            "UPDATE analyst_feedback SET {} WHERE id = ? AND tenant_id = ?",
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
                entity: "AnalystFeedback".to_string(),
                id: id.to_string(),
            });
        }

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "AnalystFeedback".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let id_str = id.to_string();
        let tenant_id_str = tenant_id.to_string();

        let result = sqlx::query("DELETE FROM analyst_feedback WHERE id = ? AND tenant_id = ?")
            .bind(&id_str)
            .bind(&tenant_id_str)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_stats(&self, tenant_id: Uuid) -> Result<FeedbackStats, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let row: StatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_feedback,
                SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_count,
                SUM(CASE WHEN feedback_type = 'incorrect_verdict' THEN 1 ELSE 0 END) as incorrect_verdict_count,
                SUM(CASE WHEN feedback_type = 'incorrect_severity' THEN 1 ELSE 0 END) as incorrect_severity_count,
                SUM(CASE WHEN feedback_type = 'missing_context' THEN 1 ELSE 0 END) as missing_context_count,
                SUM(CASE WHEN feedback_type = 'incorrect_mitre' THEN 1 ELSE 0 END) as incorrect_mitre_count,
                SUM(CASE WHEN feedback_type = 'other' THEN 1 ELSE 0 END) as other_count
            FROM analyst_feedback
            WHERE tenant_id = ?
            "#,
        )
        .bind(&tenant_id_str)
        .fetch_one(&self.pool)
        .await?;

        let mut stats = row.into_stats();
        stats.calculate_accuracy();
        Ok(stats)
    }

    async fn get_stats_for_range(
        &self,
        tenant_id: Uuid,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<FeedbackStats, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let since_str = since.to_rfc3339();
        let until_str = until.to_rfc3339();

        let row: StatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_feedback,
                SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_count,
                SUM(CASE WHEN feedback_type = 'incorrect_verdict' THEN 1 ELSE 0 END) as incorrect_verdict_count,
                SUM(CASE WHEN feedback_type = 'incorrect_severity' THEN 1 ELSE 0 END) as incorrect_severity_count,
                SUM(CASE WHEN feedback_type = 'missing_context' THEN 1 ELSE 0 END) as missing_context_count,
                SUM(CASE WHEN feedback_type = 'incorrect_mitre' THEN 1 ELSE 0 END) as incorrect_mitre_count,
                SUM(CASE WHEN feedback_type = 'other' THEN 1 ELSE 0 END) as other_count
            FROM analyst_feedback
            WHERE tenant_id = ? AND created_at >= ? AND created_at <= ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&since_str)
        .bind(&until_str)
        .fetch_one(&self.pool)
        .await?;

        let mut stats = row.into_stats();
        stats.calculate_accuracy();
        Ok(stats)
    }

    async fn get_latest_per_incident(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let rows: Vec<FeedbackRow> = sqlx::query_as(
            r#"
            SELECT f.id, f.incident_id, f.tenant_id, f.analyst_id,
                   f.original_verdict, f.corrected_verdict,
                   f.original_severity, f.corrected_severity,
                   f.original_confidence, f.feedback_type, f.notes,
                   f.original_mitre_techniques, f.corrected_mitre_techniques,
                   f.created_at, f.updated_at
            FROM analyst_feedback f
            INNER JOIN (
                SELECT incident_id, MAX(created_at) as max_created
                FROM analyst_feedback
                WHERE tenant_id = ?
                GROUP BY incident_id
            ) latest ON f.incident_id = latest.incident_id AND f.created_at = latest.max_created
            WHERE f.tenant_id = ?
            ORDER BY f.created_at DESC
            LIMIT ?
            "#,
        )
        .bind(&tenant_id_str)
        .bind(&tenant_id_str)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_corrections(
        &self,
        tenant_id: Uuid,
        since: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let tenant_id_str = tenant_id.to_string();

        let query = if since.is_some() {
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = ?
              AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)
              AND created_at >= ?
            ORDER BY created_at DESC
            LIMIT ?
            "#
        } else {
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = ?
              AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)
            ORDER BY created_at DESC
            LIMIT ?
            "#
        };

        let rows: Vec<FeedbackRow> = if let Some(since_dt) = since {
            sqlx::query_as(query)
                .bind(&tenant_id_str)
                .bind(since_dt.to_rfc3339())
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as(query)
                .bind(&tenant_id_str)
                .bind(limit as i64)
                .fetch_all(&self.pool)
                .await?
        };

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_for_training(
        &self,
        tenant_id: Uuid,
        corrections_only: bool,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let tenant_id_str = tenant_id.to_string();
        let limit_value = limit.unwrap_or(10000) as i64;

        // Build query based on filters
        let mut query = String::from(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = ?
            "#,
        );

        if corrections_only {
            query
                .push_str(" AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)");
        }

        if since.is_some() {
            query.push_str(" AND created_at >= ?");
        }

        if until.is_some() {
            query.push_str(" AND created_at <= ?");
        }

        query.push_str(" ORDER BY created_at DESC LIMIT ?");

        let mut query_builder = sqlx::query_as::<_, FeedbackRow>(&query);
        query_builder = query_builder.bind(&tenant_id_str);

        if let Some(since_dt) = since {
            query_builder = query_builder.bind(since_dt.to_rfc3339());
        }

        if let Some(until_dt) = until {
            query_builder = query_builder.bind(until_dt.to_rfc3339());
        }

        query_builder = query_builder.bind(limit_value);

        let rows: Vec<FeedbackRow> = query_builder.fetch_all(&self.pool).await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// PostgreSQL implementation of FeedbackRepository.
#[cfg(feature = "database")]
pub struct PgFeedbackRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgFeedbackRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl FeedbackRepository for PgFeedbackRepository {
    async fn create(&self, feedback: &AnalystFeedback) -> Result<AnalystFeedback, DbError> {
        let original_verdict = verdict_to_db_str(&feedback.original_verdict);
        let corrected_verdict = feedback.corrected_verdict.as_ref().map(verdict_to_db_str);
        let original_severity = feedback.original_severity.as_db_str();
        let corrected_severity = feedback
            .corrected_severity
            .map(|s| s.as_db_str().to_string());
        let feedback_type = feedback.feedback_type.as_db_str();

        sqlx::query(
            r#"
            INSERT INTO analyst_feedback (
                id, incident_id, tenant_id, analyst_id,
                original_verdict, corrected_verdict,
                original_severity, corrected_severity,
                original_confidence, feedback_type, notes,
                original_mitre_techniques, corrected_mitre_techniques,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
            "#,
        )
        .bind(feedback.id)
        .bind(feedback.incident_id)
        .bind(feedback.tenant_id)
        .bind(feedback.analyst_id)
        .bind(&original_verdict)
        .bind(&corrected_verdict)
        .bind(original_severity)
        .bind(&corrected_severity)
        .bind(feedback.original_confidence)
        .bind(feedback_type)
        .bind(&feedback.notes)
        .bind(serde_json::to_value(&feedback.original_mitre_techniques)?)
        .bind(
            feedback
                .corrected_mitre_techniques
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?,
        )
        .bind(feedback.created_at)
        .bind(feedback.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(feedback.clone())
    }

    async fn get(&self, id: Uuid) -> Result<Option<AnalystFeedback>, DbError> {
        let row: Option<PgFeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(row) => Ok(Some(row.try_into()?)),
            None => Ok(None),
        }
    }

    async fn get_for_tenant(
        &self,
        id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Option<AnalystFeedback>, DbError> {
        let row: Option<PgFeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE id = $1 AND tenant_id = $2
            "#,
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

    async fn get_for_incident(
        &self,
        tenant_id: Uuid,
        incident_id: Uuid,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let rows: Vec<PgFeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = $1 AND incident_id = $2
            ORDER BY created_at DESC
            "#,
        )
        .bind(tenant_id)
        .bind(incident_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn list(
        &self,
        filter: &FeedbackFilter,
        pagination: &Pagination,
    ) -> Result<PaginatedResult<AnalystFeedback>, DbError> {
        let has_correction_clause = match filter.has_correction {
            Some(true) => "AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)",
            Some(false) => "AND corrected_verdict IS NULL AND corrected_severity IS NULL",
            None => "",
        };

        let query = format!(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR analyst_id = $3)
              AND ($4::text IS NULL OR feedback_type = $4)
              AND ($5::text IS NULL OR original_verdict = $5)
              AND ($6::timestamptz IS NULL OR created_at >= $6)
              AND ($7::timestamptz IS NULL OR created_at <= $7)
              {}
            ORDER BY created_at DESC
            LIMIT $8 OFFSET $9
            "#,
            has_correction_clause
        );

        let rows: Vec<PgFeedbackRow> = sqlx::query_as(&query)
            .bind(filter.tenant_id)
            .bind(filter.incident_id)
            .bind(filter.analyst_id)
            .bind(filter.feedback_type.as_ref().map(|ft| ft.as_db_str()))
            .bind(filter.original_verdict.as_ref().map(verdict_to_db_str))
            .bind(filter.since)
            .bind(filter.until)
            .bind(pagination.limit() as i64)
            .bind(pagination.offset() as i64)
            .fetch_all(&self.pool)
            .await?;

        let items: Result<Vec<AnalystFeedback>, DbError> =
            rows.into_iter().map(|r| r.try_into()).collect();
        let total = self.count(filter).await?;

        Ok(PaginatedResult::new(items?, total, pagination))
    }

    async fn count(&self, filter: &FeedbackFilter) -> Result<u64, DbError> {
        let has_correction_clause = match filter.has_correction {
            Some(true) => "AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)",
            Some(false) => "AND corrected_verdict IS NULL AND corrected_severity IS NULL",
            None => "",
        };

        let query = format!(
            r#"
            SELECT COUNT(*)
            FROM analyst_feedback
            WHERE ($1::uuid IS NULL OR tenant_id = $1)
              AND ($2::uuid IS NULL OR incident_id = $2)
              AND ($3::uuid IS NULL OR analyst_id = $3)
              AND ($4::text IS NULL OR feedback_type = $4)
              AND ($5::text IS NULL OR original_verdict = $5)
              AND ($6::timestamptz IS NULL OR created_at >= $6)
              AND ($7::timestamptz IS NULL OR created_at <= $7)
              {}
            "#,
            has_correction_clause
        );

        let count: i64 = sqlx::query_scalar(&query)
            .bind(filter.tenant_id)
            .bind(filter.incident_id)
            .bind(filter.analyst_id)
            .bind(filter.feedback_type.as_ref().map(|ft| ft.as_db_str()))
            .bind(filter.original_verdict.as_ref().map(verdict_to_db_str))
            .bind(filter.since)
            .bind(filter.until)
            .fetch_one(&self.pool)
            .await?;

        Ok(count as u64)
    }

    async fn update(
        &self,
        id: Uuid,
        tenant_id: Uuid,
        update: &FeedbackUpdate,
    ) -> Result<AnalystFeedback, DbError> {
        sqlx::query(
            r#"
            UPDATE analyst_feedback SET
                corrected_verdict = COALESCE($3, corrected_verdict),
                corrected_severity = COALESCE($4, corrected_severity),
                feedback_type = COALESCE($5, feedback_type),
                notes = COALESCE($6, notes),
                corrected_mitre_techniques = COALESCE($7, corrected_mitre_techniques),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
            "#,
        )
        .bind(id)
        .bind(tenant_id)
        .bind(
            update
                .corrected_verdict
                .as_ref()
                .map(|cv| cv.as_ref().map(verdict_to_db_str)),
        )
        .bind(
            update
                .corrected_severity
                .as_ref()
                .map(|cs| cs.map(|s| s.as_db_str().to_string())),
        )
        .bind(update.feedback_type.as_ref().map(|ft| ft.as_db_str()))
        .bind(&update.notes)
        .bind(match &update.corrected_mitre_techniques {
            Some(Some(m)) => Some(serde_json::to_value(m)?),
            Some(None) => None,
            None => None,
        })
        .execute(&self.pool)
        .await?;

        self.get_for_tenant(id, tenant_id)
            .await?
            .ok_or_else(|| DbError::NotFound {
                entity: "AnalystFeedback".to_string(),
                id: id.to_string(),
            })
    }

    async fn delete(&self, id: Uuid, tenant_id: Uuid) -> Result<bool, DbError> {
        let result = sqlx::query("DELETE FROM analyst_feedback WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_stats(&self, tenant_id: Uuid) -> Result<FeedbackStats, DbError> {
        let row: PgStatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_feedback,
                SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_count,
                SUM(CASE WHEN feedback_type = 'incorrect_verdict' THEN 1 ELSE 0 END) as incorrect_verdict_count,
                SUM(CASE WHEN feedback_type = 'incorrect_severity' THEN 1 ELSE 0 END) as incorrect_severity_count,
                SUM(CASE WHEN feedback_type = 'missing_context' THEN 1 ELSE 0 END) as missing_context_count,
                SUM(CASE WHEN feedback_type = 'incorrect_mitre' THEN 1 ELSE 0 END) as incorrect_mitre_count,
                SUM(CASE WHEN feedback_type = 'other' THEN 1 ELSE 0 END) as other_count
            FROM analyst_feedback
            WHERE tenant_id = $1
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let mut stats = row.into_stats();
        stats.calculate_accuracy();
        Ok(stats)
    }

    async fn get_stats_for_range(
        &self,
        tenant_id: Uuid,
        since: DateTime<Utc>,
        until: DateTime<Utc>,
    ) -> Result<FeedbackStats, DbError> {
        let row: PgStatsRow = sqlx::query_as(
            r#"
            SELECT
                COUNT(*) as total_feedback,
                SUM(CASE WHEN feedback_type = 'correct' THEN 1 ELSE 0 END) as correct_count,
                SUM(CASE WHEN feedback_type = 'incorrect_verdict' THEN 1 ELSE 0 END) as incorrect_verdict_count,
                SUM(CASE WHEN feedback_type = 'incorrect_severity' THEN 1 ELSE 0 END) as incorrect_severity_count,
                SUM(CASE WHEN feedback_type = 'missing_context' THEN 1 ELSE 0 END) as missing_context_count,
                SUM(CASE WHEN feedback_type = 'incorrect_mitre' THEN 1 ELSE 0 END) as incorrect_mitre_count,
                SUM(CASE WHEN feedback_type = 'other' THEN 1 ELSE 0 END) as other_count
            FROM analyst_feedback
            WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .bind(until)
        .fetch_one(&self.pool)
        .await?;

        let mut stats = row.into_stats();
        stats.calculate_accuracy();
        Ok(stats)
    }

    async fn get_latest_per_incident(
        &self,
        tenant_id: Uuid,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let rows: Vec<PgFeedbackRow> = sqlx::query_as(
            r#"
            SELECT DISTINCT ON (incident_id)
                   id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = $1
            ORDER BY incident_id, created_at DESC
            LIMIT $2
            "#,
        )
        .bind(tenant_id)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_corrections(
        &self,
        tenant_id: Uuid,
        since: Option<DateTime<Utc>>,
        limit: u32,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let rows: Vec<PgFeedbackRow> = sqlx::query_as(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = $1
              AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)
              AND ($2::timestamptz IS NULL OR created_at >= $2)
            ORDER BY created_at DESC
            LIMIT $3
            "#,
        )
        .bind(tenant_id)
        .bind(since)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }

    async fn get_for_training(
        &self,
        tenant_id: Uuid,
        corrections_only: bool,
        since: Option<DateTime<Utc>>,
        until: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<AnalystFeedback>, DbError> {
        let limit_value = limit.unwrap_or(10000) as i64;

        let corrections_clause = if corrections_only {
            "AND (corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL)"
        } else {
            ""
        };

        let query = format!(
            r#"
            SELECT id, incident_id, tenant_id, analyst_id,
                   original_verdict, corrected_verdict,
                   original_severity, corrected_severity,
                   original_confidence, feedback_type, notes,
                   original_mitre_techniques, corrected_mitre_techniques,
                   created_at, updated_at
            FROM analyst_feedback
            WHERE tenant_id = $1
              AND ($2::timestamptz IS NULL OR created_at >= $2)
              AND ($3::timestamptz IS NULL OR created_at <= $3)
              {}
            ORDER BY created_at DESC
            LIMIT $4
            "#,
            corrections_clause
        );

        let rows: Vec<PgFeedbackRow> = sqlx::query_as(&query)
            .bind(tenant_id)
            .bind(since)
            .bind(until)
            .bind(limit_value)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter().map(|r| r.try_into()).collect()
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_feedback_repository(pool: &DbPool) -> Box<dyn FeedbackRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteFeedbackRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgFeedbackRepository::new(pool.clone())),
    }
}

// Helper function to convert TriageVerdict to database string
fn verdict_to_db_str(verdict: &TriageVerdict) -> String {
    match verdict {
        TriageVerdict::TruePositive => "true_positive",
        TriageVerdict::LikelyTruePositive => "likely_true_positive",
        TriageVerdict::Suspicious => "suspicious",
        TriageVerdict::LikelyFalsePositive => "likely_false_positive",
        TriageVerdict::FalsePositive => "false_positive",
        TriageVerdict::Inconclusive => "inconclusive",
    }
    .to_string()
}

// Helper function to parse TriageVerdict from database string
fn verdict_from_db_str(s: &str) -> Result<TriageVerdict, DbError> {
    match s {
        "true_positive" => Ok(TriageVerdict::TruePositive),
        "likely_true_positive" => Ok(TriageVerdict::LikelyTruePositive),
        "suspicious" => Ok(TriageVerdict::Suspicious),
        "likely_false_positive" => Ok(TriageVerdict::LikelyFalsePositive),
        "false_positive" => Ok(TriageVerdict::FalsePositive),
        "inconclusive" => Ok(TriageVerdict::Inconclusive),
        _ => Err(DbError::Serialization(format!("Unknown verdict: {}", s))),
    }
}

// Helper function to parse Severity from database string
fn severity_from_db_str(s: &str) -> Result<Severity, DbError> {
    match s {
        "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(DbError::Serialization(format!("Unknown severity: {}", s))),
    }
}

// Helper structs for SQLx row mapping

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct FeedbackRow {
    id: String,
    incident_id: String,
    tenant_id: String,
    analyst_id: String,
    original_verdict: String,
    corrected_verdict: Option<String>,
    original_severity: String,
    corrected_severity: Option<String>,
    original_confidence: f64,
    feedback_type: String,
    notes: Option<String>,
    original_mitre_techniques: String,
    corrected_mitre_techniques: Option<String>,
    created_at: String,
    updated_at: String,
}

#[cfg(feature = "database")]
impl TryFrom<FeedbackRow> for AnalystFeedback {
    type Error = DbError;

    fn try_from(row: FeedbackRow) -> Result<Self, Self::Error> {
        Ok(AnalystFeedback {
            id: Uuid::parse_str(&row.id).map_err(|e| DbError::Serialization(e.to_string()))?,
            incident_id: Uuid::parse_str(&row.incident_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            tenant_id: Uuid::parse_str(&row.tenant_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            analyst_id: Uuid::parse_str(&row.analyst_id)
                .map_err(|e| DbError::Serialization(e.to_string()))?,
            original_verdict: verdict_from_db_str(&row.original_verdict)?,
            corrected_verdict: row
                .corrected_verdict
                .map(|v| verdict_from_db_str(&v))
                .transpose()?,
            original_severity: severity_from_db_str(&row.original_severity)?,
            corrected_severity: row
                .corrected_severity
                .map(|s| severity_from_db_str(&s))
                .transpose()?,
            original_confidence: row.original_confidence,
            feedback_type: FeedbackType::from_db_str(&row.feedback_type).ok_or_else(|| {
                DbError::Serialization(format!("Unknown feedback type: {}", row.feedback_type))
            })?,
            notes: row.notes,
            original_mitre_techniques: serde_json::from_str(&row.original_mitre_techniques)?,
            corrected_mitre_techniques: row
                .corrected_mitre_techniques
                .map(|m| serde_json::from_str(&m))
                .transpose()?,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.updated_at)
                .map_err(|e| DbError::Serialization(e.to_string()))?
                .with_timezone(&Utc),
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgFeedbackRow {
    id: Uuid,
    incident_id: Uuid,
    tenant_id: Uuid,
    analyst_id: Uuid,
    original_verdict: String,
    corrected_verdict: Option<String>,
    original_severity: String,
    corrected_severity: Option<String>,
    original_confidence: f64,
    feedback_type: String,
    notes: Option<String>,
    original_mitre_techniques: serde_json::Value,
    corrected_mitre_techniques: Option<serde_json::Value>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[cfg(feature = "database")]
impl TryFrom<PgFeedbackRow> for AnalystFeedback {
    type Error = DbError;

    fn try_from(row: PgFeedbackRow) -> Result<Self, Self::Error> {
        Ok(AnalystFeedback {
            id: row.id,
            incident_id: row.incident_id,
            tenant_id: row.tenant_id,
            analyst_id: row.analyst_id,
            original_verdict: verdict_from_db_str(&row.original_verdict)?,
            corrected_verdict: row
                .corrected_verdict
                .map(|v| verdict_from_db_str(&v))
                .transpose()?,
            original_severity: severity_from_db_str(&row.original_severity)?,
            corrected_severity: row
                .corrected_severity
                .map(|s| severity_from_db_str(&s))
                .transpose()?,
            original_confidence: row.original_confidence,
            feedback_type: FeedbackType::from_db_str(&row.feedback_type).ok_or_else(|| {
                DbError::Serialization(format!("Unknown feedback type: {}", row.feedback_type))
            })?,
            notes: row.notes,
            original_mitre_techniques: serde_json::from_value(row.original_mitre_techniques)?,
            corrected_mitre_techniques: row
                .corrected_mitre_techniques
                .map(serde_json::from_value)
                .transpose()?,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct StatsRow {
    total_feedback: i64,
    correct_count: i64,
    incorrect_verdict_count: i64,
    incorrect_severity_count: i64,
    missing_context_count: i64,
    incorrect_mitre_count: i64,
    other_count: i64,
}

#[cfg(feature = "database")]
impl StatsRow {
    fn into_stats(self) -> FeedbackStats {
        FeedbackStats {
            total_feedback: self.total_feedback as u64,
            correct_count: self.correct_count as u64,
            incorrect_verdict_count: self.incorrect_verdict_count as u64,
            incorrect_severity_count: self.incorrect_severity_count as u64,
            missing_context_count: self.missing_context_count as u64,
            incorrect_mitre_count: self.incorrect_mitre_count as u64,
            other_count: self.other_count as u64,
            ..Default::default()
        }
    }
}

#[cfg(feature = "database")]
#[derive(sqlx::FromRow)]
struct PgStatsRow {
    total_feedback: i64,
    correct_count: Option<i64>,
    incorrect_verdict_count: Option<i64>,
    incorrect_severity_count: Option<i64>,
    missing_context_count: Option<i64>,
    incorrect_mitre_count: Option<i64>,
    other_count: Option<i64>,
}

#[cfg(feature = "database")]
impl PgStatsRow {
    fn into_stats(self) -> FeedbackStats {
        FeedbackStats {
            total_feedback: self.total_feedback as u64,
            correct_count: self.correct_count.unwrap_or(0) as u64,
            incorrect_verdict_count: self.incorrect_verdict_count.unwrap_or(0) as u64,
            incorrect_severity_count: self.incorrect_severity_count.unwrap_or(0) as u64,
            missing_context_count: self.missing_context_count.unwrap_or(0) as u64,
            incorrect_mitre_count: self.incorrect_mitre_count.unwrap_or(0) as u64,
            other_count: self.other_count.unwrap_or(0) as u64,
            ..Default::default()
        }
    }
}
