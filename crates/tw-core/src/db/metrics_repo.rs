//! Metrics repository for database queries.

use super::{DbError, DbPool};
use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

/// Metrics data for incidents.
#[derive(Debug, Clone, Default)]
pub struct IncidentMetricsData {
    pub total: u64,
    pub by_status: HashMap<String, u64>,
    pub by_severity: HashMap<String, u64>,
    pub created_last_hour: u64,
    pub resolved_last_hour: u64,
}

/// Metrics data for actions.
#[derive(Debug, Clone, Default)]
pub struct ActionMetricsData {
    pub total_executed: u64,
    pub success_count: u64,
    pub pending_approvals: u64,
}

/// Performance metrics data.
#[derive(Debug, Clone, Default)]
pub struct PerformanceMetricsData {
    pub mean_time_to_triage_seconds: Option<f64>,
    pub mean_time_to_respond_seconds: Option<f64>,
    pub auto_resolved_count: u64,
    pub total_resolved_count: u64,
}

/// Repository trait for metrics queries.
#[async_trait]
pub trait MetricsRepository: Send + Sync {
    /// Get incident-related metrics.
    async fn get_incident_metrics(&self) -> Result<IncidentMetricsData, DbError>;

    /// Get action-related metrics.
    async fn get_action_metrics(&self) -> Result<ActionMetricsData, DbError>;

    /// Get performance metrics.
    async fn get_performance_metrics(&self) -> Result<PerformanceMetricsData, DbError>;

    /// Get incident-related metrics scoped to a tenant.
    async fn get_incident_metrics_for_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> Result<IncidentMetricsData, DbError> {
        self.get_incident_metrics().await
    }

    /// Get action-related metrics scoped to a tenant.
    async fn get_action_metrics_for_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> Result<ActionMetricsData, DbError> {
        self.get_action_metrics().await
    }

    /// Get performance metrics scoped to a tenant.
    async fn get_performance_metrics_for_tenant(
        &self,
        _tenant_id: Uuid,
    ) -> Result<PerformanceMetricsData, DbError> {
        self.get_performance_metrics().await
    }
}

/// SQLite implementation of MetricsRepository.
#[cfg(feature = "database")]
pub struct SqliteMetricsRepository {
    pool: sqlx::SqlitePool,
}

#[cfg(feature = "database")]
impl SqliteMetricsRepository {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl MetricsRepository for SqliteMetricsRepository {
    async fn get_incident_metrics(&self) -> Result<IncidentMetricsData, DbError> {
        // Get total count
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents")
            .fetch_one(&self.pool)
            .await?;

        // Get counts by status
        let status_rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT status, COUNT(*) FROM incidents GROUP BY status")
                .fetch_all(&self.pool)
                .await?;

        let by_status: HashMap<String, u64> = status_rows
            .into_iter()
            .map(|(status, count)| (status, count as u64))
            .collect();

        // Get counts by severity
        let severity_rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT severity, COUNT(*) FROM incidents GROUP BY severity")
                .fetch_all(&self.pool)
                .await?;

        let by_severity: HashMap<String, u64> = severity_rows
            .into_iter()
            .map(|(severity, count)| (severity, count as u64))
            .collect();

        // Get created in last hour
        let created_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE created_at >= datetime('now', '-1 hour')",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get resolved in last hour
        let resolved_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE status = 'resolved' AND updated_at >= datetime('now', '-1 hour')",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(IncidentMetricsData {
            total: total as u64,
            by_status,
            by_severity,
            created_last_hour: created_last_hour as u64,
            resolved_last_hour: resolved_last_hour as u64,
        })
    }

    async fn get_action_metrics(&self) -> Result<ActionMetricsData, DbError> {
        // Get total executed actions
        let total_executed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE approval_status IN ('approved', 'executed')",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get success count (actions with non-null result and no error)
        let success_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE executed_at IS NOT NULL AND result IS NOT NULL AND json_extract(result, '$.error') IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get pending approvals
        let pending_approvals: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE approval_status = 'pending'")
                .fetch_one(&self.pool)
                .await?;

        Ok(ActionMetricsData {
            total_executed: total_executed as u64,
            success_count: success_count as u64,
            pending_approvals: pending_approvals as u64,
        })
    }

    async fn get_performance_metrics(&self) -> Result<PerformanceMetricsData, DbError> {
        // Mean time to triage: time from created_at to when status changed from 'new'
        // We approximate this by looking at incidents that are no longer 'new'
        let mttt: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(
                (julianday(updated_at) - julianday(created_at)) * 86400.0
            )
            FROM incidents
            WHERE status != 'new' AND created_at != updated_at
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        // Mean time to respond: time from created_at to first action execution
        let mttr: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(
                (julianday(a.executed_at) - julianday(i.created_at)) * 86400.0
            )
            FROM incidents i
            INNER JOIN actions a ON a.incident_id = i.id
            WHERE a.executed_at IS NOT NULL
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        // Auto-resolution rate: incidents resolved without manual approval
        let auto_resolved: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM incidents i
            WHERE i.status = 'resolved'
            AND NOT EXISTS (
                SELECT 1 FROM actions a
                WHERE a.incident_id = i.id
                AND a.approval_status = 'manually_approved'
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_resolved: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'")
                .fetch_one(&self.pool)
                .await?;

        Ok(PerformanceMetricsData {
            mean_time_to_triage_seconds: mttt,
            mean_time_to_respond_seconds: mttr,
            auto_resolved_count: auto_resolved as u64,
            total_resolved_count: total_resolved as u64,
        })
    }

    async fn get_incident_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<IncidentMetricsData, DbError> {
        let tenant_id = tenant_id.to_string();

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE tenant_id = ?")
            .bind(&tenant_id)
            .fetch_one(&self.pool)
            .await?;

        let status_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, COUNT(*) FROM incidents WHERE tenant_id = ? GROUP BY status",
        )
        .bind(&tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let by_status: HashMap<String, u64> = status_rows
            .into_iter()
            .map(|(status, count)| (status, count as u64))
            .collect();

        let severity_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT severity, COUNT(*) FROM incidents WHERE tenant_id = ? GROUP BY severity",
        )
        .bind(&tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let by_severity: HashMap<String, u64> = severity_rows
            .into_iter()
            .map(|(severity, count)| (severity, count as u64))
            .collect();

        let created_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = ? AND created_at >= datetime('now', '-1 hour')",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let resolved_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = ? AND status = 'resolved' AND updated_at >= datetime('now', '-1 hour')",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(IncidentMetricsData {
            total: total as u64,
            by_status,
            by_severity,
            created_last_hour: created_last_hour as u64,
            resolved_last_hour: resolved_last_hour as u64,
        })
    }

    async fn get_action_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<ActionMetricsData, DbError> {
        let tenant_id = tenant_id.to_string();

        let total_executed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = ? AND approval_status IN ('approved', 'executed')",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let success_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = ? AND executed_at IS NOT NULL AND result IS NOT NULL AND json_extract(result, '$.error') IS NULL",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let pending_approvals: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = ? AND approval_status = 'pending'",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ActionMetricsData {
            total_executed: total_executed as u64,
            success_count: success_count as u64,
            pending_approvals: pending_approvals as u64,
        })
    }

    async fn get_performance_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<PerformanceMetricsData, DbError> {
        let tenant_id = tenant_id.to_string();

        let mttt: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(
                (julianday(updated_at) - julianday(created_at)) * 86400.0
            )
            FROM incidents
            WHERE tenant_id = ? AND status != 'new' AND created_at != updated_at
            "#,
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let mttr: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(
                (julianday(a.executed_at) - julianday(i.created_at)) * 86400.0
            )
            FROM incidents i
            INNER JOIN actions a ON a.incident_id = i.id
            WHERE i.tenant_id = ? AND a.tenant_id = ? AND a.executed_at IS NOT NULL
            "#,
        )
        .bind(&tenant_id)
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let auto_resolved: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM incidents i
            WHERE i.tenant_id = ? AND i.status = 'resolved'
            AND NOT EXISTS (
                SELECT 1 FROM actions a
                WHERE a.incident_id = i.id
                AND a.tenant_id = i.tenant_id
                AND a.approval_status = 'manually_approved'
            )
            "#,
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let total_resolved: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = ? AND status = 'resolved'",
        )
        .bind(&tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(PerformanceMetricsData {
            mean_time_to_triage_seconds: mttt,
            mean_time_to_respond_seconds: mttr,
            auto_resolved_count: auto_resolved as u64,
            total_resolved_count: total_resolved as u64,
        })
    }
}

/// PostgreSQL implementation of MetricsRepository.
#[cfg(feature = "database")]
pub struct PgMetricsRepository {
    pool: sqlx::PgPool,
}

#[cfg(feature = "database")]
impl PgMetricsRepository {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[cfg(feature = "database")]
#[async_trait]
impl MetricsRepository for PgMetricsRepository {
    async fn get_incident_metrics(&self) -> Result<IncidentMetricsData, DbError> {
        // Get total count
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents")
            .fetch_one(&self.pool)
            .await?;

        // Get counts by status
        let status_rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT status::text, COUNT(*) FROM incidents GROUP BY status")
                .fetch_all(&self.pool)
                .await?;

        let by_status: HashMap<String, u64> = status_rows
            .into_iter()
            .map(|(status, count)| (status, count as u64))
            .collect();

        // Get counts by severity
        let severity_rows: Vec<(String, i64)> =
            sqlx::query_as("SELECT severity::text, COUNT(*) FROM incidents GROUP BY severity")
                .fetch_all(&self.pool)
                .await?;

        let by_severity: HashMap<String, u64> = severity_rows
            .into_iter()
            .map(|(severity, count)| (severity, count as u64))
            .collect();

        // Get created in last hour
        let created_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE created_at >= NOW() - INTERVAL '1 hour'",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get resolved in last hour
        let resolved_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE status = 'resolved' AND updated_at >= NOW() - INTERVAL '1 hour'",
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(IncidentMetricsData {
            total: total as u64,
            by_status,
            by_severity,
            created_last_hour: created_last_hour as u64,
            resolved_last_hour: resolved_last_hour as u64,
        })
    }

    async fn get_action_metrics(&self) -> Result<ActionMetricsData, DbError> {
        // Get total executed actions
        let total_executed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE approval_status IN ('approved', 'executed')",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get success count
        let success_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE executed_at IS NOT NULL AND result IS NOT NULL AND (result->>'error') IS NULL",
        )
        .fetch_one(&self.pool)
        .await?;

        // Get pending approvals
        let pending_approvals: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM actions WHERE approval_status = 'pending'")
                .fetch_one(&self.pool)
                .await?;

        Ok(ActionMetricsData {
            total_executed: total_executed as u64,
            success_count: success_count as u64,
            pending_approvals: pending_approvals as u64,
        })
    }

    async fn get_performance_metrics(&self) -> Result<PerformanceMetricsData, DbError> {
        // Mean time to triage
        let mttt: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)))
            FROM incidents
            WHERE status != 'new' AND created_at != updated_at
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        // Mean time to respond
        let mttr: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (a.executed_at - i.created_at)))
            FROM incidents i
            INNER JOIN actions a ON a.incident_id = i.id
            WHERE a.executed_at IS NOT NULL
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        // Auto-resolution counts
        let auto_resolved: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM incidents i
            WHERE i.status = 'resolved'
            AND NOT EXISTS (
                SELECT 1 FROM actions a
                WHERE a.incident_id = i.id
                AND a.approval_status = 'manually_approved'
            )
            "#,
        )
        .fetch_one(&self.pool)
        .await?;

        let total_resolved: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE status = 'resolved'")
                .fetch_one(&self.pool)
                .await?;

        Ok(PerformanceMetricsData {
            mean_time_to_triage_seconds: mttt,
            mean_time_to_respond_seconds: mttr,
            auto_resolved_count: auto_resolved as u64,
            total_resolved_count: total_resolved as u64,
        })
    }

    async fn get_incident_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<IncidentMetricsData, DbError> {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM incidents WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;

        let status_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status::text, COUNT(*) FROM incidents WHERE tenant_id = $1 GROUP BY status",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let by_status: HashMap<String, u64> = status_rows
            .into_iter()
            .map(|(status, count)| (status, count as u64))
            .collect();

        let severity_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT severity::text, COUNT(*) FROM incidents WHERE tenant_id = $1 GROUP BY severity",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let by_severity: HashMap<String, u64> = severity_rows
            .into_iter()
            .map(|(severity, count)| (severity, count as u64))
            .collect();

        let created_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = $1 AND created_at >= NOW() - INTERVAL '1 hour'",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let resolved_last_hour: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = $1 AND status = 'resolved' AND updated_at >= NOW() - INTERVAL '1 hour'",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(IncidentMetricsData {
            total: total as u64,
            by_status,
            by_severity,
            created_last_hour: created_last_hour as u64,
            resolved_last_hour: resolved_last_hour as u64,
        })
    }

    async fn get_action_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<ActionMetricsData, DbError> {
        let total_executed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = $1 AND approval_status IN ('approved', 'executed')",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let success_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = $1 AND executed_at IS NOT NULL AND result IS NOT NULL AND (result->>'error') IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let pending_approvals: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM actions WHERE tenant_id = $1 AND approval_status = 'pending'",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(ActionMetricsData {
            total_executed: total_executed as u64,
            success_count: success_count as u64,
            pending_approvals: pending_approvals as u64,
        })
    }

    async fn get_performance_metrics_for_tenant(
        &self,
        tenant_id: Uuid,
    ) -> Result<PerformanceMetricsData, DbError> {
        let mttt: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (updated_at - created_at)))
            FROM incidents
            WHERE tenant_id = $1 AND status != 'new' AND created_at != updated_at
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let mttr: Option<f64> = sqlx::query_scalar(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (a.executed_at - i.created_at)))
            FROM incidents i
            INNER JOIN actions a ON a.incident_id = i.id
            WHERE i.tenant_id = $1 AND a.tenant_id = $1 AND a.executed_at IS NOT NULL
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let auto_resolved: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*)
            FROM incidents i
            WHERE i.tenant_id = $1 AND i.status = 'resolved'
            AND NOT EXISTS (
                SELECT 1 FROM actions a
                WHERE a.incident_id = i.id
                AND a.tenant_id = i.tenant_id
                AND a.approval_status = 'manually_approved'
            )
            "#,
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        let total_resolved: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM incidents WHERE tenant_id = $1 AND status = 'resolved'",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(PerformanceMetricsData {
            mean_time_to_triage_seconds: mttt,
            mean_time_to_respond_seconds: mttr,
            auto_resolved_count: auto_resolved as u64,
            total_resolved_count: total_resolved as u64,
        })
    }
}

/// Factory function to create the appropriate repository based on pool type.
#[cfg(feature = "database")]
pub fn create_metrics_repository(pool: &DbPool) -> Box<dyn MetricsRepository> {
    match pool {
        DbPool::Sqlite(pool) => Box::new(SqliteMetricsRepository::new(pool.clone())),
        DbPool::Postgres(pool) => Box::new(PgMetricsRepository::new(pool.clone())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_incident_metrics_default() {
        let metrics = IncidentMetricsData::default();
        assert_eq!(metrics.total, 0);
        assert!(metrics.by_status.is_empty());
        assert!(metrics.by_severity.is_empty());
    }

    #[test]
    fn test_action_metrics_default() {
        let metrics = ActionMetricsData::default();
        assert_eq!(metrics.total_executed, 0);
        assert_eq!(metrics.success_count, 0);
        assert_eq!(metrics.pending_approvals, 0);
    }

    #[test]
    fn test_performance_metrics_default() {
        let metrics = PerformanceMetricsData::default();
        assert!(metrics.mean_time_to_triage_seconds.is_none());
        assert!(metrics.mean_time_to_respond_seconds.is_none());
        assert_eq!(metrics.auto_resolved_count, 0);
        assert_eq!(metrics.total_resolved_count, 0);
    }
}
