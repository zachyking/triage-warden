//! Database schema and migrations.

use super::{DbError, DbPool};

/// Runs database migrations.
#[cfg(feature = "database")]
pub async fn run_migrations(pool: &DbPool) -> Result<(), DbError> {
    use tracing::info;

    match pool {
        DbPool::Sqlite(pool) => {
            info!("Running SQLite migrations");
            sqlx::migrate!("src/db/migrations/sqlite").run(pool).await?;
        }
        DbPool::Postgres(pool) => {
            info!("Running PostgreSQL migrations");
            sqlx::migrate!("src/db/migrations/postgres")
                .run(pool)
                .await?;
        }
    }

    info!("Migrations completed successfully");
    Ok(())
}

#[cfg(not(feature = "database"))]
pub async fn run_migrations(_pool: &DbPool) -> Result<(), DbError> {
    Err(DbError::Configuration(
        "Database support not enabled".to_string(),
    ))
}

/// SQL statements for creating the schema (used for documentation and manual setup).
#[allow(dead_code)]
pub mod sql {
    /// SQL to create the incidents table.
    pub const CREATE_INCIDENTS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS incidents (
            id UUID PRIMARY KEY,
            source TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            alert_data JSONB NOT NULL,
            enrichments JSONB NOT NULL DEFAULT '[]',
            analysis JSONB,
            proposed_actions JSONB NOT NULL DEFAULT '[]',
            ticket_id TEXT,
            tags JSONB NOT NULL DEFAULT '[]',
            metadata JSONB NOT NULL DEFAULT '{}',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
            updated_at TIMESTAMP WITH TIME ZONE NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
        CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
        CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);
    "#;

    /// SQL to create the audit_logs table.
    pub const CREATE_AUDIT_LOGS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS audit_logs (
            id UUID PRIMARY KEY,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action TEXT NOT NULL,
            actor TEXT NOT NULL,
            details JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_audit_logs_incident_id ON audit_logs(incident_id);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
    "#;

    /// SQL to create the actions table.
    pub const CREATE_ACTIONS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS actions (
            id UUID PRIMARY KEY,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            action_type TEXT NOT NULL,
            target JSONB NOT NULL,
            parameters JSONB NOT NULL DEFAULT '{}',
            reason TEXT NOT NULL,
            priority INTEGER NOT NULL DEFAULT 50,
            approval_status TEXT NOT NULL,
            approved_by TEXT,
            approval_timestamp TIMESTAMP WITH TIME ZONE,
            result JSONB,
            created_at TIMESTAMP WITH TIME ZONE NOT NULL,
            executed_at TIMESTAMP WITH TIME ZONE
        );

        CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id);
        CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(approval_status);
        CREATE INDEX IF NOT EXISTS idx_actions_created_at ON actions(created_at);
    "#;

    /// SQL to create the approvals table for tracking approval workflows.
    pub const CREATE_APPROVALS_TABLE: &str = r#"
        CREATE TABLE IF NOT EXISTS approvals (
            id UUID PRIMARY KEY,
            action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
            incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            approval_level TEXT NOT NULL,
            status TEXT NOT NULL,
            requested_by TEXT NOT NULL,
            requested_at TIMESTAMP WITH TIME ZONE NOT NULL,
            decided_by TEXT,
            decided_at TIMESTAMP WITH TIME ZONE,
            decision_reason TEXT,
            expires_at TIMESTAMP WITH TIME ZONE
        );

        CREATE INDEX IF NOT EXISTS idx_approvals_action_id ON approvals(action_id);
        CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
        CREATE INDEX IF NOT EXISTS idx_approvals_expires_at ON approvals(expires_at);
    "#;
}
