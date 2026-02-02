-- Add composite indexes for common query patterns (PostgreSQL)

-- Composite index for audit logs: queries by incident ordered by time
-- Used by: get_logs_for_incident(), dashboard audit trails
CREATE INDEX IF NOT EXISTS idx_audit_logs_incident_created
    ON audit_logs(incident_id, created_at DESC);

-- Composite index for incidents: status + severity + time filtering
-- Used by: incident dashboard, filtered queries, priority views
CREATE INDEX IF NOT EXISTS idx_incidents_status_severity_created
    ON incidents(status, severity, created_at DESC);

-- Composite index for incidents: status + created_at for timeline views
-- Used by: incident timeline, status-based queries
CREATE INDEX IF NOT EXISTS idx_incidents_status_created
    ON incidents(status, created_at DESC);

-- Composite index for actions: incident lookup with status filtering
-- Used by: pending actions view, incident action history
CREATE INDEX IF NOT EXISTS idx_actions_incident_status
    ON actions(incident_id, approval_status);

-- Composite index for approvals: pending approvals by expiry
-- Used by: approval dashboard, expiration checks
CREATE INDEX IF NOT EXISTS idx_approvals_status_expires
    ON approvals(status, expires_at);

-- Partial index for active incidents (PostgreSQL-specific optimization)
-- Only indexes non-closed incidents for faster active incident queries
CREATE INDEX IF NOT EXISTS idx_incidents_active
    ON incidents(status, severity, created_at DESC)
    WHERE status NOT IN ('resolved', 'false_positive', 'closed');

-- Partial index for pending approvals (PostgreSQL-specific optimization)
-- Used for quick lookup of approvals that need attention
CREATE INDEX IF NOT EXISTS idx_approvals_pending
    ON approvals(expires_at, incident_id)
    WHERE status = 'pending';
