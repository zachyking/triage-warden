-- Add composite indexes for common query patterns (SQLite)

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
