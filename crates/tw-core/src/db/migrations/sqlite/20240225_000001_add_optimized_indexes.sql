-- Add optimized indexes for common query patterns (SQLite)
-- Task 1.6.2: Database Index Optimization
--
-- These indexes are optimized for multi-tenant queries where tenant_id
-- is always the leading filter column.

-- ============================================================================
-- INCIDENTS TABLE - Optimized composite indexes
-- ============================================================================

-- Composite index for tenant-scoped status and time filtering
-- Used by: incident dashboard filtered by status, timeline views
-- Query pattern: WHERE tenant_id = ? AND status = ? ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status_created
    ON incidents(tenant_id, status, created_at DESC);

-- Composite index for tenant-scoped severity and status filtering
-- Used by: priority triage view, severity-based filtering
-- Query pattern: WHERE tenant_id = ? AND severity = ? AND status = ?
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity_status
    ON incidents(tenant_id, severity, status);

-- Note: SQLite does not support partial indexes with complex WHERE clauses
-- using IN or NOT IN, so we create a simpler covering index instead.
-- The query planner will still use this for active incident queries.
-- For true partial index support, use PostgreSQL.

-- ============================================================================
-- AUDIT_LOGS TABLE - Optimized composite indexes
-- ============================================================================

-- Composite index for tenant-scoped incident audit log queries
-- Used by: get audit logs for an incident within a tenant
-- Query pattern: WHERE tenant_id = ? AND incident_id = ? ORDER BY created_at
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_incident_created
    ON audit_logs(tenant_id, incident_id, created_at DESC);

-- Composite index for tenant-scoped actor queries
-- Used by: audit trail by actor within a tenant
-- Query pattern: WHERE tenant_id = ? AND actor = ? ORDER BY created_at DESC
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_actor_created
    ON audit_logs(tenant_id, actor, created_at DESC);

-- ============================================================================
-- ACTIONS TABLE - Additional optimized indexes
-- ============================================================================

-- Composite index for pending actions by tenant and creation time
-- Used by: pending approvals dashboard
-- Query pattern: WHERE tenant_id = ? AND approval_status = 'pending' ORDER BY created_at
CREATE INDEX IF NOT EXISTS idx_actions_tenant_pending_created
    ON actions(tenant_id, approval_status, created_at DESC);

-- ============================================================================
-- APPROVALS TABLE - Additional optimized indexes
-- ============================================================================

-- Composite index for expiring approvals by tenant
-- Used by: approval expiration monitoring
-- Query pattern: WHERE tenant_id = ? AND status = 'pending' AND expires_at < ?
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_pending_expires
    ON approvals(tenant_id, status, expires_at);
