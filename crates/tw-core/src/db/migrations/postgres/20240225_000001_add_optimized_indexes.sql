-- Add optimized indexes for common query patterns (PostgreSQL)
-- Task 1.6.2: Database Index Optimization
--
-- These indexes are optimized for multi-tenant queries where tenant_id
-- is always the leading filter column. PostgreSQL supports partial indexes
-- for more efficient storage and query performance.

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

-- Partial index for active incidents only (PostgreSQL-specific optimization)
-- Only indexes incidents that are not closed, resolved, or false positives
-- Used by: active incidents dashboard, triage queue
-- This significantly reduces index size for tenants with many historical incidents
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_active
    ON incidents(tenant_id, status, severity, created_at DESC)
    WHERE status NOT IN ('closed', 'resolved', 'false_positive');

-- Partial index for high-priority incidents requiring immediate attention
-- Used by: critical incident alerts, priority escalation
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_critical_active
    ON incidents(tenant_id, created_at DESC)
    WHERE severity IN ('critical', 'high')
    AND status NOT IN ('closed', 'resolved', 'false_positive');

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

-- Partial index for pending actions only (PostgreSQL-specific optimization)
-- Reduces index size by only indexing pending actions
CREATE INDEX IF NOT EXISTS idx_actions_tenant_pending_only
    ON actions(tenant_id, incident_id, created_at DESC)
    WHERE approval_status = 'pending';

-- ============================================================================
-- APPROVALS TABLE - Additional optimized indexes
-- ============================================================================

-- Composite index for expiring approvals by tenant
-- Used by: approval expiration monitoring
-- Query pattern: WHERE tenant_id = ? AND status = 'pending' AND expires_at < ?
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_pending_expires
    ON approvals(tenant_id, status, expires_at);

-- Partial index for pending approvals only (PostgreSQL-specific optimization)
-- Reduces index size by only indexing pending approvals
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_pending_only
    ON approvals(tenant_id, expires_at, incident_id)
    WHERE status = 'pending';
