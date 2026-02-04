-- Add tenant_id to all tenant-scoped tables (SQLite)
-- This migration adds multi-tenancy support to the core data model.
--
-- Note: SQLite doesn't support ALTER TABLE ADD COLUMN with NOT NULL unless
-- there's a default value, so we use a different approach:
-- 1. Add column with default value pointing to the default tenant
-- 2. Create new indexes
--
-- Default tenant UUID: 00000000-0000-0000-0000-000000000001

-- ============================================================================
-- INCIDENTS TABLE
-- ============================================================================
ALTER TABLE incidents ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- AUDIT_LOGS TABLE
-- ============================================================================
ALTER TABLE audit_logs ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- ACTIONS TABLE
-- ============================================================================
ALTER TABLE actions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- APPROVALS TABLE
-- ============================================================================
ALTER TABLE approvals ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- USERS TABLE
-- ============================================================================
ALTER TABLE users ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- Note: SQLite doesn't support dropping constraints, so we'll create new unique indexes
-- The original unique constraints on email/username will remain but tenant-scoped uniqueness
-- is enforced by the new indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username);

-- ============================================================================
-- API_KEYS TABLE
-- ============================================================================
ALTER TABLE api_keys ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- PLAYBOOKS TABLE
-- ============================================================================
ALTER TABLE playbooks ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- POLICIES TABLE
-- ============================================================================
ALTER TABLE policies ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- CONNECTORS TABLE
-- ============================================================================
ALTER TABLE connectors ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- NOTIFICATION_CHANNELS TABLE
-- ============================================================================
ALTER TABLE notification_channels ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE;

-- ============================================================================
-- SETTINGS TABLE
-- SQLite requires table recreation for changing primary key
-- ============================================================================
CREATE TABLE settings_new (
    tenant_id TEXT NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, key)
);

-- Copy existing data with default tenant
INSERT INTO settings_new (tenant_id, key, value, updated_at)
SELECT '00000000-0000-0000-0000-000000000001', key, value, updated_at FROM settings;

-- Drop old table and rename new one
DROP TABLE settings;
ALTER TABLE settings_new RENAME TO settings;

-- ============================================================================
-- FEATURE_FLAGS TABLE (if exists)
-- Feature flags are global, tenant_id is nullable for global flags
-- ============================================================================
-- Note: SQLite doesn't support IF EXISTS in ALTER TABLE, so we handle this
-- by checking if the table exists in the application layer

-- ============================================================================
-- COMPOSITE INDEXES for query performance
-- All queries will filter by tenant_id, so it should be the leading column
-- ============================================================================

-- Incidents indexes
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity ON incidents(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_created_at ON incidents(tenant_id, created_at);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_incident ON audit_logs(tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created_at ON audit_logs(tenant_id, created_at);

-- Actions indexes
CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions(tenant_id, approval_status);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_incident ON actions(tenant_id, incident_id);

-- Approvals indexes
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status ON approvals(tenant_id, status);

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role);
CREATE INDEX IF NOT EXISTS idx_users_tenant_enabled ON users(tenant_id, enabled);

-- API keys indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_user ON api_keys(tenant_id, user_id);

-- Playbooks indexes
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_enabled ON playbooks(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_trigger ON playbooks(tenant_id, trigger_type);

-- Policies indexes
CREATE INDEX IF NOT EXISTS idx_policies_tenant_enabled ON policies(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_priority ON policies(tenant_id, priority);

-- Connectors indexes
CREATE INDEX IF NOT EXISTS idx_connectors_tenant_enabled ON connectors(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant_type ON connectors(tenant_id, connector_type);

-- Notification channels indexes
CREATE INDEX IF NOT EXISTS idx_notification_channels_tenant_enabled ON notification_channels(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_notification_channels_tenant_type ON notification_channels(tenant_id, channel_type);

-- Settings index
CREATE INDEX IF NOT EXISTS idx_settings_tenant_id ON settings(tenant_id);
