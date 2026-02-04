-- Migration: Add tenant_id to all tenant-scoped tables
-- This migration adds the tenant_id foreign key column to support multi-tenancy.
-- Existing data is assigned to the default tenant.
--
-- Strategy:
-- 1. Add tenant_id column as nullable
-- 2. Update existing rows to reference default tenant
-- 3. Make column NOT NULL
-- 4. Add foreign key constraint
-- 5. Create composite indexes for query performance

-- Get the default tenant ID (created in 20240215_000001_create_tenants.sql)
-- Default tenant UUID: '00000000-0000-0000-0000-000000000001'

-- ============================================================================
-- INCIDENTS TABLE
-- ============================================================================
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE incidents SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE incidents ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE incidents ADD CONSTRAINT fk_incidents_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Composite indexes for common query patterns
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity ON incidents(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_created ON incidents(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_updated ON incidents(tenant_id, updated_at DESC);

-- ============================================================================
-- AUDIT_LOGS TABLE
-- ============================================================================
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill from incidents table
UPDATE audit_logs al SET tenant_id = i.tenant_id
FROM incidents i
WHERE al.incident_id = i.id AND al.tenant_id IS NULL;

-- For any orphaned audit logs, use default tenant
UPDATE audit_logs SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE audit_logs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_actor ON audit_logs(tenant_id, actor);

-- ============================================================================
-- ACTIONS TABLE
-- ============================================================================
ALTER TABLE actions ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill from incidents table
UPDATE actions a SET tenant_id = i.tenant_id
FROM incidents i
WHERE a.incident_id = i.id AND a.tenant_id IS NULL;

-- For any orphaned actions, use default tenant
UPDATE actions SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE actions ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE actions ADD CONSTRAINT fk_actions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_actions_tenant_status ON actions(tenant_id, approval_status);
CREATE INDEX IF NOT EXISTS idx_actions_tenant_created ON actions(tenant_id, created_at DESC);

-- ============================================================================
-- APPROVALS TABLE
-- ============================================================================
ALTER TABLE approvals ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill from incidents table
UPDATE approvals ap SET tenant_id = i.tenant_id
FROM incidents i
WHERE ap.incident_id = i.id AND ap.tenant_id IS NULL;

-- For any orphaned approvals, use default tenant
UPDATE approvals SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE approvals ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE approvals ADD CONSTRAINT fk_approvals_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_approvals_tenant_status ON approvals(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_approvals_tenant_expires ON approvals(tenant_id, expires_at);

-- ============================================================================
-- USERS TABLE
-- ============================================================================
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE users ADD CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

-- Drop existing unique constraints and recreate with tenant_id
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username);

CREATE INDEX IF NOT EXISTS idx_users_tenant_role ON users(tenant_id, role);
CREATE INDEX IF NOT EXISTS idx_users_tenant_enabled ON users(tenant_id, enabled);

-- ============================================================================
-- API_KEYS TABLE
-- ============================================================================
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS tenant_id UUID;

-- Backfill from users table
UPDATE api_keys ak SET tenant_id = u.tenant_id
FROM users u
WHERE ak.user_id = u.id AND ak.tenant_id IS NULL;

-- For any orphaned api_keys, use default tenant
UPDATE api_keys SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE api_keys ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE api_keys ADD CONSTRAINT fk_api_keys_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_user ON api_keys(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_tenant_prefix ON api_keys(tenant_id, key_prefix);

-- ============================================================================
-- SESSIONS TABLE
-- ============================================================================
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE sessions SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE sessions ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE sessions ADD CONSTRAINT fk_sessions_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);

-- ============================================================================
-- PLAYBOOKS TABLE
-- ============================================================================
ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE playbooks SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE playbooks ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE playbooks ADD CONSTRAINT fk_playbooks_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_enabled ON playbooks(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_playbooks_tenant_trigger ON playbooks(tenant_id, trigger_type);

-- ============================================================================
-- CONNECTORS TABLE
-- ============================================================================
ALTER TABLE connectors ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE connectors SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE connectors ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE connectors ADD CONSTRAINT fk_connectors_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_connectors_tenant_type ON connectors(tenant_id, connector_type);
CREATE INDEX IF NOT EXISTS idx_connectors_tenant_enabled ON connectors(tenant_id, enabled);

-- ============================================================================
-- POLICIES TABLE
-- ============================================================================
ALTER TABLE policies ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE policies SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE policies ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE policies ADD CONSTRAINT fk_policies_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_policies_tenant_enabled ON policies(tenant_id, enabled);
CREATE INDEX IF NOT EXISTS idx_policies_tenant_priority ON policies(tenant_id, priority DESC);

-- ============================================================================
-- NOTIFICATION_CHANNELS TABLE
-- ============================================================================
ALTER TABLE notification_channels ADD COLUMN IF NOT EXISTS tenant_id UUID;

UPDATE notification_channels SET tenant_id = '00000000-0000-0000-0000-000000000001'::uuid WHERE tenant_id IS NULL;

ALTER TABLE notification_channels ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE notification_channels ADD CONSTRAINT fk_notification_channels_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_notification_channels_tenant_type ON notification_channels(tenant_id, channel_type);
CREATE INDEX IF NOT EXISTS idx_notification_channels_tenant_enabled ON notification_channels(tenant_id, enabled);

-- ============================================================================
-- SETTINGS TABLE
-- Convert from single key to (tenant_id, key) composite primary key
-- ============================================================================

-- Create new settings table with tenant_id
CREATE TABLE IF NOT EXISTS settings_new (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, key)
);

-- Migrate existing settings to default tenant
INSERT INTO settings_new (tenant_id, key, value, updated_at)
SELECT '00000000-0000-0000-0000-000000000001'::uuid, key, value, updated_at
FROM settings
ON CONFLICT (tenant_id, key) DO NOTHING;

-- Drop old table and rename new one
DROP TABLE IF EXISTS settings;
ALTER TABLE settings_new RENAME TO settings;

CREATE INDEX IF NOT EXISTS idx_settings_tenant ON settings(tenant_id);
