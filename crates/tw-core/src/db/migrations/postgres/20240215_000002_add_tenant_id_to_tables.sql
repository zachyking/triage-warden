-- Add tenant_id to all tenant-scoped tables (PostgreSQL)
-- This migration adds multi-tenancy support to the core data model.
--
-- Strategy: Three-step approach for backward compatibility:
-- 1. Add nullable tenant_id column
-- 2. Backfill existing rows with default tenant
-- 3. Add NOT NULL constraint
--
-- Tables modified:
-- - incidents
-- - audit_logs
-- - actions
-- - approvals
-- - users
-- - api_keys
-- - playbooks
-- - policies
-- - connectors
-- - notification_channels
-- - settings (key becomes composite with tenant_id)

-- Default tenant UUID (must match the one in create_tenants migration)
-- Using DO block to create a variable for reuse
DO $$
DECLARE
    default_tenant_id UUID := '00000000-0000-0000-0000-000000000001';
BEGIN

-- ============================================================================
-- INCIDENTS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'incidents' AND column_name = 'tenant_id'
) THEN
    -- Step 1: Add nullable column
    ALTER TABLE incidents ADD COLUMN tenant_id UUID;

    -- Step 2: Backfill with default tenant
    UPDATE incidents SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;

    -- Step 3: Add NOT NULL constraint and foreign key
    ALTER TABLE incidents
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_incidents_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- AUDIT_LOGS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'audit_logs' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE audit_logs ADD COLUMN tenant_id UUID;
    UPDATE audit_logs SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE audit_logs
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- ACTIONS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'actions' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE actions ADD COLUMN tenant_id UUID;
    UPDATE actions SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE actions
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_actions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- APPROVALS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'approvals' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE approvals ADD COLUMN tenant_id UUID;
    UPDATE approvals SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE approvals
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_approvals_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- USERS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'users' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE users ADD COLUMN tenant_id UUID;
    UPDATE users SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE users
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;

    -- Drop existing unique constraint on email and username, add tenant-scoped unique
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
    ALTER TABLE users DROP CONSTRAINT IF EXISTS users_username_key;
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_email ON users(tenant_id, email);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_tenant_username ON users(tenant_id, username);
END IF;

-- ============================================================================
-- API_KEYS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'api_keys' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE api_keys ADD COLUMN tenant_id UUID;
    UPDATE api_keys SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE api_keys
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_api_keys_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- PLAYBOOKS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'playbooks' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE playbooks ADD COLUMN tenant_id UUID;
    UPDATE playbooks SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE playbooks
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_playbooks_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- POLICIES TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'policies' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE policies ADD COLUMN tenant_id UUID;
    UPDATE policies SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE policies
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_policies_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- CONNECTORS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'connectors' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE connectors ADD COLUMN tenant_id UUID;
    UPDATE connectors SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE connectors
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_connectors_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- NOTIFICATION_CHANNELS TABLE
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'notification_channels' AND column_name = 'tenant_id'
) THEN
    ALTER TABLE notification_channels ADD COLUMN tenant_id UUID;
    UPDATE notification_channels SET tenant_id = default_tenant_id WHERE tenant_id IS NULL;
    ALTER TABLE notification_channels
        ALTER COLUMN tenant_id SET NOT NULL,
        ADD CONSTRAINT fk_notification_channels_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

-- ============================================================================
-- SETTINGS TABLE
-- Settings are special: key was the primary key, now we need (tenant_id, key)
-- ============================================================================
IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'settings' AND column_name = 'tenant_id'
) THEN
    -- Create new settings table with tenant_id
    CREATE TABLE settings_new (
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        key TEXT NOT NULL,
        value JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (tenant_id, key)
    );

    -- Copy existing data with default tenant
    INSERT INTO settings_new (tenant_id, key, value, updated_at)
    SELECT default_tenant_id, key, value, updated_at FROM settings;

    -- Drop old table and rename new one
    DROP TABLE settings;
    ALTER TABLE settings_new RENAME TO settings;

    -- Create index for tenant lookups
    CREATE INDEX IF NOT EXISTS idx_settings_tenant_id ON settings(tenant_id);
END IF;

-- ============================================================================
-- FEATURE_FLAGS TABLE (if exists)
-- Feature flags may need tenant-specific overrides
-- ============================================================================
IF EXISTS (
    SELECT 1 FROM information_schema.tables WHERE table_name = 'feature_flags'
) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'feature_flags' AND column_name = 'tenant_id'
) THEN
    -- Feature flags are global by default, tenant_id is nullable for global flags
    ALTER TABLE feature_flags ADD COLUMN tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
END IF;

END $$;

-- ============================================================================
-- COMPOSITE INDEXES for query performance
-- All queries will filter by tenant_id, so it should be the leading column
-- ============================================================================

-- Incidents indexes
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_status ON incidents(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_severity ON incidents(tenant_id, severity);
CREATE INDEX IF NOT EXISTS idx_incidents_tenant_created_at ON incidents(tenant_id, created_at DESC);

-- Audit logs indexes
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_incident ON audit_logs(tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created_at ON audit_logs(tenant_id, created_at DESC);

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
