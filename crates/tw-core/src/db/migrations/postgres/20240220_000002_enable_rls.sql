-- Migration: Enable Row-Level Security (RLS) for multi-tenant isolation
--
-- This migration enables PostgreSQL RLS on all tenant-scoped tables to provide
-- defense-in-depth tenant isolation. Even if application code has bugs, RLS
-- prevents cross-tenant data access at the database level.
--
-- HOW IT WORKS:
-- 1. Application sets: SET app.current_tenant = 'tenant-uuid'
-- 2. All queries automatically filtered by tenant_id
-- 3. Superusers bypass RLS - use dedicated app role for normal operations
--
-- IMPORTANT: The application MUST set app.current_tenant before executing queries.
-- If not set, queries will return no rows (fail-secure behavior).

-- ============================================================================
-- CREATE APPLICATION ROLE FOR RLS ENFORCEMENT
-- ============================================================================
-- This role will have RLS policies applied, unlike superuser which bypasses RLS

DO $$
BEGIN
    -- Create application role if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tw_app') THEN
        CREATE ROLE tw_app WITH LOGIN;
    END IF;
END $$;

-- Grant necessary permissions to the app role
GRANT USAGE ON SCHEMA public TO tw_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tw_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO tw_app;

-- Ensure future tables also get these grants
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO tw_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO tw_app;

-- ============================================================================
-- ENABLE RLS ON TENANT-SCOPED TABLES
-- ============================================================================

-- Enable RLS (policies are not enforced until we create them)
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE playbooks ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;

-- Force RLS for table owners too (important for security)
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE actions FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE playbooks FORCE ROW LEVEL SECURITY;
ALTER TABLE connectors FORCE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
ALTER TABLE settings FORCE ROW LEVEL SECURITY;

-- ============================================================================
-- CREATE RLS POLICIES
-- ============================================================================
-- Policy naming convention: {table}_{operation}_tenant_isolation
--
-- Using current_setting('app.current_tenant', true):
-- - 'true' parameter returns NULL if setting doesn't exist (instead of error)
-- - When NULL, the comparison fails and no rows match (fail-secure)

-- INCIDENTS
DROP POLICY IF EXISTS incidents_select_tenant_isolation ON incidents;
CREATE POLICY incidents_select_tenant_isolation ON incidents
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS incidents_insert_tenant_isolation ON incidents;
CREATE POLICY incidents_insert_tenant_isolation ON incidents
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS incidents_update_tenant_isolation ON incidents;
CREATE POLICY incidents_update_tenant_isolation ON incidents
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS incidents_delete_tenant_isolation ON incidents;
CREATE POLICY incidents_delete_tenant_isolation ON incidents
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- AUDIT_LOGS
DROP POLICY IF EXISTS audit_logs_select_tenant_isolation ON audit_logs;
CREATE POLICY audit_logs_select_tenant_isolation ON audit_logs
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS audit_logs_insert_tenant_isolation ON audit_logs;
CREATE POLICY audit_logs_insert_tenant_isolation ON audit_logs
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- Audit logs are append-only: no UPDATE or DELETE policies
-- Any attempts to modify/delete audit logs will be denied by RLS

-- ACTIONS
DROP POLICY IF EXISTS actions_select_tenant_isolation ON actions;
CREATE POLICY actions_select_tenant_isolation ON actions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS actions_insert_tenant_isolation ON actions;
CREATE POLICY actions_insert_tenant_isolation ON actions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS actions_update_tenant_isolation ON actions;
CREATE POLICY actions_update_tenant_isolation ON actions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS actions_delete_tenant_isolation ON actions;
CREATE POLICY actions_delete_tenant_isolation ON actions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- APPROVALS
DROP POLICY IF EXISTS approvals_select_tenant_isolation ON approvals;
CREATE POLICY approvals_select_tenant_isolation ON approvals
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS approvals_insert_tenant_isolation ON approvals;
CREATE POLICY approvals_insert_tenant_isolation ON approvals
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS approvals_update_tenant_isolation ON approvals;
CREATE POLICY approvals_update_tenant_isolation ON approvals
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS approvals_delete_tenant_isolation ON approvals;
CREATE POLICY approvals_delete_tenant_isolation ON approvals
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- USERS
DROP POLICY IF EXISTS users_select_tenant_isolation ON users;
CREATE POLICY users_select_tenant_isolation ON users
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS users_insert_tenant_isolation ON users;
CREATE POLICY users_insert_tenant_isolation ON users
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS users_update_tenant_isolation ON users;
CREATE POLICY users_update_tenant_isolation ON users
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS users_delete_tenant_isolation ON users;
CREATE POLICY users_delete_tenant_isolation ON users
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- API_KEYS
DROP POLICY IF EXISTS api_keys_select_tenant_isolation ON api_keys;
CREATE POLICY api_keys_select_tenant_isolation ON api_keys
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS api_keys_insert_tenant_isolation ON api_keys;
CREATE POLICY api_keys_insert_tenant_isolation ON api_keys
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS api_keys_update_tenant_isolation ON api_keys;
CREATE POLICY api_keys_update_tenant_isolation ON api_keys
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS api_keys_delete_tenant_isolation ON api_keys;
CREATE POLICY api_keys_delete_tenant_isolation ON api_keys
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- SESSIONS
DROP POLICY IF EXISTS sessions_select_tenant_isolation ON sessions;
CREATE POLICY sessions_select_tenant_isolation ON sessions
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS sessions_insert_tenant_isolation ON sessions;
CREATE POLICY sessions_insert_tenant_isolation ON sessions
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS sessions_update_tenant_isolation ON sessions;
CREATE POLICY sessions_update_tenant_isolation ON sessions
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS sessions_delete_tenant_isolation ON sessions;
CREATE POLICY sessions_delete_tenant_isolation ON sessions
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- PLAYBOOKS
DROP POLICY IF EXISTS playbooks_select_tenant_isolation ON playbooks;
CREATE POLICY playbooks_select_tenant_isolation ON playbooks
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS playbooks_insert_tenant_isolation ON playbooks;
CREATE POLICY playbooks_insert_tenant_isolation ON playbooks
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS playbooks_update_tenant_isolation ON playbooks;
CREATE POLICY playbooks_update_tenant_isolation ON playbooks
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS playbooks_delete_tenant_isolation ON playbooks;
CREATE POLICY playbooks_delete_tenant_isolation ON playbooks
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- CONNECTORS
DROP POLICY IF EXISTS connectors_select_tenant_isolation ON connectors;
CREATE POLICY connectors_select_tenant_isolation ON connectors
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS connectors_insert_tenant_isolation ON connectors;
CREATE POLICY connectors_insert_tenant_isolation ON connectors
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS connectors_update_tenant_isolation ON connectors;
CREATE POLICY connectors_update_tenant_isolation ON connectors
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS connectors_delete_tenant_isolation ON connectors;
CREATE POLICY connectors_delete_tenant_isolation ON connectors
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- POLICIES (the approval/automation rules table)
DROP POLICY IF EXISTS policies_select_tenant_isolation ON policies;
CREATE POLICY policies_select_tenant_isolation ON policies
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS policies_insert_tenant_isolation ON policies;
CREATE POLICY policies_insert_tenant_isolation ON policies
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS policies_update_tenant_isolation ON policies;
CREATE POLICY policies_update_tenant_isolation ON policies
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS policies_delete_tenant_isolation ON policies;
CREATE POLICY policies_delete_tenant_isolation ON policies
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- NOTIFICATION_CHANNELS
DROP POLICY IF EXISTS notification_channels_select_tenant_isolation ON notification_channels;
CREATE POLICY notification_channels_select_tenant_isolation ON notification_channels
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS notification_channels_insert_tenant_isolation ON notification_channels;
CREATE POLICY notification_channels_insert_tenant_isolation ON notification_channels
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS notification_channels_update_tenant_isolation ON notification_channels;
CREATE POLICY notification_channels_update_tenant_isolation ON notification_channels
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS notification_channels_delete_tenant_isolation ON notification_channels;
CREATE POLICY notification_channels_delete_tenant_isolation ON notification_channels
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- SETTINGS
DROP POLICY IF EXISTS settings_select_tenant_isolation ON settings;
CREATE POLICY settings_select_tenant_isolation ON settings
    FOR SELECT
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS settings_insert_tenant_isolation ON settings;
CREATE POLICY settings_insert_tenant_isolation ON settings
    FOR INSERT
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS settings_update_tenant_isolation ON settings;
CREATE POLICY settings_update_tenant_isolation ON settings
    FOR UPDATE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant', true)::uuid);

DROP POLICY IF EXISTS settings_delete_tenant_isolation ON settings;
CREATE POLICY settings_delete_tenant_isolation ON settings
    FOR DELETE
    USING (tenant_id = current_setting('app.current_tenant', true)::uuid);

-- ============================================================================
-- CREATE HELPER FUNCTION FOR SETTING TENANT CONTEXT
-- ============================================================================
-- This function provides a clean interface for setting the tenant context.
-- Returns the previous tenant ID (if any) for optional restoration.

CREATE OR REPLACE FUNCTION set_tenant_context(p_tenant_id UUID)
RETURNS UUID AS $$
DECLARE
    v_previous_tenant UUID;
BEGIN
    -- Get current setting (returns NULL if not set)
    BEGIN
        v_previous_tenant := current_setting('app.current_tenant', true)::uuid;
    EXCEPTION WHEN OTHERS THEN
        v_previous_tenant := NULL;
    END;

    -- Set the new tenant context for this session
    PERFORM set_config('app.current_tenant', p_tenant_id::text, false);

    RETURN v_previous_tenant;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Allow the app role to call this function
GRANT EXECUTE ON FUNCTION set_tenant_context(UUID) TO tw_app;

-- ============================================================================
-- CREATE HELPER FUNCTION FOR CLEARING TENANT CONTEXT
-- ============================================================================
-- Useful for admin operations or background jobs that need to operate
-- without tenant context (which will fail all RLS-protected queries).

CREATE OR REPLACE FUNCTION clear_tenant_context()
RETURNS VOID AS $$
BEGIN
    PERFORM set_config('app.current_tenant', '', false);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION clear_tenant_context() TO tw_app;

-- ============================================================================
-- CREATE HELPER FUNCTION TO GET CURRENT TENANT
-- ============================================================================

CREATE OR REPLACE FUNCTION get_current_tenant()
RETURNS UUID AS $$
DECLARE
    v_tenant_id UUID;
BEGIN
    BEGIN
        v_tenant_id := current_setting('app.current_tenant', true)::uuid;
    EXCEPTION WHEN OTHERS THEN
        v_tenant_id := NULL;
    END;
    RETURN v_tenant_id;
END;
$$ LANGUAGE plpgsql STABLE SECURITY DEFINER;

GRANT EXECUTE ON FUNCTION get_current_tenant() TO tw_app;

-- ============================================================================
-- DOCUMENTATION: HOW TO USE RLS IN THE APPLICATION
-- ============================================================================
--
-- 1. SET TENANT CONTEXT (at the start of each request):
--    SELECT set_tenant_context('tenant-uuid-here');
--    -- or --
--    SET app.current_tenant = 'tenant-uuid-here';
--
-- 2. EXECUTE QUERIES (automatically filtered by tenant):
--    SELECT * FROM incidents;  -- Only returns current tenant's incidents
--    INSERT INTO incidents (...) VALUES (...);  -- tenant_id must match
--
-- 3. ADMIN OPERATIONS (bypass RLS):
--    Option A: Use a superuser connection (bypasses RLS)
--    Option B: Create a separate admin role with BYPASSRLS privilege
--
-- 4. VERIFY RLS IS WORKING:
--    SET app.current_tenant = 'tenant-a-uuid';
--    SELECT count(*) FROM incidents;  -- Count for tenant A
--
--    SET app.current_tenant = 'tenant-b-uuid';
--    SELECT count(*) FROM incidents;  -- Count for tenant B (different!)
--
-- 5. DEBUGGING:
--    SELECT get_current_tenant();  -- Shows current tenant context
--    SELECT * FROM pg_policies WHERE tablename = 'incidents';  -- Show policies
--
