-- Tenants table for multi-tenant support (PostgreSQL)
-- This table is the foundation of multi-tenancy - every tenant-scoped entity references this table.

-- Tenant status enum
DO $$ BEGIN
    CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'pending_deletion');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status tenant_status NOT NULL DEFAULT 'active',
    settings JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for slug lookups (subdomain routing)
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- Index for active tenants
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_tenants_updated_at ON tenants;
CREATE TRIGGER update_tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Insert default tenant for backward compatibility with existing data
-- Using a fixed UUID for reproducibility across environments
INSERT INTO tenants (id, name, slug, status, settings, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001'::uuid,
    'Default Organization',
    'default',
    'active',
    '{}'::jsonb,
    NOW(),
    NOW()
)
ON CONFLICT (slug) DO NOTHING;
