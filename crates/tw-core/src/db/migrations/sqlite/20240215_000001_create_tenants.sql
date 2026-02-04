-- Tenants table for multi-tenant support (SQLite)
-- This table is the foundation of multi-tenancy - every tenant-scoped entity references this table.

-- Tenants table
CREATE TABLE IF NOT EXISTS tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'pending_deletion')),
    settings TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Index for slug lookups (subdomain routing)
CREATE UNIQUE INDEX IF NOT EXISTS idx_tenants_slug ON tenants(slug);

-- Index for active tenants
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- Insert default tenant for backward compatibility with existing data
-- Using a fixed UUID for reproducibility across environments
INSERT OR IGNORE INTO tenants (id, name, slug, status, settings, created_at, updated_at)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default Organization',
    'default',
    'active',
    '{}',
    datetime('now'),
    datetime('now')
);
