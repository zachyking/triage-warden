-- RBAC roles and assignments for granular authorization (Stage 6.2)

CREATE TABLE IF NOT EXISTS rbac_roles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    permissions TEXT NOT NULL,
    is_system INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rbac_roles_tenant_id ON rbac_roles(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_roles_tenant_name
    ON rbac_roles(tenant_id, name);

CREATE TABLE IF NOT EXISTS rbac_user_roles (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    assigned_by TEXT,
    assigned_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_user_roles_unique ON rbac_user_roles(user_id, role_id);
CREATE INDEX IF NOT EXISTS idx_rbac_user_roles_tenant_user ON rbac_user_roles(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_rbac_user_roles_tenant_role ON rbac_user_roles(tenant_id, role_id);
