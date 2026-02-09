-- RBAC roles and assignments for granular authorization (Stage 6.2)

CREATE TABLE IF NOT EXISTS rbac_roles (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    permissions JSONB NOT NULL,
    is_system BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rbac_roles_tenant_id ON rbac_roles(tenant_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_roles_tenant_name
    ON rbac_roles(tenant_id, name);

CREATE TABLE IF NOT EXISTS rbac_user_roles (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES rbac_roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_rbac_user_roles_unique ON rbac_user_roles(user_id, role_id);
CREATE INDEX IF NOT EXISTS idx_rbac_user_roles_tenant_user ON rbac_user_roles(tenant_id, user_id);
CREATE INDEX IF NOT EXISTS idx_rbac_user_roles_tenant_role ON rbac_user_roles(tenant_id, role_id);
