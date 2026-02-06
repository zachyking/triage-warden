-- Lessons learned table
CREATE TABLE IF NOT EXISTS lessons_learned (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'identified',
    owner TEXT,
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_lessons_tenant_id ON lessons_learned(tenant_id);
CREATE INDEX IF NOT EXISTS idx_lessons_incident_id ON lessons_learned(incident_id);
CREATE INDEX IF NOT EXISTS idx_lessons_status ON lessons_learned(status);
CREATE INDEX IF NOT EXISTS idx_lessons_category ON lessons_learned(category);
CREATE INDEX IF NOT EXISTS idx_lessons_owner ON lessons_learned(owner);

-- Shift handoffs table
CREATE TABLE IF NOT EXISTS shift_handoffs (
    id TEXT PRIMARY KEY NOT NULL,
    tenant_id TEXT NOT NULL,
    shift_start TEXT NOT NULL,
    shift_end TEXT NOT NULL,
    analyst_id TEXT NOT NULL,
    analyst_name TEXT NOT NULL,
    open_incidents TEXT NOT NULL DEFAULT '[]',
    pending_actions TEXT NOT NULL DEFAULT '[]',
    notable_events TEXT NOT NULL DEFAULT '[]',
    recommendations TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_handoffs_tenant_id ON shift_handoffs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_handoffs_analyst_id ON shift_handoffs(analyst_id);
CREATE INDEX IF NOT EXISTS idx_handoffs_created_at ON shift_handoffs(created_at);
