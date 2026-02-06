-- Lessons learned table
CREATE TABLE IF NOT EXISTS lessons_learned (
    id UUID PRIMARY KEY NOT NULL,
    tenant_id UUID NOT NULL,
    incident_id UUID NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'identified',
    owner UUID,
    due_date TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_lessons_tenant_id ON lessons_learned(tenant_id);
CREATE INDEX IF NOT EXISTS idx_lessons_incident_id ON lessons_learned(incident_id);
CREATE INDEX IF NOT EXISTS idx_lessons_status ON lessons_learned(status);
CREATE INDEX IF NOT EXISTS idx_lessons_category ON lessons_learned(category);
CREATE INDEX IF NOT EXISTS idx_lessons_owner ON lessons_learned(owner);

-- Shift handoffs table
CREATE TABLE IF NOT EXISTS shift_handoffs (
    id UUID PRIMARY KEY NOT NULL,
    tenant_id UUID NOT NULL,
    shift_start TIMESTAMPTZ NOT NULL,
    shift_end TIMESTAMPTZ NOT NULL,
    analyst_id UUID NOT NULL,
    analyst_name TEXT NOT NULL,
    open_incidents JSONB NOT NULL DEFAULT '[]'::jsonb,
    pending_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    notable_events JSONB NOT NULL DEFAULT '[]'::jsonb,
    recommendations JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_handoffs_tenant_id ON shift_handoffs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_handoffs_analyst_id ON shift_handoffs(analyst_id);
CREATE INDEX IF NOT EXISTS idx_handoffs_created_at ON shift_handoffs(created_at);
