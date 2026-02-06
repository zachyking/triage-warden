-- Comments table
CREATE TABLE IF NOT EXISTS incident_comments (
    id UUID PRIMARY KEY NOT NULL,
    incident_id UUID NOT NULL,
    author_id UUID NOT NULL,
    content TEXT NOT NULL,
    comment_type TEXT NOT NULL,
    mentions JSONB NOT NULL DEFAULT '[]',
    tenant_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    edited BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_comments_incident_id ON incident_comments(incident_id);
CREATE INDEX IF NOT EXISTS idx_comments_author_id ON incident_comments(author_id);
CREATE INDEX IF NOT EXISTS idx_comments_tenant_id ON incident_comments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON incident_comments(created_at);

-- Activity entries table
CREATE TABLE IF NOT EXISTS activity_entries (
    id UUID PRIMARY KEY NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    actor_id UUID,
    actor_name TEXT,
    activity_type TEXT NOT NULL,
    incident_id UUID,
    description TEXT NOT NULL,
    metadata JSONB,
    tenant_id UUID NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_incident_id ON activity_entries(incident_id);
CREATE INDEX IF NOT EXISTS idx_activity_type ON activity_entries(activity_type);
CREATE INDEX IF NOT EXISTS idx_activity_tenant_id ON activity_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activity_actor_id ON activity_entries(actor_id);
