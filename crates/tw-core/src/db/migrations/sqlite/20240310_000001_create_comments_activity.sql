-- Comments table
CREATE TABLE IF NOT EXISTS incident_comments (
    id TEXT PRIMARY KEY NOT NULL,
    incident_id TEXT NOT NULL,
    author_id TEXT NOT NULL,
    content TEXT NOT NULL,
    comment_type TEXT NOT NULL,
    mentions TEXT NOT NULL DEFAULT '[]',
    tenant_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    edited INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_comments_incident_id ON incident_comments(incident_id);
CREATE INDEX IF NOT EXISTS idx_comments_author_id ON incident_comments(author_id);
CREATE INDEX IF NOT EXISTS idx_comments_tenant_id ON incident_comments(tenant_id);
CREATE INDEX IF NOT EXISTS idx_comments_created_at ON incident_comments(created_at);

-- Activity entries table
CREATE TABLE IF NOT EXISTS activity_entries (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    actor_id TEXT,
    actor_name TEXT,
    activity_type TEXT NOT NULL,
    incident_id TEXT,
    description TEXT NOT NULL,
    metadata TEXT,
    tenant_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_incident_id ON activity_entries(incident_id);
CREATE INDEX IF NOT EXISTS idx_activity_type ON activity_entries(activity_type);
CREATE INDEX IF NOT EXISTS idx_activity_tenant_id ON activity_entries(tenant_id);
CREATE INDEX IF NOT EXISTS idx_activity_actor_id ON activity_entries(actor_id);
