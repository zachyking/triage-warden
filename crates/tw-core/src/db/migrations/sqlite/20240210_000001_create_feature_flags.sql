-- Feature flags table for controlling feature availability
CREATE TABLE IF NOT EXISTS feature_flags (
    name TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    default_enabled INTEGER NOT NULL DEFAULT 0,
    tenant_overrides TEXT NOT NULL DEFAULT '{}',
    percentage_rollout INTEGER CHECK (percentage_rollout IS NULL OR (percentage_rollout >= 0 AND percentage_rollout <= 100)),
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Index for querying recently updated flags
CREATE INDEX IF NOT EXISTS idx_feature_flags_updated ON feature_flags(updated_at);

-- Seed default feature flags for Stage 1 horizontal scaling features
INSERT OR IGNORE INTO feature_flags (name, description, default_enabled, created_at, updated_at) VALUES
    ('multi_tenancy', 'Enable multi-tenant mode with tenant isolation', 0, datetime('now'), datetime('now')),
    ('distributed_queue', 'Use Redis Streams message queue instead of in-memory', 0, datetime('now'), datetime('now')),
    ('enrichment_cache', 'Enable Redis caching for enrichment results', 0, datetime('now'), datetime('now')),
    ('rag_analysis', 'Enable RAG-enhanced AI analysis', 0, datetime('now'), datetime('now')),
    ('nl_query', 'Enable natural language query interface', 0, datetime('now'), datetime('now'));
