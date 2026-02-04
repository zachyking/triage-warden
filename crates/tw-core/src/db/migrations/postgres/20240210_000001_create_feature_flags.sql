-- Feature flags table for controlling feature availability
CREATE TABLE IF NOT EXISTS feature_flags (
    name VARCHAR(100) PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    default_enabled BOOLEAN NOT NULL DEFAULT false,
    tenant_overrides JSONB NOT NULL DEFAULT '{}'::jsonb,
    percentage_rollout SMALLINT CHECK (percentage_rollout IS NULL OR (percentage_rollout >= 0 AND percentage_rollout <= 100)),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying recently updated flags
CREATE INDEX IF NOT EXISTS idx_feature_flags_updated ON feature_flags(updated_at);

-- Seed default feature flags for Stage 1 horizontal scaling features
INSERT INTO feature_flags (name, description, default_enabled) VALUES
    ('multi_tenancy', 'Enable multi-tenant mode with tenant isolation', false),
    ('distributed_queue', 'Use Redis Streams message queue instead of in-memory', false),
    ('enrichment_cache', 'Enable Redis caching for enrichment results', false),
    ('rag_analysis', 'Enable RAG-enhanced AI analysis', false),
    ('nl_query', 'Enable natural language query interface', false)
ON CONFLICT (name) DO NOTHING;
