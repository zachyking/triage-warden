-- Knowledge base table for RAG integration (PostgreSQL)
-- Stores organizational knowledge documents like runbooks, threat intel reports, and policies.

-- Knowledge type enum
DO $$ BEGIN
    CREATE TYPE knowledge_type AS ENUM (
        'runbook',
        'threat_intel_report',
        'security_policy',
        'post_mortem',
        'vendor_documentation'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Knowledge documents table
CREATE TABLE IF NOT EXISTS knowledge_documents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Document classification
    doc_type TEXT NOT NULL,

    -- Document content
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,

    -- Metadata (JSONB for efficient querying)
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    -- Status
    is_active BOOLEAN NOT NULL DEFAULT true,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    indexed_at TIMESTAMPTZ,

    -- User tracking
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_by UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Index for tenant + doc_type lookups (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_tenant_type
    ON knowledge_documents(tenant_id, doc_type);

-- Index for active documents
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_active
    ON knowledge_documents(tenant_id, is_active)
    WHERE is_active = true;

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_created_at
    ON knowledge_documents(tenant_id, created_at DESC);

-- Index for documents needing indexing
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_needs_indexing
    ON knowledge_documents(tenant_id, updated_at)
    WHERE indexed_at IS NULL OR indexed_at < updated_at;

-- GIN index for JSONB metadata queries (tags, keywords, MITRE techniques)
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_metadata
    ON knowledge_documents USING GIN (metadata);

-- Full-text search index using tsvector
ALTER TABLE knowledge_documents
    ADD COLUMN IF NOT EXISTS search_vector tsvector
    GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(summary, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(content, '')), 'C')
    ) STORED;

CREATE INDEX IF NOT EXISTS idx_knowledge_documents_search
    ON knowledge_documents USING GIN (search_vector);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_knowledge_documents_updated_at ON knowledge_documents;
CREATE TRIGGER update_knowledge_documents_updated_at
    BEFORE UPDATE ON knowledge_documents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Enable Row-Level Security (RLS) for tenant isolation
ALTER TABLE knowledge_documents ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS knowledge_documents_tenant_isolation ON knowledge_documents;
CREATE POLICY knowledge_documents_tenant_isolation ON knowledge_documents
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Comments for documentation
COMMENT ON TABLE knowledge_documents IS 'Stores organizational knowledge documents for RAG integration including runbooks, threat intel, and policies';
COMMENT ON COLUMN knowledge_documents.doc_type IS 'Document type: runbook, threat_intel_report, security_policy, post_mortem, vendor_documentation';
COMMENT ON COLUMN knowledge_documents.content IS 'Full document content in plain text or markdown format';
COMMENT ON COLUMN knowledge_documents.metadata IS 'JSONB metadata including tags, keywords, MITRE techniques, author, version';
COMMENT ON COLUMN knowledge_documents.indexed_at IS 'When the document was last indexed in the vector store';
COMMENT ON COLUMN knowledge_documents.search_vector IS 'Auto-generated tsvector for full-text search';
