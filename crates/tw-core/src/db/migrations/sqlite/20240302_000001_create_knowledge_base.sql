-- Knowledge base table for RAG integration (SQLite)
-- Stores organizational knowledge documents like runbooks, threat intel reports, and policies.

-- Knowledge documents table
CREATE TABLE IF NOT EXISTS knowledge_documents (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Document classification
    doc_type TEXT NOT NULL CHECK (doc_type IN (
        'runbook', 'threat_intel_report', 'security_policy',
        'post_mortem', 'vendor_documentation'
    )),

    -- Document content
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    summary TEXT,

    -- Metadata (JSON)
    metadata TEXT NOT NULL DEFAULT '{}',

    -- Status
    is_active INTEGER NOT NULL DEFAULT 1,

    -- Timestamps
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    indexed_at TEXT,

    -- User tracking
    created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL
);

-- Index for tenant + doc_type lookups (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_tenant_type
    ON knowledge_documents(tenant_id, doc_type);

-- Index for active documents
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_active
    ON knowledge_documents(tenant_id, is_active);

-- Index for time-based queries
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_created_at
    ON knowledge_documents(tenant_id, created_at);

-- Index for title search
CREATE INDEX IF NOT EXISTS idx_knowledge_documents_title
    ON knowledge_documents(tenant_id, title);

-- Full-text search index (SQLite FTS5)
-- Note: This creates a virtual table for full-text search
CREATE VIRTUAL TABLE IF NOT EXISTS knowledge_documents_fts USING fts5(
    title,
    content,
    summary,
    content='knowledge_documents',
    content_rowid='rowid'
);

-- Trigger to keep FTS in sync on INSERT
CREATE TRIGGER IF NOT EXISTS knowledge_documents_fts_insert
    AFTER INSERT ON knowledge_documents
BEGIN
    INSERT INTO knowledge_documents_fts(rowid, title, content, summary)
    VALUES (NEW.rowid, NEW.title, NEW.content, NEW.summary);
END;

-- Trigger to keep FTS in sync on UPDATE
CREATE TRIGGER IF NOT EXISTS knowledge_documents_fts_update
    AFTER UPDATE ON knowledge_documents
BEGIN
    INSERT INTO knowledge_documents_fts(knowledge_documents_fts, rowid, title, content, summary)
    VALUES ('delete', OLD.rowid, OLD.title, OLD.content, OLD.summary);
    INSERT INTO knowledge_documents_fts(rowid, title, content, summary)
    VALUES (NEW.rowid, NEW.title, NEW.content, NEW.summary);
END;

-- Trigger to keep FTS in sync on DELETE
CREATE TRIGGER IF NOT EXISTS knowledge_documents_fts_delete
    AFTER DELETE ON knowledge_documents
BEGIN
    INSERT INTO knowledge_documents_fts(knowledge_documents_fts, rowid, title, content, summary)
    VALUES ('delete', OLD.rowid, OLD.title, OLD.content, OLD.summary);
END;
