-- Create connectors table for external integrations (SQLite)

CREATE TABLE IF NOT EXISTS connectors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',  -- JSON config (api_key, base_url, etc.)
    status TEXT NOT NULL DEFAULT 'unknown',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_health_check TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_connectors_name ON connectors(name);
CREATE INDEX IF NOT EXISTS idx_connectors_connector_type ON connectors(connector_type);
CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON connectors(enabled);
