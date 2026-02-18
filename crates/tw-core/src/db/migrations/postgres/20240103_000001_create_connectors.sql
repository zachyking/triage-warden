-- Create connectors table for external integrations (PostgreSQL)

CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,  -- JSON config (api_key, base_url, etc.)
    status TEXT NOT NULL DEFAULT 'unknown',
    enabled BOOLEAN NOT NULL DEFAULT true,
    last_health_check TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_connectors_name ON connectors(name);
CREATE INDEX IF NOT EXISTS idx_connectors_connector_type ON connectors(connector_type);
CREATE INDEX IF NOT EXISTS idx_connectors_status ON connectors(status);
CREATE INDEX IF NOT EXISTS idx_connectors_enabled ON connectors(enabled);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_connectors_updated_at ON connectors;
CREATE TRIGGER update_connectors_updated_at
    BEFORE UPDATE ON connectors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
