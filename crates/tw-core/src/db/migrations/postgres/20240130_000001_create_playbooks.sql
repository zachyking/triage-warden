-- Create playbooks table for automation workflows (PostgreSQL)

CREATE TABLE IF NOT EXISTS playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL,
    trigger_condition TEXT,
    stages JSONB NOT NULL DEFAULT '[]'::jsonb,  -- JSON array of stages
    enabled BOOLEAN NOT NULL DEFAULT true,
    execution_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(name);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_type ON playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks(enabled);
CREATE INDEX IF NOT EXISTS idx_playbooks_created_at ON playbooks(created_at);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_playbooks_updated_at ON playbooks;
CREATE TRIGGER update_playbooks_updated_at
    BEFORE UPDATE ON playbooks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
