-- Create playbooks table for automation workflows (SQLite)

CREATE TABLE IF NOT EXISTS playbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL,
    trigger_condition TEXT,
    stages TEXT NOT NULL DEFAULT '[]',  -- JSON array of stages
    enabled INTEGER NOT NULL DEFAULT 1,
    execution_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_playbooks_name ON playbooks(name);
CREATE INDEX IF NOT EXISTS idx_playbooks_trigger_type ON playbooks(trigger_type);
CREATE INDEX IF NOT EXISTS idx_playbooks_enabled ON playbooks(enabled);
CREATE INDEX IF NOT EXISTS idx_playbooks_created_at ON playbooks(created_at);
