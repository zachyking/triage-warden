-- Settings table for storing key-value configuration
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Insert default settings
INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES
    ('general', '{"org_name":"My Organization","timezone":"UTC","mode":"supervised"}', datetime('now')),
    ('rate_limits', '{"isolate_host_hour":10,"disable_user_hour":5,"block_ip_hour":20}', datetime('now'));
