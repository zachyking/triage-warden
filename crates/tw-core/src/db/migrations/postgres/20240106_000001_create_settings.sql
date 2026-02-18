-- Settings table for storing key-value configuration
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Insert default settings
INSERT INTO settings (key, value, updated_at) VALUES
    ('general', '{"org_name":"My Organization","timezone":"UTC","mode":"supervised"}', NOW()),
    ('rate_limits', '{"isolate_host_hour":10,"disable_user_hour":5,"block_ip_hour":20}', NOW())
ON CONFLICT (key) DO NOTHING;
