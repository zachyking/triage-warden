-- Create notification_channels table for alerting (PostgreSQL)

CREATE TABLE IF NOT EXISTS notification_channels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL,  -- slack, teams, email, pagerduty, webhook
    config JSONB NOT NULL DEFAULT '{}'::jsonb,  -- JSON config
    events JSONB NOT NULL DEFAULT '[]'::jsonb,  -- JSON array of event types
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_notification_channels_name ON notification_channels(name);
CREATE INDEX IF NOT EXISTS idx_notification_channels_channel_type ON notification_channels(channel_type);
CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled ON notification_channels(enabled);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_notification_channels_updated_at ON notification_channels;
CREATE TRIGGER update_notification_channels_updated_at
    BEFORE UPDATE ON notification_channels
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
