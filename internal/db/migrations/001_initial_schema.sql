-- Migration: 001_initial_schema
-- Description: Create initial schema for YouTube stream monitoring system

-- monitors table
CREATE TABLE IF NOT EXISTS monitors (
    id VARCHAR(40) PRIMARY KEY,  -- mon- + uuid (36 chars with hyphens)
    stream_url VARCHAR(512) NOT NULL,
    callback_url VARCHAR(512) NOT NULL,
    config JSONB NOT NULL DEFAULT '{}',
    metadata JSONB DEFAULT '{}',
    status VARCHAR(20) NOT NULL DEFAULT 'initializing',
    pod_name VARCHAR(63),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT monitors_status_check CHECK (status IN ('initializing', 'waiting', 'monitoring', 'completed', 'stopped', 'error'))
);

-- monitor_stats table
CREATE TABLE IF NOT EXISTS monitor_stats (
    monitor_id VARCHAR(40) PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
    total_segments INT NOT NULL DEFAULT 0,
    blackout_events INT NOT NULL DEFAULT 0,
    silence_events INT NOT NULL DEFAULT 0,
    last_check_at TIMESTAMPTZ,
    video_health VARCHAR(20) DEFAULT 'unknown',
    audio_health VARCHAR(20) DEFAULT 'unknown',
    stream_status VARCHAR(20) DEFAULT 'unknown'
);

-- monitor_events table
CREATE TABLE IF NOT EXISTS monitor_events (
    id UUID PRIMARY KEY,
    monitor_id VARCHAR(40) NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    webhook_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    webhook_attempts INT NOT NULL DEFAULT 0,
    webhook_last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sent_at TIMESTAMPTZ,
    CONSTRAINT monitor_events_webhook_status_check CHECK (webhook_status IN ('pending', 'sent', 'failed'))
);

-- Indexes
-- Unique constraint for active monitors with same stream_url
CREATE UNIQUE INDEX IF NOT EXISTS idx_monitors_stream_url_active
    ON monitors(stream_url)
    WHERE status IN ('initializing', 'waiting', 'monitoring');

-- Indexes for monitor_events
CREATE INDEX IF NOT EXISTS idx_monitor_events_monitor_id ON monitor_events(monitor_id);
CREATE INDEX IF NOT EXISTS idx_monitor_events_created_at ON monitor_events(created_at);
CREATE INDEX IF NOT EXISTS idx_monitor_events_webhook_status ON monitor_events(webhook_status)
    WHERE webhook_status = 'pending';

-- Updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply trigger to monitors table
DROP TRIGGER IF EXISTS update_monitors_updated_at ON monitors;
CREATE TRIGGER update_monitors_updated_at
    BEFORE UPDATE ON monitors
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
