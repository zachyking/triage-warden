-- Initial schema for Triage Warden (PostgreSQL)

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Severity enum
DO $$ BEGIN
    CREATE TYPE severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Incident status enum
DO $$ BEGIN
    CREATE TYPE incident_status AS ENUM (
        'new', 'enriching', 'analyzing', 'pending_review',
        'pending_approval', 'executing', 'resolved',
        'false_positive', 'escalated', 'closed'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Approval status enum
DO $$ BEGIN
    CREATE TYPE approval_status AS ENUM ('pending', 'auto_approved', 'approved', 'denied', 'executed', 'failed');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Approval workflow status enum
DO $$ BEGIN
    CREATE TYPE approval_workflow_status AS ENUM ('pending', 'approved', 'denied', 'expired');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Incidents table
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    source TEXT NOT NULL,
    severity severity NOT NULL,
    status incident_status NOT NULL DEFAULT 'new',
    alert_data JSONB NOT NULL,
    enrichments JSONB NOT NULL DEFAULT '[]'::jsonb,
    analysis JSONB,
    proposed_actions JSONB NOT NULL DEFAULT '[]'::jsonb,
    ticket_id TEXT,
    tags JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents(created_at);
CREATE INDEX IF NOT EXISTS idx_incidents_updated_at ON incidents(updated_at);
CREATE INDEX IF NOT EXISTS idx_incidents_tags ON incidents USING GIN (tags);

-- Audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_incident_id ON audit_logs(incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor);

-- Actions table
CREATE TABLE IF NOT EXISTS actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type TEXT NOT NULL,
    target JSONB NOT NULL,
    parameters JSONB NOT NULL DEFAULT '{}'::jsonb,
    reason TEXT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 50,
    approval_status approval_status NOT NULL DEFAULT 'pending',
    approved_by TEXT,
    approval_timestamp TIMESTAMPTZ,
    result JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    executed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_actions_incident_id ON actions(incident_id);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions(approval_status);
CREATE INDEX IF NOT EXISTS idx_actions_created_at ON actions(created_at);

-- Approvals table (for tracking approval workflows)
CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    action_id UUID NOT NULL REFERENCES actions(id) ON DELETE CASCADE,
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    approval_level TEXT NOT NULL,
    status approval_workflow_status NOT NULL DEFAULT 'pending',
    requested_by TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_by TEXT,
    decided_at TIMESTAMPTZ,
    decision_reason TEXT,
    expires_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_approvals_action_id ON approvals(action_id);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
CREATE INDEX IF NOT EXISTS idx_approvals_expires_at ON approvals(expires_at);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger for incidents table
DROP TRIGGER IF EXISTS update_incidents_updated_at ON incidents;
CREATE TRIGGER update_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
