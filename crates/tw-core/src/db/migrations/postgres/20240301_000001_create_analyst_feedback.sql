-- Analyst feedback table for AI improvement (PostgreSQL)
-- Stores analyst feedback on AI-generated verdicts for continuous learning and calibration.

-- Feedback type enum
DO $$ BEGIN
    CREATE TYPE feedback_type AS ENUM (
        'correct',
        'incorrect_verdict',
        'incorrect_severity',
        'missing_context',
        'incorrect_mitre',
        'other'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Analyst feedback table
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    analyst_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Original AI predictions
    original_verdict TEXT NOT NULL,
    original_severity TEXT NOT NULL,
    original_confidence DOUBLE PRECISION NOT NULL,
    original_mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,

    -- Analyst corrections (null if AI was correct)
    corrected_verdict TEXT,
    corrected_severity TEXT,
    corrected_mitre_techniques JSONB,

    -- Feedback metadata
    feedback_type TEXT NOT NULL,
    notes TEXT,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for incident lookups (most common query pattern)
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_incident
    ON analyst_feedback(tenant_id, incident_id);

-- Index for analyst lookups
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_analyst
    ON analyst_feedback(tenant_id, analyst_id);

-- Index for feedback type analytics
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_type
    ON analyst_feedback(tenant_id, feedback_type);

-- Index for time-based queries (training data export, analytics)
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_created_at
    ON analyst_feedback(tenant_id, created_at DESC);

-- Index for finding corrections (training data)
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_corrections
    ON analyst_feedback(tenant_id, created_at DESC)
    WHERE corrected_verdict IS NOT NULL OR corrected_severity IS NOT NULL;

-- Composite index for verdict accuracy analysis
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_verdict_analysis
    ON analyst_feedback(tenant_id, original_verdict, feedback_type);

-- Trigger for updated_at
DROP TRIGGER IF EXISTS update_analyst_feedback_updated_at ON analyst_feedback;
CREATE TRIGGER update_analyst_feedback_updated_at
    BEFORE UPDATE ON analyst_feedback
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Enable Row-Level Security (RLS) for tenant isolation
ALTER TABLE analyst_feedback ENABLE ROW LEVEL SECURITY;

-- RLS policy for tenant isolation
DROP POLICY IF EXISTS analyst_feedback_tenant_isolation ON analyst_feedback;
CREATE POLICY analyst_feedback_tenant_isolation ON analyst_feedback
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

-- Comment for documentation
COMMENT ON TABLE analyst_feedback IS 'Stores analyst feedback on AI-generated triage verdicts for continuous learning and model improvement';
COMMENT ON COLUMN analyst_feedback.original_verdict IS 'The AI-generated verdict (true_positive, false_positive, etc.)';
COMMENT ON COLUMN analyst_feedback.corrected_verdict IS 'Analyst correction if the AI verdict was wrong';
COMMENT ON COLUMN analyst_feedback.original_confidence IS 'AI confidence score (0.0 - 1.0)';
COMMENT ON COLUMN analyst_feedback.feedback_type IS 'Type of feedback: correct, incorrect_verdict, incorrect_severity, missing_context, incorrect_mitre, other';
