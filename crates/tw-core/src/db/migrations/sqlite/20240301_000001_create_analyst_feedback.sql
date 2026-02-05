-- Analyst feedback table for AI improvement (SQLite)
-- Stores analyst feedback on AI-generated verdicts for continuous learning and calibration.

-- Analyst feedback table
CREATE TABLE IF NOT EXISTS analyst_feedback (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    analyst_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Original AI predictions
    original_verdict TEXT NOT NULL CHECK (original_verdict IN (
        'true_positive', 'likely_true_positive', 'suspicious',
        'likely_false_positive', 'false_positive', 'inconclusive'
    )),
    original_severity TEXT NOT NULL CHECK (original_severity IN (
        'info', 'low', 'medium', 'high', 'critical'
    )),
    original_confidence REAL NOT NULL CHECK (original_confidence >= 0.0 AND original_confidence <= 1.0),
    original_mitre_techniques TEXT NOT NULL DEFAULT '[]',

    -- Analyst corrections (null if AI was correct)
    corrected_verdict TEXT CHECK (corrected_verdict IS NULL OR corrected_verdict IN (
        'true_positive', 'likely_true_positive', 'suspicious',
        'likely_false_positive', 'false_positive', 'inconclusive'
    )),
    corrected_severity TEXT CHECK (corrected_severity IS NULL OR corrected_severity IN (
        'info', 'low', 'medium', 'high', 'critical'
    )),
    corrected_mitre_techniques TEXT,

    -- Feedback metadata
    feedback_type TEXT NOT NULL CHECK (feedback_type IN (
        'correct', 'incorrect_verdict', 'incorrect_severity',
        'missing_context', 'incorrect_mitre', 'other'
    )),
    notes TEXT,

    -- Timestamps
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
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
    ON analyst_feedback(tenant_id, created_at);

-- Composite index for verdict accuracy analysis
CREATE INDEX IF NOT EXISTS idx_analyst_feedback_verdict_analysis
    ON analyst_feedback(tenant_id, original_verdict, feedback_type);
