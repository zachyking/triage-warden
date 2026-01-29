"""Workflow orchestration components for Triage Warden.

This module provides high-level workflow orchestration for security triage,
combining multiple analysis steps into complete investigation pipelines.
"""

from tw_ai.workflows.phishing import (
    PhishingTriageWorkflow,
    WorkflowResult,
    TriageResult,
    TriageDecision,
    DecisionThresholds,
    # Stage constants for AI-integrated workflow
    STAGE_PARSE,
    STAGE_ANALYZE,
    STAGE_ENRICH,
    STAGE_DECIDE,
    STAGE_APPROVE,
)

__all__ = [
    "PhishingTriageWorkflow",
    "WorkflowResult",
    "TriageResult",
    "TriageDecision",
    "DecisionThresholds",
    "STAGE_PARSE",
    "STAGE_ANALYZE",
    "STAGE_ENRICH",
    "STAGE_DECIDE",
    "STAGE_APPROVE",
]
