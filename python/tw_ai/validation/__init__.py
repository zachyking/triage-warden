"""Validation utilities for AI-generated analysis.

This module provides:
- Hallucination detection for triage analyses (Task 2.4.3)
- Action validation before execution (Task 2.4.5)

The validators ensure AI outputs are accurate, safe, and appropriate
for the incident context before any automated actions are taken.
"""

# Hallucination detection (Task 2.4.3)
# Action validation (Task 2.4.5)
from tw_ai.validation.action import (
    # Constants
    DEFAULT_ACTION_RISK_LEVELS,
    # Core types
    ActionRiskLevel,
    ActionToValidate,
    ActionValidator,
    ActionValidatorConfig,
    IncidentContext,
    ProtectedEntityConfig,
    TargetExistenceChecker,
    ValidationCheck,
    ValidationDecision,
    ValidationResult,
    # Factory functions
    create_action_validator,
    load_guardrails_config,
)
from tw_ai.validation.hallucination import (
    HallucinationConfig,
    HallucinationDetector,
    HallucinationResult,
    HallucinationSeverity,
    HallucinationWarning,
    WarningType,
    check_for_hallucinations,
    get_default_detector,
)

__all__ = [
    # Hallucination detection (Task 2.4.3)
    "HallucinationConfig",
    "HallucinationDetector",
    "HallucinationResult",
    "HallucinationSeverity",
    "HallucinationWarning",
    "WarningType",
    "check_for_hallucinations",
    "get_default_detector",
    # Action validation (Task 2.4.5)
    "ActionRiskLevel",
    "ActionToValidate",
    "ActionValidator",
    "ActionValidatorConfig",
    "IncidentContext",
    "ProtectedEntityConfig",
    "TargetExistenceChecker",
    "ValidationCheck",
    "ValidationDecision",
    "ValidationResult",
    "create_action_validator",
    "load_guardrails_config",
    "DEFAULT_ACTION_RISK_LEVELS",
]
