"""Action validation for AI-recommended security response actions.

This module implements Task 2.4.4/2.4.5 from the AI Capabilities roadmap, providing
validation for recommended actions before they are executed. The validation layer:

1. Verifies that action targets exist in the environment
2. Checks if targets are protected entities (production systems, service accounts, etc.)
3. Validates that action risk level is appropriate for incident severity
4. Returns structured validation results with clear decision and reasoning

The validator integrates with:
- Guardrails configuration for protected entity lists
- Connector infrastructure for target existence verification
- Policy engine for action risk assessment
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger()


# =============================================================================
# Risk Level Definitions
# =============================================================================


class ActionRiskLevel(str, Enum):
    """Risk level for an action type.

    Risk levels determine how much scrutiny an action requires before execution.
    Higher risk actions require more approval and validation.
    """

    # Informational/no-impact actions
    INFO = "info"
    # Low risk - easily reversible, minimal impact
    LOW = "low"
    # Medium risk - may require remediation if wrong
    MEDIUM = "medium"
    # High risk - significant impact, hard to reverse
    HIGH = "high"
    # Critical - potentially catastrophic, irreversible
    CRITICAL = "critical"

    def __lt__(self, other: ActionRiskLevel) -> bool:  # type: ignore[override]
        """Compare risk levels for ordering."""
        order = {
            ActionRiskLevel.INFO: 0,
            ActionRiskLevel.LOW: 1,
            ActionRiskLevel.MEDIUM: 2,
            ActionRiskLevel.HIGH: 3,
            ActionRiskLevel.CRITICAL: 4,
        }
        return order[self] < order[other]

    def __le__(self, other: ActionRiskLevel) -> bool:  # type: ignore[override]
        """Compare risk levels for ordering."""
        return self < other or self == other

    def __gt__(self, other: ActionRiskLevel) -> bool:  # type: ignore[override]
        """Compare risk levels for ordering."""
        return not self <= other

    def __ge__(self, other: ActionRiskLevel) -> bool:  # type: ignore[override]
        """Compare risk levels for ordering."""
        return not self < other

    @classmethod
    def from_severity(cls, severity: str) -> ActionRiskLevel:
        """Convert incident severity to equivalent risk level.

        Args:
            severity: Incident severity string (critical, high, medium, low, info).

        Returns:
            Corresponding ActionRiskLevel.
        """
        mapping = {
            "critical": cls.CRITICAL,
            "high": cls.HIGH,
            "medium": cls.MEDIUM,
            "low": cls.LOW,
            "info": cls.INFO,
            "informational": cls.INFO,
        }
        return mapping.get(severity.lower(), cls.MEDIUM)


# Default risk levels for each action type
DEFAULT_ACTION_RISK_LEVELS: dict[str, ActionRiskLevel] = {
    # Critical risk - irreversible or highly impactful
    "delete_email": ActionRiskLevel.CRITICAL,
    "delete_user": ActionRiskLevel.CRITICAL,
    "wipe_host": ActionRiskLevel.CRITICAL,
    # High risk - significant impact, requires careful consideration
    "isolate_host": ActionRiskLevel.HIGH,
    "unisolate_host": ActionRiskLevel.HIGH,
    "disable_user": ActionRiskLevel.HIGH,
    "enable_user": ActionRiskLevel.HIGH,
    "reset_password": ActionRiskLevel.HIGH,
    "revoke_sessions": ActionRiskLevel.HIGH,
    "collect_forensics": ActionRiskLevel.HIGH,
    # Medium risk - noticeable impact but manageable
    "block_ip": ActionRiskLevel.MEDIUM,
    "unblock_ip": ActionRiskLevel.MEDIUM,
    "block_domain": ActionRiskLevel.MEDIUM,
    "quarantine_email": ActionRiskLevel.MEDIUM,
    "block_sender": ActionRiskLevel.MEDIUM,
    "run_search": ActionRiskLevel.MEDIUM,
    # Low risk - minimal impact, easily reversible
    "create_ticket": ActionRiskLevel.LOW,
    "update_ticket": ActionRiskLevel.LOW,
    "add_ticket_comment": ActionRiskLevel.LOW,
    "send_notification": ActionRiskLevel.LOW,
}


# =============================================================================
# Validation Result Types
# =============================================================================


class ValidationDecision(str, Enum):
    """Decision from action validation."""

    # Action is valid and can proceed
    VALID = "valid"
    # Action requires explicit approval/override to proceed
    REQUIRES_APPROVAL = "requires_approval"
    # Action requires override due to protected entity
    REQUIRES_OVERRIDE = "requires_override"
    # Action is invalid and cannot proceed
    INVALID = "invalid"


@dataclass
class ValidationCheck:
    """Result of an individual validation check."""

    name: str
    passed: bool
    message: str
    severity: str = "info"  # info, warning, error
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "name": self.name,
            "passed": self.passed,
            "message": self.message,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass
class ValidationResult:
    """Result of action validation.

    Contains the validation decision, reasoning, and details of all checks performed.
    """

    decision: ValidationDecision
    reason: str
    action_type: str
    target: str
    checks: list[ValidationCheck] = field(default_factory=list)
    required_approval_level: str | None = None
    risk_level: ActionRiskLevel | None = None
    incident_severity: str | None = None
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    validation_time_ms: int = 0

    @classmethod
    def valid(
        cls, action_type: str, target: str, checks: list[ValidationCheck]
    ) -> ValidationResult:
        """Create a valid result."""
        return cls(
            decision=ValidationDecision.VALID,
            reason="All validation checks passed",
            action_type=action_type,
            target=target,
            checks=checks,
        )

    @classmethod
    def requires_approval(
        cls,
        reason: str,
        action_type: str,
        target: str,
        checks: list[ValidationCheck],
        approval_level: str = "analyst",
    ) -> ValidationResult:
        """Create a requires_approval result."""
        return cls(
            decision=ValidationDecision.REQUIRES_APPROVAL,
            reason=reason,
            action_type=action_type,
            target=target,
            checks=checks,
            required_approval_level=approval_level,
        )

    @classmethod
    def requires_override(
        cls,
        reason: str,
        action_type: str,
        target: str,
        checks: list[ValidationCheck],
        approval_level: str = "senior",
    ) -> ValidationResult:
        """Create a requires_override result."""
        return cls(
            decision=ValidationDecision.REQUIRES_OVERRIDE,
            reason=reason,
            action_type=action_type,
            target=target,
            checks=checks,
            required_approval_level=approval_level,
        )

    @classmethod
    def invalid(
        cls,
        reason: str,
        action_type: str,
        target: str,
        checks: list[ValidationCheck],
    ) -> ValidationResult:
        """Create an invalid result."""
        return cls(
            decision=ValidationDecision.INVALID,
            reason=reason,
            action_type=action_type,
            target=target,
            checks=checks,
        )

    @property
    def is_valid(self) -> bool:
        """Check if the action is valid without additional approval."""
        return self.decision == ValidationDecision.VALID

    @property
    def can_proceed(self) -> bool:
        """Check if the action can potentially proceed (valid or with approval)."""
        return self.decision != ValidationDecision.INVALID

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "action_type": self.action_type,
            "target": self.target,
            "checks": [c.to_dict() for c in self.checks],
            "required_approval_level": self.required_approval_level,
            "risk_level": self.risk_level.value if self.risk_level else None,
            "incident_severity": self.incident_severity,
            "validated_at": self.validated_at.isoformat(),
            "validation_time_ms": self.validation_time_ms,
        }


# =============================================================================
# Action and Incident Types (for validation)
# =============================================================================


@dataclass
class ActionToValidate:
    """Action to be validated before execution.

    This is a simplified representation of the action for validation purposes.
    The full ProposedAction model exists in the Rust backend.
    """

    action_type: str
    target_type: str  # host, user, ip, domain, email, ticket, none
    target_value: str
    parameters: dict[str, Any] = field(default_factory=dict)
    reason: str = ""
    priority: int = 50  # 0-100, lower = higher priority

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActionToValidate:
        """Create from dictionary."""
        return cls(
            action_type=data.get("action_type", ""),
            target_type=data.get("target_type", "none"),
            target_value=data.get("target_value", ""),
            parameters=data.get("parameters", {}),
            reason=data.get("reason", ""),
            priority=data.get("priority", 50),
        )

    @property
    def target_identifier(self) -> str:
        """Get a string identifier for the target."""
        if self.target_type == "none":
            return ""
        return f"{self.target_type}:{self.target_value}"


@dataclass
class IncidentContext:
    """Incident context for validation.

    Provides the context needed to validate an action, including
    severity, confidence, and available target data.
    """

    incident_id: str
    severity: str  # critical, high, medium, low, info
    confidence: float  # 0.0 - 1.0
    verdict: str  # true_positive, false_positive, suspicious, inconclusive
    known_hosts: set[str] = field(default_factory=set)
    known_users: set[str] = field(default_factory=set)
    known_ips: set[str] = field(default_factory=set)
    known_domains: set[str] = field(default_factory=set)
    enrichment_data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> IncidentContext:
        """Create from dictionary."""
        return cls(
            incident_id=data.get("incident_id", ""),
            severity=data.get("severity", "medium"),
            confidence=data.get("confidence", 0.0),
            verdict=data.get("verdict", "inconclusive"),
            known_hosts=set(data.get("known_hosts", [])),
            known_users=set(data.get("known_users", [])),
            known_ips=set(data.get("known_ips", [])),
            known_domains=set(data.get("known_domains", [])),
            enrichment_data=data.get("enrichment_data", {}),
        )


# =============================================================================
# Protected Entity Configuration
# =============================================================================


@dataclass
class ProtectedEntityConfig:
    """Configuration for protected entities.

    Defines which targets are protected and cannot be affected by automated actions
    without explicit override.
    """

    # Exact match protected values
    protected_users: set[str] = field(default_factory=set)
    protected_ips: set[str] = field(default_factory=set)
    protected_hosts: set[str] = field(default_factory=set)
    protected_domains: set[str] = field(default_factory=set)

    # Wildcard/pattern matching (uses fnmatch)
    protected_user_patterns: list[str] = field(default_factory=list)
    protected_host_patterns: list[str] = field(default_factory=list)
    protected_domain_patterns: list[str] = field(default_factory=list)

    # Regex patterns for more complex matching
    protected_target_regexes: list[str] = field(default_factory=list)

    # Compiled regexes (populated on load)
    _compiled_regexes: list[re.Pattern[str]] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        """Compile regex patterns after initialization."""
        self._compile_regexes()

    def _compile_regexes(self) -> None:
        """Compile regex patterns for efficient matching."""
        self._compiled_regexes = []
        for pattern in self.protected_target_regexes:
            try:
                self._compiled_regexes.append(re.compile(pattern))
            except re.error as e:
                logger.warning(
                    "invalid_protected_target_regex",
                    pattern=pattern,
                    error=str(e),
                )

    def is_protected(self, target_type: str, target_value: str) -> tuple[bool, str]:
        """Check if a target is protected.

        Args:
            target_type: Type of target (user, host, ip, domain).
            target_value: Value of the target.

        Returns:
            Tuple of (is_protected, reason).
        """
        if not target_value:
            return False, ""

        target_lower = target_value.lower()

        # Check exact matches
        if target_type == "user" and target_lower in self.protected_users:
            return True, f"User '{target_value}' is in protected users list"

        if target_type == "ip" and target_value in self.protected_ips:
            return True, f"IP '{target_value}' is in protected IPs list"

        if target_type == "host":
            if target_lower in self.protected_hosts:
                return True, f"Host '{target_value}' is in protected hosts list"
            # Check wildcard patterns
            for pattern in self.protected_host_patterns:
                if fnmatch.fnmatch(target_lower, pattern.lower()):
                    return True, f"Host '{target_value}' matches protected pattern '{pattern}'"

        if target_type == "domain":
            if target_lower in self.protected_domains:
                return True, f"Domain '{target_value}' is in protected domains list"
            for pattern in self.protected_domain_patterns:
                if fnmatch.fnmatch(target_lower, pattern.lower()):
                    return True, f"Domain '{target_value}' matches protected pattern '{pattern}'"

        if target_type == "user":
            for pattern in self.protected_user_patterns:
                if fnmatch.fnmatch(target_lower, pattern.lower()):
                    return True, f"User '{target_value}' matches protected pattern '{pattern}'"

        # Check regex patterns against full target identifier
        full_target = f"{target_type}:{target_value}"
        for regex in self._compiled_regexes:
            if regex.search(full_target) or regex.search(target_value):
                return True, f"Target '{target_value}' matches protected regex pattern"

        return False, ""

    @classmethod
    def from_guardrails_config(cls, config: dict[str, Any]) -> ProtectedEntityConfig:
        """Create from guardrails YAML config.

        Args:
            config: The deny_list section of guardrails.yaml.

        Returns:
            Configured ProtectedEntityConfig.
        """
        deny_list = config.get("deny_list", {})

        return cls(
            protected_users=set(u.lower() for u in deny_list.get("protected_users", [])),
            protected_ips=set(deny_list.get("protected_ips", [])),
            protected_hosts=set(h.lower() for h in deny_list.get("protected_hosts", [])),
            protected_domains=set(d.lower() for d in deny_list.get("protected_domains", [])),
            protected_user_patterns=deny_list.get("protected_users", []),
            protected_host_patterns=deny_list.get("target_patterns", []),
            protected_domain_patterns=deny_list.get("protected_domain_patterns", []),
            protected_target_regexes=deny_list.get("target_patterns", []),
        )


# =============================================================================
# Target Existence Verification
# =============================================================================


class TargetExistenceChecker:
    """Checks if action targets exist in the environment.

    Can be configured with callbacks to query external systems (EDR, IdP, SIEM)
    for real-time verification, or use cached data from incident enrichment.
    """

    def __init__(self) -> None:
        """Initialize the checker with empty callbacks."""
        self._host_checker: Callable[[str], bool] | None = None
        self._user_checker: Callable[[str], bool] | None = None
        self._ip_checker: Callable[[str], bool] | None = None
        self._domain_checker: Callable[[str], bool] | None = None

    def register_host_checker(self, checker: Callable[[str], bool]) -> None:
        """Register a callback to verify host existence."""
        self._host_checker = checker

    def register_user_checker(self, checker: Callable[[str], bool]) -> None:
        """Register a callback to verify user existence."""
        self._user_checker = checker

    def register_ip_checker(self, checker: Callable[[str], bool]) -> None:
        """Register a callback to verify IP existence."""
        self._ip_checker = checker

    def register_domain_checker(self, checker: Callable[[str], bool]) -> None:
        """Register a callback to verify domain existence."""
        self._domain_checker = checker

    def check_exists(
        self,
        target_type: str,
        target_value: str,
        incident_context: IncidentContext | None = None,
    ) -> tuple[bool, str]:
        """Check if a target exists.

        First checks against incident context (known entities from enrichment),
        then falls back to registered checkers if available.

        Args:
            target_type: Type of target (host, user, ip, domain).
            target_value: Value of the target.
            incident_context: Optional context with known entities.

        Returns:
            Tuple of (exists, reason).
        """
        if not target_value:
            return True, "No target specified"

        target_lower = target_value.lower()

        # Check against incident context first
        if incident_context:
            if target_type == "host" and target_lower in incident_context.known_hosts:
                return True, "Host found in incident enrichment data"
            if target_type == "user" and target_lower in incident_context.known_users:
                return True, "User found in incident enrichment data"
            if target_type == "ip" and target_value in incident_context.known_ips:
                return True, "IP found in incident enrichment data"
            if target_type == "domain" and target_lower in incident_context.known_domains:
                return True, "Domain found in incident enrichment data"

        # Fall back to registered checkers
        if target_type == "host" and self._host_checker:
            exists = self._host_checker(target_value)
            msg = "Host verified via EDR/endpoint check" if exists else "Host not found"
            return exists, msg

        if target_type == "user" and self._user_checker:
            exists = self._user_checker(target_value)
            msg = "User verified via identity provider" if exists else "User not found"
            return exists, msg

        if target_type == "ip" and self._ip_checker:
            exists = self._ip_checker(target_value)
            msg = "IP verified in network inventory" if exists else "IP not found"
            return exists, msg

        if target_type == "domain" and self._domain_checker:
            exists = self._domain_checker(target_value)
            return exists, "Domain verified" if exists else "Domain not found"

        # If no checker available, warn but allow (better to allow with logging than block)
        msg = f"No verification available for {target_type} targets (proceeding with caution)"
        return True, msg


# =============================================================================
# Action Validator
# =============================================================================


@dataclass
class ActionValidatorConfig:
    """Configuration for the action validator."""

    # Risk level overrides (action_type -> risk level)
    action_risk_levels: dict[str, ActionRiskLevel] = field(
        default_factory=lambda: dict(DEFAULT_ACTION_RISK_LEVELS)
    )

    # Protected entity configuration
    protected_entities: ProtectedEntityConfig = field(default_factory=ProtectedEntityConfig)

    # Validation behavior
    require_target_existence: bool = True
    allow_higher_risk_with_approval: bool = True
    min_confidence_for_auto_actions: float = 0.8

    # Approval levels for different scenarios
    protected_override_level: str = "senior"
    risk_mismatch_approval_level: str = "analyst"
    low_confidence_approval_level: str = "analyst"


class ActionValidator:
    """Validates recommended actions before execution.

    Performs the following validation checks:
    1. Target existence verification
    2. Protected entity detection
    3. Risk level vs incident severity comparison
    4. Confidence threshold checks

    Usage:
        config = ActionValidatorConfig(...)
        validator = ActionValidator(config)

        result = validator.validate(action, incident_context)
        if result.is_valid:
            # Proceed with action
        elif result.can_proceed:
            # Request approval at result.required_approval_level
        else:
            # Action cannot be executed
    """

    def __init__(
        self,
        config: ActionValidatorConfig | None = None,
        existence_checker: TargetExistenceChecker | None = None,
    ) -> None:
        """Initialize the action validator.

        Args:
            config: Validator configuration.
            existence_checker: Target existence checker.
        """
        self._config = config or ActionValidatorConfig()
        self._existence_checker = existence_checker or TargetExistenceChecker()

        logger.info(
            "action_validator_initialized",
            require_target_existence=self._config.require_target_existence,
            min_confidence=self._config.min_confidence_for_auto_actions,
            num_protected_users=len(self._config.protected_entities.protected_users),
            num_protected_ips=len(self._config.protected_entities.protected_ips),
        )

    def validate(
        self,
        action: ActionToValidate,
        incident: IncidentContext,
    ) -> ValidationResult:
        """Validate an action before execution.

        Args:
            action: The action to validate.
            incident: Context about the incident triggering this action.

        Returns:
            ValidationResult with decision and reasoning.
        """
        import time

        start_time = time.perf_counter()
        checks: list[ValidationCheck] = []

        target_identifier = action.target_identifier
        action_risk = self._get_action_risk_level(action.action_type)
        incident_risk = ActionRiskLevel.from_severity(incident.severity)

        # Track for logging
        validation_decision: ValidationDecision | None = None
        validation_reason = ""

        # =================================================================
        # Check 1: Target Existence
        # =================================================================
        if self._config.require_target_existence and action.target_type != "none":
            exists, exist_reason = self._existence_checker.check_exists(
                action.target_type,
                action.target_value,
                incident,
            )

            checks.append(
                ValidationCheck(
                    name="target_existence",
                    passed=exists,
                    message=exist_reason,
                    severity="error" if not exists else "info",
                    details={
                        "target_type": action.target_type,
                        "target_value": action.target_value,
                    },
                )
            )

            if not exists:
                validation_decision = ValidationDecision.INVALID
                validation_reason = f"Target not found: {exist_reason}"

        # =================================================================
        # Check 2: Protected Entity
        # =================================================================
        is_protected, protected_reason = self._config.protected_entities.is_protected(
            action.target_type,
            action.target_value,
        )

        checks.append(
            ValidationCheck(
                name="protected_entity",
                passed=not is_protected,
                message=protected_reason if is_protected else "Target is not a protected entity",
                severity="warning" if is_protected else "info",
                details={
                    "is_protected": is_protected,
                    "target_type": action.target_type,
                    "target_value": action.target_value,
                },
            )
        )

        if is_protected and validation_decision is None:
            validation_decision = ValidationDecision.REQUIRES_OVERRIDE
            validation_reason = protected_reason

        # =================================================================
        # Check 3: Risk Level vs Incident Severity
        # =================================================================
        risk_appropriate = action_risk <= incident_risk

        checks.append(
            ValidationCheck(
                name="risk_level",
                passed=risk_appropriate,
                message=(
                    f"Action risk ({action_risk.value}) is appropriate for "
                    f"incident severity ({incident.severity})"
                    if risk_appropriate
                    else f"Action risk ({action_risk.value}) exceeds "
                    f"incident severity ({incident.severity})"
                ),
                severity="warning" if not risk_appropriate else "info",
                details={
                    "action_risk": action_risk.value,
                    "incident_severity": incident.severity,
                    "incident_risk_equivalent": incident_risk.value,
                },
            )
        )

        if not risk_appropriate and validation_decision is None:
            if self._config.allow_higher_risk_with_approval:
                validation_decision = ValidationDecision.REQUIRES_APPROVAL
                validation_reason = (
                    f"Action risk level ({action_risk.value}) exceeds incident "
                    f"severity ({incident.severity})"
                )
            else:
                validation_decision = ValidationDecision.INVALID
                validation_reason = (
                    f"Action risk level ({action_risk.value}) too high for "
                    f"incident severity ({incident.severity})"
                )

        # =================================================================
        # Check 4: Confidence Threshold
        # =================================================================
        confidence_met = incident.confidence >= self._config.min_confidence_for_auto_actions

        checks.append(
            ValidationCheck(
                name="confidence_threshold",
                passed=confidence_met,
                message=(
                    f"Confidence ({incident.confidence:.0%}) meets threshold "
                    f"({self._config.min_confidence_for_auto_actions:.0%})"
                    if confidence_met
                    else f"Confidence ({incident.confidence:.0%}) below threshold "
                    f"({self._config.min_confidence_for_auto_actions:.0%})"
                ),
                severity="warning" if not confidence_met else "info",
                details={
                    "confidence": incident.confidence,
                    "threshold": self._config.min_confidence_for_auto_actions,
                },
            )
        )

        if not confidence_met and validation_decision is None:
            validation_decision = ValidationDecision.REQUIRES_APPROVAL
            validation_reason = f"Low confidence ({incident.confidence:.0%}) requires approval"

        # =================================================================
        # Determine final result
        # =================================================================
        validation_time_ms = int((time.perf_counter() - start_time) * 1000)

        if validation_decision is None:
            # All checks passed
            result = ValidationResult.valid(action.action_type, target_identifier, checks)
        elif validation_decision == ValidationDecision.REQUIRES_OVERRIDE:
            result = ValidationResult.requires_override(
                validation_reason,
                action.action_type,
                target_identifier,
                checks,
                self._config.protected_override_level,
            )
        elif validation_decision == ValidationDecision.REQUIRES_APPROVAL:
            # Determine appropriate approval level
            approval_level = self._config.risk_mismatch_approval_level
            if not confidence_met:
                approval_level = self._config.low_confidence_approval_level

            result = ValidationResult.requires_approval(
                validation_reason,
                action.action_type,
                target_identifier,
                checks,
                approval_level,
            )
        else:
            result = ValidationResult.invalid(
                validation_reason,
                action.action_type,
                target_identifier,
                checks,
            )

        # Add additional context to result
        result.risk_level = action_risk
        result.incident_severity = incident.severity
        result.validation_time_ms = validation_time_ms

        # Log validation result
        logger.info(
            "action_validation_complete",
            action_type=action.action_type,
            target=target_identifier,
            decision=result.decision.value,
            reason=result.reason,
            checks_passed=sum(1 for c in checks if c.passed),
            checks_total=len(checks),
            validation_time_ms=validation_time_ms,
        )

        return result

    def validate_batch(
        self,
        actions: list[ActionToValidate],
        incident: IncidentContext,
    ) -> list[ValidationResult]:
        """Validate multiple actions for the same incident.

        Args:
            actions: List of actions to validate.
            incident: Context about the incident.

        Returns:
            List of ValidationResults in the same order as input actions.
        """
        return [self.validate(action, incident) for action in actions]

    def _get_action_risk_level(self, action_type: str) -> ActionRiskLevel:
        """Get the risk level for an action type.

        Args:
            action_type: The action type string.

        Returns:
            ActionRiskLevel for this action.
        """
        action_type_lower = action_type.lower()

        # Check config overrides first
        if action_type_lower in self._config.action_risk_levels:
            return self._config.action_risk_levels[action_type_lower]

        # Fall back to defaults
        if action_type_lower in DEFAULT_ACTION_RISK_LEVELS:
            return DEFAULT_ACTION_RISK_LEVELS[action_type_lower]

        # Unknown actions default to medium risk
        logger.warning("unknown_action_type_risk", action_type=action_type)
        return ActionRiskLevel.MEDIUM


# =============================================================================
# Factory Functions
# =============================================================================


def create_action_validator(
    guardrails_config: dict[str, Any] | None = None,
    existence_checker: TargetExistenceChecker | None = None,
    action_risk_overrides: dict[str, ActionRiskLevel] | None = None,
) -> ActionValidator:
    """Create an action validator from configuration.

    Args:
        guardrails_config: Guardrails YAML config dict (optional).
        existence_checker: Target existence checker (optional).
        action_risk_overrides: Override default action risk levels (optional).

    Returns:
        Configured ActionValidator.
    """
    # Build protected entities config
    protected_entities = ProtectedEntityConfig()
    if guardrails_config:
        protected_entities = ProtectedEntityConfig.from_guardrails_config(guardrails_config)

    # Build action risk levels
    action_risk_levels = dict(DEFAULT_ACTION_RISK_LEVELS)
    if action_risk_overrides:
        action_risk_levels.update(action_risk_overrides)

    config = ActionValidatorConfig(
        action_risk_levels=action_risk_levels,
        protected_entities=protected_entities,
    )

    return ActionValidator(
        config=config,
        existence_checker=existence_checker,
    )


def load_guardrails_config(config_path: str = "config/guardrails.yaml") -> dict[str, Any]:
    """Load guardrails configuration from YAML file.

    Args:
        config_path: Path to guardrails.yaml file.

    Returns:
        Parsed configuration dictionary.
    """
    from pathlib import Path

    import yaml  # type: ignore[import-untyped]

    path = Path(config_path)
    if not path.exists():
        logger.warning("guardrails_config_not_found", path=config_path)
        return {}

    with open(path) as f:
        return yaml.safe_load(f) or {}


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Core types
    "ActionRiskLevel",
    "ValidationDecision",
    "ValidationCheck",
    "ValidationResult",
    # Input types
    "ActionToValidate",
    "IncidentContext",
    # Configuration
    "ProtectedEntityConfig",
    "ActionValidatorConfig",
    # Validators
    "TargetExistenceChecker",
    "ActionValidator",
    # Factory functions
    "create_action_validator",
    "load_guardrails_config",
    # Constants
    "DEFAULT_ACTION_RISK_LEVELS",
]
