"""Tests for action validation (Task 2.4.4/2.4.5).

These tests verify the action validator correctly:
1. Validates action targets exist
2. Detects protected entities
3. Checks risk level vs incident severity
4. Returns appropriate validation decisions
"""

import pytest

from tw_ai.validation.action import (
    ActionRiskLevel,
    ActionToValidate,
    ActionValidator,
    ActionValidatorConfig,
    IncidentContext,
    ProtectedEntityConfig,
    TargetExistenceChecker,
    ValidationDecision,
    ValidationResult,
    create_action_validator,
    DEFAULT_ACTION_RISK_LEVELS,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def basic_incident() -> IncidentContext:
    """Create a basic incident context for testing."""
    return IncidentContext(
        incident_id="INC-001",
        severity="high",
        confidence=0.9,
        verdict="true_positive",
        known_hosts={"workstation-001", "server-web-01"},
        known_users={"jsmith", "admin_test"},
        known_ips={"192.168.1.100", "10.0.0.50"},
        known_domains={"example.com", "malicious.evil.com"},
    )


@pytest.fixture
def protected_entities() -> ProtectedEntityConfig:
    """Create protected entity configuration."""
    return ProtectedEntityConfig(
        protected_users={"admin", "root", "administrator"},
        protected_ips={"10.0.0.1", "10.0.0.2", "10.0.0.3"},
        protected_hosts={"dc01", "dc02"},
        protected_domains={"corp.internal"},
        protected_user_patterns=["svc-*", "service-account-*"],
        protected_host_patterns=["*-prod-*", "dc*"],
        protected_domain_patterns=["*.internal"],
        protected_target_regexes=[r".*-critical-.*"],
    )


@pytest.fixture
def validator_config(protected_entities: ProtectedEntityConfig) -> ActionValidatorConfig:
    """Create validator configuration with protected entities."""
    return ActionValidatorConfig(
        protected_entities=protected_entities,
        require_target_existence=True,
        allow_higher_risk_with_approval=True,
        min_confidence_for_auto_actions=0.8,
    )


@pytest.fixture
def validator(validator_config: ActionValidatorConfig) -> ActionValidator:
    """Create an action validator."""
    return ActionValidator(config=validator_config)


# =============================================================================
# ActionRiskLevel Tests
# =============================================================================


class TestActionRiskLevel:
    """Tests for ActionRiskLevel enum."""

    def test_risk_level_ordering(self) -> None:
        """Test that risk levels are properly ordered."""
        assert ActionRiskLevel.INFO < ActionRiskLevel.LOW
        assert ActionRiskLevel.LOW < ActionRiskLevel.MEDIUM
        assert ActionRiskLevel.MEDIUM < ActionRiskLevel.HIGH
        assert ActionRiskLevel.HIGH < ActionRiskLevel.CRITICAL

    def test_risk_level_comparison(self) -> None:
        """Test risk level comparisons."""
        assert ActionRiskLevel.LOW <= ActionRiskLevel.MEDIUM
        assert ActionRiskLevel.HIGH >= ActionRiskLevel.MEDIUM
        assert not (ActionRiskLevel.LOW > ActionRiskLevel.HIGH)

    def test_from_severity(self) -> None:
        """Test converting severity to risk level."""
        assert ActionRiskLevel.from_severity("critical") == ActionRiskLevel.CRITICAL
        assert ActionRiskLevel.from_severity("high") == ActionRiskLevel.HIGH
        assert ActionRiskLevel.from_severity("medium") == ActionRiskLevel.MEDIUM
        assert ActionRiskLevel.from_severity("low") == ActionRiskLevel.LOW
        assert ActionRiskLevel.from_severity("info") == ActionRiskLevel.INFO
        assert ActionRiskLevel.from_severity("informational") == ActionRiskLevel.INFO

    def test_from_severity_case_insensitive(self) -> None:
        """Test severity conversion is case insensitive."""
        assert ActionRiskLevel.from_severity("CRITICAL") == ActionRiskLevel.CRITICAL
        assert ActionRiskLevel.from_severity("High") == ActionRiskLevel.HIGH

    def test_from_severity_unknown_defaults_medium(self) -> None:
        """Test unknown severity defaults to medium."""
        assert ActionRiskLevel.from_severity("unknown") == ActionRiskLevel.MEDIUM


# =============================================================================
# ProtectedEntityConfig Tests
# =============================================================================


class TestProtectedEntityConfig:
    """Tests for ProtectedEntityConfig."""

    def test_exact_match_protected_user(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test exact match for protected users."""
        is_protected, reason = protected_entities.is_protected("user", "admin")
        assert is_protected
        assert "protected users list" in reason

    def test_exact_match_protected_ip(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test exact match for protected IPs."""
        is_protected, reason = protected_entities.is_protected("ip", "10.0.0.1")
        assert is_protected
        assert "protected IPs list" in reason

    def test_exact_match_protected_host(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test exact match for protected hosts."""
        is_protected, reason = protected_entities.is_protected("host", "dc01")
        assert is_protected
        assert "protected hosts list" in reason

    def test_pattern_match_protected_user(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test pattern matching for protected users."""
        is_protected, reason = protected_entities.is_protected("user", "svc-database")
        assert is_protected
        assert "matches protected pattern" in reason

    def test_pattern_match_protected_host(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test pattern matching for protected hosts."""
        is_protected, reason = protected_entities.is_protected("host", "web-prod-01")
        assert is_protected
        assert "matches protected pattern" in reason

    def test_regex_match_protected_target(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test regex matching for protected targets."""
        is_protected, reason = protected_entities.is_protected("host", "app-critical-server")
        assert is_protected
        assert "matches protected regex" in reason

    def test_unprotected_user(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test non-protected user is not flagged."""
        is_protected, reason = protected_entities.is_protected("user", "jsmith")
        assert not is_protected
        assert reason == ""

    def test_unprotected_ip(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test non-protected IP is not flagged."""
        is_protected, reason = protected_entities.is_protected("ip", "192.168.1.100")
        assert not is_protected
        assert reason == ""

    def test_case_insensitive_user_match(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test user matching is case insensitive."""
        is_protected, _ = protected_entities.is_protected("user", "ADMIN")
        assert is_protected

    def test_empty_target_not_protected(self, protected_entities: ProtectedEntityConfig) -> None:
        """Test empty target is not flagged as protected."""
        is_protected, _ = protected_entities.is_protected("user", "")
        assert not is_protected

    def test_from_guardrails_config(self) -> None:
        """Test creating config from guardrails YAML format."""
        config = {
            "deny_list": {
                "protected_users": ["admin", "svc-*"],
                "protected_ips": ["10.0.0.1"],
                "target_patterns": [r".*-prod-.*"],
            }
        }
        protected = ProtectedEntityConfig.from_guardrails_config(config)

        is_protected, _ = protected.is_protected("user", "admin")
        assert is_protected

        is_protected, _ = protected.is_protected("ip", "10.0.0.1")
        assert is_protected


# =============================================================================
# TargetExistenceChecker Tests
# =============================================================================


class TestTargetExistenceChecker:
    """Tests for TargetExistenceChecker."""

    def test_check_from_incident_context(self, basic_incident: IncidentContext) -> None:
        """Test checking existence from incident context."""
        checker = TargetExistenceChecker()

        # Host in known_hosts
        exists, reason = checker.check_exists("host", "workstation-001", basic_incident)
        assert exists
        assert "incident enrichment" in reason

        # User in known_users
        exists, reason = checker.check_exists("user", "jsmith", basic_incident)
        assert exists

        # IP in known_ips
        exists, reason = checker.check_exists("ip", "192.168.1.100", basic_incident)
        assert exists

    def test_check_missing_from_context(self, basic_incident: IncidentContext) -> None:
        """Test checking non-existent target with no external checker."""
        checker = TargetExistenceChecker()

        # Host not in known_hosts and no checker registered
        exists, reason = checker.check_exists("host", "unknown-server", basic_incident)
        # Without a registered checker, it defaults to allowing
        assert exists
        assert "No verification available" in reason

    def test_registered_host_checker(self) -> None:
        """Test using registered host checker."""
        checker = TargetExistenceChecker()

        # Register a mock checker
        known_hosts = {"server-01", "server-02"}
        checker.register_host_checker(lambda h: h in known_hosts)

        exists, reason = checker.check_exists("host", "server-01", None)
        assert exists
        assert "verified via EDR" in reason

        exists, reason = checker.check_exists("host", "unknown-server", None)
        assert not exists
        assert "not found" in reason

    def test_registered_user_checker(self) -> None:
        """Test using registered user checker."""
        checker = TargetExistenceChecker()

        known_users = {"alice", "bob"}
        checker.register_user_checker(lambda u: u in known_users)

        exists, reason = checker.check_exists("user", "alice", None)
        assert exists
        assert "identity provider" in reason

        exists, reason = checker.check_exists("user", "unknown", None)
        assert not exists

    def test_empty_target_always_exists(self) -> None:
        """Test empty target is treated as existing."""
        checker = TargetExistenceChecker()
        exists, _ = checker.check_exists("host", "", None)
        assert exists


# =============================================================================
# ActionValidator Tests
# =============================================================================


class TestActionValidator:
    """Tests for ActionValidator."""

    def test_valid_action_all_checks_pass(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test a valid action that passes all checks."""
        action = ActionToValidate(
            action_type="quarantine_email",
            target_type="email",
            target_value="msg-12345",
            reason="Phishing email detected",
        )

        result = validator.validate(action, basic_incident)

        assert result.is_valid
        assert result.decision == ValidationDecision.VALID
        assert result.can_proceed
        assert len(result.checks) >= 3

    def test_protected_entity_requires_override(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test action on protected entity requires override."""
        action = ActionToValidate(
            action_type="disable_user",
            target_type="user",
            target_value="admin",
            reason="Compromised account",
        )

        result = validator.validate(action, basic_incident)

        assert result.decision == ValidationDecision.REQUIRES_OVERRIDE
        assert result.required_approval_level == "senior"
        assert "protected" in result.reason.lower()

    def test_protected_pattern_match_requires_override(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test action on pattern-matched protected entity requires override."""
        action = ActionToValidate(
            action_type="isolate_host",
            target_type="host",
            target_value="app-prod-web01",
            reason="Malware detected",
        )

        result = validator.validate(action, basic_incident)

        assert result.decision == ValidationDecision.REQUIRES_OVERRIDE

    def test_high_risk_low_severity_requires_approval(
        self,
        validator: ActionValidator,
    ) -> None:
        """Test high-risk action on low-severity incident requires approval."""
        low_severity_incident = IncidentContext(
            incident_id="INC-002",
            severity="low",
            confidence=0.95,
            verdict="suspicious",
        )

        action = ActionToValidate(
            action_type="isolate_host",  # High risk
            target_type="host",
            target_value="workstation-user",
            reason="Suspicious activity",
        )

        result = validator.validate(action, low_severity_incident)

        assert result.decision == ValidationDecision.REQUIRES_APPROVAL
        assert "risk" in result.reason.lower()

    def test_low_confidence_requires_approval(
        self,
        validator: ActionValidator,
    ) -> None:
        """Test action with low confidence requires approval."""
        low_conf_incident = IncidentContext(
            incident_id="INC-003",
            severity="high",
            confidence=0.5,  # Below threshold
            verdict="suspicious",
        )

        action = ActionToValidate(
            action_type="block_ip",
            target_type="ip",
            target_value="192.168.1.100",
            reason="Suspicious IP",
        )

        result = validator.validate(action, low_conf_incident)

        assert result.decision == ValidationDecision.REQUIRES_APPROVAL
        assert "confidence" in result.reason.lower()

    def test_target_not_found_invalid(
        self,
        validator_config: ActionValidatorConfig,
        basic_incident: IncidentContext,
    ) -> None:
        """Test action on non-existent target is invalid."""
        # Create checker that always returns False
        checker = TargetExistenceChecker()
        checker.register_host_checker(lambda _: False)

        validator = ActionValidator(config=validator_config, existence_checker=checker)

        action = ActionToValidate(
            action_type="isolate_host",
            target_type="host",
            target_value="nonexistent-host",
            reason="Isolate compromised host",
        )

        result = validator.validate(action, basic_incident)

        assert result.decision == ValidationDecision.INVALID
        assert "not found" in result.reason.lower()

    def test_ticket_action_low_risk(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test ticket operations are low risk and pass easily."""
        action = ActionToValidate(
            action_type="create_ticket",
            target_type="none",
            target_value="",
            reason="Create incident ticket",
        )

        result = validator.validate(action, basic_incident)

        assert result.is_valid
        assert result.risk_level == ActionRiskLevel.LOW

    def test_notification_action_low_risk(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test notifications are low risk."""
        action = ActionToValidate(
            action_type="send_notification",
            target_type="none",
            target_value="",
            reason="Notify SOC team",
        )

        result = validator.validate(action, basic_incident)

        assert result.is_valid
        assert result.risk_level == ActionRiskLevel.LOW

    def test_unknown_action_type_medium_risk(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test unknown action types default to medium risk."""
        action = ActionToValidate(
            action_type="custom_action",
            target_type="none",
            target_value="",
            reason="Custom operation",
        )

        result = validator.validate(action, basic_incident)

        assert result.risk_level == ActionRiskLevel.MEDIUM

    def test_validation_result_to_dict(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test validation result serialization."""
        action = ActionToValidate(
            action_type="block_ip",
            target_type="ip",
            target_value="192.168.1.100",
        )

        result = validator.validate(action, basic_incident)
        result_dict = result.to_dict()

        assert "decision" in result_dict
        assert "reason" in result_dict
        assert "checks" in result_dict
        assert "validated_at" in result_dict
        assert isinstance(result_dict["checks"], list)

    def test_validate_batch(
        self,
        validator: ActionValidator,
        basic_incident: IncidentContext,
    ) -> None:
        """Test batch validation of multiple actions."""
        actions = [
            ActionToValidate(action_type="create_ticket", target_type="none", target_value=""),
            ActionToValidate(action_type="block_ip", target_type="ip", target_value="192.168.1.100"),
            ActionToValidate(action_type="disable_user", target_type="user", target_value="admin"),
        ]

        results = validator.validate_batch(actions, basic_incident)

        assert len(results) == 3
        assert results[0].is_valid  # create_ticket should be valid
        assert results[2].decision == ValidationDecision.REQUIRES_OVERRIDE  # admin is protected


# =============================================================================
# Integration Tests
# =============================================================================


class TestActionValidatorIntegration:
    """Integration tests for ActionValidator with full workflow."""

    def test_phishing_incident_workflow(self) -> None:
        """Test typical phishing incident action validation workflow."""
        # Create incident context
        incident = IncidentContext(
            incident_id="PHISH-001",
            severity="high",
            confidence=0.95,
            verdict="true_positive",
            known_users={"victim_user"},
            known_domains={"malicious-site.evil.com"},
        )

        # Create validator with realistic config
        protected = ProtectedEntityConfig(
            protected_users={"admin", "ceo", "cfo"},
            protected_user_patterns=["svc-*"],
        )
        config = ActionValidatorConfig(
            protected_entities=protected,
            min_confidence_for_auto_actions=0.9,
        )
        validator = ActionValidator(config=config)

        # Test email quarantine - should pass
        quarantine = ActionToValidate(
            action_type="quarantine_email",
            target_type="email",
            target_value="msg-phish-001",
            reason="Phishing email detected",
        )
        result = validator.validate(quarantine, incident)
        assert result.is_valid

        # Test password reset for victim - should pass
        reset = ActionToValidate(
            action_type="reset_password",
            target_type="user",
            target_value="victim_user",
            reason="Potential credential compromise",
        )
        result = validator.validate(reset, incident)
        assert result.is_valid  # High severity, high confidence

        # Test password reset for CEO - should require override
        reset_ceo = ActionToValidate(
            action_type="reset_password",
            target_type="user",
            target_value="ceo",
            reason="Potential credential compromise",
        )
        result = validator.validate(reset_ceo, incident)
        assert result.decision == ValidationDecision.REQUIRES_OVERRIDE

    def test_malware_incident_workflow(self) -> None:
        """Test typical malware incident action validation workflow."""
        incident = IncidentContext(
            incident_id="MALWARE-001",
            severity="critical",
            confidence=0.98,
            verdict="true_positive",
            known_hosts={"infected-workstation"},
            known_ips={"192.168.1.50"},
        )

        validator = create_action_validator()

        # Host isolation - should pass (critical incident, high confidence)
        isolate = ActionToValidate(
            action_type="isolate_host",
            target_type="host",
            target_value="infected-workstation",
            reason="Active malware detected",
        )
        result = validator.validate(isolate, incident)
        assert result.is_valid or result.decision == ValidationDecision.REQUIRES_APPROVAL

    def test_create_validator_from_guardrails(self) -> None:
        """Test creating validator from guardrails config."""
        guardrails = {
            "deny_list": {
                "protected_users": ["admin", "service-*"],
                "protected_ips": ["10.0.0.1", "10.0.0.2"],
                "target_patterns": [r".*-prod-.*"],
            }
        }

        validator = create_action_validator(guardrails_config=guardrails)

        incident = IncidentContext(
            incident_id="TEST-001",
            severity="high",
            confidence=0.9,
            verdict="suspicious",
        )

        # Test protected user
        action = ActionToValidate(
            action_type="disable_user",
            target_type="user",
            target_value="admin",
        )
        result = validator.validate(action, incident)
        assert result.decision == ValidationDecision.REQUIRES_OVERRIDE

    def test_validation_includes_all_check_types(self) -> None:
        """Test that validation includes all expected check types."""
        validator = create_action_validator()
        incident = IncidentContext(
            incident_id="TEST-001",
            severity="medium",
            confidence=0.85,
            verdict="suspicious",
        )

        action = ActionToValidate(
            action_type="block_ip",
            target_type="ip",
            target_value="192.168.1.100",
        )

        result = validator.validate(action, incident)

        check_names = {c.name for c in result.checks}
        assert "protected_entity" in check_names
        assert "risk_level" in check_names
        assert "confidence_threshold" in check_names


# =============================================================================
# Default Risk Levels Tests
# =============================================================================


class TestDefaultActionRiskLevels:
    """Tests for default action risk level mappings."""

    def test_destructive_actions_are_critical(self) -> None:
        """Test destructive actions have critical risk."""
        assert DEFAULT_ACTION_RISK_LEVELS["delete_email"] == ActionRiskLevel.CRITICAL

    def test_isolation_actions_are_high_risk(self) -> None:
        """Test isolation actions have high risk."""
        assert DEFAULT_ACTION_RISK_LEVELS["isolate_host"] == ActionRiskLevel.HIGH
        assert DEFAULT_ACTION_RISK_LEVELS["disable_user"] == ActionRiskLevel.HIGH

    def test_blocking_actions_are_medium_risk(self) -> None:
        """Test blocking actions have medium risk."""
        assert DEFAULT_ACTION_RISK_LEVELS["block_ip"] == ActionRiskLevel.MEDIUM
        assert DEFAULT_ACTION_RISK_LEVELS["quarantine_email"] == ActionRiskLevel.MEDIUM

    def test_ticket_actions_are_low_risk(self) -> None:
        """Test ticket operations have low risk."""
        assert DEFAULT_ACTION_RISK_LEVELS["create_ticket"] == ActionRiskLevel.LOW
        assert DEFAULT_ACTION_RISK_LEVELS["update_ticket"] == ActionRiskLevel.LOW
        assert DEFAULT_ACTION_RISK_LEVELS["send_notification"] == ActionRiskLevel.LOW


# =============================================================================
# ActionToValidate Tests
# =============================================================================


class TestActionToValidate:
    """Tests for ActionToValidate model."""

    def test_from_dict(self) -> None:
        """Test creating action from dictionary."""
        data = {
            "action_type": "block_ip",
            "target_type": "ip",
            "target_value": "192.168.1.100",
            "reason": "Malicious IP",
            "priority": 10,
        }

        action = ActionToValidate.from_dict(data)

        assert action.action_type == "block_ip"
        assert action.target_type == "ip"
        assert action.target_value == "192.168.1.100"
        assert action.priority == 10

    def test_target_identifier(self) -> None:
        """Test target identifier generation."""
        action = ActionToValidate(
            action_type="disable_user",
            target_type="user",
            target_value="jsmith",
        )

        assert action.target_identifier == "user:jsmith"

    def test_target_identifier_none_target(self) -> None:
        """Test target identifier for no-target actions."""
        action = ActionToValidate(
            action_type="create_ticket",
            target_type="none",
            target_value="",
        )

        assert action.target_identifier == ""


# =============================================================================
# IncidentContext Tests
# =============================================================================


class TestIncidentContext:
    """Tests for IncidentContext model."""

    def test_from_dict(self) -> None:
        """Test creating context from dictionary."""
        data = {
            "incident_id": "INC-001",
            "severity": "high",
            "confidence": 0.9,
            "verdict": "true_positive",
            "known_hosts": ["server-01"],
            "known_users": ["admin"],
        }

        context = IncidentContext.from_dict(data)

        assert context.incident_id == "INC-001"
        assert context.severity == "high"
        assert context.confidence == 0.9
        assert "server-01" in context.known_hosts
        assert "admin" in context.known_users

    def test_default_values(self) -> None:
        """Test default values for optional fields."""
        context = IncidentContext(
            incident_id="INC-001",
            severity="medium",
            confidence=0.5,
            verdict="suspicious",
        )

        assert len(context.known_hosts) == 0
        assert len(context.known_users) == 0
        assert len(context.enrichment_data) == 0
