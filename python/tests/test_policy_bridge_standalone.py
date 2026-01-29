"""Standalone tests for the PolicyBridge integration.

This test file is designed to run with Python 3.9+ and tests the mock
implementations directly without importing the full tw_ai package.
"""

import sys
import uuid
from typing import Any, Dict, Optional
from dataclasses import dataclass, field

import pytest


# =============================================================================
# Minimal Implementations for Standalone Testing
# =============================================================================


@dataclass
class ToolResult:
    """Result of a tool execution."""

    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time_ms: int = 0

    @classmethod
    def ok(cls, data: Dict[str, Any], execution_time_ms: int = 0) -> "ToolResult":
        """Create a successful result."""
        return cls(success=True, data=data, execution_time_ms=execution_time_ms)

    @classmethod
    def fail(cls, error: str, execution_time_ms: int = 0) -> "ToolResult":
        """Create a failed result."""
        return cls(success=False, error=error, execution_time_ms=execution_time_ms)


# =============================================================================
# Mock Policy Implementations (copied from tools.py)
# =============================================================================


def _mock_check_action(action_type: str, target: str, confidence: float) -> Dict[str, Any]:
    """Mock policy check for testing when bridge is unavailable."""
    # Dangerous actions are always denied
    if action_type in ("delete_user", "wipe_host", "destroy_data"):
        return {
            "decision": "denied",
            "reason": f"Action '{action_type}' is not allowed by policy",
            "approval_level": None,
        }

    # Low-risk actions with high confidence are allowed
    if action_type in ("create_ticket", "add_ticket_comment", "send_notification") and confidence >= 0.9:
        return {
            "decision": "allowed",
            "reason": None,
            "approval_level": None,
        }

    # Host isolation requires analyst approval
    if action_type == "isolate_host":
        return {
            "decision": "requires_approval",
            "reason": "Action requires analyst approval",
            "approval_level": "analyst",
        }

    # Protected targets require senior approval
    protected_patterns = ["-prod-", "dc01", "dc02", "admin", "root"]
    if any(pattern in target.lower() for pattern in protected_patterns):
        return {
            "decision": "requires_approval",
            "reason": "Target is protected and requires senior approval",
            "approval_level": "senior",
        }

    # Default: require analyst approval
    return {
        "decision": "requires_approval",
        "reason": "Action requires analyst approval",
        "approval_level": "analyst",
    }


def _mock_get_operation_mode() -> str:
    """Mock operation mode for testing when bridge is unavailable."""
    return "supervised"


def _mock_is_kill_switch_active() -> bool:
    """Mock kill switch status for testing when bridge is unavailable."""
    return False


# Approval request storage for mock fallback
_mock_approval_requests: Dict[str, Dict[str, Any]] = {}


def _mock_submit_approval_request(action_type: str, target: str, level: str) -> str:
    """Mock approval request submission when bridge is unavailable."""
    request_id = str(uuid.uuid4())
    _mock_approval_requests[request_id] = {
        "action_type": action_type,
        "target": target,
        "level": level,
        "status": "pending",
        "decided_by": None,
    }
    return request_id


def _mock_check_approval_status(request_id: str) -> Dict[str, Any]:
    """Mock approval status check when bridge is unavailable."""
    if request_id in _mock_approval_requests:
        req = _mock_approval_requests[request_id]
        return {
            "status": req["status"],
            "decided_by": req["decided_by"],
        }
    return {
        "status": "expired",
        "decided_by": None,
    }


def is_action_allowed(action_type: str, target: str, confidence: float) -> bool:
    """Check if an action is allowed by the policy engine."""
    result = _mock_check_action(action_type, target, confidence)
    return result.get("decision") == "allowed"


# =============================================================================
# Test Mock Fallback Implementations
# =============================================================================


class TestMockPolicyFallback:
    """Test the mock fallback implementations when bridge is unavailable."""

    def test_mock_check_action_allow_low_risk_high_confidence(self):
        """Low-risk actions with high confidence should be allowed."""
        result = _mock_check_action("create_ticket", "INC-001", 0.95)
        assert result["decision"] == "allowed"
        assert result["reason"] is None
        assert result["approval_level"] is None

    def test_mock_check_action_allow_send_notification(self):
        """Send notification with high confidence should be allowed."""
        result = _mock_check_action("send_notification", "user@example.com", 0.92)
        assert result["decision"] == "allowed"

    def test_mock_check_action_deny_dangerous_actions(self):
        """Dangerous actions should be denied."""
        dangerous_actions = ["delete_user", "wipe_host", "destroy_data"]
        for action in dangerous_actions:
            result = _mock_check_action(action, "target", 0.99)
            assert result["decision"] == "denied", f"{action} should be denied"
            assert "not allowed" in result["reason"].lower()

    def test_mock_check_action_require_approval_isolate_host(self):
        """Host isolation should require analyst approval."""
        result = _mock_check_action("isolate_host", "workstation-001", 0.95)
        assert result["decision"] == "requires_approval"
        assert result["approval_level"] == "analyst"

    def test_mock_check_action_require_approval_protected_targets(self):
        """Protected targets should require senior approval."""
        protected_targets = [
            "web-prod-01",
            "dc01.corp.local",
            "admin-workstation",
            "root-server",
        ]
        for target in protected_targets:
            result = _mock_check_action("some_action", target, 0.9)
            assert result["decision"] == "requires_approval", f"{target} should require approval"
            assert result["approval_level"] == "senior"

    def test_mock_check_action_default_requires_approval(self):
        """Unknown actions should require analyst approval by default."""
        result = _mock_check_action("unknown_action", "regular-target", 0.85)
        assert result["decision"] == "requires_approval"
        assert result["approval_level"] == "analyst"

    def test_mock_check_action_low_confidence_requires_approval(self):
        """Low-risk actions with low confidence should require approval."""
        result = _mock_check_action("create_ticket", "INC-001", 0.5)
        assert result["decision"] == "requires_approval"

    def test_mock_get_operation_mode(self):
        """Default operation mode should be supervised."""
        mode = _mock_get_operation_mode()
        assert mode == "supervised"

    def test_mock_is_kill_switch_active(self):
        """Default kill switch should be inactive."""
        active = _mock_is_kill_switch_active()
        assert active is False


class TestMockApprovalWorkflow:
    """Test the mock approval workflow."""

    def setup_method(self):
        """Clear mock approval requests before each test."""
        _mock_approval_requests.clear()

    def test_submit_approval_request(self):
        """Submitting an approval request should return a valid UUID."""
        request_id = _mock_submit_approval_request(
            "isolate_host", "workstation-001", "analyst"
        )
        # Verify it's a valid UUID
        uuid.UUID(request_id)

        # Verify it was stored
        assert request_id in _mock_approval_requests
        assert _mock_approval_requests[request_id]["status"] == "pending"

    def test_check_approval_status_pending(self):
        """Checking status of pending request should return pending."""
        request_id = _mock_submit_approval_request(
            "isolate_host", "server-001", "senior"
        )
        status = _mock_check_approval_status(request_id)
        assert status["status"] == "pending"
        assert status["decided_by"] is None

    def test_check_approval_status_not_found(self):
        """Checking status of non-existent request should return expired."""
        status = _mock_check_approval_status("non-existent-id")
        assert status["status"] == "expired"
        assert status["decided_by"] is None

    def test_check_approval_status_approved(self):
        """Checking status of approved request should reflect approval."""
        request_id = _mock_submit_approval_request(
            "block_ip", "192.168.1.100", "analyst"
        )
        # Manually approve
        _mock_approval_requests[request_id]["status"] = "approved"
        _mock_approval_requests[request_id]["decided_by"] = "analyst@example.com"

        status = _mock_check_approval_status(request_id)
        assert status["status"] == "approved"
        assert status["decided_by"] == "analyst@example.com"


class TestIsActionAllowed:
    """Test the is_action_allowed helper function."""

    def test_is_action_allowed_returns_true_for_allowed(self):
        """is_action_allowed should return True for allowed actions."""
        result = is_action_allowed("create_ticket", "INC-001", 0.95)
        assert result is True

    def test_is_action_allowed_returns_false_for_denied(self):
        """is_action_allowed should return False for denied actions."""
        result = is_action_allowed("delete_user", "admin", 0.99)
        assert result is False

    def test_is_action_allowed_returns_false_for_requires_approval(self):
        """is_action_allowed should return False when approval is required."""
        result = is_action_allowed("isolate_host", "workstation-001", 0.9)
        assert result is False


class TestProtectedTargets:
    """Test policy behavior for protected targets."""

    @pytest.mark.parametrize(
        "target,expected_level",
        [
            ("web-prod-01", "senior"),
            ("db-prod-cluster", "senior"),
            ("dc01.corp.local", "senior"),
            ("dc02", "senior"),
            ("admin-workstation", "senior"),
            ("root-server", "senior"),
        ],
    )
    def test_protected_targets_require_senior_approval(self, target, expected_level):
        """Protected targets should require senior approval."""
        result = _mock_check_action("some_action", target, 0.9)
        assert result["decision"] == "requires_approval"
        assert result["approval_level"] == expected_level

    @pytest.mark.parametrize(
        "target",
        [
            "workstation-001",
            "laptop-dev-123",
            "user-machine",
            "test-server",
        ],
    )
    def test_regular_targets_require_analyst_approval(self, target):
        """Regular targets should require analyst approval by default."""
        result = _mock_check_action("unknown_action", target, 0.9)
        assert result["decision"] == "requires_approval"
        assert result["approval_level"] == "analyst"


class TestOperationModes:
    """Test operation mode retrieval."""

    def test_default_mode_is_supervised(self):
        """Default operation mode should be supervised."""
        mode = _mock_get_operation_mode()
        assert mode == "supervised"
        assert mode in ["assisted", "supervised", "autonomous"]


class TestKillSwitch:
    """Test kill switch status checks."""

    def test_kill_switch_inactive_by_default(self):
        """Kill switch should be inactive by default."""
        active = _mock_is_kill_switch_active()
        assert active is False


class TestApprovalLevels:
    """Test approval level handling."""

    def test_all_approval_levels_stored_correctly(self):
        """All valid approval levels should be stored correctly."""
        _mock_approval_requests.clear()

        levels = ["analyst", "senior", "manager", "executive"]
        for level in levels:
            request_id = _mock_submit_approval_request("test_action", "test_target", level)
            assert _mock_approval_requests[request_id]["level"] == level


class TestPolicyWorkflowIntegration:
    """Test complete policy checking workflow."""

    def test_full_approval_workflow(self):
        """Test complete flow: check -> submit -> check status."""
        _mock_approval_requests.clear()

        # 1. Check policy for an action that requires approval
        check_result = _mock_check_action("isolate_host", "server-001", 0.9)
        assert check_result["decision"] == "requires_approval"
        approval_level = check_result["approval_level"]

        # 2. Submit approval request
        request_id = _mock_submit_approval_request(
            "isolate_host", "server-001", approval_level
        )
        assert request_id in _mock_approval_requests

        # 3. Check approval status (should be pending)
        status_result = _mock_check_approval_status(request_id)
        assert status_result["status"] == "pending"

        # 4. Simulate approval
        _mock_approval_requests[request_id]["status"] = "approved"
        _mock_approval_requests[request_id]["decided_by"] = "soc-analyst@example.com"

        # 5. Check status again (should be approved)
        final_result = _mock_check_approval_status(request_id)
        assert final_result["status"] == "approved"
        assert final_result["decided_by"] == "soc-analyst@example.com"

    def test_allowed_action_no_approval_needed(self):
        """Test that allowed actions don't need approval workflow."""
        result = _mock_check_action("create_ticket", "INC-001", 0.95)
        assert result["decision"] == "allowed"


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_ok_result(self):
        """Test creating successful result."""
        result = ToolResult.ok({"key": "value"}, execution_time_ms=100)
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None
        assert result.execution_time_ms == 100

    def test_fail_result(self):
        """Test creating failed result."""
        result = ToolResult.fail("Something went wrong", execution_time_ms=50)
        assert result.success is False
        assert result.data == {}
        assert result.error == "Something went wrong"
        assert result.execution_time_ms == 50


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
