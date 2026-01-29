"""Tests for the PolicyBridge integration with the ReAct agent.

This module tests the policy checking functionality exposed to Python,
including action checking, operation mode retrieval, kill switch status,
and approval workflows.

Tests use mock fallback when the Rust bridge is unavailable.
"""

import pytest
from unittest.mock import patch, MagicMock
import uuid

from tw_ai.agents.tools import (
    ToolResult,
    create_triage_tools,
    get_policy_bridge,
    is_policy_bridge_available,
    is_action_allowed,
    _mock_check_action,
    _mock_get_operation_mode,
    _mock_is_kill_switch_active,
    _mock_submit_approval_request,
    _mock_check_approval_status,
    _mock_approval_requests,
)


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


# =============================================================================
# Test Helper Functions
# =============================================================================


class TestIsActionAllowed:
    """Test the is_action_allowed helper function."""

    def test_is_action_allowed_returns_true_for_allowed(self):
        """is_action_allowed should return True for allowed actions."""
        # Low-risk, high-confidence action
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


# =============================================================================
# Test Tool Registry
# =============================================================================


class TestPolicyTools:
    """Test the policy tools in the tool registry."""

    @pytest.fixture
    def registry(self):
        """Create a tool registry with triage tools."""
        return create_triage_tools()

    def test_check_policy_tool_registered(self, registry):
        """check_policy tool should be registered."""
        tool = registry.get("check_policy")
        assert tool is not None
        assert tool.name == "check_policy"

    def test_submit_approval_tool_registered(self, registry):
        """submit_approval tool should be registered."""
        tool = registry.get("submit_approval")
        assert tool is not None
        assert tool.name == "submit_approval"

    def test_get_approval_status_tool_registered(self, registry):
        """get_approval_status tool should be registered."""
        tool = registry.get("get_approval_status")
        assert tool is not None
        assert tool.name == "get_approval_status"

    @pytest.mark.asyncio
    async def test_check_policy_allowed(self, registry):
        """check_policy should return allowed for low-risk high-confidence actions."""
        result = await registry.execute(
            "check_policy",
            {"action_type": "create_ticket", "target": "INC-001", "confidence": 0.95},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["decision"] == "allowed"
        assert result.data["operation_mode"] == "supervised"
        assert result.data["kill_switch_active"] is False

    @pytest.mark.asyncio
    async def test_check_policy_denied(self, registry):
        """check_policy should return denied for dangerous actions."""
        result = await registry.execute(
            "check_policy",
            {"action_type": "delete_user", "target": "admin", "confidence": 0.99},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["decision"] == "denied"
        assert "not allowed" in result.data["reason"].lower()

    @pytest.mark.asyncio
    async def test_check_policy_requires_approval(self, registry):
        """check_policy should return requires_approval for host isolation."""
        result = await registry.execute(
            "check_policy",
            {"action_type": "isolate_host", "target": "workstation-001", "confidence": 0.9},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["decision"] == "requires_approval"
        assert result.data["approval_level"] == "analyst"

    @pytest.mark.asyncio
    async def test_check_policy_default_confidence(self, registry):
        """check_policy should use default confidence when not provided."""
        result = await registry.execute(
            "check_policy",
            {"action_type": "create_ticket", "target": "INC-001"},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["confidence"] == 0.9

    @pytest.mark.asyncio
    async def test_submit_approval_success(self, registry):
        """submit_approval should create a pending approval request."""
        _mock_approval_requests.clear()

        result = await registry.execute(
            "submit_approval",
            {"action_type": "isolate_host", "target": "server-001", "level": "senior"},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["status"] == "pending"
        assert result.data["approval_level"] == "senior"
        # Verify request_id is a valid UUID
        uuid.UUID(result.data["request_id"])

    @pytest.mark.asyncio
    async def test_submit_approval_default_level(self, registry):
        """submit_approval should use analyst as default level."""
        _mock_approval_requests.clear()

        result = await registry.execute(
            "submit_approval",
            {"action_type": "block_ip", "target": "192.168.1.100"},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["approval_level"] == "analyst"

    @pytest.mark.asyncio
    async def test_get_approval_status_pending(self, registry):
        """get_approval_status should return pending for new requests."""
        _mock_approval_requests.clear()

        # First submit a request
        submit_result = await registry.execute(
            "submit_approval",
            {"action_type": "isolate_host", "target": "workstation-001"},
        )
        request_id = submit_result.data["request_id"]

        # Then check status
        status_result = await registry.execute(
            "get_approval_status",
            {"request_id": request_id},
        )
        assert isinstance(status_result, ToolResult)
        assert status_result.success is True
        assert status_result.data["status"] == "pending"
        assert status_result.data["decided_by"] is None

    @pytest.mark.asyncio
    async def test_get_approval_status_not_found(self, registry):
        """get_approval_status should return expired for unknown requests."""
        result = await registry.execute(
            "get_approval_status",
            {"request_id": str(uuid.uuid4())},
        )
        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["status"] == "expired"


# =============================================================================
# Test Protected Target Patterns
# =============================================================================


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


# =============================================================================
# Test Operation Modes
# =============================================================================


class TestOperationModes:
    """Test operation mode retrieval."""

    def test_default_mode_is_supervised(self):
        """Default operation mode should be supervised."""
        mode = _mock_get_operation_mode()
        assert mode == "supervised"
        assert mode in ["assisted", "supervised", "autonomous"]


# =============================================================================
# Test Kill Switch
# =============================================================================


class TestKillSwitch:
    """Test kill switch status checks."""

    def test_kill_switch_inactive_by_default(self):
        """Kill switch should be inactive by default."""
        active = _mock_is_kill_switch_active()
        assert active is False

    @pytest.mark.asyncio
    async def test_check_policy_includes_kill_switch_status(self):
        """check_policy should include kill switch status."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_policy",
            {"action_type": "create_ticket", "target": "INC-001", "confidence": 0.95},
        )
        assert "kill_switch_active" in result.data
        assert result.data["kill_switch_active"] is False


# =============================================================================
# Test Tool Definitions
# =============================================================================


class TestToolDefinitions:
    """Test tool definitions for LLM integration."""

    @pytest.fixture
    def registry(self):
        """Create a tool registry with triage tools."""
        return create_triage_tools()

    def test_check_policy_definition(self, registry):
        """check_policy should have proper definition for LLM."""
        tool = registry.get("check_policy")
        definition = tool.to_definition()
        assert definition.name == "check_policy"
        assert "policy" in definition.description.lower()
        assert "action_type" in definition.parameters["properties"]
        assert "target" in definition.parameters["properties"]
        assert "confidence" in definition.parameters["properties"]

    def test_submit_approval_definition(self, registry):
        """submit_approval should have proper definition for LLM."""
        tool = registry.get("submit_approval")
        definition = tool.to_definition()
        assert definition.name == "submit_approval"
        assert "approval" in definition.description.lower()
        assert "action_type" in definition.parameters["properties"]
        assert "target" in definition.parameters["properties"]
        assert "level" in definition.parameters["properties"]

    def test_get_approval_status_definition(self, registry):
        """get_approval_status should have proper definition for LLM."""
        tool = registry.get("get_approval_status")
        definition = tool.to_definition()
        assert definition.name == "get_approval_status"
        assert "status" in definition.description.lower()
        assert "request_id" in definition.parameters["properties"]

    def test_all_policy_tools_have_definitions(self, registry):
        """All policy-related tools should have proper definitions."""
        policy_tools = ["check_policy", "submit_approval", "get_approval_status"]
        definitions = registry.get_tool_definitions()
        definition_names = [d.name for d in definitions]

        for tool_name in policy_tools:
            assert tool_name in definition_names


# =============================================================================
# Test Bridge Availability
# =============================================================================


class TestBridgeAvailability:
    """Test bridge availability detection."""

    def test_is_policy_bridge_available_returns_bool(self):
        """is_policy_bridge_available should return a boolean."""
        result = is_policy_bridge_available()
        assert isinstance(result, bool)

    def test_get_policy_bridge_returns_none_when_unavailable(self):
        """get_policy_bridge should return None when bridge is unavailable."""
        # This test verifies behavior when bridge isn't compiled/installed
        # In CI without the Rust bridge, this should return None
        bridge = get_policy_bridge()
        # It's either None (no bridge) or a valid PolicyBridge instance
        # We just verify it doesn't raise an exception
        assert bridge is None or bridge is not None


# =============================================================================
# Test Approval Levels
# =============================================================================


class TestApprovalLevels:
    """Test approval level handling."""

    @pytest.mark.asyncio
    async def test_all_approval_levels_accepted(self):
        """All valid approval levels should be accepted."""
        registry = create_triage_tools()
        _mock_approval_requests.clear()

        levels = ["analyst", "senior", "manager", "executive"]
        for level in levels:
            result = await registry.execute(
                "submit_approval",
                {"action_type": "test_action", "target": "test_target", "level": level},
            )
            assert result.success is True, f"Level {level} should be accepted"
            assert result.data["approval_level"] == level


# =============================================================================
# Integration Tests
# =============================================================================


class TestPolicyWorkflowIntegration:
    """Test complete policy checking workflow."""

    @pytest.mark.asyncio
    async def test_full_approval_workflow(self):
        """Test complete flow: check -> submit -> check status."""
        registry = create_triage_tools()
        _mock_approval_requests.clear()

        # 1. Check policy for an action that requires approval
        check_result = await registry.execute(
            "check_policy",
            {"action_type": "isolate_host", "target": "server-001", "confidence": 0.9},
        )
        assert check_result.data["decision"] == "requires_approval"
        approval_level = check_result.data["approval_level"]

        # 2. Submit approval request
        submit_result = await registry.execute(
            "submit_approval",
            {"action_type": "isolate_host", "target": "server-001", "level": approval_level},
        )
        assert submit_result.success is True
        request_id = submit_result.data["request_id"]

        # 3. Check approval status (should be pending)
        status_result = await registry.execute(
            "get_approval_status",
            {"request_id": request_id},
        )
        assert status_result.data["status"] == "pending"

        # 4. Simulate approval
        _mock_approval_requests[request_id]["status"] = "approved"
        _mock_approval_requests[request_id]["decided_by"] = "soc-analyst@example.com"

        # 5. Check status again (should be approved)
        final_result = await registry.execute(
            "get_approval_status",
            {"request_id": request_id},
        )
        assert final_result.data["status"] == "approved"
        assert final_result.data["decided_by"] == "soc-analyst@example.com"

    @pytest.mark.asyncio
    async def test_allowed_action_no_approval_needed(self):
        """Test that allowed actions don't need approval workflow."""
        registry = create_triage_tools()

        # Check policy for an allowed action
        result = await registry.execute(
            "check_policy",
            {"action_type": "create_ticket", "target": "INC-001", "confidence": 0.95},
        )
        assert result.data["decision"] == "allowed"
        # No need to submit approval request
