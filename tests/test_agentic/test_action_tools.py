"""Tests for action tool definitions and registry."""

from __future__ import annotations

from tw_ai.agents.action_tools import (
    ActionTool,
    ActionToolRegistry,
    ParameterSpec,
    _is_valid_email,
    _is_valid_hostname,
    _is_valid_ip,
)
from tw_ai.agents.response_planner import RiskLevel

# =============================================================================
# ParameterSpec tests
# =============================================================================


class TestParameterSpec:
    def test_basic_creation(self):
        spec = ParameterSpec(
            name="hostname",
            param_type="hostname",
            description="Target host",
        )
        assert spec.name == "hostname"
        assert spec.required

    def test_optional_parameter(self):
        spec = ParameterSpec(
            name="reason",
            param_type="string",
            required=False,
            default="automated",
        )
        assert not spec.required
        assert spec.default == "automated"


# =============================================================================
# ActionTool tests
# =============================================================================


class TestActionTool:
    def test_basic_tool(self):
        tool = ActionTool(
            name="test_tool",
            description="A test tool",
            category="investigation",
        )
        assert tool.name == "test_tool"
        assert tool.risk_level == RiskLevel.LOW
        assert not tool.requires_approval

    def test_validate_params_required_missing(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="containment",
            parameters=[ParameterSpec(name="hostname", param_type="hostname")],
        )
        valid, errors = tool.validate_params({})
        assert not valid
        assert any("Missing" in e for e in errors)

    def test_validate_params_optional_default(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="reason",
                    param_type="string",
                    required=True,
                    default="auto",
                )
            ],
        )
        # Required with default -> still need to provide it
        valid, errors = tool.validate_params({})
        # Has a default, so it's ok to omit
        assert valid

    def test_validate_params_valid(self):
        tool = ActionTool(
            name="block_ip",
            description="Block IP",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="ip_address",
                    param_type="ip_address",
                ),
            ],
        )
        valid, errors = tool.validate_params({"ip_address": "192.168.1.1"})
        assert valid
        assert len(errors) == 0

    def test_validate_params_invalid_ip(self):
        tool = ActionTool(
            name="block_ip",
            description="Block IP",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="ip_address",
                    param_type="ip_address",
                ),
            ],
        )
        valid, errors = tool.validate_params({"ip_address": "not-an-ip"})
        assert not valid
        assert any("IP address" in e for e in errors)

    def test_validate_params_invalid_hostname(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="host",
                    param_type="hostname",
                ),
            ],
        )
        valid, errors = tool.validate_params({"host": "-invalid"})
        assert not valid

    def test_validate_params_invalid_email(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="notification",
            parameters=[
                ParameterSpec(
                    name="recipient",
                    param_type="email",
                ),
            ],
        )
        valid, errors = tool.validate_params({"recipient": "not-an-email"})
        assert not valid

    def test_validate_params_integer_type(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="investigation",
            parameters=[
                ParameterSpec(
                    name="count",
                    param_type="integer",
                ),
            ],
        )
        valid, _ = tool.validate_params({"count": 10})
        assert valid

        valid, errors = tool.validate_params({"count": "not-int"})
        assert not valid

    def test_validate_params_boolean_type(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="flag",
                    param_type="boolean",
                ),
            ],
        )
        valid, _ = tool.validate_params({"flag": True})
        assert valid

        valid, errors = tool.validate_params({"flag": "yes"})
        assert not valid

    def test_validate_params_unknown_param(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="investigation",
            parameters=[],
        )
        valid, errors = tool.validate_params({"unknown_key": "value"})
        assert not valid
        assert any("Unknown" in e for e in errors)

    def test_validate_params_pattern(self):
        tool = ActionTool(
            name="test",
            description="Test",
            category="containment",
            parameters=[
                ParameterSpec(
                    name="hash_value",
                    param_type="string",
                    validation_pattern=r"^[a-fA-F0-9]{64}$",
                ),
            ],
        )
        valid_hash = "a" * 64
        valid, _ = tool.validate_params({"hash_value": valid_hash})
        assert valid

        valid, errors = tool.validate_params({"hash_value": "short"})
        assert not valid
        assert any("pattern" in e for e in errors)


# =============================================================================
# Validation helper tests
# =============================================================================


class TestValidationHelpers:
    def test_valid_ipv4(self):
        assert _is_valid_ip("192.168.1.1")
        assert _is_valid_ip("10.0.0.1")
        assert _is_valid_ip("0.0.0.0")
        assert _is_valid_ip("255.255.255.255")

    def test_invalid_ipv4(self):
        assert not _is_valid_ip("256.1.1.1")
        assert not _is_valid_ip("abc.def.ghi.jkl")
        assert not _is_valid_ip("")
        assert not _is_valid_ip("10.0.0")

    def test_valid_hostname(self):
        assert _is_valid_hostname("host1")
        assert _is_valid_hostname("web-server.corp.local")
        assert _is_valid_hostname("a")

    def test_invalid_hostname(self):
        assert not _is_valid_hostname("")
        assert not _is_valid_hostname("-invalid")
        assert not _is_valid_hostname("a" * 254)

    def test_valid_email(self):
        assert _is_valid_email("user@example.com")
        assert _is_valid_email("name.last@corp.co")

    def test_invalid_email(self):
        assert not _is_valid_email("not-an-email")
        assert not _is_valid_email("@example.com")
        assert not _is_valid_email("")


# =============================================================================
# ActionToolRegistry tests
# =============================================================================


class TestActionToolRegistry:
    def test_default_tools_registered(self):
        registry = ActionToolRegistry()
        tools = registry.list_tools()
        assert len(tools) >= 14
        names = [t.name for t in tools]
        assert "isolate_host" in names
        assert "disable_user" in names
        assert "block_ip" in names
        assert "block_domain" in names
        assert "quarantine_email" in names
        assert "search_logs" in names
        assert "create_ticket" in names
        assert "notify_user" in names
        assert "scan_host" in names
        assert "enable_user" in names
        assert "unisolate_host" in names
        assert "block_hash" in names
        assert "reset_password" in names
        assert "revoke_sessions" in names

    def test_get_tool(self):
        registry = ActionToolRegistry()
        tool = registry.get("isolate_host")
        assert tool is not None
        assert tool.name == "isolate_host"
        assert tool.category == "containment"
        assert tool.requires_approval
        assert tool.risk_level == RiskLevel.HIGH

    def test_get_nonexistent(self):
        registry = ActionToolRegistry()
        assert registry.get("nonexistent") is None

    def test_list_by_category(self):
        registry = ActionToolRegistry()
        containment = registry.list_tools(category="containment")
        assert len(containment) > 0
        assert all(t.category == "containment" for t in containment)

        investigation = registry.list_tools(category="investigation")
        assert len(investigation) > 0
        assert all(t.category == "investigation" for t in investigation)

    def test_list_categories(self):
        registry = ActionToolRegistry()
        categories = registry.list_categories()
        assert "containment" in categories
        assert "eradication" in categories
        assert "recovery" in categories
        assert "investigation" in categories
        assert "notification" in categories

    def test_register_custom_tool(self):
        registry = ActionToolRegistry()
        custom = ActionTool(
            name="custom_scan",
            description="Custom scanning tool",
            category="investigation",
            risk_level=RiskLevel.LOW,
        )
        registry.register(custom)
        assert registry.get("custom_scan") is not None

    def test_register_overwrites(self):
        registry = ActionToolRegistry()
        original = registry.get("block_ip")
        assert original is not None

        replacement = ActionTool(
            name="block_ip",
            description="Replacement",
            category="containment",
            risk_level=RiskLevel.CRITICAL,
        )
        registry.register(replacement)
        updated = registry.get("block_ip")
        assert updated.risk_level == RiskLevel.CRITICAL

    def test_tools_sorted_by_name(self):
        registry = ActionToolRegistry()
        tools = registry.list_tools()
        names = [t.name for t in tools]
        assert names == sorted(names)

    def test_tool_rollback_references(self):
        registry = ActionToolRegistry()
        isolate = registry.get("isolate_host")
        assert isolate.rollback_tool == "unisolate_host"
        unisolate = registry.get("unisolate_host")
        assert unisolate.rollback_tool == "isolate_host"

    def test_high_risk_tools_require_approval(self):
        registry = ActionToolRegistry()
        for tool in registry.list_tools():
            if tool.risk_level == RiskLevel.HIGH:
                assert (
                    tool.requires_approval
                ), f"Tool '{tool.name}' is high risk but doesn't require approval"

    def test_tool_parameter_validation(self):
        registry = ActionToolRegistry()
        isolate = registry.get("isolate_host")
        valid, errors = isolate.validate_params({"hostname": "ws-001"})
        assert valid

    def test_tool_missing_required_param(self):
        registry = ActionToolRegistry()
        isolate = registry.get("isolate_host")
        valid, errors = isolate.validate_params({})
        assert not valid
        assert any("hostname" in e for e in errors)
