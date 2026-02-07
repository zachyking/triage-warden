"""Tests for production guardrails on mock tool fallbacks."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

import tw_ai.agents.tools as _tools


@pytest.mark.asyncio
async def test_lookup_domain_fails_closed_when_mock_fallback_disabled() -> None:
    """In production, domain lookups should fail closed when no connector exists."""
    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, "get_threat_intel_bridge", return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute("lookup_domain", {"domain": "example.com"})

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
async def test_check_policy_fails_closed_when_mock_fallback_disabled() -> None:
    """In production, policy checks should fail closed when no policy bridge exists."""
    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, "get_policy_bridge", return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute(
                "check_policy",
                {"action_type": "isolate_host", "target": "workstation-01"},
            )

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
async def test_sender_reputation_fails_closed_when_mock_fallback_disabled() -> None:
    """In production, sender reputation should fail closed without connector."""
    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, "get_threat_intel_bridge", return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute(
                "check_sender_reputation",
                {"sender_email": "user@example.com"},
            )

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
async def test_mock_fallback_override_allows_production_mock_mode() -> None:
    """Production can explicitly allow mock fallback with an env override."""
    with patch.dict(
        os.environ,
        {
            "TW_ENV": "production",
            _tools.MOCK_FALLBACK_OVERRIDE_ENV: "true",
        },
    ):
        with patch.object(_tools, "get_threat_intel_bridge", return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute("lookup_domain", {"domain": "example.com"})

    assert result.success is True
    assert result.data.get("is_mock") is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "bridge_getter"),
    [
        ("search_siem", {"query": "login_failure"}, "get_siem_bridge"),
        ("get_recent_alerts", {}, "get_siem_bridge"),
        ("get_host_info", {"hostname": "workstation-001"}, "get_edr_bridge"),
        ("get_detections", {"hostname": "workstation-001"}, "get_edr_bridge"),
        (
            "get_processes",
            {"hostname": "workstation-001", "hours": 24},
            "get_edr_bridge",
        ),
        (
            "get_network_connections",
            {"hostname": "workstation-001", "hours": 24},
            "get_edr_bridge",
        ),
    ],
)
async def test_siem_and_edr_tools_fail_closed_when_mock_fallback_disabled(
    tool_name: str, arguments: dict[str, object], bridge_getter: str
) -> None:
    """In production, SIEM/EDR read tools should fail closed without connectors."""
    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, bridge_getter, return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute(tool_name, arguments)

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "bridge_getter"),
    [
        ("search_siem", {"query": "login_failure"}, "get_siem_bridge"),
        ("get_recent_alerts", {}, "get_siem_bridge"),
        ("get_host_info", {"hostname": "workstation-001"}, "get_edr_bridge"),
        ("get_detections", {"hostname": "workstation-001"}, "get_edr_bridge"),
        (
            "get_processes",
            {"hostname": "workstation-001", "hours": 24},
            "get_edr_bridge",
        ),
        (
            "get_network_connections",
            {"hostname": "workstation-001", "hours": 24},
            "get_edr_bridge",
        ),
    ],
)
async def test_siem_and_edr_tools_allow_mock_with_production_override(
    tool_name: str, arguments: dict[str, object], bridge_getter: str
) -> None:
    """Production can explicitly allow SIEM/EDR mock fallbacks with override."""
    with patch.dict(
        os.environ,
        {
            "TW_ENV": "production",
            _tools.MOCK_FALLBACK_OVERRIDE_ENV: "true",
        },
    ):
        with patch.object(_tools, bridge_getter, return_value=None):
            registry = _tools.create_triage_tools()
            result = await registry.execute(tool_name, arguments)

    assert result.success is True
    assert result.data is not None
    assert result.data.get("is_mock") is True


def test_is_action_allowed_fails_closed_without_policy_bridge_in_production() -> None:
    """In production, helper policy checks should fail closed without connector."""
    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, "get_policy_bridge", return_value=None):
            assert _tools.is_action_allowed("create_ticket", "test-target", 0.9) is False


def test_is_action_allowed_allows_mock_with_production_override() -> None:
    """Production can explicitly allow mock helper policy checks with override."""
    with patch.dict(
        os.environ,
        {
            "TW_ENV": "production",
            _tools.MOCK_FALLBACK_OVERRIDE_ENV: "true",
        },
    ):
        with patch.object(_tools, "get_policy_bridge", return_value=None):
            assert _tools.is_action_allowed("create_ticket", "test-target", 0.9) is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "bridge_getter"),
    [
        (
            "quarantine_email",
            {"message_id": "MSG-123", "reason": "phishing"},
            "get_email_gateway_bridge",
        ),
        (
            "block_sender",
            {"sender": "attacker@evil.com", "block_type": "email", "reason": "phishing"},
            "get_email_gateway_bridge",
        ),
        (
            "create_security_ticket",
            {
                "title": "Malicious email campaign",
                "description": "Detected malicious sender and links",
                "severity": "high",
                "indicators": ["attacker@evil.com"],
            },
            "get_ticketing_bridge",
        ),
        (
            "notify_user",
            {
                "recipient": "user@example.com",
                "notification_type": "phishing_warning",
                "subject": "Warning",
                "body": "A phishing message was detected.",
            },
            None,
        ),
    ],
)
async def test_action_tools_fail_closed_when_mock_fallback_disabled(
    tool_name: str, arguments: dict[str, object], bridge_getter: str | None
) -> None:
    """In production, action tools should fail closed without required connectors."""
    policy_bridge = MagicMock()
    policy_bridge.check_action.return_value = {"decision": "allowed"}

    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(_tools, "get_policy_bridge", return_value=policy_bridge):
            if bridge_getter is not None:
                with patch.object(_tools, bridge_getter, return_value=None):
                    registry = _tools.create_triage_tools()
                    result = await registry.execute(tool_name, arguments)
            else:
                registry = _tools.create_triage_tools()
                result = await registry.execute(tool_name, arguments)

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("tool_name", "arguments", "bridge_getter"),
    [
        (
            "quarantine_email",
            {"message_id": "MSG-123", "reason": "phishing"},
            "get_email_gateway_bridge",
        ),
        (
            "block_sender",
            {"sender": "attacker@evil.com", "block_type": "email", "reason": "phishing"},
            "get_email_gateway_bridge",
        ),
        (
            "create_security_ticket",
            {
                "title": "Malicious email campaign",
                "description": "Detected malicious sender and links",
                "severity": "high",
                "indicators": ["attacker@evil.com"],
            },
            "get_ticketing_bridge",
        ),
        (
            "notify_user",
            {
                "recipient": "user@example.com",
                "notification_type": "phishing_warning",
                "subject": "Warning",
                "body": "A phishing message was detected.",
            },
            None,
        ),
    ],
)
async def test_action_tools_allow_mock_with_production_override(
    tool_name: str, arguments: dict[str, object], bridge_getter: str | None
) -> None:
    """Production can explicitly allow action-tool mock fallbacks with override."""
    policy_bridge = MagicMock()
    policy_bridge.check_action.return_value = {"decision": "allowed"}

    with patch.dict(
        os.environ,
        {
            "TW_ENV": "production",
            _tools.MOCK_FALLBACK_OVERRIDE_ENV: "true",
        },
    ):
        with patch.object(_tools, "get_policy_bridge", return_value=policy_bridge):
            if bridge_getter is not None:
                with patch.object(_tools, bridge_getter, return_value=None):
                    registry = _tools.create_triage_tools()
                    result = await registry.execute(tool_name, arguments)
            else:
                registry = _tools.create_triage_tools()
                result = await registry.execute(tool_name, arguments)

    assert result.success is True
    assert result.data is not None
    assert result.data.get("is_mock") is True
