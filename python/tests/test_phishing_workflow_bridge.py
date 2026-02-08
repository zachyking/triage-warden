"""Focused tests for threat-intel bridge integration in phishing workflow."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tw_ai.workflows.phishing import PhishingTriageWorkflow


@pytest.mark.asyncio
async def test_sender_reputation_uses_threat_intel_bridge() -> None:
    """Sender reputation should use bridge lookups when available."""
    workflow = PhishingTriageWorkflow()
    mock_bridge = MagicMock()
    mock_bridge.lookup_domain.return_value = {
        "verdict": "malicious",
        "malicious_score": 80,
        "categories": ["phishing"],
        "domain_age_days": 5,
    }

    with patch.object(workflow, "_get_threat_intel_bridge", return_value=mock_bridge):
        result = await workflow._check_sender_reputation("user@evil.example.com")

    assert result.is_mock is False
    assert result.domain == "evil.example.com"
    assert result.score == 20
    assert result.risk_level == "high"
    assert result.domain_age_days == 5
    mock_bridge.lookup_domain.assert_called_once_with("evil.example.com")


@pytest.mark.asyncio
async def test_url_check_uses_threat_intel_bridge() -> None:
    """URL checks should use bridge-backed domain verdicts when available."""
    workflow = PhishingTriageWorkflow()
    mock_bridge = MagicMock()
    mock_bridge.lookup_domain.return_value = {
        "verdict": "suspicious",
        "malicious_score": 65,
        "categories": ["newly_registered", "phishing"],
    }

    with patch.object(workflow, "_get_threat_intel_bridge", return_value=mock_bridge):
        result = await workflow._check_single_url(
            "http://suspicious-site.net/login",
            "suspicious-site.net",
        )

    assert result.is_mock is False
    assert result.verdict == "suspicious"
    assert result.score == 65
    assert "newly_registered" in result.categories
    mock_bridge.lookup_domain.assert_called_once_with("suspicious-site.net")


@pytest.mark.asyncio
async def test_quarantine_action_uses_tool_registry_when_available() -> None:
    """Workflow actions should call tool registry instead of local mock path."""
    tools = MagicMock()
    tools.execute = AsyncMock(
        return_value=MagicMock(
            success=True,
            data={
                "success": True,
                "action_id": "qe-123",
                "message": "Email MSG-1 quarantined",
            },
            error=None,
        )
    )
    workflow = PhishingTriageWorkflow(tools=tools)

    result = await workflow._action_quarantine_email("MSG-1", ["phishing link"])

    assert result.success is True
    assert result.action_id == "qe-123"
    tools.execute.assert_awaited_once_with(
        "quarantine_email",
        {"message_id": "MSG-1", "reason": "phishing link"},
    )


@pytest.mark.asyncio
async def test_create_ticket_action_uses_tool_registry_when_available() -> None:
    """Workflow ticket action should use create_security_ticket tool."""
    tools = MagicMock()
    tools.execute = AsyncMock(
        return_value=MagicMock(
            success=True,
            data={
                "success": True,
                "ticket_id": "SEC-1001",
                "message": "Ticket created",
            },
            error=None,
        )
    )
    workflow = PhishingTriageWorkflow(tools=tools)

    email_analysis = MagicMock()
    email_analysis.sender = "attacker@evil.com"
    email_analysis.subject = "Urgent: Verify account"

    indicators = MagicMock()
    indicators.overall_risk_score = 72
    indicators.risk_factors = ["suspicious sender", "credential harvest"]
    indicators.suspicious_urls = ["http://evil.example.com/login"]

    result = await workflow._action_create_ticket(email_analysis, indicators, 0.91)

    assert result.success is True
    assert result.action_id == "SEC-1001"
    tools.execute.assert_awaited()
    tool_name, tool_args = tools.execute.await_args.args
    assert tool_name == "create_security_ticket"
    assert tool_args["severity"] == "high"
    assert "attacker@evil.com" in tool_args["indicators"]


@pytest.mark.asyncio
async def test_notify_action_fails_closed_without_tools_in_production() -> None:
    """In production, workflow should not silently use local mock notify action."""
    workflow = PhishingTriageWorkflow(tools=None, dry_run=False)

    with patch.dict(os.environ, {"TW_ENV": "production"}):
        result = await workflow._action_notify_user(
            "user@example.com",
            "Important account update",
            "phishing_warning",
        )

    assert result.success is False
    assert result.error is not None
    assert "mock fallback is disabled" in result.error.lower()


@pytest.mark.asyncio
async def test_sender_reputation_fails_closed_without_threat_intel_in_production() -> None:
    """In production, sender enrichment should use conservative fail-closed values."""
    workflow = PhishingTriageWorkflow()

    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(workflow, "_get_threat_intel_bridge", return_value=None):
            result = await workflow._check_sender_reputation("user@unknown.example")

    assert result.is_mock is False
    assert result.score == 0
    assert result.risk_level == "high"


@pytest.mark.asyncio
async def test_url_check_fails_closed_without_threat_intel_in_production() -> None:
    """In production, URL enrichment should use conservative fail-closed verdicts."""
    workflow = PhishingTriageWorkflow()

    with patch.dict(os.environ, {"TW_ENV": "production"}):
        with patch.object(workflow, "_get_threat_intel_bridge", return_value=None):
            result = await workflow._check_single_url(
                "http://unknown.example/path",
                "unknown.example",
            )

    assert result.is_mock is False
    assert result.verdict == "suspicious"
    assert result.score == 100
    assert "threat_intel_unavailable" in result.categories
