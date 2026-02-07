"""Focused tests for bridge-backed sender reputation tool behavior."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import tw_ai.agents.tools as _tools
from tw_ai.agents.tools import create_triage_tools


@pytest.mark.asyncio
async def test_check_sender_reputation_uses_bridge_data() -> None:
    """check_sender_reputation should use threat-intel bridge when available."""
    mock_bridge = MagicMock()
    mock_bridge.lookup_domain.return_value = {
        "indicator": "suspicious-site.net",
        "indicator_type": "domain",
        "verdict": "malicious",
        "malicious_score": 78,
        "categories": ["phishing"],
        "source": "virustotal",
    }

    with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
        with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
            with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                registry = create_triage_tools()
                result = await registry.execute(
                    "check_sender_reputation",
                    {"sender_email": "user@suspicious-site.net"},
                )

    assert result.success is True
    assert result.data["is_mock"] is False
    assert result.data["domain"] == "suspicious-site.net"
    assert result.data["score"] == 22
    assert result.data["risk_level"] == "high"
    assert result.data["category"] == "phishing"
    mock_bridge.lookup_domain.assert_called_once_with("suspicious-site.net")


@pytest.mark.asyncio
async def test_check_sender_reputation_bridge_clean_domain() -> None:
    """Bridge clean verdict should produce low-risk known sender output."""
    mock_bridge = MagicMock()
    mock_bridge.lookup_domain.return_value = {
        "indicator": "microsoft.com",
        "indicator_type": "domain",
        "verdict": "clean",
        "malicious_score": 0,
        "categories": ["technology"],
        "domain_age_days": 10000,
        "source": "virustotal",
    }

    with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
        with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
            with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                registry = create_triage_tools()
                result = await registry.execute(
                    "check_sender_reputation",
                    {"sender_email": "contact@microsoft.com"},
                )

    assert result.success is True
    assert result.data["is_mock"] is False
    assert result.data["score"] == 100
    assert result.data["risk_level"] == "low"
    assert result.data["is_known_sender"] is True
    assert result.data["domain_age_days"] == 10000
