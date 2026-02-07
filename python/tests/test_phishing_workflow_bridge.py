"""Focused tests for threat-intel bridge integration in phishing workflow."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
