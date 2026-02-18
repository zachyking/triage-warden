"""Fixtures for triage service tests."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tw_ai.agents.models import (
    Indicator,
    MITRETechnique,
    RecommendedAction,
    TriageAnalysis,
)
from tw_ai.agents.react import AgentResult


def make_analysis(**overrides: Any) -> TriageAnalysis:
    """Create a TriageAnalysis with sensible defaults."""
    defaults = dict(
        verdict="true_positive",
        confidence=92,
        severity="high",
        summary="Phishing campaign detected targeting PayPal credentials",
        reasoning="URL analysis revealed typosquatted domain paypa1.com",
        indicators=[
            Indicator(type="domain", value="paypa1.com", verdict="malicious"),
        ],
        mitre_techniques=[
            MITRETechnique(
                id="T1566",
                name="Phishing",
                tactic="Initial Access",
                relevance="Phishing email with malicious link",
            ),
        ],
        recommended_actions=[
            RecommendedAction(
                action="Quarantine email",
                priority="immediate",
                reason="Prevent further clicks",
            ),
        ],
    )
    defaults.update(overrides)
    return TriageAnalysis(**defaults)


def make_agent_result(analysis: TriageAnalysis | None = None, **overrides: Any) -> AgentResult:
    """Create an AgentResult wrapping an analysis."""
    if analysis is None:
        analysis = make_analysis()
    defaults = dict(
        success=True,
        analysis=analysis,
        tokens_used=1200,
        execution_time_seconds=2.5,
    )
    defaults.update(overrides)
    return AgentResult(**defaults)


@pytest.fixture()
def mock_config():
    """A mock TriageServiceConfig that reports LLM as configured."""
    cfg = MagicMock()
    cfg.is_llm_configured.return_value = True
    cfg.llm_provider = "mock"
    cfg.llm_model = "mock-model"
    return cfg


@pytest.fixture()
def mock_config_unconfigured():
    """A mock TriageServiceConfig that reports LLM as NOT configured."""
    cfg = MagicMock()
    cfg.is_llm_configured.return_value = False
    cfg.llm_provider = "none"
    cfg.llm_model = "none"
    return cfg


@pytest.fixture()
def default_agent_result():
    """A default successful AgentResult."""
    return make_agent_result()


@pytest.fixture()
async def triage_client(mock_config, default_agent_result):
    """Async test client with a mocked agent that returns a successful result."""
    mock_agent = MagicMock()
    mock_agent.run = AsyncMock(return_value=default_agent_result)

    with (
        patch("tw_ai.triage_service.app.get_config", return_value=mock_config),
        patch("tw_ai.triage_service.app._get_or_create_agent", return_value=mock_agent),
    ):
        from tw_ai.triage_service.app import create_app

        app = create_app(mock_config)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client
