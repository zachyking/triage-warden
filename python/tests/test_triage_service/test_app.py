"""Tests for triage service FastAPI endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from tw_ai.agents.react import AgentResult
from tw_ai.triage_service.app import create_app

from .conftest import make_agent_result, make_analysis


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _client_with(
    llm_configured: bool = True,
    agent_result: AgentResult | None = None,
    agent_side_effect: Exception | None = None,
):
    """Create a test client with controlled mocking."""
    cfg = MagicMock()
    cfg.is_llm_configured.return_value = llm_configured
    cfg.llm_provider = "mock"
    cfg.llm_model = "mock-model"

    mock_agent = MagicMock()
    if agent_side_effect:
        mock_agent.run = AsyncMock(side_effect=agent_side_effect)
    elif agent_result:
        mock_agent.run = AsyncMock(return_value=agent_result)
    else:
        mock_agent.run = AsyncMock(return_value=make_agent_result())

    with (
        patch("tw_ai.triage_service.app.get_config", return_value=cfg),
        patch("tw_ai.triage_service.app._get_or_create_agent", return_value=mock_agent),
    ):
        app = create_app(cfg)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            yield client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_returns_200(self):
        async for client in _client_with():
            resp = await client.get("/health")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "healthy"
            assert data["service"] == "tw-triage-service"


class TestStatusEndpoint:
    @pytest.mark.asyncio
    async def test_status_configured(self):
        async for client in _client_with(llm_configured=True):
            resp = await client.get("/api/triage/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ready"] is True
            assert data["llm_configured"] is True

    @pytest.mark.asyncio
    async def test_status_not_configured(self):
        async for client in _client_with(llm_configured=False):
            resp = await client.get("/api/triage/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["ready"] is False

    @pytest.mark.asyncio
    async def test_create_app_uses_explicit_config_not_global_singleton(self):
        explicit_cfg = MagicMock()
        explicit_cfg.is_llm_configured.return_value = True
        explicit_cfg.llm_provider = "explicit"
        explicit_cfg.llm_model = "explicit-model"

        global_cfg = MagicMock()
        global_cfg.is_llm_configured.return_value = False
        global_cfg.llm_provider = "global"
        global_cfg.llm_model = "global-model"

        with patch("tw_ai.triage_service.app.get_config", return_value=global_cfg):
            app = create_app(explicit_cfg)
            transport = ASGITransport(app=app)
            async with AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.get("/api/triage/status")
                assert resp.status_code == 200
                data = resp.json()
                assert data["ready"] is True
                assert data["llm_configured"] is True
                assert data["llm_provider"] == "explicit"
                assert data["llm_model"] == "explicit-model"


class TestTriageEndpoint:
    @pytest.mark.asyncio
    async def test_valid_phishing_request(self):
        async for client in _client_with():
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "phishing",
                    "alert_data": {"sender": "bad@paypa1.com", "subject": "Reset"},
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["verdict"] == "true_positive"
            assert 0.0 <= data["confidence"] <= 1.0
            assert data["severity"] == "high"
            assert data["analyzed_by"] == "react-agent"
            assert len(data["summary"]) > 0

    @pytest.mark.asyncio
    async def test_valid_malware_request(self):
        analysis = make_analysis(
            verdict="true_positive",
            confidence=95,
            severity="critical",
            summary="Malware detected on endpoint",
        )
        result = make_agent_result(analysis=analysis)
        async for client in _client_with(agent_result=result):
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "malware",
                    "alert_data": {"hash": "abc123", "hostname": "ws-01"},
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["verdict"] == "true_positive"
            assert data["severity"] == "critical"

    @pytest.mark.asyncio
    async def test_valid_brute_force_request(self):
        analysis = make_analysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Brute force attack detected",
        )
        result = make_agent_result(analysis=analysis)
        async for client in _client_with(agent_result=result):
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "brute_force",
                    "alert_data": {"source_ip": "198.51.100.1", "failures": 50},
                },
            )
            assert resp.status_code == 200
            assert resp.json()["verdict"] == "true_positive"

    @pytest.mark.asyncio
    async def test_invalid_payload_missing_alert_data(self):
        async for client in _client_with():
            resp = await client.post(
                "/api/triage",
                json={"alert_type": "phishing"},
            )
            assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_empty_body_422(self):
        async for client in _client_with():
            resp = await client.post("/api/triage", json={})
            assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_llm_not_configured_503(self):
        async for client in _client_with(llm_configured=False):
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "phishing",
                    "alert_data": {"sender": "bad@evil.com"},
                },
            )
            assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_agent_exception_returns_500(self):
        async for client in _client_with(
            agent_side_effect=RuntimeError("LLM connection refused")
        ):
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "phishing",
                    "alert_data": {"sender": "bad@evil.com"},
                },
            )
            assert resp.status_code == 500

    @pytest.mark.asyncio
    async def test_agent_parse_failure_returns_422(self):
        result = AgentResult(
            success=False,
            analysis=None,
            error="Could not parse LLM output as JSON",
            raw_output="some garbled text",
        )
        async for client in _client_with(agent_result=result):
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "phishing",
                    "alert_data": {"sender": "bad@evil.com"},
                },
            )
            assert resp.status_code == 422
            data = resp.json()
            assert data["error"] == "analysis_parse_failed"

    @pytest.mark.asyncio
    async def test_response_has_all_fields(self):
        async for client in _client_with():
            resp = await client.post(
                "/api/triage",
                json={
                    "alert_type": "phishing",
                    "alert_data": {"sender": "bad@evil.com"},
                    "priority": "high",
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            expected_fields = {
                "verdict", "confidence", "severity", "summary", "reasoning",
                "indicators", "mitre_techniques", "recommended_actions",
                "evidence", "analyzed_by", "tokens_used", "execution_time_seconds",
            }
            assert expected_fields.issubset(set(data.keys()))
