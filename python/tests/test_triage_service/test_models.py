"""Tests for triage service Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from tw_ai.triage_service.models import (
    HealthResponse,
    IndicatorResponse,
    StatusResponse,
    TriageErrorResponse,
    TriageServiceRequest,
    TriageServiceResponse,
)


class TestTriageServiceRequest:
    def test_minimal_valid(self):
        req = TriageServiceRequest(
            alert_type="phishing",
            alert_data={"sender": "bad@evil.com"},
        )
        assert req.alert_type == "phishing"
        assert req.context is None
        assert req.priority is None

    def test_full_request(self):
        req = TriageServiceRequest(
            alert_type="malware",
            alert_data={"hash": "abc123"},
            context={"asset_id": "ws-01"},
            priority="high",
        )
        assert req.priority == "high"
        assert req.context == {"asset_id": "ws-01"}

    def test_missing_alert_type_fails(self):
        with pytest.raises(ValidationError):
            TriageServiceRequest(alert_data={"x": 1})  # type: ignore[call-arg]

    def test_missing_alert_data_fails(self):
        with pytest.raises(ValidationError):
            TriageServiceRequest(alert_type="phishing")  # type: ignore[call-arg]


class TestTriageServiceResponse:
    def test_valid_response(self):
        resp = TriageServiceResponse(
            verdict="true_positive",
            confidence=0.92,
            severity="high",
            summary="Phishing detected",
        )
        assert resp.verdict == "true_positive"
        assert resp.analyzed_by == "react-agent"

    def test_confidence_bounds(self):
        with pytest.raises(ValidationError):
            TriageServiceResponse(
                verdict="true_positive",
                confidence=1.5,
                severity="high",
                summary="Bad confidence",
            )

    def test_with_indicators(self):
        resp = TriageServiceResponse(
            verdict="suspicious",
            confidence=0.7,
            severity="medium",
            summary="Suspicious activity",
            indicators=[
                IndicatorResponse(type="ip", value="1.2.3.4", verdict="malicious"),
            ],
        )
        assert len(resp.indicators) == 1


class TestHealthResponse:
    def test_defaults(self):
        h = HealthResponse()
        assert h.status == "healthy"
        assert h.service == "tw-triage-service"


class TestStatusResponse:
    def test_ready(self):
        s = StatusResponse(
            ready=True,
            llm_configured=True,
            llm_provider="openai",
            llm_model="gpt-4",
        )
        assert s.ready is True

    def test_not_ready(self):
        s = StatusResponse(
            ready=False,
            llm_configured=False,
            llm_provider="openai",
            llm_model="gpt-4",
        )
        assert s.ready is False


class TestTriageErrorResponse:
    def test_error(self):
        e = TriageErrorResponse(error="timeout", detail="Agent timed out")
        assert e.error == "timeout"
        assert e.fallback_used is False
