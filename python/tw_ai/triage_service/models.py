"""Pydantic request/response models for the triage HTTP service."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TriageServiceRequest(BaseModel):
    """Request body for POST /api/triage."""

    alert_type: str = Field(description="Type of alert (phishing, malware, brute_force, etc.)")
    alert_data: dict[str, Any] = Field(description="Raw alert data to analyze")
    context: dict[str, Any] | None = Field(default=None, description="Optional additional context")
    priority: str | None = Field(default=None, description="Optional priority level")


class IndicatorResponse(BaseModel):
    """An indicator of compromise in the response."""

    type: str
    value: str
    verdict: str
    context: str | None = None


class MITRETechniqueResponse(BaseModel):
    """A MITRE ATT&CK technique in the response."""

    id: str
    name: str
    tactic: str
    relevance: str


class RecommendedActionResponse(BaseModel):
    """A recommended action in the response."""

    action: str
    priority: str
    reason: str
    requires_approval: bool = False


class EvidenceItemResponse(BaseModel):
    """An evidence item in the response."""

    source_type: str
    source_name: str
    data_type: str
    value: dict[str, Any]
    finding: str
    relevance: str
    confidence: int


class TriageServiceResponse(BaseModel):
    """Response body from POST /api/triage."""

    verdict: str = Field(description="true_positive, false_positive, suspicious, or inconclusive")
    confidence: float = Field(ge=0, le=1.0, description="Confidence score 0.0-1.0")
    severity: str = Field(description="critical, high, medium, low, or informational")
    summary: str = Field(description="Brief summary of findings")
    reasoning: str = Field(default="", description="Detailed reasoning")
    indicators: list[IndicatorResponse] = Field(default_factory=list)
    mitre_techniques: list[MITRETechniqueResponse] = Field(default_factory=list)
    recommended_actions: list[RecommendedActionResponse] = Field(default_factory=list)
    evidence: list[EvidenceItemResponse] = Field(default_factory=list)
    analyzed_by: str = Field(default="react-agent", description="Which analyzer produced this")
    tokens_used: int = Field(default=0, description="Total tokens consumed")
    execution_time_seconds: float = Field(default=0.0, description="Wall-clock time")


class TriageErrorResponse(BaseModel):
    """Error response body."""

    error: str
    detail: str | None = None
    fallback_used: bool = False


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "healthy"
    service: str = "tw-triage-service"
    version: str = "0.1.1"


class StatusResponse(BaseModel):
    """Readiness status response."""

    ready: bool
    llm_configured: bool
    llm_provider: str
    llm_model: str
