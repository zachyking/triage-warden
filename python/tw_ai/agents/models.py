"""Pydantic v2 models for triage analysis output parsing."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# =============================================================================
# Evidence Models (Stage 2.1.2)
# =============================================================================


class EvidenceItem(BaseModel):
    """A piece of evidence supporting the triage analysis verdict.

    Evidence items are collected during investigation and provide
    audit-ready citations for every finding.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    source_type: Literal[
        "threat_intel",
        "siem",
        "edr",
        "email",
        "enrichment",
        "alert_data",
        "manual",
        "cloud",
        "identity_provider",
    ] = Field(description="Category of evidence source")

    source_name: str = Field(
        description="Specific source (e.g., 'VirusTotal', 'Splunk', 'CrowdStrike')"
    )

    data_type: Literal[
        "network_activity",
        "file_artifact",
        "process_execution",
        "user_behavior",
        "email_content",
        "threat_intel_match",
        "mitre_observation",
        "system_change",
        "dns_activity",
        "web_activity",
        "cloud_activity",
        "authentication_event",
        "data_access",
        "malware_indicator",
    ] = Field(description="Type of evidence data")

    value: dict[str, Any] = Field(description="The actual evidence data/values")

    finding: str = Field(description="What this evidence shows or indicates")

    relevance: str = Field(description="How this evidence relates to and supports the verdict")

    confidence: int = Field(
        ge=0,
        le=100,
        description="Confidence in this specific piece of evidence (0-100)",
    )

    link: str | None = Field(
        default=None,
        description="Optional deep link to view evidence in source system",
    )

    @field_validator("source_name", "finding", "relevance")
    @classmethod
    def not_empty(cls, v: str) -> str:
        """Ensure required string fields are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class InvestigationStep(BaseModel):
    """A step in the investigation process.

    Investigation steps document the actions taken during analysis,
    providing an audit trail for reproducibility.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    order: int = Field(
        ge=1,
        description="Step order in the investigation (1-indexed)",
    )

    action: str = Field(description="Description of the action taken")

    result: str = Field(description="Result or output of this step")

    tool: str | None = Field(
        default=None,
        description="Optional: tool or system used for this step",
    )

    status: Literal["completed", "failed", "skipped"] = Field(
        default="completed",
        description="Status of this investigation step",
    )

    @field_validator("action", "result")
    @classmethod
    def not_empty(cls, v: str) -> str:
        """Ensure action and result are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


# =============================================================================
# Indicator Models
# =============================================================================


class Indicator(BaseModel):
    """Security indicator extracted during triage analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    type: Literal["ip", "domain", "url", "hash", "email", "file", "registry", "process", "other"]
    value: str
    verdict: str = Field(
        description="Assessment of the indicator (e.g., 'malicious', 'suspicious', 'benign')"
    )
    context: str | None = Field(
        default=None,
        description="Additional context about this indicator",
    )

    @field_validator("value")
    @classmethod
    def value_not_empty(cls, v: str) -> str:
        """Ensure indicator value is not empty."""
        if not v or not v.strip():
            raise ValueError("Indicator value cannot be empty")
        return v.strip()


class MITRETechnique(BaseModel):
    """MITRE ATT&CK technique mapping."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(
        description="MITRE technique ID (e.g., T1566.001)",
        examples=["T1566", "T1566.001"],
    )
    name: str = Field(description="Technique name")
    tactic: str = Field(description="Associated tactic (e.g., 'Initial Access')")
    relevance: str = Field(description="How this technique relates to the incident")

    @field_validator("id")
    @classmethod
    def validate_mitre_id(cls, v: str) -> str:
        """Validate MITRE technique ID format (T####.### or T####)."""
        # Pattern: T followed by 4 digits, optionally followed by .### (1-3 digits)
        pattern = r"^T\d{4}(\.\d{1,3})?$"
        if not re.match(pattern, v):
            raise ValueError(
                f"Invalid MITRE technique ID format: '{v}'. "
                "Expected format: T#### or T####.### (e.g., T1566 or T1566.001)"
            )
        return v

    @field_validator("name", "tactic")
    @classmethod
    def not_empty(cls, v: str) -> str:
        """Ensure name and tactic are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class RecommendedAction(BaseModel):
    """Recommended response action from triage analysis."""

    model_config = ConfigDict(str_strip_whitespace=True)

    action: str = Field(description="Description of the recommended action")
    priority: Literal["immediate", "high", "medium", "low"] = Field(
        description="Priority level for this action"
    )
    reason: str = Field(description="Justification for this recommendation")
    requires_approval: bool = Field(
        default=False,
        description="Whether this action requires human approval before execution",
    )

    @field_validator("action", "reason")
    @classmethod
    def not_empty(cls, v: str) -> str:
        """Ensure action and reason are not empty."""
        if not v or not v.strip():
            raise ValueError("Field cannot be empty")
        return v.strip()


class TriageAnalysis(BaseModel):
    """Complete triage analysis result from the AI agent.

    This model now includes evidence and investigation_steps fields
    (Stage 2.1.2) for audit-ready investigation reports.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    verdict: Literal["true_positive", "false_positive", "suspicious", "inconclusive"] = Field(
        description="Overall assessment of the alert/incident"
    )
    confidence: int = Field(
        ge=0,
        le=100,
        description="Confidence score from 0-100",
    )
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(
        description="Severity level of the incident"
    )
    summary: str = Field(description="Brief summary of the analysis findings")
    indicators: list[Indicator] = Field(
        default_factory=list,
        description="List of indicators of compromise (IOCs) identified",
    )
    mitre_techniques: list[MITRETechnique] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques",
    )
    recommended_actions: list[RecommendedAction] = Field(
        default_factory=list,
        description="Recommended response actions",
    )
    reasoning: str = Field(
        default="",
        description="Detailed reasoning behind the analysis",
    )

    # Stage 2.1.2: Evidence collection fields
    evidence: list[EvidenceItem] = Field(
        default_factory=list,
        description="List of evidence items supporting the analysis verdict",
    )
    investigation_steps: list[InvestigationStep] = Field(
        default_factory=list,
        description="Ordered list of investigation steps taken during analysis",
    )

    # Stage 2.3.4: RAG context and citations
    rag_context_used: bool = Field(
        default=False,
        description="Whether RAG context was used in this analysis",
    )
    rag_citations: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Citations to RAG documents used in analysis",
    )

    @field_validator("summary")
    @classmethod
    def summary_not_empty(cls, v: str) -> str:
        """Ensure summary is not empty."""
        if not v or not v.strip():
            raise ValueError("Summary cannot be empty")
        return v.strip()

    @model_validator(mode="after")
    def validate_severity_confidence_consistency(self) -> TriageAnalysis:
        """Warn if confidence is low but severity is critical (non-blocking)."""
        # This is informational - we don't raise an error but could log
        # The model is still valid but the combination may warrant review
        return self

    def get_evidence_summary(self) -> dict[str, Any]:
        """Get a summary of evidence collected during analysis.

        Returns:
            Dictionary with evidence statistics and breakdown.
        """
        if not self.evidence:
            return {
                "total_evidence": 0,
                "avg_confidence": 0.0,
                "sources": [],
                "data_types": [],
            }

        sources = list({e.source_name for e in self.evidence})
        data_types = list({e.data_type for e in self.evidence})
        avg_confidence = sum(e.confidence for e in self.evidence) / len(self.evidence)

        return {
            "total_evidence": len(self.evidence),
            "avg_confidence": round(avg_confidence, 1),
            "sources": sources,
            "data_types": data_types,
            "high_confidence_count": sum(1 for e in self.evidence if e.confidence >= 80),
            "medium_confidence_count": sum(1 for e in self.evidence if 50 <= e.confidence < 80),
            "low_confidence_count": sum(1 for e in self.evidence if e.confidence < 50),
        }

    def has_sufficient_evidence(self, min_items: int = 3, min_avg_confidence: float = 50.0) -> bool:
        """Check if analysis has sufficient evidence for the verdict.

        Args:
            min_items: Minimum number of evidence items required.
            min_avg_confidence: Minimum average confidence score required.

        Returns:
            True if evidence requirements are met.
        """
        if len(self.evidence) < min_items:
            return False

        if not self.evidence:
            return False

        avg_confidence = sum(e.confidence for e in self.evidence) / len(self.evidence)
        return avg_confidence >= min_avg_confidence
