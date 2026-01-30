"""Pydantic v2 models for triage analysis output parsing."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    """Complete triage analysis result from the AI agent."""

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
