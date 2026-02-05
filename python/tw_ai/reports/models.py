"""Data models for investigation reports.

This module defines the structured output format for investigation reports
that can be exported to JSON, HTML, or PDF formats.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ReportFormat(str, Enum):
    """Supported report export formats."""

    JSON = "json"
    HTML = "html"
    PDF = "pdf"


class ReportMetadata(BaseModel):
    """Metadata about the generated report."""

    model_config = ConfigDict(str_strip_whitespace=True)

    incident_id: str = Field(description="UUID of the incident")
    generated_at: datetime = Field(description="When the report was generated")
    generated_by: str = Field(
        default="Triage Warden",
        description="System or analyst that generated the report",
    )
    report_version: str = Field(
        default="1.0",
        description="Version of the report format",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Tenant ID for multi-tenant deployments",
    )


class TimelineEntry(BaseModel):
    """A single entry in the investigation timeline."""

    model_config = ConfigDict(str_strip_whitespace=True)

    order: int = Field(description="Step order in the timeline")
    timestamp: datetime | None = Field(
        default=None,
        description="When this step occurred",
    )
    action: str = Field(description="Description of the action taken")
    result: str = Field(description="Result or output of this step")
    tool: str | None = Field(
        default=None,
        description="Tool or system used for this step",
    )
    status: Literal["completed", "failed", "skipped"] = Field(
        default="completed",
        description="Status of this step",
    )
    duration_ms: int | None = Field(
        default=None,
        description="Duration of this step in milliseconds",
    )


class FormattedEvidence(BaseModel):
    """Evidence formatted for report display."""

    model_config = ConfigDict(str_strip_whitespace=True)

    order: int = Field(description="Display order in the evidence table")
    source_type: str = Field(description="Category of evidence source")
    source_name: str = Field(description="Specific source name")
    data_type: str = Field(description="Type of evidence data")
    finding: str = Field(description="What this evidence shows")
    relevance: str = Field(description="How it supports the verdict")
    confidence: int = Field(description="Confidence score (0-100)")
    link: str | None = Field(
        default=None,
        description="Deep link to view in source system",
    )
    raw_value: dict[str, Any] = Field(
        default_factory=dict,
        description="Original evidence data",
    )


class FormattedMitreTechnique(BaseModel):
    """MITRE ATT&CK technique formatted for report display."""

    model_config = ConfigDict(str_strip_whitespace=True)

    technique_id: str = Field(description="MITRE technique ID (e.g., T1566.001)")
    name: str = Field(description="Technique name")
    tactic: str = Field(description="Associated tactic (e.g., Initial Access)")
    relevance: str = Field(description="How this technique relates to the incident")
    url: str = Field(
        default="",
        description="URL to MITRE ATT&CK page for this technique",
    )


class FormattedIndicator(BaseModel):
    """Indicator of Compromise formatted for report display."""

    model_config = ConfigDict(str_strip_whitespace=True)

    indicator_type: str = Field(description="Type of indicator (ip, domain, hash, etc.)")
    value: str = Field(description="The indicator value")
    verdict: str = Field(description="Assessment (malicious, suspicious, benign)")
    context: str | None = Field(
        default=None,
        description="Additional context about this indicator",
    )


class FormattedAction(BaseModel):
    """Recommended action formatted for report display."""

    model_config = ConfigDict(str_strip_whitespace=True)

    order: int = Field(description="Priority order (1 = highest priority)")
    action: str = Field(description="Description of the recommended action")
    priority: Literal["immediate", "high", "medium", "low"] = Field(description="Priority level")
    reason: str = Field(description="Justification for this recommendation")
    requires_approval: bool = Field(
        default=False,
        description="Whether human approval is required",
    )


class EvidenceSummary(BaseModel):
    """Summary statistics about collected evidence."""

    model_config = ConfigDict(str_strip_whitespace=True)

    total_evidence: int = Field(description="Total number of evidence items")
    average_confidence: float = Field(description="Average confidence score")
    high_confidence_count: int = Field(description="Number of high-confidence items (>=80)")
    medium_confidence_count: int = Field(description="Number of medium-confidence items (50-79)")
    low_confidence_count: int = Field(description="Number of low-confidence items (<50)")
    sources_used: list[str] = Field(
        default_factory=list,
        description="Unique source names that provided evidence",
    )
    data_types_found: list[str] = Field(
        default_factory=list,
        description="Unique data types in the evidence",
    )


class VerdictSummary(BaseModel):
    """Summary of the triage verdict and confidence."""

    model_config = ConfigDict(str_strip_whitespace=True)

    verdict: str = Field(
        description="Verdict (true_positive, false_positive, suspicious, inconclusive)"
    )
    verdict_display: str = Field(description="Human-readable verdict label")
    confidence: int = Field(description="Confidence score (0-100)")
    calibrated_confidence: int | None = Field(
        default=None,
        description="Calibrated confidence if available",
    )
    severity: str = Field(description="Severity level (critical, high, medium, low, informational)")
    severity_display: str = Field(description="Human-readable severity label")
    risk_score: int | None = Field(
        default=None,
        description="Risk score (0-100) if available",
    )


class AlertSummary(BaseModel):
    """Summary of the original alert."""

    model_config = ConfigDict(str_strip_whitespace=True)

    alert_id: str = Field(description="Original alert ID from source system")
    source: str = Field(description="Alert source system")
    alert_type: str | None = Field(
        default=None,
        description="Type/category of the alert",
    )
    title: str | None = Field(
        default=None,
        description="Alert title",
    )
    created_at: datetime | None = Field(
        default=None,
        description="When the incident was created",
    )


class AuditLogEntry(BaseModel):
    """Formatted audit log entry for the report appendix."""

    model_config = ConfigDict(str_strip_whitespace=True)

    timestamp: datetime = Field(description="When the action occurred")
    action: str = Field(description="Action that was performed")
    actor: str = Field(description="Who performed the action")
    details: str | None = Field(
        default=None,
        description="Additional details about the action",
    )


class InvestigationReport(BaseModel):
    """Complete investigation report model.

    This model represents a fully-formed investigation report that can be
    exported to JSON, HTML, or PDF format. It contains all the information
    needed to render a comprehensive audit-ready document.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    # Metadata
    metadata: ReportMetadata = Field(description="Report metadata")

    # Executive Summary Section
    executive_summary: str = Field(description="2-3 sentence overview of findings")
    verdict: VerdictSummary = Field(description="Verdict and confidence details")
    alert: AlertSummary = Field(description="Original alert summary")

    # Investigation Timeline Section
    timeline: list[TimelineEntry] = Field(
        default_factory=list,
        description="Chronological investigation steps",
    )

    # Evidence Section
    evidence: list[FormattedEvidence] = Field(
        default_factory=list,
        description="All evidence items supporting the verdict",
    )
    evidence_summary: EvidenceSummary = Field(
        description="Summary statistics about evidence",
    )

    # MITRE ATT&CK Section
    mitre_techniques: list[FormattedMitreTechnique] = Field(
        default_factory=list,
        description="Mapped MITRE ATT&CK techniques",
    )

    # Indicators of Compromise Section
    indicators: list[FormattedIndicator] = Field(
        default_factory=list,
        description="Extracted IOCs",
    )

    # Recommendations Section
    recommended_actions: list[FormattedAction] = Field(
        default_factory=list,
        description="Ordered recommended response actions",
    )

    # Detailed Analysis Section
    reasoning: str = Field(
        default="",
        description="Full chain-of-thought analysis reasoning",
    )

    # Appendix
    raw_alert_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Original raw alert data",
    )
    enrichments: list[dict[str, Any]] = Field(
        default_factory=list,
        description="All enrichment data gathered",
    )
    audit_log: list[AuditLogEntry] = Field(
        default_factory=list,
        description="Audit trail of actions taken",
    )

    def to_json(self) -> str:
        """Export report as JSON string."""
        return self.model_dump_json(indent=2)

    def to_dict(self) -> dict[str, Any]:
        """Export report as dictionary."""
        return self.model_dump()
