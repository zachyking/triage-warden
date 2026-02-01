"""Data models for RAG documents and queries.

Defines Pydantic models for:
- Document types: incidents, playbooks, MITRE techniques, threat intel
- Query request and response structures
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# =============================================================================
# Document Models
# =============================================================================


class BaseDocument(BaseModel):
    """Base class for all RAG documents."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(description="Unique document identifier")
    content: str = Field(description="Text content for embedding")
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when document was created",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert document fields to ChromaDB metadata.

        Returns:
            Dictionary of metadata fields for storage.
        """
        # Subclasses override to add specific metadata
        return {
            "created_at": self.created_at.isoformat(),
        }


class IncidentDocument(BaseDocument):
    """Document representing a historical triage incident."""

    verdict: Literal["true_positive", "false_positive", "suspicious", "inconclusive"]
    severity: Literal["critical", "high", "medium", "low", "informational"]
    confidence: int = Field(ge=0, le=100)
    alert_type: str = Field(description="Type of alert (phishing, malware, etc.)")
    alert_id: str = Field(description="Original alert identifier")

    # Optional enrichment
    technique_ids: list[str] = Field(
        default_factory=list,
        description="MITRE technique IDs identified",
    )
    indicator_count: int = Field(
        default=0,
        description="Number of indicators extracted",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert to ChromaDB metadata."""
        metadata = super().to_metadata()
        metadata.update(
            {
                "verdict": self.verdict,
                "severity": self.severity,
                "confidence": self.confidence,
                "alert_type": self.alert_type,
                "alert_id": self.alert_id,
                "technique_ids": ",".join(self.technique_ids) if self.technique_ids else "",
                "indicator_count": self.indicator_count,
            }
        )
        return metadata


class PlaybookDocument(BaseDocument):
    """Document representing a security playbook/runbook."""

    name: str = Field(description="Playbook name")
    version: str = Field(default="1.0", description="Playbook version")
    trigger_types: list[str] = Field(
        default_factory=list,
        description="Alert types that trigger this playbook",
    )
    stage_count: int = Field(
        default=0,
        description="Number of stages in the playbook",
    )
    has_branches: bool = Field(
        default=False,
        description="Whether playbook has conditional branches",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert to ChromaDB metadata."""
        metadata = super().to_metadata()
        metadata.update(
            {
                "name": self.name,
                "version": self.version,
                "trigger_types": ",".join(self.trigger_types) if self.trigger_types else "",
                "stage_count": self.stage_count,
                "has_branches": self.has_branches,
            }
        )
        return metadata


class MITREDocument(BaseDocument):
    """Document representing a MITRE ATT&CK technique."""

    technique_id: str = Field(description="MITRE technique ID (e.g., T1566)")
    name: str = Field(description="Technique name")
    tactic: str = Field(description="MITRE tactic (e.g., Initial Access)")
    is_subtechnique: bool = Field(
        default=False,
        description="Whether this is a sub-technique",
    )
    parent_technique_id: str | None = Field(
        default=None,
        description="Parent technique ID if sub-technique",
    )
    keywords: list[str] = Field(
        default_factory=list,
        description="Keywords for matching",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert to ChromaDB metadata."""
        metadata = super().to_metadata()
        metadata.update(
            {
                "technique_id": self.technique_id,
                "name": self.name,
                "tactic": self.tactic,
                "is_subtechnique": self.is_subtechnique,
                "parent_technique_id": self.parent_technique_id or "",
                "keywords": ",".join(self.keywords) if self.keywords else "",
            }
        )
        return metadata


class ThreatIntelDocument(BaseDocument):
    """Document representing a threat intelligence indicator."""

    indicator: str = Field(description="The indicator value")
    indicator_type: Literal["ip", "domain", "url", "hash", "email", "other"] = Field(
        description="Type of indicator"
    )
    verdict: Literal["malicious", "suspicious", "benign", "unknown"] = Field(
        description="Threat verdict"
    )
    threat_actor: str | None = Field(
        default=None,
        description="Associated threat actor if known",
    )
    confidence: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Confidence in the verdict",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert to ChromaDB metadata."""
        metadata = super().to_metadata()
        metadata.update(
            {
                "indicator": self.indicator,
                "indicator_type": self.indicator_type,
                "verdict": self.verdict,
                "threat_actor": self.threat_actor or "",
                "confidence": self.confidence,
            }
        )
        return metadata


# =============================================================================
# Query Models
# =============================================================================


class QueryRequest(BaseModel):
    """Request for a RAG query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(description="Natural language query text")
    collection: str = Field(description="Collection to search")
    top_k: int = Field(default=5, ge=1, le=100, description="Number of results")
    min_similarity: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Minimum similarity threshold",
    )
    filters: dict[str, Any] = Field(
        default_factory=dict,
        description="Metadata filters for the query",
    )


class QueryResult(BaseModel):
    """A single result from a RAG query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(description="Document ID")
    content: str = Field(description="Document content")
    similarity: float = Field(
        ge=0.0,
        le=1.0,
        description="Similarity score (0-1, higher is better)",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Document metadata",
    )


class QueryResponse(BaseModel):
    """Response from a RAG query."""

    model_config = ConfigDict(str_strip_whitespace=True)

    query: str = Field(description="Original query text")
    collection: str = Field(description="Collection searched")
    results: list[QueryResult] = Field(
        default_factory=list,
        description="Matching documents",
    )
    total_results: int = Field(
        default=0,
        description="Total number of results before filtering",
    )
    execution_time_ms: int = Field(
        default=0,
        description="Query execution time in milliseconds",
    )
