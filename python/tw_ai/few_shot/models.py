"""Data models for few-shot examples (Stage 2.4.2).

Defines Pydantic models for:
- Few-shot examples with quality metadata
- Example documents for vector store storage
- Example sets for prompt construction
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class ExampleQuality(str, Enum):
    """Quality tier for few-shot examples.

    Examples are curated and assigned quality tiers based on:
    - Accuracy of verdict and confidence
    - Completeness of evidence and reasoning
    - Clarity of the analysis explanation
    - Diversity in the example set (covers edge cases)
    """

    HIGH = "high"  # Analyst-verified, exemplary quality
    MEDIUM = "medium"  # Good quality, may have minor issues
    LOW = "low"  # Usable but not ideal, needs review


class ExampleMetadata(BaseModel):
    """Metadata for a few-shot example.

    Captures attributes used for filtering and selection.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    # Quality and curation
    quality: ExampleQuality = Field(
        default=ExampleQuality.MEDIUM,
        description="Quality tier of the example",
    )
    labeled: bool = Field(
        default=True,
        description="Whether example has been human-labeled/verified",
    )
    curator: str | None = Field(
        default=None,
        description="Username of analyst who curated this example",
    )
    curated_at: datetime | None = Field(
        default=None,
        description="When the example was curated",
    )

    # Alert classification
    alert_type: str = Field(
        description="Type of alert (phishing, malware, suspicious_login, etc.)",
    )
    verdict: Literal["malicious", "benign", "suspicious", "inconclusive"] = Field(
        description="Ground truth verdict for the example",
    )
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(
        description="Severity level of the example",
    )
    confidence_range: tuple[int, int] = Field(
        default=(0, 100),
        description="Confidence range this example represents (min, max)",
    )

    # MITRE mapping
    technique_ids: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs demonstrated",
    )

    # Usage tracking
    usage_count: int = Field(
        default=0,
        description="Number of times this example has been selected",
    )
    last_used_at: datetime | None = Field(
        default=None,
        description="When the example was last used",
    )

    # Feedback
    positive_feedback: int = Field(
        default=0,
        description="Analyst upvotes for this example",
    )
    negative_feedback: int = Field(
        default=0,
        description="Analyst downvotes for this example",
    )


class Example(BaseModel):
    """A single few-shot example for security triage.

    Contains the alert context, analysis output, and metadata
    used for similarity-based retrieval.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(description="Unique example identifier")

    # Content
    alert_context: str = Field(
        description="The alert data/context presented to the model",
    )
    analysis_output: str = Field(
        description="The JSON output that the model should produce",
    )
    reasoning_explanation: str = Field(
        description="Human-readable explanation of why this analysis is correct",
    )

    # Embedding source (what gets embedded for similarity search)
    embedding_text: str = Field(
        description="Text used for computing embeddings (typically alert_context + key features)",
    )

    # Metadata for filtering
    metadata: ExampleMetadata = Field(
        description="Example metadata for filtering and quality control",
    )

    # Source tracking
    source_incident_id: str | None = Field(
        default=None,
        description="ID of original incident if derived from real data",
    )
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="When the example was created",
    )


class ExampleDocument(BaseModel):
    """Document model for storing examples in vector store.

    Mirrors the RAG document pattern for consistency with existing
    vector store infrastructure.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    id: str = Field(description="Unique document identifier")
    content: str = Field(description="Text content for embedding (embedding_text)")
    created_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="Timestamp when document was created",
    )

    # Example-specific fields
    alert_context: str = Field(description="Alert context for the example")
    analysis_output: str = Field(description="Expected analysis JSON output")
    reasoning_explanation: str = Field(description="Explanation of the analysis")

    # Metadata (flattened for ChromaDB compatibility)
    quality: str = Field(description="Quality tier (high/medium/low)")
    labeled: bool = Field(description="Whether example is labeled")
    alert_type: str = Field(description="Alert type")
    verdict: str = Field(description="Verdict")
    severity: str = Field(description="Severity level")
    confidence_min: int = Field(description="Min confidence range")
    confidence_max: int = Field(description="Max confidence range")
    technique_ids: str = Field(
        default="",
        description="Comma-separated MITRE technique IDs",
    )

    def to_metadata(self) -> dict[str, Any]:
        """Convert to ChromaDB metadata format.

        Returns:
            Dictionary of metadata fields for storage.
        """
        return {
            "created_at": self.created_at.isoformat(),
            "quality": self.quality,
            "labeled": self.labeled,
            "alert_type": self.alert_type,
            "verdict": self.verdict,
            "severity": self.severity,
            "confidence_min": self.confidence_min,
            "confidence_max": self.confidence_max,
            "technique_ids": self.technique_ids,
            # Store full content as metadata for retrieval
            "alert_context": self.alert_context[:2000],  # Truncate for metadata limits
            "analysis_output": self.analysis_output[:4000],
            "reasoning_explanation": self.reasoning_explanation[:1000],
        }

    @classmethod
    def from_example(cls, example: Example) -> ExampleDocument:
        """Create a document from an Example model.

        Args:
            example: The example to convert.

        Returns:
            ExampleDocument ready for vector store insertion.
        """
        return cls(
            id=example.id,
            content=example.embedding_text,
            created_at=example.created_at,
            alert_context=example.alert_context,
            analysis_output=example.analysis_output,
            reasoning_explanation=example.reasoning_explanation,
            quality=example.metadata.quality.value,
            labeled=example.metadata.labeled,
            alert_type=example.metadata.alert_type,
            verdict=example.metadata.verdict,
            severity=example.metadata.severity,
            confidence_min=example.metadata.confidence_range[0],
            confidence_max=example.metadata.confidence_range[1],
            technique_ids=",".join(example.metadata.technique_ids),
        )


class ExampleSet(BaseModel):
    """A set of examples selected for a prompt.

    Contains the examples along with selection metadata
    for tracking and analysis.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    examples: list[Example] = Field(
        default_factory=list,
        description="Selected examples in order of relevance",
    )
    selection_method: Literal["similarity", "random", "static", "hybrid"] = Field(
        default="similarity",
        description="Method used to select examples",
    )
    query_text: str = Field(
        description="Query text used for similarity search",
    )
    execution_time_ms: int = Field(
        default=0,
        description="Time taken to select examples in milliseconds",
    )

    @property
    def count(self) -> int:
        """Number of examples in the set."""
        return len(self.examples)

    @property
    def alert_types(self) -> set[str]:
        """Unique alert types in the example set."""
        return {ex.metadata.alert_type for ex in self.examples}

    @property
    def verdicts(self) -> set[str]:
        """Unique verdicts in the example set."""
        return {ex.metadata.verdict for ex in self.examples}


class FormattedExamples(BaseModel):
    """Formatted examples ready for prompt injection.

    Contains the markdown-formatted example text along with
    metadata about what examples were included.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    formatted_text: str = Field(
        description="Markdown-formatted examples for prompt",
    )
    example_count: int = Field(
        description="Number of examples included",
    )
    example_ids: list[str] = Field(
        default_factory=list,
        description="IDs of examples included for tracking",
    )
    total_tokens_estimate: int = Field(
        default=0,
        description="Estimated token count for the formatted text",
    )
    alert_types_covered: list[str] = Field(
        default_factory=list,
        description="Alert types represented in examples",
    )
    verdicts_covered: list[str] = Field(
        default_factory=list,
        description="Verdicts represented in examples",
    )
