"""Configuration for few-shot example selection (Stage 2.4.2).

Provides settings for dynamic example selection including
collection names, selection parameters, and A/B testing.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class FewShotConfig(BaseModel):
    """Configuration for few-shot example selection."""

    model_config = ConfigDict(frozen=True)

    # Collection settings
    examples_collection: str = Field(
        default="few_shot_examples",
        description="ChromaDB collection for few-shot examples",
    )

    # Selection parameters
    default_k: int = Field(
        default=3,
        ge=1,
        le=10,
        description="Default number of examples to select",
    )
    min_similarity_threshold: float = Field(
        default=0.4,
        ge=0.0,
        le=1.0,
        description="Minimum similarity for example inclusion",
    )
    quality_filter: Literal["high", "medium", "all"] = Field(
        default="high",
        description="Minimum quality tier for examples",
    )
    require_labeled: bool = Field(
        default=True,
        description="Only select human-labeled examples",
    )

    # Diversity settings
    diversity_penalty: float = Field(
        default=0.1,
        ge=0.0,
        le=1.0,
        description="Penalty for selecting similar examples (MMR-style)",
    )
    require_verdict_diversity: bool = Field(
        default=True,
        description="Ensure examples cover different verdicts when possible",
    )

    # Token budget
    max_example_tokens: int = Field(
        default=3000,
        ge=500,
        le=10000,
        description="Maximum token budget for all examples",
    )
    tokens_per_char_estimate: float = Field(
        default=0.25,
        description="Estimated tokens per character for budget calculation",
    )

    # A/B testing configuration
    ab_test_enabled: bool = Field(
        default=False,
        description="Whether A/B testing between static and dynamic is enabled",
    )
    ab_test_dynamic_percentage: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
        description="Percentage of requests using dynamic selection",
    )

    # Fallback settings
    fallback_to_static: bool = Field(
        default=True,
        description="Fall back to static examples if vector search fails",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retries for vector store queries",
    )

    def get_quality_filters(self) -> dict[str, str] | None:
        """Get quality-based metadata filters for queries.

        Returns:
            Filter dict for ChromaDB or None if no filtering.
        """
        if self.quality_filter == "all":
            return None
        elif self.quality_filter == "high":
            return {"quality": "high"}
        else:  # medium
            # ChromaDB doesn't support OR easily, so filter post-query
            return None

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for text.

        Args:
            text: Text to estimate tokens for.

        Returns:
            Estimated token count.
        """
        return int(len(text) * self.tokens_per_char_estimate)
