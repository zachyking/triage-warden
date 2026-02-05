"""Few-shot example selector using vector similarity search (Stage 2.4.2).

Implements dynamic selection of few-shot examples based on semantic
similarity to the current incident, replacing static hardcoded examples.
"""

from __future__ import annotations

import hashlib
import random
import time
from typing import TYPE_CHECKING, Any

import structlog

from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.models import (
    Example,
    ExampleMetadata,
    ExampleQuality,
    ExampleSet,
    FormattedExamples,
)

if TYPE_CHECKING:
    from tw_ai.rag import RAGService

logger = structlog.get_logger()


class FewShotSelector:
    """Selects relevant few-shot examples using vector similarity search.

    This class implements the dynamic example selection pattern from Task 2.4.2,
    replacing static hardcoded examples with similarity-based retrieval from
    a curated example collection.

    Example usage:
        >>> selector = create_few_shot_selector(rag_service)
        >>> examples = await selector.select_examples(
        ...     incident_text="User received email from support@micros0ft.com",
        ...     alert_type="phishing",
        ...     k=3
        ... )
        >>> formatted = selector.format_for_prompt(examples)
    """

    def __init__(
        self,
        rag_service: RAGService,
        config: FewShotConfig | None = None,
    ) -> None:
        """Initialize the few-shot selector.

        Args:
            rag_service: RAG service for vector similarity search.
            config: Configuration for example selection.
        """
        self._rag = rag_service
        self._config = config or FewShotConfig()
        self._static_examples: dict[str, list[Example]] = {}

    def register_static_examples(
        self,
        alert_type: str,
        examples: list[Example],
    ) -> None:
        """Register static fallback examples for an alert type.

        Used when vector store is unavailable or for A/B testing baseline.

        Args:
            alert_type: Type of alert (phishing, malware, etc.)
            examples: List of static examples to register.
        """
        self._static_examples[alert_type] = examples
        logger.info(
            "registered_static_examples",
            alert_type=alert_type,
            count=len(examples),
        )

    async def select_examples(
        self,
        incident_text: str,
        alert_type: str | None = None,
        k: int | None = None,
        verdict_filter: str | None = None,
        technique_filter: list[str] | None = None,
    ) -> ExampleSet:
        """Select the most relevant examples for an incident.

        Uses vector similarity search to find examples that are semantically
        similar to the current incident. Applies quality and metadata filters
        to ensure only high-quality, relevant examples are selected.

        Args:
            incident_text: Description/context of the current incident.
            alert_type: Optional alert type filter (phishing, malware, etc.)
            k: Number of examples to select. Defaults to config.default_k.
            verdict_filter: Optional filter for specific verdict type.
            technique_filter: Optional filter for MITRE technique IDs.

        Returns:
            ExampleSet containing selected examples with metadata.
        """
        start_time = time.perf_counter()
        k = k or self._config.default_k

        # Check if A/B testing is enabled and should use static
        if self._should_use_static(incident_text):
            return self._select_static_examples(
                incident_text=incident_text,
                alert_type=alert_type,
                k=k,
            )

        try:
            # Build filters for vector search
            filters = self._build_filters(
                alert_type=alert_type,
                verdict_filter=verdict_filter,
                technique_filter=technique_filter,
            )

            # Fetch more candidates than needed for diversity selection
            fetch_k = min(k * 3, 15)

            # Execute vector similarity search
            response = self._rag.retrieval.search(
                query=incident_text,
                collection=self._config.examples_collection,
                top_k=fetch_k,
                min_similarity=self._config.min_similarity_threshold,
                filters=filters,
            )

            # Convert results to Example objects
            candidates = self._parse_query_results(response.results)

            # Apply diversity selection (MMR-style)
            selected = self._select_diverse(candidates, k)

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            logger.info(
                "examples_selected",
                query_length=len(incident_text),
                alert_type=alert_type,
                candidates_found=len(candidates),
                selected_count=len(selected),
                execution_time_ms=execution_time_ms,
            )

            return ExampleSet(
                examples=selected,
                selection_method="similarity",
                query_text=incident_text[:200],  # Truncate for logging
                execution_time_ms=execution_time_ms,
            )

        except Exception as e:
            logger.warning(
                "example_selection_failed",
                error=str(e),
                falling_back="static" if self._config.fallback_to_static else "empty",
            )

            if self._config.fallback_to_static:
                return self._select_static_examples(
                    incident_text=incident_text,
                    alert_type=alert_type,
                    k=k,
                )

            return ExampleSet(
                examples=[],
                selection_method="similarity",
                query_text=incident_text[:200],
                execution_time_ms=int((time.perf_counter() - start_time) * 1000),
            )

    def _should_use_static(self, incident_text: str) -> bool:
        """Determine if static examples should be used (for A/B testing).

        Uses consistent hashing so the same incident always gets the same
        treatment assignment.

        Args:
            incident_text: Incident text for consistent hashing.

        Returns:
            True if static examples should be used.
        """
        if not self._config.ab_test_enabled:
            return False

        # Hash the incident for consistent assignment
        hash_val = int(hashlib.md5(incident_text.encode()).hexdigest(), 16)
        use_dynamic = (hash_val % 100) < self._config.ab_test_dynamic_percentage

        return not use_dynamic

    def _select_static_examples(
        self,
        incident_text: str,
        alert_type: str | None,
        k: int,
    ) -> ExampleSet:
        """Select from static registered examples.

        Args:
            incident_text: Incident text for the query.
            alert_type: Optional alert type filter.
            k: Number of examples to select.

        Returns:
            ExampleSet with static examples.
        """
        if alert_type and alert_type in self._static_examples:
            pool = self._static_examples[alert_type]
        else:
            # Combine all static examples if no type specified
            pool = []
            for examples in self._static_examples.values():
                pool.extend(examples)

        # Select randomly if we have more than needed
        selected = random.sample(pool, min(k, len(pool))) if pool else []

        return ExampleSet(
            examples=selected,
            selection_method="static",
            query_text=incident_text[:200],
            execution_time_ms=0,
        )

    def _build_filters(
        self,
        alert_type: str | None,
        verdict_filter: str | None,
        technique_filter: list[str] | None,
    ) -> dict[str, Any] | None:
        """Build ChromaDB metadata filters.

        Args:
            alert_type: Optional alert type filter.
            verdict_filter: Optional verdict filter.
            technique_filter: Optional technique IDs filter.

        Returns:
            Filter dict for ChromaDB or None.
        """
        filters: dict[str, Any] = {}

        # Quality filter from config
        quality_filter = self._config.get_quality_filters()
        if quality_filter:
            filters.update(quality_filter)

        # Labeled filter
        if self._config.require_labeled:
            filters["labeled"] = True

        # Alert type filter
        if alert_type:
            filters["alert_type"] = alert_type

        # Verdict filter
        if verdict_filter:
            filters["verdict"] = verdict_filter

        # Note: technique_filter would require $contains which ChromaDB
        # doesn't handle well, so we filter post-query if needed

        return filters if filters else None

    def _parse_query_results(
        self,
        results: list[Any],
    ) -> list[Example]:
        """Parse vector store query results into Example objects.

        Args:
            results: QueryResult objects from vector store.

        Returns:
            List of Example objects.
        """
        examples = []

        for result in results:
            try:
                metadata = result.metadata or {}

                # Parse confidence range from metadata
                confidence_min = metadata.get("confidence_min", 0)
                confidence_max = metadata.get("confidence_max", 100)

                # Parse technique IDs
                technique_ids_str = metadata.get("technique_ids", "")
                technique_ids = (
                    [t.strip() for t in technique_ids_str.split(",") if t.strip()]
                    if technique_ids_str
                    else []
                )

                # Build Example from stored data
                example = Example(
                    id=result.id,
                    alert_context=metadata.get("alert_context", ""),
                    analysis_output=metadata.get("analysis_output", ""),
                    reasoning_explanation=metadata.get("reasoning_explanation", ""),
                    embedding_text=result.content,
                    metadata=ExampleMetadata(
                        quality=ExampleQuality(metadata.get("quality", "medium")),
                        labeled=metadata.get("labeled", True),
                        alert_type=metadata.get("alert_type", "unknown"),
                        verdict=metadata.get("verdict", "inconclusive"),
                        severity=metadata.get("severity", "medium"),
                        confidence_range=(confidence_min, confidence_max),
                        technique_ids=technique_ids,
                    ),
                )
                examples.append(example)

            except Exception as e:
                logger.warning(
                    "failed_to_parse_example",
                    result_id=result.id,
                    error=str(e),
                )
                continue

        return examples

    def _select_diverse(
        self,
        candidates: list[Example],
        k: int,
    ) -> list[Example]:
        """Select diverse examples using MMR-style selection.

        Balances relevance (similarity score) with diversity by penalizing
        examples that are too similar to already-selected ones.

        Args:
            candidates: Candidate examples sorted by similarity.
            k: Number of examples to select.

        Returns:
            List of diverse examples.
        """
        if len(candidates) <= k:
            return candidates

        if not self._config.require_verdict_diversity:
            # Simple top-k selection
            return candidates[:k]

        # Select diverse examples based on verdict coverage
        selected: list[Example] = []
        verdicts_seen: set[str] = set()

        # First pass: try to get one of each verdict
        for candidate in candidates:
            verdict = candidate.metadata.verdict
            if verdict not in verdicts_seen:
                selected.append(candidate)
                verdicts_seen.add(verdict)
                if len(selected) >= k:
                    break

        # Second pass: fill remaining with top-ranked
        if len(selected) < k:
            for candidate in candidates:
                if candidate not in selected:
                    selected.append(candidate)
                    if len(selected) >= k:
                        break

        return selected[:k]

    def format_for_prompt(
        self,
        example_set: ExampleSet,
        max_tokens: int | None = None,
    ) -> FormattedExamples:
        """Format selected examples for prompt injection.

        Creates markdown-formatted example text matching the existing
        prompt format used in phishing.py, malware.py, etc.

        Args:
            example_set: Set of selected examples.
            max_tokens: Maximum token budget. Defaults to config setting.

        Returns:
            FormattedExamples with markdown text.
        """
        max_tokens = max_tokens or self._config.max_example_tokens
        formatted_parts: list[str] = []
        example_ids: list[str] = []
        alert_types: set[str] = set()
        verdicts: set[str] = set()
        total_chars = 0
        char_budget = int(max_tokens / self._config.tokens_per_char_estimate)

        formatted_parts.append("## Example Analyses\n")

        for i, example in enumerate(example_set.examples):
            # Format single example
            example_text = self._format_single_example(example, i + 1)

            # Check if we're within budget
            if total_chars + len(example_text) > char_budget:
                logger.debug(
                    "example_truncated_for_budget",
                    example_id=example.id,
                    budget_remaining=char_budget - total_chars,
                    example_chars=len(example_text),
                )
                break

            formatted_parts.append(example_text)
            example_ids.append(example.id)
            alert_types.add(example.metadata.alert_type)
            verdicts.add(example.metadata.verdict)
            total_chars += len(example_text)

        formatted_text = "\n".join(formatted_parts)

        return FormattedExamples(
            formatted_text=formatted_text,
            example_count=len(example_ids),
            example_ids=example_ids,
            total_tokens_estimate=self._config.estimate_tokens(formatted_text),
            alert_types_covered=list(alert_types),
            verdicts_covered=list(verdicts),
        )

    def _format_single_example(self, example: Example, number: int) -> str:
        """Format a single example for prompt injection.

        Args:
            example: Example to format.
            number: Example number for display.

        Returns:
            Markdown-formatted example string.
        """
        verdict_display = example.metadata.verdict.replace("_", " ").title()
        severity = example.metadata.severity.title()

        return f"""### Example {number}: {verdict_display} ({severity} Severity)

**Alert Context**:
{example.alert_context}

**Analysis Output**:
```json
{example.analysis_output}
```

**Why This Analysis**:
{example.reasoning_explanation}
"""


def create_few_shot_selector(
    rag_service: RAGService,
    config: FewShotConfig | None = None,
) -> FewShotSelector:
    """Create a configured FewShotSelector instance.

    Factory function for creating selectors with proper configuration.

    Args:
        rag_service: RAG service for vector operations.
        config: Optional configuration. Uses defaults if not provided.

    Returns:
        Configured FewShotSelector instance.
    """
    return FewShotSelector(rag_service=rag_service, config=config)
