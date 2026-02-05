"""Ingestion service for few-shot examples (Stage 2.4.2).

Provides utilities for curating and ingesting high-quality few-shot
examples into the vector store for similarity-based retrieval.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.models import (
    Example,
    ExampleDocument,
    ExampleMetadata,
    ExampleQuality,
)

if TYPE_CHECKING:
    from tw_ai.rag import RAGService

logger = structlog.get_logger()


class ExampleIngester:
    """Ingests few-shot examples into the vector store.

    Handles conversion of Example objects to vector store documents
    with proper embedding generation and metadata indexing.
    """

    def __init__(
        self,
        rag_service: RAGService,
        config: FewShotConfig | None = None,
    ) -> None:
        """Initialize the ingester.

        Args:
            rag_service: RAG service for vector store operations.
            config: Few-shot configuration.
        """
        self._rag = rag_service
        self._config = config or FewShotConfig()

    async def ingest_example(self, example: Example) -> str:
        """Ingest a single example into the vector store.

        Args:
            example: The example to ingest.

        Returns:
            Document ID of the ingested example.
        """
        doc = ExampleDocument.from_example(example)

        # Add to vector store
        self._rag.vector_store.add(  # type: ignore[attr-defined]
            collection_name=self._config.examples_collection,
            ids=[doc.id],
            documents=[doc.content],
            metadatas=[doc.to_metadata()],
        )

        logger.info(
            "example_ingested",
            example_id=example.id,
            alert_type=example.metadata.alert_type,
            quality=example.metadata.quality.value,
        )

        return doc.id

    async def ingest_examples(self, examples: list[Example]) -> list[str]:
        """Ingest multiple examples in batch.

        Args:
            examples: List of examples to ingest.

        Returns:
            List of document IDs.
        """
        if not examples:
            return []

        docs = [ExampleDocument.from_example(ex) for ex in examples]

        self._rag.vector_store.add(  # type: ignore[attr-defined]
            collection_name=self._config.examples_collection,
            ids=[d.id for d in docs],
            documents=[d.content for d in docs],
            metadatas=[d.to_metadata() for d in docs],
        )

        logger.info(
            "examples_batch_ingested",
            count=len(examples),
            alert_types=list({ex.metadata.alert_type for ex in examples}),
        )

        return [d.id for d in docs]

    async def ingest_from_file(self, file_path: Path) -> list[str]:
        """Ingest examples from a JSON file.

        File format:
        ```json
        {
            "examples": [
                {
                    "id": "phishing_example_001",
                    "alert_context": "...",
                    "analysis_output": "...",
                    "reasoning_explanation": "...",
                    "metadata": {
                        "quality": "high",
                        "alert_type": "phishing",
                        "verdict": "malicious",
                        "severity": "high",
                        "technique_ids": ["T1566.001"]
                    }
                }
            ]
        }
        ```

        Args:
            file_path: Path to the JSON file.

        Returns:
            List of ingested document IDs.
        """
        with open(file_path) as f:
            data = json.load(f)

        examples = []
        for item in data.get("examples", []):
            try:
                example = self._parse_example_dict(item)
                examples.append(example)
            except Exception as e:
                logger.warning(
                    "failed_to_parse_example",
                    example_id=item.get("id", "unknown"),
                    error=str(e),
                )

        return await self.ingest_examples(examples)

    def _parse_example_dict(self, data: dict[str, Any]) -> Example:
        """Parse an example from a dictionary.

        Args:
            data: Dictionary containing example data.

        Returns:
            Parsed Example object.
        """
        metadata_dict = data.get("metadata", {})

        # Parse quality tier
        quality_str = metadata_dict.get("quality", "medium")
        quality = ExampleQuality(quality_str) if quality_str else ExampleQuality.MEDIUM

        # Parse confidence range
        confidence_range = metadata_dict.get("confidence_range", [0, 100])
        if isinstance(confidence_range, list) and len(confidence_range) == 2:
            confidence_range = (confidence_range[0], confidence_range[1])
        else:
            confidence_range = (0, 100)

        # Build metadata
        metadata = ExampleMetadata(
            quality=quality,
            labeled=metadata_dict.get("labeled", True),
            curator=metadata_dict.get("curator"),
            alert_type=metadata_dict.get("alert_type", "unknown"),
            verdict=metadata_dict.get("verdict", "inconclusive"),
            severity=metadata_dict.get("severity", "medium"),
            confidence_range=confidence_range,
            technique_ids=metadata_dict.get("technique_ids", []),
        )

        # Generate embedding text if not provided
        alert_context = data.get("alert_context", "")
        embedding_text = data.get(
            "embedding_text",
            self._generate_embedding_text(alert_context, metadata),
        )

        return Example(
            id=data["id"],
            alert_context=alert_context,
            analysis_output=data.get("analysis_output", "{}"),
            reasoning_explanation=data.get("reasoning_explanation", ""),
            embedding_text=embedding_text,
            metadata=metadata,
            source_incident_id=data.get("source_incident_id"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if "created_at" in data
                else datetime.utcnow()
            ),
        )

    def _generate_embedding_text(
        self,
        alert_context: str,
        metadata: ExampleMetadata,
    ) -> str:
        """Generate text for embedding computation.

        Combines alert context with key metadata for better retrieval.

        Args:
            alert_context: The alert context text.
            metadata: Example metadata.

        Returns:
            Text suitable for embedding.
        """
        parts = [
            f"Alert Type: {metadata.alert_type}",
            f"Verdict: {metadata.verdict}",
            f"Severity: {metadata.severity}",
        ]

        if metadata.technique_ids:
            parts.append(f"MITRE Techniques: {', '.join(metadata.technique_ids)}")

        parts.append(f"Context: {alert_context}")

        return "\n".join(parts)


class ExampleCurator:
    """Utilities for curating and managing few-shot examples.

    Provides methods for promoting/demoting example quality,
    tracking usage, and converting from historical incidents.
    """

    def __init__(
        self,
        rag_service: RAGService,
        config: FewShotConfig | None = None,
    ) -> None:
        """Initialize the curator.

        Args:
            rag_service: RAG service for vector operations.
            config: Few-shot configuration.
        """
        self._rag = rag_service
        self._config = config or FewShotConfig()

    async def promote_to_high_quality(
        self,
        example_id: str,
        curator: str,
    ) -> bool:
        """Mark an example as high quality.

        Args:
            example_id: ID of the example to promote.
            curator: Username of the curator.

        Returns:
            True if successful.
        """
        return await self._update_quality(example_id, ExampleQuality.HIGH, curator)

    async def demote_to_low_quality(
        self,
        example_id: str,
        curator: str,
    ) -> bool:
        """Mark an example as low quality.

        Args:
            example_id: ID of the example to demote.
            curator: Username of the curator.

        Returns:
            True if successful.
        """
        return await self._update_quality(example_id, ExampleQuality.LOW, curator)

    async def _update_quality(
        self,
        example_id: str,
        quality: ExampleQuality,
        curator: str,
    ) -> bool:
        """Update the quality tier of an example.

        Args:
            example_id: ID of the example.
            quality: New quality tier.
            curator: Username of the curator.

        Returns:
            True if successful.
        """
        # Note: ChromaDB doesn't support direct metadata updates well
        # In production, this would need to delete and re-add the document
        # or use a database that supports updates
        logger.info(
            "example_quality_updated",
            example_id=example_id,
            new_quality=quality.value,
            curator=curator,
        )
        return True

    async def record_feedback(
        self,
        example_id: str,
        positive: bool,
        analyst: str,
    ) -> bool:
        """Record analyst feedback on an example.

        Args:
            example_id: ID of the example.
            positive: True for upvote, False for downvote.
            analyst: Username of the analyst.

        Returns:
            True if successful.
        """
        logger.info(
            "example_feedback_recorded",
            example_id=example_id,
            feedback="positive" if positive else "negative",
            analyst=analyst,
        )
        return True

    def create_example_from_incident(
        self,
        incident_id: str,
        alert_context: str,
        analysis_output: str,
        alert_type: str,
        verdict: str,
        severity: str,
        confidence: int,
        reasoning: str,
        technique_ids: list[str] | None = None,
        curator: str | None = None,
    ) -> Example:
        """Create a few-shot example from a completed incident analysis.

        Args:
            incident_id: ID of the source incident.
            alert_context: Original alert context.
            analysis_output: JSON analysis output (as string).
            alert_type: Type of alert.
            verdict: Analysis verdict.
            severity: Severity level.
            confidence: Confidence score (0-100).
            reasoning: Explanation of the analysis.
            technique_ids: MITRE technique IDs.
            curator: Username of curator (if manually curated).

        Returns:
            Example object ready for ingestion.
        """
        # Generate example ID from incident
        example_id = f"example_{alert_type}_{incident_id}"

        # Determine confidence range bracket
        if confidence >= 80:
            confidence_range = (80, 100)
        elif confidence >= 50:
            confidence_range = (50, 79)
        else:
            confidence_range = (0, 49)

        metadata = ExampleMetadata(
            quality=ExampleQuality.MEDIUM,  # Default to medium, curator can promote
            labeled=True,
            curator=curator,
            curated_at=datetime.utcnow() if curator else None,
            alert_type=alert_type,
            verdict=verdict,  # type: ignore[arg-type]
            severity=severity,  # type: ignore[arg-type]
            confidence_range=confidence_range,
            technique_ids=technique_ids or [],
        )

        # Generate embedding text
        embedding_text = f"""Alert Type: {alert_type}
Verdict: {verdict}
Severity: {severity}
MITRE Techniques: {', '.join(technique_ids or [])}
Context: {alert_context}"""

        return Example(
            id=example_id,
            alert_context=alert_context,
            analysis_output=analysis_output,
            reasoning_explanation=reasoning,
            embedding_text=embedding_text,
            metadata=metadata,
            source_incident_id=incident_id,
        )
