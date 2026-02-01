"""Threat intelligence ingester.

Ingests threat intelligence indicators for similarity search.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import TYPE_CHECKING, Any, Literal

import structlog

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import ThreatIntelDocument

if TYPE_CHECKING:
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()


class ThreatIntelIngester(BaseIngester):
    """Ingester for threat intelligence indicators.

    Ingests IOCs and threat context for semantic search.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize threat intel ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the threat intel collection name."""
        return self._vector_store._config.threat_intel_collection

    async def ingest(self) -> int:
        """Ingest threat intel - placeholder for batch ingestion.

        For individual indicator ingestion, use ingest_indicator().

        Returns:
            Number of indicators ingested (0 for placeholder).
        """
        # This could be extended to ingest from threat feeds
        logger.info("threat_intel_batch_ingestion_not_implemented")
        return 0

    async def ingest_indicator(
        self,
        indicator: str,
        indicator_type: Literal["ip", "domain", "url", "hash", "email", "other"],
        verdict: Literal["malicious", "suspicious", "benign", "unknown"],
        context: str,
        threat_actor: str | None = None,
        confidence: int = 50,
    ) -> str:
        """Ingest a single threat intelligence indicator.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.
            verdict: Threat verdict.
            context: Contextual information about the indicator.
            threat_actor: Associated threat actor if known.
            confidence: Confidence in the verdict (0-100).

        Returns:
            Document ID of ingested indicator.
        """
        # Generate unique document ID
        doc_id = self._generate_doc_id(indicator, indicator_type)

        # Build content for embedding
        content = self._build_content(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            context=context,
            threat_actor=threat_actor,
        )

        doc = ThreatIntelDocument(
            id=doc_id,
            content=content,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            threat_actor=threat_actor,
            confidence=confidence,
            created_at=datetime.utcnow(),
        )

        self._add_document(doc)

        logger.info(
            "threat_intel_ingested",
            doc_id=doc_id,
            indicator_type=indicator_type,
            verdict=verdict,
        )

        return doc_id

    async def ingest_batch(
        self,
        indicators: list[dict[str, Any]],
    ) -> int:
        """Ingest multiple threat intelligence indicators.

        Args:
            indicators: List of indicator dictionaries with keys:
                - indicator: str
                - indicator_type: str
                - verdict: str
                - context: str
                - threat_actor: str (optional)
                - confidence: int (optional)

        Returns:
            Number of indicators ingested.
        """
        documents = []

        for ind in indicators:
            indicator = ind["indicator"]
            indicator_type = ind["indicator_type"]
            verdict = ind["verdict"]
            context = ind["context"]
            threat_actor = ind.get("threat_actor")
            confidence = ind.get("confidence", 50)

            doc_id = self._generate_doc_id(indicator, indicator_type)
            content = self._build_content(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                context=context,
                threat_actor=threat_actor,
            )

            doc = ThreatIntelDocument(
                id=doc_id,
                content=content,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                threat_actor=threat_actor,
                confidence=confidence,
                created_at=datetime.utcnow(),
            )
            documents.append(doc)

        if documents:
            self._add_documents(documents)

        logger.info("threat_intel_batch_ingested", count=len(documents))
        return len(documents)

    def _generate_doc_id(self, indicator: str, indicator_type: str) -> str:
        """Generate a unique document ID.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.

        Returns:
            Unique document ID.
        """
        content = f"{indicator_type}:{indicator}"
        hash_value = hashlib.md5(content.encode()).hexdigest()[:12]
        return f"ti_{indicator_type}_{hash_value}"

    def _build_content(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str,
        context: str,
        threat_actor: str | None = None,
    ) -> str:
        """Build text content for threat intel embedding.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.
            verdict: Threat verdict.
            context: Contextual information.
            threat_actor: Associated threat actor.

        Returns:
            Text content for embedding.
        """
        parts = [
            f"Threat Intelligence Indicator: {indicator}",
            f"Type: {indicator_type}",
            f"Verdict: {verdict}",
            f"Context: {context}",
        ]

        if threat_actor:
            parts.append(f"Threat Actor: {threat_actor}")

        return "\n".join(parts)
