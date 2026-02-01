"""Incident ingester for historical triage results.

Ingests completed TriageAnalysis results as historical incidents
for similarity search.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import TYPE_CHECKING

import structlog

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import IncidentDocument

if TYPE_CHECKING:
    from tw_ai.agents.models import TriageAnalysis
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()


class IncidentIngester(BaseIngester):
    """Ingester for historical triage incidents.

    Converts TriageAnalysis results into searchable documents
    containing the summary, reasoning, indicators, and techniques.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize incident ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the incidents collection name."""
        return self._vector_store._config.incidents_collection

    async def ingest(self) -> int:
        """Ingest incidents - placeholder for batch ingestion.

        For individual incident ingestion, use ingest_analysis().

        Returns:
            Number of incidents ingested (0 for placeholder).
        """
        # This could be extended to ingest from a database or file
        logger.info("incident_batch_ingestion_not_implemented")
        return 0

    async def ingest_analysis(
        self,
        analysis: TriageAnalysis,
        alert_id: str,
        alert_type: str,
    ) -> str:
        """Ingest a single triage analysis as a historical incident.

        Args:
            analysis: Completed triage analysis.
            alert_id: Original alert identifier.
            alert_type: Type of alert (phishing, malware, etc.)

        Returns:
            Document ID of ingested incident.
        """
        # Generate unique document ID
        doc_id = self._generate_doc_id(alert_id, analysis)

        # Build content from analysis
        content = self._build_content(analysis)

        # Extract technique IDs
        technique_ids = [t.id for t in analysis.mitre_techniques]

        doc = IncidentDocument(
            id=doc_id,
            content=content,
            verdict=analysis.verdict,
            severity=analysis.severity,
            confidence=analysis.confidence,
            alert_type=alert_type,
            alert_id=alert_id,
            technique_ids=technique_ids,
            indicator_count=len(analysis.indicators),
            created_at=datetime.utcnow(),
        )

        self._add_document(doc)

        logger.info(
            "incident_ingested",
            doc_id=doc_id,
            alert_id=alert_id,
            verdict=analysis.verdict,
        )

        return doc_id

    def _generate_doc_id(self, alert_id: str, analysis: TriageAnalysis) -> str:
        """Generate a unique document ID.

        Args:
            alert_id: Alert identifier.
            analysis: Triage analysis.

        Returns:
            Unique document ID.
        """
        # Create hash from alert_id and key analysis fields
        content = f"{alert_id}:{analysis.verdict}:{analysis.summary[:100]}"
        hash_suffix = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"incident_{alert_id}_{hash_suffix}"

    def _build_content(self, analysis: TriageAnalysis) -> str:
        """Build text content from a triage analysis.

        Args:
            analysis: Triage analysis result.

        Returns:
            Text content for embedding.
        """
        parts = [
            f"Verdict: {analysis.verdict}",
            f"Severity: {analysis.severity}",
            f"Confidence: {analysis.confidence}%",
            f"Summary: {analysis.summary}",
        ]

        # Add reasoning if present
        if analysis.reasoning:
            parts.append(f"Reasoning: {analysis.reasoning}")

        # Add indicators
        if analysis.indicators:
            indicators_str = "; ".join(
                f"{i.type}: {i.value} ({i.verdict})" for i in analysis.indicators
            )
            parts.append(f"Indicators: {indicators_str}")

        # Add MITRE techniques
        if analysis.mitre_techniques:
            techniques_str = "; ".join(
                f"{t.id} - {t.name} ({t.tactic})" for t in analysis.mitre_techniques
            )
            parts.append(f"MITRE Techniques: {techniques_str}")

        # Add recommended actions
        if analysis.recommended_actions:
            actions_str = "; ".join(
                f"{a.action} ({a.priority})" for a in analysis.recommended_actions
            )
            parts.append(f"Recommended Actions: {actions_str}")

        return "\n".join(parts)
