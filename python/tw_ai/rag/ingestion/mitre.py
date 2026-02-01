"""MITRE ATT&CK ingester.

Ingests MITRE techniques from the built-in MITRE_MAPPINGS.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from tw_ai.analysis.mitre import TechniqueInfo
from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import MITREDocument

if TYPE_CHECKING:
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()


class MITREIngester(BaseIngester):
    """Ingester for MITRE ATT&CK techniques.

    Loads techniques from the built-in MITRE_MAPPINGS dictionary
    in tw_ai.analysis.mitre module.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize MITRE ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the MITRE collection name."""
        return self._vector_store._config.mitre_collection

    async def ingest(self) -> int:
        """Ingest all MITRE techniques from built-in mappings.

        Returns:
            Number of techniques ingested.
        """
        from tw_ai.analysis.mitre import MITRE_MAPPINGS

        logger.info("ingesting_mitre_techniques", count=len(MITRE_MAPPINGS))

        documents = []
        for technique_id, info in MITRE_MAPPINGS.items():
            # Determine if this is a sub-technique
            is_subtechnique = "." in technique_id
            parent_id = technique_id.split(".")[0] if is_subtechnique else None

            # Build rich content for embedding
            content = self._build_content(info)

            doc = MITREDocument(
                id=f"mitre_{technique_id}",
                content=content,
                technique_id=technique_id,
                name=info.name,
                tactic=info.tactic,
                is_subtechnique=is_subtechnique,
                parent_technique_id=parent_id,
                keywords=info.keywords,
            )
            documents.append(doc)

        # Add all documents
        self._add_documents(documents)

        logger.info("mitre_ingestion_complete", count=len(documents))
        return len(documents)

    def _build_content(self, info: TechniqueInfo) -> str:
        """Build rich text content for a MITRE technique.

        Args:
            info: TechniqueInfo from MITRE_MAPPINGS.

        Returns:
            Text content combining technique details.
        """
        parts = [
            f"MITRE ATT&CK Technique: {info.id} - {info.name}",
            f"Tactic: {info.tactic}",
            f"Keywords: {', '.join(info.keywords)}",
        ]
        return "\n".join(parts)
