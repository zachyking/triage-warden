"""RAG (Retrieval-Augmented Generation) system for security knowledge retrieval.

This module provides semantic search capabilities over security knowledge bases
including historical incidents, playbooks, MITRE ATT&CK techniques, and threat
intelligence.

Public API:
    - create_rag_service(): Factory for RAGService
    - create_rag_tools(): Factory for agent tools
    - register_rag_tools(): Register tools with ToolRegistry
    - RAGService: High-level facade for all RAG operations
    - RAGConfig: Configuration settings
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from tw_ai.rag.config import RAGConfig
from tw_ai.rag.embeddings import EmbeddingService
from tw_ai.rag.models import (
    IncidentDocument,
    MITREDocument,
    PlaybookDocument,
    QueryRequest,
    QueryResponse,
    QueryResult,
    ThreatIntelDocument,
)
from tw_ai.rag.retrieval import RetrievalService
from tw_ai.rag.tools import create_rag_tools, register_rag_tools
from tw_ai.rag.vector_store import VectorStore

if TYPE_CHECKING:
    from tw_ai.agents.models import TriageAnalysis

__all__ = [
    # Configuration
    "RAGConfig",
    # Services
    "EmbeddingService",
    "VectorStore",
    "RetrievalService",
    "RAGService",
    # Factory functions
    "create_rag_service",
    "create_rag_tools",
    "register_rag_tools",
    # Document models
    "IncidentDocument",
    "PlaybookDocument",
    "MITREDocument",
    "ThreatIntelDocument",
    # Query models
    "QueryRequest",
    "QueryResult",
    "QueryResponse",
]


class RAGService:
    """High-level facade for RAG operations.

    Combines embedding, vector store, retrieval, and ingestion components
    into a unified interface for the security knowledge base.
    """

    def __init__(self, config: RAGConfig | None = None) -> None:
        """Initialize RAG service with optional configuration.

        Args:
            config: RAG configuration. Uses defaults if not provided.
        """
        self.config = config or RAGConfig()
        self._embedding: EmbeddingService | None = None
        self._vector_store: VectorStore | None = None
        self._retrieval: RetrievalService | None = None

    @property
    def embedding(self) -> EmbeddingService:
        """Lazy-loaded embedding service."""
        if self._embedding is None:
            self._embedding = EmbeddingService(self.config)
        return self._embedding

    @property
    def vector_store(self) -> VectorStore:
        """Lazy-loaded vector store."""
        if self._vector_store is None:
            self._vector_store = VectorStore(self.config, self.embedding)
        return self._vector_store

    @property
    def retrieval(self) -> RetrievalService:
        """Lazy-loaded retrieval service."""
        if self._retrieval is None:
            self._retrieval = RetrievalService(self.vector_store, self.config)
        return self._retrieval

    async def ingest_mitre(self) -> int:
        """Ingest MITRE ATT&CK techniques from built-in mappings.

        Returns:
            Number of techniques ingested.
        """
        from tw_ai.rag.ingestion import MITREIngester

        ingester = MITREIngester(self.vector_store)
        return await ingester.ingest()

    async def ingest_playbooks(self, playbooks_dir: str | None = None) -> int:
        """Ingest playbooks from YAML files.

        Args:
            playbooks_dir: Path to playbooks directory.
                Defaults to config/playbooks/.

        Returns:
            Number of playbooks ingested.
        """
        from pathlib import Path

        from tw_ai.rag.ingestion import PlaybookIngester

        if playbooks_dir is None:
            playbooks_dir = "config/playbooks"

        ingester = PlaybookIngester(self.vector_store)
        return await ingester.ingest(Path(playbooks_dir))

    async def ingest_incident(
        self,
        analysis: TriageAnalysis,
        alert_id: str,
        alert_type: str,
    ) -> str:
        """Ingest a completed triage analysis as a historical incident.

        Args:
            analysis: Completed triage analysis result.
            alert_id: Unique identifier for the alert.
            alert_type: Type of alert (e.g., "phishing", "malware").

        Returns:
            Document ID of ingested incident.
        """
        from tw_ai.rag.ingestion import IncidentIngester

        ingester = IncidentIngester(self.vector_store)
        return await ingester.ingest_analysis(analysis, alert_id, alert_type)

    async def ingest_threat_intel(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str,
        context: str,
        threat_actor: str | None = None,
    ) -> str:
        """Ingest a threat intelligence indicator.

        Args:
            indicator: The indicator value (IP, domain, hash, etc.)
            indicator_type: Type of indicator.
            verdict: Threat verdict (malicious, suspicious, benign).
            context: Contextual information about the indicator.
            threat_actor: Associated threat actor if known.

        Returns:
            Document ID of ingested indicator.
        """
        from tw_ai.rag.ingestion import ThreatIntelIngester

        ingester = ThreatIntelIngester(self.vector_store)
        return await ingester.ingest_indicator(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            context=context,
            threat_actor=threat_actor,
        )


def create_rag_service(config: RAGConfig | None = None) -> RAGService:
    """Create a RAG service instance.

    Args:
        config: Optional configuration. Uses defaults if not provided.

    Returns:
        Configured RAGService instance.
    """
    return RAGService(config)
