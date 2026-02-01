"""Retrieval service for RAG queries.

Provides high-level query interface with collection-specific methods,
metadata filtering, and score-based ranking.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import structlog

from tw_ai.rag.models import QueryResponse, QueryResult

if TYPE_CHECKING:
    from tw_ai.rag.config import RAGConfig
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()


class RetrievalService:
    """High-level retrieval interface for RAG queries.

    Provides specialized methods for each collection type with
    appropriate metadata filtering and result formatting.
    """

    def __init__(
        self,
        vector_store: VectorStore,
        config: RAGConfig | None = None,
    ) -> None:
        """Initialize retrieval service.

        Args:
            vector_store: Vector store for document queries.
            config: RAG configuration.
        """
        from tw_ai.rag.config import RAGConfig

        self._vector_store = vector_store
        self._config = config or RAGConfig()

    def _distance_to_similarity(self, distance: float) -> float:
        """Convert ChromaDB distance to similarity score.

        ChromaDB returns L2 distances or cosine distances depending on
        collection settings. With cosine distance, distance = 1 - similarity.

        Args:
            distance: Distance value from ChromaDB.

        Returns:
            Similarity score between 0 and 1.
        """
        # For cosine distance: similarity = 1 - distance
        # Clamp to [0, 1] range
        return max(0.0, min(1.0, 1.0 - distance))

    def search(
        self,
        query: str,
        collection: str,
        top_k: int | None = None,
        min_similarity: float | None = None,
        filters: dict[str, Any] | None = None,
    ) -> QueryResponse:
        """Execute a general search query.

        Args:
            query: Natural language query text.
            collection: Collection to search.
            top_k: Number of results to return.
            min_similarity: Minimum similarity threshold.
            filters: Metadata filters.

        Returns:
            Query response with matching documents.
        """
        start_time = time.perf_counter()

        top_k = top_k or self._config.default_top_k
        min_similarity = min_similarity or self._config.min_similarity_threshold

        try:
            # Execute query
            raw_results = self._vector_store.query(
                collection_name=collection,
                query_text=query,
                n_results=top_k,
                where=filters,
            )

            # Process results
            results = []
            total_results = 0

            if raw_results and raw_results.get("ids"):
                ids = raw_results["ids"][0] if raw_results["ids"] else []
                documents = raw_results.get("documents", [[]])[0]
                distances = raw_results.get("distances", [[]])[0]
                metadatas = raw_results.get("metadatas", [[]])[0]

                total_results = len(ids)

                for i, doc_id in enumerate(ids):
                    similarity = self._distance_to_similarity(distances[i])

                    # Apply similarity threshold
                    if similarity >= min_similarity:
                        results.append(
                            QueryResult(
                                id=doc_id,
                                content=documents[i] if documents else "",
                                similarity=similarity,
                                metadata=metadatas[i] if metadatas else {},
                            )
                        )

            # Sort by similarity descending
            results.sort(key=lambda r: r.similarity, reverse=True)

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            logger.debug(
                "search_executed",
                collection=collection,
                query_length=len(query),
                total_results=total_results,
                filtered_results=len(results),
                execution_time_ms=execution_time_ms,
            )

            return QueryResponse(
                query=query,
                collection=collection,
                results=results,
                total_results=total_results,
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            logger.error(
                "search_failed",
                collection=collection,
                query_length=len(query),
                error=str(e),
            )
            raise

    def search_similar_incidents(
        self,
        query: str,
        top_k: int = 5,
        verdict: str | None = None,
        severity: str | None = None,
        alert_type: str | None = None,
        min_confidence: int | None = None,
    ) -> QueryResponse:
        """Search for similar historical incidents.

        Args:
            query: Description of the current incident.
            top_k: Number of results.
            verdict: Filter by verdict (true_positive, false_positive, etc.)
            severity: Filter by severity level.
            alert_type: Filter by alert type.
            min_confidence: Minimum confidence score.

        Returns:
            Matching historical incidents.
        """
        filters = self._build_filters(
            verdict=verdict,
            severity=severity,
            alert_type=alert_type,
        )

        response = self.search(
            query=query,
            collection=self._config.incidents_collection,
            top_k=top_k,
            filters=filters if filters else None,
        )

        # Apply confidence filter post-query (ChromaDB doesn't support >= operators well)
        if min_confidence is not None:
            response.results = [
                r for r in response.results if r.metadata.get("confidence", 0) >= min_confidence
            ]

        return response

    def search_playbooks(
        self,
        query: str,
        top_k: int = 3,
        trigger_type: str | None = None,
    ) -> QueryResponse:
        """Search for relevant playbooks.

        Args:
            query: Description of the scenario.
            top_k: Number of results.
            trigger_type: Filter by trigger type.

        Returns:
            Matching playbooks.
        """
        filters = None
        if trigger_type:
            # ChromaDB $contains for comma-separated list
            filters = {"trigger_types": {"$contains": trigger_type}}

        return self.search(
            query=query,
            collection=self._config.playbooks_collection,
            top_k=top_k,
            filters=filters,
        )

    def search_mitre_techniques(
        self,
        query: str,
        top_k: int = 5,
        tactic: str | None = None,
        include_subtechniques: bool = True,
    ) -> QueryResponse:
        """Search for MITRE ATT&CK techniques.

        Args:
            query: Description of observed behavior.
            top_k: Number of results.
            tactic: Filter by MITRE tactic.
            include_subtechniques: Whether to include sub-techniques.

        Returns:
            Matching MITRE techniques.
        """
        filters: dict[str, Any] = {}

        if tactic:
            filters["tactic"] = tactic

        if not include_subtechniques:
            filters["is_subtechnique"] = False

        return self.search(
            query=query,
            collection=self._config.mitre_collection,
            top_k=top_k,
            filters=filters if filters else None,
        )

    def search_threat_intel(
        self,
        query: str,
        top_k: int = 5,
        indicator_type: str | None = None,
        verdict: str | None = None,
        threat_actor: str | None = None,
    ) -> QueryResponse:
        """Search threat intelligence.

        Args:
            query: Description or indicator to search.
            top_k: Number of results.
            indicator_type: Filter by indicator type (ip, domain, hash, etc.)
            verdict: Filter by verdict (malicious, suspicious, benign).
            threat_actor: Filter by threat actor.

        Returns:
            Matching threat intel.
        """
        filters = self._build_filters(
            indicator_type=indicator_type,
            verdict=verdict,
            threat_actor=threat_actor,
        )

        return self.search(
            query=query,
            collection=self._config.threat_intel_collection,
            top_k=top_k,
            filters=filters if filters else None,
        )

    def _build_filters(self, **kwargs: Any) -> dict[str, Any] | None:
        """Build ChromaDB filter dict from keyword arguments.

        Args:
            **kwargs: Field names and values to filter on.

        Returns:
            Filter dict or None if no filters.
        """
        filters = {k: v for k, v in kwargs.items() if v is not None}
        return filters if filters else None
