"""Base ingester protocol for RAG data sources.

Defines the interface that all ingesters must implement.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tw_ai.rag.models import BaseDocument
    from tw_ai.rag.vector_store import VectorStore


class BaseIngester(ABC):
    """Abstract base class for RAG data ingesters.

    Subclasses must implement the ingest() method to load data from
    their specific source and store it in the vector store.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize ingester with vector store.

        Args:
            vector_store: Vector store for document storage.
        """
        self._vector_store = vector_store

    @property
    @abstractmethod
    def collection_name(self) -> str:
        """Get the target collection name for this ingester."""
        ...

    @abstractmethod
    async def ingest(self, *args: Any, **kwargs: Any) -> int:
        """Ingest data from the source.

        Returns:
            Number of documents ingested.
        """
        ...

    def _add_document(self, document: BaseDocument) -> str:
        """Add a single document to the collection.

        Args:
            document: Document to add.

        Returns:
            Document ID.
        """
        return self._vector_store.add_document(self.collection_name, document)

    def _add_documents(self, documents: Sequence[BaseDocument]) -> list[str]:
        """Add multiple documents to the collection.

        Args:
            documents: Documents to add.

        Returns:
            List of document IDs.
        """
        return self._vector_store.add_documents(self.collection_name, list(documents))
