"""ChromaDB vector store wrapper.

Provides collection management and document operations for the RAG system.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, cast

import structlog

if TYPE_CHECKING:
    from chromadb.api.models.Collection import Collection

    from tw_ai.rag.config import RAGConfig
    from tw_ai.rag.embeddings import EmbeddingService
    from tw_ai.rag.models import BaseDocument

logger = structlog.get_logger()


class VectorStore:
    """ChromaDB vector store with collection management.

    Wraps ChromaDB client to provide:
    - Automatic collection creation
    - Document add/query operations
    - Metadata filtering
    - Batch operations
    """

    def __init__(
        self,
        config: RAGConfig | None = None,
        embedding_service: EmbeddingService | None = None,
    ) -> None:
        """Initialize vector store.

        Args:
            config: RAG configuration.
            embedding_service: Service for generating embeddings.
        """
        from tw_ai.rag.config import RAGConfig
        from tw_ai.rag.embeddings import EmbeddingService

        self._config = config or RAGConfig()
        self._embedding_service = embedding_service or EmbeddingService(self._config)
        self._client: Any = None
        self._collections: dict[str, Collection] = {}

    @property
    def client(self) -> Any:
        """Lazy-load and return the ChromaDB client."""
        if self._client is None:
            self._client = self._create_client()
        return self._client

    def _create_client(self) -> Any:
        """Create ChromaDB client.

        Returns:
            ChromaDB client instance.
        """
        import chromadb

        if self._config.use_persistent_storage:
            persist_path = str(self._config.persist_directory.absolute())
            logger.info("initializing_chromadb", persist_path=persist_path)

            # ChromaDB 0.4+ uses PersistentClient for persistent storage
            client = chromadb.PersistentClient(path=persist_path)
        else:
            logger.info("initializing_chromadb", persist_path="in-memory")
            # Ephemeral in-memory client
            client = chromadb.EphemeralClient()

        return client

    def get_collection(self, name: str) -> Collection:
        """Get or create a collection by name.

        Args:
            name: Collection name.

        Returns:
            ChromaDB collection.
        """
        if name not in self._collections:
            logger.debug("getting_collection", name=name)
            self._collections[name] = self.client.get_or_create_collection(
                name=name,
                metadata={"hnsw:space": "cosine"},
            )
        return self._collections[name]

    def add_document(
        self,
        collection_name: str,
        document: BaseDocument,
    ) -> str:
        """Add a single document to a collection.

        Args:
            collection_name: Target collection name.
            document: Document to add.

        Returns:
            Document ID.
        """
        try:
            collection = self.get_collection(collection_name)
            embedding = self._embedding_service.embed(document.content)

            collection.add(
                ids=[document.id],
                embeddings=cast(list[Sequence[float]], [embedding]),
                documents=[document.content],
                metadatas=[document.to_metadata()],
            )

            logger.debug(
                "document_added",
                collection=collection_name,
                document_id=document.id,
            )

            return document.id
        except Exception as e:
            logger.error(
                "add_document_failed",
                collection=collection_name,
                document_id=document.id,
                error=str(e),
            )
            raise

    def add_documents(
        self,
        collection_name: str,
        documents: list[BaseDocument],
        batch_size: int = 100,
    ) -> list[str]:
        """Add multiple documents to a collection.

        Args:
            collection_name: Target collection name.
            documents: Documents to add.
            batch_size: Batch size for embedding generation.

        Returns:
            List of document IDs.
        """
        if not documents:
            return []

        try:
            collection = self.get_collection(collection_name)

            # Generate embeddings in batches
            contents = [doc.content for doc in documents]
            embeddings = self._embedding_service.embed_batch(contents, batch_size=batch_size)

            # Add to collection
            collection.add(
                ids=[doc.id for doc in documents],
                embeddings=cast(list[Sequence[float]], embeddings),
                documents=contents,
                metadatas=[doc.to_metadata() for doc in documents],
            )

            logger.info(
                "documents_added",
                collection=collection_name,
                count=len(documents),
            )

            return [doc.id for doc in documents]
        except Exception as e:
            logger.error(
                "add_documents_failed",
                collection=collection_name,
                count=len(documents),
                error=str(e),
            )
            raise

    def query(
        self,
        collection_name: str,
        query_text: str,
        n_results: int = 5,
        where: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Query a collection for similar documents.

        Args:
            collection_name: Collection to query.
            query_text: Query text.
            n_results: Number of results to return.
            where: Metadata filter conditions.

        Returns:
            Query results with ids, documents, distances, and metadatas.
        """
        try:
            collection = self.get_collection(collection_name)
            query_embedding = self._embedding_service.embed(query_text)

            results = collection.query(
                query_embeddings=cast(list[Sequence[float]], [query_embedding]),
                n_results=n_results,
                where=where,
                include=["documents", "distances", "metadatas"],
            )

            logger.debug(
                "query_executed",
                collection=collection_name,
                n_results=n_results,
                has_filters=where is not None,
            )

            # Cast to dict for consistent return type
            return cast(dict[str, Any], results)
        except Exception as e:
            logger.error(
                "query_failed",
                collection=collection_name,
                n_results=n_results,
                error=str(e),
            )
            raise

    def delete_document(self, collection_name: str, document_id: str) -> None:
        """Delete a document from a collection.

        Args:
            collection_name: Collection name.
            document_id: Document ID to delete.
        """
        try:
            collection = self.get_collection(collection_name)
            collection.delete(ids=[document_id])

            logger.debug(
                "document_deleted",
                collection=collection_name,
                document_id=document_id,
            )
        except Exception as e:
            logger.error(
                "delete_document_failed",
                collection=collection_name,
                document_id=document_id,
                error=str(e),
            )
            raise

    def delete_collection(self, collection_name: str) -> None:
        """Delete an entire collection.

        Args:
            collection_name: Collection name to delete.
        """
        try:
            self.client.delete_collection(collection_name)
            self._collections.pop(collection_name, None)

            logger.info("collection_deleted", collection=collection_name)
        except Exception as e:
            logger.error(
                "delete_collection_failed",
                collection=collection_name,
                error=str(e),
            )
            raise

    def collection_count(self, collection_name: str) -> int:
        """Get the number of documents in a collection.

        Args:
            collection_name: Collection name.

        Returns:
            Number of documents.
        """
        collection = self.get_collection(collection_name)
        return collection.count()

    def persist(self) -> None:
        """Persist the vector store to disk.

        Note: In ChromaDB 0.4+, PersistentClient automatically persists.
        This method is kept for API compatibility but is a no-op.
        """
        # ChromaDB 0.4+ auto-persists with PersistentClient
        logger.debug("vector_store_persist_called", note="auto-persisted by PersistentClient")
