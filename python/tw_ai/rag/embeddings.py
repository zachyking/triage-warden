"""Embedding service using sentence-transformers.

Provides a wrapper around sentence-transformers with lazy model loading
to minimize startup time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

    from tw_ai.rag.config import RAGConfig

logger = structlog.get_logger()


class EmbeddingService:
    """Sentence-transformers embedding service with lazy loading.

    The embedding model is loaded on first use to minimize startup latency.
    Default model is all-MiniLM-L6-v2 which provides good quality embeddings
    with 384 dimensions.
    """

    def __init__(self, config: RAGConfig | None = None) -> None:
        """Initialize embedding service.

        Args:
            config: RAG configuration with model settings.
        """
        from tw_ai.rag.config import RAGConfig

        self._config = config or RAGConfig()
        self._model: SentenceTransformer | None = None
        self._dimension: int | None = None

    @property
    def model_name(self) -> str:
        """Get the embedding model name."""
        return self._config.embedding_model

    @property
    def dimension(self) -> int:
        """Get the embedding dimension.

        Loads the model if not already loaded to get the actual dimension.
        """
        if self._dimension is None:
            # Load model to get actual dimension
            _ = self.model
        return self._dimension or self._config.embedding_dimension

    @property
    def model(self) -> SentenceTransformer:
        """Lazy-load and return the sentence-transformers model."""
        if self._model is None:
            self._model = self._load_model()
        return self._model

    def _load_model(self) -> SentenceTransformer:
        """Load the sentence-transformers model.

        Returns:
            Loaded SentenceTransformer model.
        """
        from sentence_transformers import SentenceTransformer

        logger.info(
            "loading_embedding_model",
            model=self._config.embedding_model,
            device=self._config.embedding_device,
        )

        model = SentenceTransformer(
            self._config.embedding_model,
            device=self._config.embedding_device,
        )

        # Get actual dimension from model
        self._dimension = model.get_sentence_embedding_dimension()

        logger.info(
            "embedding_model_loaded",
            model=self._config.embedding_model,
            dimension=self._dimension,
        )

        return model

    def embed(self, text: str) -> list[float]:
        """Generate embedding for a single text.

        Args:
            text: Text to embed.

        Returns:
            Embedding vector as list of floats.
        """
        embedding = self.model.encode(text, convert_to_numpy=True)
        return embedding.tolist()

    def embed_batch(self, texts: list[str], batch_size: int = 32) -> list[list[float]]:
        """Generate embeddings for multiple texts.

        Args:
            texts: List of texts to embed.
            batch_size: Batch size for encoding.

        Returns:
            List of embedding vectors.
        """
        if not texts:
            return []

        embeddings = self.model.encode(
            texts,
            batch_size=batch_size,
            convert_to_numpy=True,
            show_progress_bar=False,
        )

        return [emb.tolist() for emb in embeddings]

    def similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts.

        Args:
            text1: First text.
            text2: Second text.

        Returns:
            Cosine similarity score (0-1).
        """
        from sentence_transformers import util

        emb1 = self.model.encode(text1, convert_to_numpy=True)
        emb2 = self.model.encode(text2, convert_to_numpy=True)

        return float(util.cos_sim(emb1, emb2)[0][0])
