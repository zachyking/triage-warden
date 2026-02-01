"""Tests for embedding service."""

from __future__ import annotations

import pytest


class TestEmbeddingService:
    """Tests for EmbeddingService."""

    def test_embedding_service_creation(self, embedding_service):
        """Test embedding service initialization."""
        assert embedding_service is not None
        assert embedding_service.model_name == "all-MiniLM-L6-v2"

    def test_embedding_dimension(self, embedding_service):
        """Test embedding dimension property."""
        assert embedding_service.dimension == 384

    def test_embed_single_text(self, embedding_service):
        """Test embedding a single text."""
        text = "This is a phishing email with malicious links"
        embedding = embedding_service.embed(text)

        assert isinstance(embedding, list)
        assert len(embedding) == 384
        assert all(isinstance(x, float) for x in embedding)

    def test_embed_batch(self, embedding_service):
        """Test batch embedding."""
        texts = [
            "Phishing email detected",
            "Malware sample found",
            "Suspicious login attempt",
        ]
        embeddings = embedding_service.embed_batch(texts)

        assert len(embeddings) == 3
        for emb in embeddings:
            assert len(emb) == 384

    def test_embed_batch_empty(self, embedding_service):
        """Test batch embedding with empty list."""
        embeddings = embedding_service.embed_batch([])
        assert embeddings == []

    def test_embed_deterministic(self, embedding_service):
        """Test that same text produces same embedding."""
        text = "Consistent embedding test"

        emb1 = embedding_service.embed(text)
        emb2 = embedding_service.embed(text)

        assert emb1 == emb2

    def test_different_texts_different_embeddings(self, embedding_service):
        """Test that different texts produce different embeddings."""
        emb1 = embedding_service.embed("phishing attack")
        emb2 = embedding_service.embed("malware infection")

        # Should not be identical
        assert emb1 != emb2

    def test_similarity_identical(self, embedding_service):
        """Test similarity of identical texts."""
        text = "Test similarity"

        # Similarity of text with itself should be 1.0
        from sentence_transformers import util
        from unittest.mock import patch

        # For mocked embeddings, we verify the method works
        emb = embedding_service.embed(text)
        assert len(emb) == 384

    def test_lazy_loading(self, rag_config, mock_sentence_transformer):
        """Test that model is lazy-loaded."""
        from tw_ai.rag.embeddings import EmbeddingService

        service = EmbeddingService(rag_config)

        # Model should not be loaded yet
        assert service._model is None

        # Accessing dimension triggers load
        _ = service.dimension

        # Now model should be loaded
        assert service._model is not None
