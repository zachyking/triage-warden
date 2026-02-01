"""Tests for RAG configuration."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestRAGConfig:
    """Tests for RAGConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        from tw_ai.rag.config import RAGConfig

        config = RAGConfig()

        assert config.embedding_model == "all-MiniLM-L6-v2"
        assert config.embedding_dimension == 384
        assert config.embedding_device == "cpu"
        assert config.persist_directory == Path(".chroma")
        assert config.use_persistent_storage is True
        assert config.incidents_collection == "triage_incidents"
        assert config.playbooks_collection == "security_playbooks"
        assert config.mitre_collection == "mitre_attack"
        assert config.threat_intel_collection == "threat_intelligence"
        assert config.default_top_k == 5
        assert config.min_similarity_threshold == 0.3

    def test_custom_config(self):
        """Test custom configuration."""
        from tw_ai.rag.config import RAGConfig

        config = RAGConfig(
            embedding_model="custom-model",
            persist_directory=Path("/custom/path"),
            default_top_k=10,
        )

        assert config.embedding_model == "custom-model"
        assert config.persist_directory == Path("/custom/path")
        assert config.default_top_k == 10

    def test_collections_property(self):
        """Test collections property returns all collections."""
        from tw_ai.rag.config import RAGConfig

        config = RAGConfig()
        collections = config.collections

        assert "incidents" in collections
        assert "playbooks" in collections
        assert "mitre" in collections
        assert "threat_intel" in collections

        assert collections["incidents"].name == "triage_incidents"
        assert collections["mitre"].name == "mitre_attack"

    def test_config_is_frozen(self):
        """Test that config is immutable."""
        from tw_ai.rag.config import RAGConfig

        config = RAGConfig()

        with pytest.raises(Exception):  # ValidationError or similar
            config.embedding_model = "new-model"

    def test_top_k_validation(self):
        """Test top_k validation bounds."""
        from tw_ai.rag.config import RAGConfig

        # Valid bounds
        config = RAGConfig(default_top_k=1)
        assert config.default_top_k == 1

        config = RAGConfig(default_top_k=100)
        assert config.default_top_k == 100

        # Invalid - below minimum
        with pytest.raises(ValueError):
            RAGConfig(default_top_k=0)

        # Invalid - above maximum
        with pytest.raises(ValueError):
            RAGConfig(default_top_k=101)

    def test_similarity_threshold_validation(self):
        """Test similarity threshold validation."""
        from tw_ai.rag.config import RAGConfig

        # Valid bounds
        config = RAGConfig(min_similarity_threshold=0.0)
        assert config.min_similarity_threshold == 0.0

        config = RAGConfig(min_similarity_threshold=1.0)
        assert config.min_similarity_threshold == 1.0

        # Invalid - below minimum
        with pytest.raises(ValueError):
            RAGConfig(min_similarity_threshold=-0.1)

        # Invalid - above maximum
        with pytest.raises(ValueError):
            RAGConfig(min_similarity_threshold=1.1)
