"""Pytest fixtures for RAG tests."""

from __future__ import annotations

from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_sentence_transformer() -> Generator[MagicMock, None, None]:
    """Mock sentence-transformers to avoid model downloads in tests."""
    import numpy as np

    mock_model = MagicMock()
    mock_model.get_sentence_embedding_dimension.return_value = 384

    # Generate consistent embeddings based on input hash
    def mock_encode(texts, **kwargs):
        if isinstance(texts, str):
            texts = [texts]
        # Generate pseudo-random but deterministic embeddings
        embeddings = []
        for text in texts:
            # Use hash to generate consistent values
            seed = hash(text) % (2**32)
            np.random.seed(seed)
            emb = np.random.randn(384).astype(np.float32)
            # Normalize to unit length for cosine similarity
            emb = emb / np.linalg.norm(emb)
            embeddings.append(emb)
        return np.array(embeddings) if len(embeddings) > 1 else embeddings[0]

    mock_model.encode.side_effect = mock_encode

    with patch("sentence_transformers.SentenceTransformer", return_value=mock_model):
        yield mock_model


@pytest.fixture
def temp_chroma_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for ChromaDB persistence."""
    chroma_dir = tmp_path / ".chroma"
    chroma_dir.mkdir()
    return chroma_dir


@pytest.fixture
def rag_config(temp_chroma_dir: Path):
    """Create RAG config with temporary storage."""
    from tw_ai.rag.config import RAGConfig

    return RAGConfig(
        persist_directory=temp_chroma_dir,
        use_persistent_storage=True,  # Use PersistentClient with tmp_path for isolation
        min_similarity_threshold=0.0,  # Disable threshold for mock embeddings
    )


@pytest.fixture
def embedding_service(rag_config, mock_sentence_transformer):
    """Create embedding service with mocked model."""
    from tw_ai.rag.embeddings import EmbeddingService

    return EmbeddingService(rag_config)


@pytest.fixture
def vector_store(rag_config, embedding_service):
    """Create vector store with mocked embeddings."""
    from tw_ai.rag.vector_store import VectorStore

    return VectorStore(rag_config, embedding_service)


@pytest.fixture
def retrieval_service(vector_store, rag_config):
    """Create retrieval service."""
    from tw_ai.rag.retrieval import RetrievalService

    return RetrievalService(vector_store, rag_config)


@pytest.fixture
def sample_playbook_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with sample playbook YAML files."""
    playbooks_dir = tmp_path / "playbooks"
    playbooks_dir.mkdir()

    # Create sample playbook
    phishing_playbook = playbooks_dir / "phishing-triage.yaml"
    phishing_playbook.write_text(
        """
name: phishing-triage
version: "1.0"
description: "Automated triage workflow for phishing email alerts"

trigger:
  sources:
    - email_security_gateway
    - user_reported
  alert_types:
    - suspected_phishing
    - user_reported_phishing

stages:
  - name: extraction
    description: Extract indicators from email
  - name: enrichment
    description: Gather threat intel
  - name: analysis
    description: Run AI analysis

branches:
  true_positive:
    conditions:
      - verdict: true_positive
    steps:
      - action: quarantine_email
      - action: block_sender

sla:
  time_to_triage: 5m
  time_to_respond: 15m
"""
    )

    malware_playbook = playbooks_dir / "malware-analysis.yaml"
    malware_playbook.write_text(
        """
name: malware-analysis
version: "1.0"
description: "Malware sample analysis workflow"

trigger:
  sources:
    - edr_alerts
  alert_types:
    - malware_detected
    - suspicious_file

stages:
  - name: sandbox
    description: Submit to sandbox
  - name: analysis
    description: Analyze results
"""
    )

    return playbooks_dir
