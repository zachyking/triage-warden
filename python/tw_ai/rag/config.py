"""Configuration for the RAG system.

Provides Pydantic settings for embedding models, vector store persistence,
and collection management.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CollectionConfig(BaseModel):
    """Configuration for a ChromaDB collection."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(description="Collection name in ChromaDB")
    description: str = Field(description="Human-readable description")


class RAGConfig(BaseModel):
    """Configuration for the RAG system."""

    model_config = ConfigDict(frozen=True)

    # Embedding model settings
    embedding_model: str = Field(
        default="all-MiniLM-L6-v2",
        description="Sentence-transformers model name for embeddings",
    )
    embedding_dimension: int = Field(
        default=384,
        description="Dimension of embedding vectors (must match model)",
    )
    embedding_device: Literal["cpu", "cuda", "mps"] = Field(
        default="cpu",
        description="Device for embedding computation",
    )

    # Vector store settings
    persist_directory: Path = Field(
        default=Path(".chroma"),
        description="Directory for ChromaDB persistent storage",
    )
    use_persistent_storage: bool = Field(
        default=True,
        description="Whether to persist the vector store to disk",
    )

    # Collection names
    incidents_collection: str = Field(
        default="triage_incidents",
        description="Collection for historical triage incidents",
    )
    playbooks_collection: str = Field(
        default="security_playbooks",
        description="Collection for security playbooks/runbooks",
    )
    mitre_collection: str = Field(
        default="mitre_attack",
        description="Collection for MITRE ATT&CK techniques",
    )
    threat_intel_collection: str = Field(
        default="threat_intelligence",
        description="Collection for threat intelligence indicators",
    )

    # Query settings
    default_top_k: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Default number of results to return",
    )
    min_similarity_threshold: float = Field(
        default=0.3,
        ge=0.0,
        le=1.0,
        description="Minimum similarity score for results",
    )

    @property
    def collections(self) -> dict[str, CollectionConfig]:
        """Get all collection configurations."""
        return {
            "incidents": CollectionConfig(
                name=self.incidents_collection,
                description="Historical triage analysis results",
            ),
            "playbooks": CollectionConfig(
                name=self.playbooks_collection,
                description="Security playbooks and runbooks",
            ),
            "mitre": CollectionConfig(
                name=self.mitre_collection,
                description="MITRE ATT&CK techniques",
            ),
            "threat_intel": CollectionConfig(
                name=self.threat_intel_collection,
                description="Threat intelligence indicators",
            ),
        }
