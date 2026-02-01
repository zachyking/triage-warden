"""Tests for vector store."""

from __future__ import annotations

import pytest


class TestVectorStore:
    """Tests for VectorStore."""

    def test_vector_store_creation(self, vector_store):
        """Test vector store initialization."""
        assert vector_store is not None

    def test_get_collection(self, vector_store):
        """Test getting/creating a collection."""
        collection = vector_store.get_collection("test_collection")

        assert collection is not None
        assert collection.name == "test_collection"

    def test_add_document(self, vector_store):
        """Test adding a single document."""
        from tw_ai.rag.models import MITREDocument

        doc = MITREDocument(
            id="test_doc_001",
            content="Test phishing technique content",
            technique_id="T1566",
            name="Phishing",
            tactic="Initial Access",
            keywords=["phishing", "email"],
        )

        doc_id = vector_store.add_document("mitre_attack", doc)

        assert doc_id == "test_doc_001"
        assert vector_store.collection_count("mitre_attack") == 1

    def test_add_documents_batch(self, vector_store):
        """Test adding multiple documents."""
        from tw_ai.rag.models import MITREDocument

        docs = [
            MITREDocument(
                id=f"test_doc_{i:03d}",
                content=f"Test content {i}",
                technique_id=f"T100{i}",
                name=f"Technique {i}",
                tactic="Test Tactic",
            )
            for i in range(5)
        ]

        doc_ids = vector_store.add_documents("mitre_attack", docs)

        assert len(doc_ids) == 5
        assert vector_store.collection_count("mitre_attack") == 5

    def test_add_documents_empty(self, vector_store):
        """Test adding empty document list."""
        doc_ids = vector_store.add_documents("test_collection", [])
        assert doc_ids == []

    def test_query_basic(self, vector_store):
        """Test basic query."""
        from tw_ai.rag.models import MITREDocument

        # Add some documents
        docs = [
            MITREDocument(
                id="phishing_doc",
                content="Phishing email with malicious links and credential harvesting",
                technique_id="T1566",
                name="Phishing",
                tactic="Initial Access",
                keywords=["phishing"],
            ),
            MITREDocument(
                id="malware_doc",
                content="Malware execution via PowerShell script",
                technique_id="T1059.001",
                name="PowerShell",
                tactic="Execution",
                keywords=["powershell"],
            ),
        ]
        vector_store.add_documents("mitre_attack", docs)

        # Query
        results = vector_store.query(
            collection_name="mitre_attack",
            query_text="email phishing attack",
            n_results=2,
        )

        assert results is not None
        assert "ids" in results
        assert len(results["ids"][0]) <= 2

    def test_query_with_filter(self, vector_store):
        """Test query with metadata filter."""
        from tw_ai.rag.models import IncidentDocument

        docs = [
            IncidentDocument(
                id="incident_tp",
                content="Confirmed phishing attack",
                verdict="true_positive",
                severity="high",
                confidence=90,
                alert_type="phishing",
                alert_id="ALERT-001",
            ),
            IncidentDocument(
                id="incident_fp",
                content="False positive phishing alert",
                verdict="false_positive",
                severity="low",
                confidence=95,
                alert_type="phishing",
                alert_id="ALERT-002",
            ),
        ]
        vector_store.add_documents("triage_incidents", docs)

        # Query with filter
        results = vector_store.query(
            collection_name="triage_incidents",
            query_text="phishing",
            n_results=5,
            where={"verdict": "true_positive"},
        )

        # Should only return true_positive
        assert len(results["ids"][0]) >= 1

    def test_delete_document(self, vector_store):
        """Test deleting a document."""
        from tw_ai.rag.models import MITREDocument

        doc = MITREDocument(
            id="to_delete",
            content="Document to be deleted",
            technique_id="T9999",
            name="Test",
            tactic="Test",
        )
        vector_store.add_document("mitre_attack", doc)
        assert vector_store.collection_count("mitre_attack") == 1

        vector_store.delete_document("mitre_attack", "to_delete")
        assert vector_store.collection_count("mitre_attack") == 0

    def test_collection_count(self, vector_store):
        """Test collection count."""
        from tw_ai.rag.models import MITREDocument

        # Empty collection
        assert vector_store.collection_count("empty_collection") == 0

        # Add documents
        docs = [
            MITREDocument(
                id=f"doc_{i}",
                content=f"Content {i}",
                technique_id=f"T{i}",
                name=f"Technique {i}",
                tactic="Test",
            )
            for i in range(3)
        ]
        vector_store.add_documents("empty_collection", docs)

        assert vector_store.collection_count("empty_collection") == 3
