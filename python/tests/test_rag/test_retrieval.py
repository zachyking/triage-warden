"""Tests for retrieval service."""

from __future__ import annotations

import pytest


class TestRetrievalService:
    """Tests for RetrievalService."""

    def test_retrieval_service_creation(self, retrieval_service):
        """Test retrieval service initialization."""
        assert retrieval_service is not None

    def test_search_basic(self, retrieval_service, vector_store):
        """Test basic search functionality."""
        from tw_ai.rag.models import MITREDocument

        # Add test documents
        docs = [
            MITREDocument(
                id="doc_phishing",
                content="Phishing email attack with credential harvesting",
                technique_id="T1566",
                name="Phishing",
                tactic="Initial Access",
            ),
            MITREDocument(
                id="doc_powershell",
                content="PowerShell script execution for malware delivery",
                technique_id="T1059.001",
                name="PowerShell",
                tactic="Execution",
            ),
        ]
        vector_store.add_documents("mitre_attack", docs)

        # Search
        response = retrieval_service.search(
            query="phishing email",
            collection="mitre_attack",
            top_k=5,
        )

        assert response.query == "phishing email"
        assert response.collection == "mitre_attack"
        assert len(response.results) > 0
        assert response.execution_time_ms >= 0

    def test_search_similar_incidents(self, retrieval_service, vector_store):
        """Test incident search."""
        from tw_ai.rag.models import IncidentDocument

        docs = [
            IncidentDocument(
                id="incident_001",
                content="Phishing email from fake IT support requesting password reset",
                verdict="true_positive",
                severity="high",
                confidence=90,
                alert_type="phishing",
                alert_id="ALERT-001",
            ),
            IncidentDocument(
                id="incident_002",
                content="Legitimate IT notification about system maintenance",
                verdict="false_positive",
                severity="informational",
                confidence=95,
                alert_type="phishing",
                alert_id="ALERT-002",
            ),
        ]
        vector_store.add_documents("triage_incidents", docs)

        response = retrieval_service.search_similar_incidents(
            query="IT support password reset email",
            top_k=5,
        )

        assert len(response.results) > 0
        # Results should be sorted by similarity
        if len(response.results) > 1:
            assert response.results[0].similarity >= response.results[1].similarity

    def test_search_playbooks(self, retrieval_service, vector_store):
        """Test playbook search."""
        from tw_ai.rag.models import PlaybookDocument

        docs = [
            PlaybookDocument(
                id="playbook_phishing",
                content="Phishing email triage and response playbook",
                name="phishing-triage",
                trigger_types=["suspected_phishing"],
                stage_count=3,
            ),
            PlaybookDocument(
                id="playbook_malware",
                content="Malware analysis and containment playbook",
                name="malware-response",
                trigger_types=["malware_detected"],
                stage_count=4,
            ),
        ]
        vector_store.add_documents("security_playbooks", docs)

        response = retrieval_service.search_playbooks(
            query="how to handle phishing email",
            top_k=3,
        )

        assert len(response.results) > 0

    def test_search_mitre_techniques(self, retrieval_service, vector_store):
        """Test MITRE technique search."""
        from tw_ai.rag.models import MITREDocument

        docs = [
            MITREDocument(
                id="mitre_T1566",
                content="Phishing technique for initial access via email",
                technique_id="T1566",
                name="Phishing",
                tactic="Initial Access",
                is_subtechnique=False,
            ),
            MITREDocument(
                id="mitre_T1566.001",
                content="Spearphishing attachment with malicious file",
                technique_id="T1566.001",
                name="Spearphishing Attachment",
                tactic="Initial Access",
                is_subtechnique=True,
                parent_technique_id="T1566",
            ),
        ]
        vector_store.add_documents("mitre_attack", docs)

        response = retrieval_service.search_mitre_techniques(
            query="email with malicious attachment",
            top_k=5,
        )

        assert len(response.results) > 0
        # Should find techniques related to phishing/attachments
        technique_ids = [r.metadata.get("technique_id") for r in response.results]
        assert any("T1566" in tid for tid in technique_ids if tid)

    def test_search_threat_intel(self, retrieval_service, vector_store):
        """Test threat intel search."""
        from tw_ai.rag.models import ThreatIntelDocument

        docs = [
            ThreatIntelDocument(
                id="ti_001",
                content="Malicious IP associated with APT29 C2 infrastructure",
                indicator="192.168.1.100",
                indicator_type="ip",
                verdict="malicious",
                threat_actor="APT29",
                confidence=95,
            ),
            ThreatIntelDocument(
                id="ti_002",
                content="Suspicious domain used in phishing campaign",
                indicator="evil-paypal.com",
                indicator_type="domain",
                verdict="malicious",
                confidence=85,
            ),
        ]
        vector_store.add_documents("threat_intelligence", docs)

        response = retrieval_service.search_threat_intel(
            query="APT29 command and control",
            top_k=5,
        )

        assert len(response.results) > 0

    def test_search_with_min_similarity(self, retrieval_service, vector_store):
        """Test similarity threshold filtering."""
        from tw_ai.rag.models import MITREDocument

        docs = [
            MITREDocument(
                id="doc_1",
                content="Phishing attack",
                technique_id="T1566",
                name="Phishing",
                tactic="Initial Access",
            ),
        ]
        vector_store.add_documents("mitre_attack", docs)

        # High threshold should filter out low-similarity results
        response = retrieval_service.search(
            query="completely unrelated query about cooking recipes",
            collection="mitre_attack",
            min_similarity=0.99,  # Very high threshold
        )

        # With mock embeddings, results may vary but threshold should be applied
        assert all(r.similarity >= 0.99 for r in response.results)

    def test_search_with_filters(self, retrieval_service, vector_store):
        """Test search with metadata filters."""
        from tw_ai.rag.models import IncidentDocument

        docs = [
            IncidentDocument(
                id="inc_critical",
                content="Critical ransomware attack",
                verdict="true_positive",
                severity="critical",
                confidence=98,
                alert_type="malware",
                alert_id="ALERT-C1",
            ),
            IncidentDocument(
                id="inc_low",
                content="Low severity test alert",
                verdict="false_positive",
                severity="low",
                confidence=90,
                alert_type="test",
                alert_id="ALERT-L1",
            ),
        ]
        vector_store.add_documents("triage_incidents", docs)

        response = retrieval_service.search_similar_incidents(
            query="ransomware",
            verdict="true_positive",
            severity="critical",
        )

        # Should only return the critical incident
        for result in response.results:
            if result.metadata.get("verdict"):
                assert result.metadata.get("verdict") == "true_positive"

    def test_distance_to_similarity(self, retrieval_service):
        """Test distance to similarity conversion."""
        # Cosine distance: similarity = 1 - distance
        assert retrieval_service._distance_to_similarity(0.0) == 1.0
        assert retrieval_service._distance_to_similarity(1.0) == 0.0
        assert retrieval_service._distance_to_similarity(0.5) == 0.5

        # Should clamp to [0, 1]
        assert retrieval_service._distance_to_similarity(-0.5) == 1.0
        assert retrieval_service._distance_to_similarity(1.5) == 0.0
