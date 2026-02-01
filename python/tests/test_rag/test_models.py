"""Tests for RAG data models."""

from __future__ import annotations

from datetime import datetime

import pytest


class TestDocumentModels:
    """Tests for document models."""

    def test_incident_document_creation(self):
        """Test IncidentDocument creation."""
        from tw_ai.rag.models import IncidentDocument

        doc = IncidentDocument(
            id="incident_001",
            content="Phishing email detected from suspicious sender",
            verdict="true_positive",
            severity="high",
            confidence=85,
            alert_type="phishing",
            alert_id="ALERT-001",
            technique_ids=["T1566", "T1566.001"],
            indicator_count=3,
        )

        assert doc.id == "incident_001"
        assert doc.verdict == "true_positive"
        assert doc.severity == "high"
        assert doc.confidence == 85
        assert doc.technique_ids == ["T1566", "T1566.001"]

    def test_incident_document_metadata(self):
        """Test IncidentDocument metadata conversion."""
        from tw_ai.rag.models import IncidentDocument

        doc = IncidentDocument(
            id="incident_001",
            content="Test content",
            verdict="false_positive",
            severity="low",
            confidence=90,
            alert_type="suspicious_login",
            alert_id="ALERT-002",
            technique_ids=["T1078"],
        )

        metadata = doc.to_metadata()

        assert metadata["verdict"] == "false_positive"
        assert metadata["severity"] == "low"
        assert metadata["confidence"] == 90
        assert metadata["alert_type"] == "suspicious_login"
        assert metadata["technique_ids"] == "T1078"
        assert "created_at" in metadata

    def test_playbook_document_creation(self):
        """Test PlaybookDocument creation."""
        from tw_ai.rag.models import PlaybookDocument

        doc = PlaybookDocument(
            id="playbook_phishing",
            content="Phishing triage playbook",
            name="phishing-triage",
            version="1.0",
            trigger_types=["suspected_phishing", "user_reported_phishing"],
            stage_count=3,
            has_branches=True,
        )

        assert doc.name == "phishing-triage"
        assert doc.trigger_types == ["suspected_phishing", "user_reported_phishing"]
        assert doc.has_branches is True

    def test_playbook_document_metadata(self):
        """Test PlaybookDocument metadata conversion."""
        from tw_ai.rag.models import PlaybookDocument

        doc = PlaybookDocument(
            id="playbook_test",
            content="Test",
            name="test-playbook",
            trigger_types=["alert_a", "alert_b"],
            stage_count=2,
        )

        metadata = doc.to_metadata()

        assert metadata["name"] == "test-playbook"
        assert metadata["trigger_types"] == "alert_a,alert_b"
        assert metadata["stage_count"] == 2

    def test_mitre_document_creation(self):
        """Test MITREDocument creation."""
        from tw_ai.rag.models import MITREDocument

        doc = MITREDocument(
            id="mitre_T1566",
            content="Phishing technique",
            technique_id="T1566",
            name="Phishing",
            tactic="Initial Access",
            is_subtechnique=False,
            keywords=["phishing", "email", "social engineering"],
        )

        assert doc.technique_id == "T1566"
        assert doc.tactic == "Initial Access"
        assert doc.is_subtechnique is False
        assert "phishing" in doc.keywords

    def test_mitre_subtechnique(self):
        """Test MITREDocument for sub-technique."""
        from tw_ai.rag.models import MITREDocument

        doc = MITREDocument(
            id="mitre_T1566.001",
            content="Spearphishing Attachment",
            technique_id="T1566.001",
            name="Spearphishing Attachment",
            tactic="Initial Access",
            is_subtechnique=True,
            parent_technique_id="T1566",
            keywords=["spearphishing", "attachment"],
        )

        assert doc.is_subtechnique is True
        assert doc.parent_technique_id == "T1566"

    def test_threat_intel_document_creation(self):
        """Test ThreatIntelDocument creation."""
        from tw_ai.rag.models import ThreatIntelDocument

        doc = ThreatIntelDocument(
            id="ti_ip_001",
            content="Malicious IP associated with APT29",
            indicator="192.168.1.100",
            indicator_type="ip",
            verdict="malicious",
            threat_actor="APT29",
            confidence=95,
        )

        assert doc.indicator == "192.168.1.100"
        assert doc.indicator_type == "ip"
        assert doc.verdict == "malicious"
        assert doc.threat_actor == "APT29"


class TestQueryModels:
    """Tests for query models."""

    def test_query_request_creation(self):
        """Test QueryRequest creation."""
        from tw_ai.rag.models import QueryRequest

        request = QueryRequest(
            query="phishing email with credential harvesting",
            collection="triage_incidents",
            top_k=10,
            min_similarity=0.5,
            filters={"verdict": "true_positive"},
        )

        assert request.query == "phishing email with credential harvesting"
        assert request.collection == "triage_incidents"
        assert request.top_k == 10
        assert request.min_similarity == 0.5
        assert request.filters == {"verdict": "true_positive"}

    def test_query_result_creation(self):
        """Test QueryResult creation."""
        from tw_ai.rag.models import QueryResult

        result = QueryResult(
            id="doc_001",
            content="Test content",
            similarity=0.85,
            metadata={"verdict": "true_positive"},
        )

        assert result.id == "doc_001"
        assert result.similarity == 0.85
        assert result.metadata["verdict"] == "true_positive"

    def test_query_response_creation(self):
        """Test QueryResponse creation."""
        from tw_ai.rag.models import QueryResponse, QueryResult

        results = [
            QueryResult(id="doc_001", content="Content 1", similarity=0.9),
            QueryResult(id="doc_002", content="Content 2", similarity=0.8),
        ]

        response = QueryResponse(
            query="test query",
            collection="test_collection",
            results=results,
            total_results=2,
            execution_time_ms=50,
        )

        assert response.query == "test query"
        assert len(response.results) == 2
        assert response.total_results == 2
        assert response.execution_time_ms == 50

    def test_confidence_validation(self):
        """Test confidence score validation."""
        from tw_ai.rag.models import IncidentDocument

        # Valid confidence
        doc = IncidentDocument(
            id="test",
            content="test",
            verdict="suspicious",
            severity="medium",
            confidence=50,
            alert_type="test",
            alert_id="test",
        )
        assert doc.confidence == 50

        # Invalid - below minimum
        with pytest.raises(ValueError):
            IncidentDocument(
                id="test",
                content="test",
                verdict="suspicious",
                severity="medium",
                confidence=-1,
                alert_type="test",
                alert_id="test",
            )

        # Invalid - above maximum
        with pytest.raises(ValueError):
            IncidentDocument(
                id="test",
                content="test",
                verdict="suspicious",
                severity="medium",
                confidence=101,
                alert_type="test",
                alert_id="test",
            )
