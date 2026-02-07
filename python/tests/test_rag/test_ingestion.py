"""Tests for ingestion pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestMITREIngester:
    """Tests for MITREIngester."""

    @pytest.mark.asyncio
    async def test_ingest_mitre(self, vector_store):
        """Test MITRE technique ingestion."""
        from tw_ai.rag.ingestion import MITREIngester

        ingester = MITREIngester(vector_store)
        count = await ingester.ingest()

        # Should ingest techniques from MITRE_MAPPINGS
        assert count > 0

        # Verify documents were added
        collection_count = vector_store.collection_count("mitre_attack")
        assert collection_count == count

    @pytest.mark.asyncio
    async def test_ingest_mitre_content(self, vector_store):
        """Test MITRE ingestion content format."""
        from tw_ai.rag.ingestion import MITREIngester

        ingester = MITREIngester(vector_store)
        await ingester.ingest()

        # Query for a known technique
        results = vector_store.query(
            collection_name="mitre_attack",
            query_text="phishing email attack",
            n_results=5,
        )

        assert results is not None
        assert len(results["ids"][0]) > 0

        # Check metadata
        if results["metadatas"][0]:
            metadata = results["metadatas"][0][0]
            assert "technique_id" in metadata
            assert "tactic" in metadata


class TestPlaybookIngester:
    """Tests for PlaybookIngester."""

    @pytest.mark.asyncio
    async def test_ingest_playbooks(self, vector_store, sample_playbook_dir):
        """Test playbook ingestion from YAML files."""
        from tw_ai.rag.ingestion import PlaybookIngester

        ingester = PlaybookIngester(vector_store)
        count = await ingester.ingest(sample_playbook_dir)

        # Should ingest 2 sample playbooks
        assert count == 2

        # Verify documents were added
        collection_count = vector_store.collection_count("security_playbooks")
        assert collection_count == 2

    @pytest.mark.asyncio
    async def test_ingest_playbooks_missing_dir(self, vector_store, tmp_path):
        """Test playbook ingestion with missing directory."""
        from tw_ai.rag.ingestion import PlaybookIngester

        ingester = PlaybookIngester(vector_store)
        count = await ingester.ingest(tmp_path / "nonexistent")

        assert count == 0

    @pytest.mark.asyncio
    async def test_ingest_playbooks_metadata(self, vector_store, sample_playbook_dir):
        """Test playbook metadata extraction."""
        from tw_ai.rag.ingestion import PlaybookIngester

        ingester = PlaybookIngester(vector_store)
        await ingester.ingest(sample_playbook_dir)

        # Query for phishing playbook
        results = vector_store.query(
            collection_name="security_playbooks",
            query_text="phishing email triage",
            n_results=5,
        )

        assert len(results["metadatas"][0]) > 0
        metadata = results["metadatas"][0][0]
        assert "name" in metadata
        assert "stage_count" in metadata


class TestIncidentIngester:
    """Tests for IncidentIngester."""

    @pytest.mark.asyncio
    async def test_ingest_analysis(self, vector_store):
        """Test incident ingestion from TriageAnalysis."""
        from tw_ai.rag.ingestion import IncidentIngester
        from tw_ai.agents.models import (
            TriageAnalysis,
            Indicator,
            MITRETechnique,
            RecommendedAction,
        )

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=90,
            severity="high",
            summary="Phishing email attempting credential theft",
            reasoning="Email contains malicious URL and requests login credentials",
            indicators=[
                Indicator(
                    type="url",
                    value="http://evil.com/login",
                    verdict="malicious",
                ),
            ],
            mitre_techniques=[
                MITRETechnique(
                    id="T1566",
                    name="Phishing",
                    tactic="Initial Access",
                    relevance="Phishing email attack",
                ),
            ],
            recommended_actions=[
                RecommendedAction(
                    action="Block sender domain",
                    priority="high",
                    reason="Prevent further phishing",
                ),
            ],
        )

        ingester = IncidentIngester(vector_store)
        doc_id = await ingester.ingest_analysis(
            analysis=analysis,
            alert_id="ALERT-001",
            alert_type="phishing",
        )

        assert doc_id.startswith("incident_ALERT-001")

        # Verify document was added
        assert vector_store.collection_count("triage_incidents") == 1

    @pytest.mark.asyncio
    async def test_ingest_analysis_content(self, vector_store):
        """Test incident content format."""
        from tw_ai.rag.ingestion import IncidentIngester
        from tw_ai.agents.models import TriageAnalysis

        analysis = TriageAnalysis(
            verdict="false_positive",
            confidence=95,
            severity="low",
            summary="Legitimate IT notification misclassified",
        )

        ingester = IncidentIngester(vector_store)
        await ingester.ingest_analysis(
            analysis=analysis,
            alert_id="ALERT-002",
            alert_type="phishing",
        )

        # Query for the incident
        results = vector_store.query(
            collection_name="triage_incidents",
            query_text="IT notification",
            n_results=5,
        )

        assert len(results["documents"][0]) > 0
        content = results["documents"][0][0]
        assert "false_positive" in content
        assert "95" in content  # confidence

    @pytest.mark.asyncio
    async def test_ingest_batch_via_ingest(self, vector_store):
        """Test batch incident ingestion through ingest()."""
        from tw_ai.agents.models import TriageAnalysis
        from tw_ai.rag.ingestion import IncidentIngester

        analyses = [
            {
                "analysis": TriageAnalysis(
                    verdict="true_positive",
                    confidence=91,
                    severity="high",
                    summary="Credential phishing campaign detected",
                ),
                "alert_id": "ALERT-BATCH-001",
                "alert_type": "phishing",
            },
            {
                "analysis": TriageAnalysis(
                    verdict="false_positive",
                    confidence=87,
                    severity="low",
                    summary="Benign administrative script activity",
                ),
                "alert_id": "ALERT-BATCH-002",
                "alert_type": "script",
            },
        ]

        ingester = IncidentIngester(vector_store)
        count = await ingester.ingest(analyses)

        assert count == 2
        assert vector_store.collection_count("triage_incidents") == 2


class TestThreatIntelIngester:
    """Tests for ThreatIntelIngester."""

    @pytest.mark.asyncio
    async def test_ingest_indicator(self, vector_store):
        """Test single indicator ingestion."""
        from tw_ai.rag.ingestion import ThreatIntelIngester

        ingester = ThreatIntelIngester(vector_store)
        doc_id = await ingester.ingest_indicator(
            indicator="192.168.1.100",
            indicator_type="ip",
            verdict="malicious",
            context="C2 server for APT29",
            threat_actor="APT29",
            confidence=95,
        )

        assert doc_id.startswith("ti_ip_")
        assert vector_store.collection_count("threat_intelligence") == 1

    @pytest.mark.asyncio
    async def test_ingest_batch(self, vector_store):
        """Test batch indicator ingestion."""
        from tw_ai.rag.ingestion import ThreatIntelIngester

        indicators = [
            {
                "indicator": "evil.com",
                "indicator_type": "domain",
                "verdict": "malicious",
                "context": "Phishing domain",
            },
            {
                "indicator": "10.0.0.1",
                "indicator_type": "ip",
                "verdict": "suspicious",
                "context": "Unusual traffic source",
                "threat_actor": "Unknown",
            },
            {
                "indicator": "abc123def456",
                "indicator_type": "hash",
                "verdict": "malicious",
                "context": "Known malware hash",
                "confidence": 90,
            },
        ]

        ingester = ThreatIntelIngester(vector_store)
        count = await ingester.ingest_batch(indicators)

        assert count == 3
        assert vector_store.collection_count("threat_intelligence") == 3

    @pytest.mark.asyncio
    async def test_ingest_indicator_metadata(self, vector_store):
        """Test indicator metadata storage."""
        from tw_ai.rag.ingestion import ThreatIntelIngester

        ingester = ThreatIntelIngester(vector_store)
        await ingester.ingest_indicator(
            indicator="malware.evil.com",
            indicator_type="domain",
            verdict="malicious",
            context="Malware distribution domain",
            threat_actor="FIN7",
            confidence=88,
        )

        results = vector_store.query(
            collection_name="threat_intelligence",
            query_text="malware distribution",
            n_results=1,
        )

        metadata = results["metadatas"][0][0]
        assert metadata["indicator_type"] == "domain"
        assert metadata["verdict"] == "malicious"
        assert metadata["threat_actor"] == "FIN7"
        assert metadata["confidence"] == 88

    @pytest.mark.asyncio
    async def test_ingest_wrapper_uses_batch_path(self, vector_store):
        """Test threat intel ingest() wrapper for batch payloads."""
        from tw_ai.rag.ingestion import ThreatIntelIngester

        indicators = [
            {
                "indicator": "bad.example",
                "indicator_type": "domain",
                "verdict": "malicious",
                "context": "Known phishing landing domain",
            },
            {
                "indicator": "203.0.113.10",
                "indicator_type": "ip",
                "verdict": "suspicious",
                "context": "Observed scanning activity",
                "confidence": 72,
            },
        ]

        ingester = ThreatIntelIngester(vector_store)
        count = await ingester.ingest(indicators)

        assert count == 2
        assert vector_store.collection_count("threat_intelligence") == 2
