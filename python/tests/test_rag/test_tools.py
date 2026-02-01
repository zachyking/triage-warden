"""Tests for RAG agent tools."""

from __future__ import annotations

import pytest


class TestRAGTools:
    """Tests for RAG tools."""

    @pytest.fixture
    def rag_tools(self, retrieval_service):
        """Create RAG tools for testing."""
        from tw_ai.rag.tools import create_rag_tools

        return create_rag_tools(retrieval_service)

    def test_create_rag_tools(self, retrieval_service):
        """Test RAG tools creation."""
        from tw_ai.rag.tools import create_rag_tools

        tools = create_rag_tools(retrieval_service)

        assert len(tools) == 4

        tool_names = [t.name for t in tools]
        assert "search_similar_incidents" in tool_names
        assert "search_playbooks" in tool_names
        assert "search_mitre_techniques" in tool_names
        assert "search_threat_intel" in tool_names

    def test_tool_definitions(self, rag_tools):
        """Test tool definitions are valid."""
        for tool in rag_tools:
            assert tool.name
            assert tool.description
            assert tool.parameters
            assert tool.handler is not None

            # Check parameters structure
            params = tool.parameters
            assert params["type"] == "object"
            assert "properties" in params
            assert "query" in params["properties"]
            assert "required" in params
            assert "query" in params["required"]

    @pytest.mark.asyncio
    async def test_search_similar_incidents_tool(self, rag_tools, vector_store):
        """Test search_similar_incidents tool execution."""
        from tw_ai.rag.models import IncidentDocument

        # Add test data
        docs = [
            IncidentDocument(
                id="test_incident",
                content="Phishing email with credential harvesting",
                verdict="true_positive",
                severity="high",
                confidence=90,
                alert_type="phishing",
                alert_id="TEST-001",
            ),
        ]
        vector_store.add_documents("triage_incidents", docs)

        # Get the tool
        tool = next(t for t in rag_tools if t.name == "search_similar_incidents")

        # Execute
        result = await tool.handler(query="phishing credential theft")

        assert result.success is True
        assert "incidents" in result.data
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_search_playbooks_tool(self, rag_tools, vector_store):
        """Test search_playbooks tool execution."""
        from tw_ai.rag.models import PlaybookDocument

        docs = [
            PlaybookDocument(
                id="test_playbook",
                content="Phishing response playbook",
                name="phishing-triage",
                trigger_types=["suspected_phishing"],
                stage_count=3,
            ),
        ]
        vector_store.add_documents("security_playbooks", docs)

        tool = next(t for t in rag_tools if t.name == "search_playbooks")
        result = await tool.handler(query="how to respond to phishing")

        assert result.success is True
        assert "playbooks" in result.data

    @pytest.mark.asyncio
    async def test_search_mitre_techniques_tool(self, rag_tools, vector_store):
        """Test search_mitre_techniques tool execution."""
        from tw_ai.rag.models import MITREDocument

        docs = [
            MITREDocument(
                id="test_mitre",
                content="Phishing technique for initial access",
                technique_id="T1566",
                name="Phishing",
                tactic="Initial Access",
            ),
        ]
        vector_store.add_documents("mitre_attack", docs)

        tool = next(t for t in rag_tools if t.name == "search_mitre_techniques")
        result = await tool.handler(query="email social engineering attack")

        assert result.success is True
        assert "techniques" in result.data

    @pytest.mark.asyncio
    async def test_search_threat_intel_tool(self, rag_tools, vector_store):
        """Test search_threat_intel tool execution."""
        from tw_ai.rag.models import ThreatIntelDocument

        docs = [
            ThreatIntelDocument(
                id="test_intel",
                content="Malicious IP used by APT29",
                indicator="192.168.1.100",
                indicator_type="ip",
                verdict="malicious",
                threat_actor="APT29",
            ),
        ]
        vector_store.add_documents("threat_intelligence", docs)

        tool = next(t for t in rag_tools if t.name == "search_threat_intel")
        result = await tool.handler(query="APT29 infrastructure")

        assert result.success is True
        assert "intel" in result.data

    @pytest.mark.asyncio
    async def test_tool_error_handling(self, retrieval_service):
        """Test tool error handling."""
        from unittest.mock import patch
        from tw_ai.rag.tools import create_rag_tools

        tools = create_rag_tools(retrieval_service)
        tool = next(t for t in tools if t.name == "search_similar_incidents")

        # Simulate an error
        with patch.object(
            retrieval_service,
            "search_similar_incidents",
            side_effect=Exception("Database error"),
        ):
            result = await tool.handler(query="test query")

            assert result.success is False
            assert "Incident search failed" in result.error

    def test_register_rag_tools(self, retrieval_service):
        """Test registering RAG tools with ToolRegistry."""
        from tw_ai.agents.tools import ToolRegistry
        from tw_ai.rag.tools import register_rag_tools

        registry = ToolRegistry()
        register_rag_tools(registry, retrieval_service)

        tool_names = registry.list_tools()
        assert "search_similar_incidents" in tool_names
        assert "search_playbooks" in tool_names
        assert "search_mitre_techniques" in tool_names
        assert "search_threat_intel" in tool_names


class TestRAGService:
    """Tests for RAGService facade."""

    def test_create_rag_service(self, rag_config, mock_sentence_transformer):
        """Test RAGService creation."""
        from tw_ai.rag import create_rag_service

        service = create_rag_service(rag_config)

        assert service is not None
        assert service.config == rag_config

    def test_rag_service_lazy_loading(self, rag_config, mock_sentence_transformer):
        """Test RAGService lazy loading of components."""
        from tw_ai.rag import RAGService

        service = RAGService(rag_config)

        # Components should not be loaded yet
        assert service._embedding is None
        assert service._vector_store is None
        assert service._retrieval is None

        # Access embedding to trigger load
        _ = service.embedding
        assert service._embedding is not None

        # Access vector_store
        _ = service.vector_store
        assert service._vector_store is not None

        # Access retrieval
        _ = service.retrieval
        assert service._retrieval is not None

    @pytest.mark.asyncio
    async def test_rag_service_ingest_mitre(self, rag_config, mock_sentence_transformer):
        """Test MITRE ingestion via RAGService."""
        from tw_ai.rag import create_rag_service

        service = create_rag_service(rag_config)
        count = await service.ingest_mitre()

        assert count > 0

    @pytest.mark.asyncio
    async def test_rag_service_ingest_playbooks(
        self, rag_config, mock_sentence_transformer, sample_playbook_dir
    ):
        """Test playbook ingestion via RAGService."""
        from tw_ai.rag import create_rag_service

        service = create_rag_service(rag_config)
        count = await service.ingest_playbooks(str(sample_playbook_dir))

        assert count == 2

    @pytest.mark.asyncio
    async def test_rag_service_ingest_incident(
        self, rag_config, mock_sentence_transformer
    ):
        """Test incident ingestion via RAGService."""
        from tw_ai.rag import create_rag_service
        from tw_ai.agents.models import TriageAnalysis

        service = create_rag_service(rag_config)

        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="medium",
            summary="Test incident",
        )

        doc_id = await service.ingest_incident(
            analysis=analysis,
            alert_id="TEST-001",
            alert_type="test",
        )

        assert doc_id.startswith("incident_TEST-001")

    @pytest.mark.asyncio
    async def test_rag_service_ingest_threat_intel(
        self, rag_config, mock_sentence_transformer
    ):
        """Test threat intel ingestion via RAGService."""
        from tw_ai.rag import create_rag_service

        service = create_rag_service(rag_config)

        doc_id = await service.ingest_threat_intel(
            indicator="evil.com",
            indicator_type="domain",
            verdict="malicious",
            context="Known phishing domain",
            threat_actor="APT28",
        )

        assert doc_id.startswith("ti_domain_")
