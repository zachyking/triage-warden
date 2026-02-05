"""Tests for RAG-Enhanced Analysis (Task 2.3.4)."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tw_ai.analysis.rag_analyzer import (
    ContextSource,
    ContextSourceType,
    RAGAnalysisConfig,
    RAGAnalysisResult,
    RAGContext,
    RAGContextBuilder,
    RAGEnhancedAnalyzer,
    create_rag_analyzer,
)


# =============================================================================
# RAGContext Tests
# =============================================================================


class TestRAGContext:
    """Tests for RAGContext data class."""

    def test_empty_context(self):
        """Test empty RAG context."""
        context = RAGContext()
        assert context.total_sources == 0
        assert context.is_empty is True
        assert context.all_sources() == []

    def test_context_with_sources(self):
        """Test RAG context with various sources."""
        incident = ContextSource(
            source_type=ContextSourceType.SIMILAR_INCIDENT,
            document_id="inc-001",
            similarity_score=0.85,
            content_summary="Previous phishing incident",
            metadata={"verdict": "true_positive"},
        )
        playbook = ContextSource(
            source_type=ContextSourceType.PLAYBOOK,
            document_id="pb-phishing",
            similarity_score=0.72,
            content_summary="Phishing triage playbook",
            metadata={"name": "phishing-triage"},
        )

        context = RAGContext(
            similar_incidents=[incident],
            playbooks=[playbook],
            retrieval_time_ms=150,
        )

        assert context.total_sources == 2
        assert context.is_empty is False
        assert len(context.all_sources()) == 2
        assert context.retrieval_time_ms == 150

    def test_citation_summary(self):
        """Test citation summary generation."""
        context = RAGContext(
            similar_incidents=[
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id="inc-001",
                    similarity_score=0.85,
                    content_summary="Test incident",
                    metadata={},
                )
            ],
            mitre_techniques=[
                ContextSource(
                    source_type=ContextSourceType.MITRE_TECHNIQUE,
                    document_id="T1566",
                    similarity_score=0.78,
                    content_summary="Phishing technique",
                    metadata={"technique_id": "T1566"},
                )
            ],
            retrieval_time_ms=100,
        )

        summary = context.get_citation_summary()
        assert summary["total_sources"] == 2
        assert summary["retrieval_time_ms"] == 100
        assert summary["sources_by_type"]["similar_incidents"] == 1
        assert summary["sources_by_type"]["mitre_techniques"] == 1
        assert len(summary["documents"]) == 2


# =============================================================================
# RAGContextBuilder Tests
# =============================================================================


class TestRAGContextBuilder:
    """Tests for RAGContextBuilder."""

    def test_empty_context_string(self):
        """Test building context string from empty context."""
        builder = RAGContextBuilder()
        context = RAGContext()
        result = builder.build_context_string(context)
        assert result == ""

    def test_context_string_with_incidents(self):
        """Test building context string with similar incidents."""
        builder = RAGContextBuilder(max_tokens=1000)
        context = RAGContext(
            similar_incidents=[
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id="inc-001",
                    similarity_score=0.85,
                    content_summary="Email from suspicious domain with credential harvesting link",
                    metadata={
                        "verdict": "true_positive",
                        "severity": "high",
                        "confidence": 90,
                    },
                ),
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id="inc-002",
                    similarity_score=0.72,
                    content_summary="False alarm from marketing email system",
                    metadata={
                        "verdict": "false_positive",
                        "severity": "low",
                        "confidence": 85,
                    },
                ),
            ]
        )

        result = builder.build_context_string(context)

        assert "Organizational Context" in result
        assert "Similar Past Incidents" in result
        assert "inc-001" in result
        assert "true_positive" in result
        assert "85%" in result  # Similarity percentage

    def test_context_string_with_playbooks(self):
        """Test building context string with playbooks."""
        builder = RAGContextBuilder()
        context = RAGContext(
            playbooks=[
                ContextSource(
                    source_type=ContextSourceType.PLAYBOOK,
                    document_id="pb-001",
                    similarity_score=0.80,
                    content_summary="Phishing response playbook with email analysis steps",
                    metadata={"name": "Phishing Triage", "version": "2.0"},
                )
            ]
        )

        result = builder.build_context_string(context)

        assert "Relevant Playbooks" in result
        assert "Phishing Triage" in result
        assert "v2.0" in result

    def test_context_string_with_mitre(self):
        """Test building context string with MITRE techniques."""
        builder = RAGContextBuilder()
        context = RAGContext(
            mitre_techniques=[
                ContextSource(
                    source_type=ContextSourceType.MITRE_TECHNIQUE,
                    document_id="T1566.001",
                    similarity_score=0.88,
                    content_summary="Spearphishing Attachment",
                    metadata={
                        "technique_id": "T1566.001",
                        "name": "Spearphishing Attachment",
                        "tactic": "Initial Access",
                    },
                )
            ]
        )

        result = builder.build_context_string(context)

        assert "MITRE ATT&CK Techniques" in result
        assert "T1566.001" in result
        assert "Initial Access" in result

    def test_context_truncation(self):
        """Test that context is truncated to fit within limits."""
        builder = RAGContextBuilder(max_tokens=100, chars_per_token=4)  # 400 chars max

        # Create context that would exceed the limit
        long_summary = "A" * 300
        context = RAGContext(
            similar_incidents=[
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id=f"inc-{i}",
                    similarity_score=0.8,
                    content_summary=long_summary,
                    metadata={"verdict": "true_positive", "severity": "high", "confidence": 90},
                )
                for i in range(10)
            ]
        )

        result = builder.build_context_string(context)

        # Result should be truncated (won't include all 10 incidents)
        assert len(result) <= 800  # Allow some overhead for headers

    def test_context_string_all_sources(self):
        """Test building context string with all source types."""
        builder = RAGContextBuilder(max_tokens=2000)
        context = RAGContext(
            similar_incidents=[
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id="inc-001",
                    similarity_score=0.85,
                    content_summary="Past incident",
                    metadata={"verdict": "true_positive", "severity": "high", "confidence": 90},
                )
            ],
            playbooks=[
                ContextSource(
                    source_type=ContextSourceType.PLAYBOOK,
                    document_id="pb-001",
                    similarity_score=0.75,
                    content_summary="Playbook content",
                    metadata={"name": "Test Playbook", "version": "1.0"},
                )
            ],
            mitre_techniques=[
                ContextSource(
                    source_type=ContextSourceType.MITRE_TECHNIQUE,
                    document_id="T1566",
                    similarity_score=0.82,
                    content_summary="Phishing technique",
                    metadata={
                        "technique_id": "T1566",
                        "name": "Phishing",
                        "tactic": "Initial Access",
                    },
                )
            ],
            threat_intel=[
                ContextSource(
                    source_type=ContextSourceType.THREAT_INTEL,
                    document_id="ti-001",
                    similarity_score=0.70,
                    content_summary="Threat intel indicator",
                    metadata={
                        "indicator": "evil.com",
                        "indicator_type": "domain",
                        "verdict": "malicious",
                    },
                )
            ],
        )

        result = builder.build_context_string(context)

        assert "Similar Past Incidents" in result
        assert "Relevant Playbooks" in result
        assert "MITRE ATT&CK Techniques" in result
        assert "Threat Intelligence" in result


# =============================================================================
# RAGAnalysisConfig Tests
# =============================================================================


class TestRAGAnalysisConfig:
    """Tests for RAGAnalysisConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = RAGAnalysisConfig()

        assert config.similar_incidents_k == 3
        assert config.playbooks_k == 2
        assert config.mitre_techniques_k == 3
        assert config.threat_intel_k == 3
        assert config.min_incident_similarity == 0.4
        assert config.enable_similar_incidents is True
        assert config.fallback_on_retrieval_error is True

    def test_custom_config(self):
        """Test custom configuration."""
        config = RAGAnalysisConfig(
            similar_incidents_k=5,
            min_incident_similarity=0.6,
            enable_threat_intel=False,
        )

        assert config.similar_incidents_k == 5
        assert config.min_incident_similarity == 0.6
        assert config.enable_threat_intel is False


# =============================================================================
# RAGEnhancedAnalyzer Tests
# =============================================================================


class TestRAGEnhancedAnalyzer:
    """Tests for RAGEnhancedAnalyzer."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock ReAct agent."""
        agent = MagicMock()
        agent.run = AsyncMock()
        return agent

    @pytest.fixture
    def mock_rag_service(self):
        """Create a mock RAG service."""
        service = MagicMock()
        service.retrieval = MagicMock()

        # Mock retrieval methods to return empty results
        empty_response = MagicMock()
        empty_response.results = []

        service.retrieval.search_similar_incidents.return_value = empty_response
        service.retrieval.search_playbooks.return_value = empty_response
        service.retrieval.search_mitre_techniques.return_value = empty_response
        service.retrieval.search_threat_intel.return_value = empty_response

        return service

    @pytest.fixture
    def mock_triage_request(self):
        """Create a mock triage request."""
        from tw_ai.agents.react import TriageRequest

        return TriageRequest(
            alert_type="phishing",
            alert_data={
                "subject": "Urgent: Verify your account",
                "sender": "security@ev1l-bank.com",
                "recipient": "user@company.com",
                "body": "Click here to verify your credentials",
            },
        )

    def test_analyzer_initialization(self, mock_agent, mock_rag_service):
        """Test analyzer initialization."""
        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
        )

        assert analyzer._agent is mock_agent
        assert analyzer._rag_service is mock_rag_service
        assert analyzer._config is not None

    def test_analyzer_with_custom_config(self, mock_agent, mock_rag_service):
        """Test analyzer with custom configuration."""
        config = RAGAnalysisConfig(
            similar_incidents_k=5,
            enable_threat_intel=False,
        )
        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
            config=config,
        )

        assert analyzer._config.similar_incidents_k == 5
        assert analyzer._config.enable_threat_intel is False

    @pytest.mark.asyncio
    async def test_analyze_returns_result(
        self,
        mock_agent,
        mock_rag_service,
        mock_triage_request,
    ):
        """Test that analyze returns a RAGAnalysisResult."""
        from tw_ai.agents.models import TriageAnalysis
        from tw_ai.agents.react import AgentResult

        # Configure mock agent response
        mock_analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Phishing attempt detected",
        )
        mock_agent.run.return_value = AgentResult(
            success=True,
            analysis=mock_analysis,
            tokens_used=500,
            execution_time_seconds=2.5,
        )

        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
        )

        result = await analyzer.analyze(mock_triage_request)

        assert isinstance(result, RAGAnalysisResult)
        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.verdict == "true_positive"
        assert result.rag_enabled is True

    @pytest.mark.asyncio
    async def test_analyze_retrieves_context(
        self,
        mock_agent,
        mock_rag_service,
        mock_triage_request,
    ):
        """Test that analyze retrieves context from RAG service."""
        from tw_ai.agents.react import AgentResult
        from tw_ai.rag.models import QueryResponse, QueryResult

        # Configure mock retrieval responses
        incident_response = MagicMock(spec=QueryResponse)
        incident_response.results = [
            QueryResult(
                id="inc-001",
                content="Previous phishing case",
                similarity=0.85,
                metadata={"verdict": "true_positive", "severity": "high", "confidence": 90},
            )
        ]
        mock_rag_service.retrieval.search_similar_incidents.return_value = incident_response

        playbook_response = MagicMock(spec=QueryResponse)
        playbook_response.results = [
            QueryResult(
                id="pb-001",
                content="Phishing playbook",
                similarity=0.75,
                metadata={"name": "Phishing Triage", "version": "1.0"},
            )
        ]
        mock_rag_service.retrieval.search_playbooks.return_value = playbook_response

        # Configure agent response
        mock_agent.run.return_value = AgentResult(
            success=True,
            analysis=None,
            tokens_used=500,
            execution_time_seconds=2.5,
        )

        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
        )

        result = await analyzer.analyze(mock_triage_request)

        # Verify retrieval was called
        mock_rag_service.retrieval.search_similar_incidents.assert_called_once()
        mock_rag_service.retrieval.search_playbooks.assert_called_once()

        # Verify context was collected
        assert len(result.rag_context.similar_incidents) == 1
        assert len(result.rag_context.playbooks) == 1

    @pytest.mark.asyncio
    async def test_analyze_without_rag(
        self,
        mock_agent,
        mock_rag_service,
        mock_triage_request,
    ):
        """Test analyze_without_rag bypasses RAG retrieval."""
        from tw_ai.agents.react import AgentResult

        mock_agent.run.return_value = AgentResult(
            success=True,
            analysis=None,
            tokens_used=300,
            execution_time_seconds=1.5,
        )

        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
        )

        result = await analyzer.analyze_without_rag(mock_triage_request)

        assert result.rag_enabled is False
        assert result.rag_context.is_empty is True
        mock_rag_service.retrieval.search_similar_incidents.assert_not_called()

    @pytest.mark.asyncio
    async def test_analyze_handles_retrieval_errors(
        self,
        mock_agent,
        mock_rag_service,
        mock_triage_request,
    ):
        """Test that analyze handles retrieval errors gracefully."""
        from tw_ai.agents.react import AgentResult

        # Make retrieval raise an exception
        mock_rag_service.retrieval.search_similar_incidents.side_effect = Exception(
            "Connection error"
        )

        mock_agent.run.return_value = AgentResult(
            success=True,
            analysis=None,
            tokens_used=300,
            execution_time_seconds=1.5,
        )

        config = RAGAnalysisConfig(fallback_on_retrieval_error=True)
        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
            config=config,
        )

        result = await analyzer.analyze(mock_triage_request)

        # Should still succeed with fallback
        assert result.success is True
        assert len(result.retrieval_errors) > 0
        assert "Connection error" in result.retrieval_errors[0]

    def test_generate_incident_description(
        self,
        mock_agent,
        mock_rag_service,
        mock_triage_request,
    ):
        """Test incident description generation from request."""
        analyzer = RAGEnhancedAnalyzer(
            agent=mock_agent,
            rag_service=mock_rag_service,
        )

        description = analyzer._generate_incident_description(mock_triage_request)

        assert "phishing" in description.lower()
        assert "security@ev1l-bank.com" in description or "sender" in description.lower()


# =============================================================================
# Factory Function Tests
# =============================================================================


class TestCreateRAGAnalyzer:
    """Tests for create_rag_analyzer factory function."""

    def test_create_with_provided_service(self):
        """Test creating analyzer with provided RAG service."""
        mock_agent = MagicMock()
        mock_service = MagicMock()

        analyzer = create_rag_analyzer(
            agent=mock_agent,
            rag_service=mock_service,
        )

        assert analyzer._agent is mock_agent
        assert analyzer._rag_service is mock_service

    def test_create_with_custom_config(self):
        """Test creating analyzer with custom analysis config."""
        mock_agent = MagicMock()
        mock_service = MagicMock()

        config = RAGAnalysisConfig(
            similar_incidents_k=10,
            enable_mitre_techniques=False,
        )

        analyzer = create_rag_analyzer(
            agent=mock_agent,
            rag_service=mock_service,
            analysis_config=config,
        )

        assert analyzer._config.similar_incidents_k == 10
        assert analyzer._config.enable_mitre_techniques is False


# =============================================================================
# RAGAnalysisResult Tests
# =============================================================================


class TestRAGAnalysisResult:
    """Tests for RAGAnalysisResult."""

    def test_get_metrics(self):
        """Test metrics extraction from result."""
        from tw_ai.agents.models import TriageAnalysis
        from tw_ai.agents.react import AgentResult

        agent_result = AgentResult(
            success=True,
            analysis=TriageAnalysis(
                verdict="true_positive",
                confidence=90,
                severity="high",
                summary="Test",
            ),
            tokens_used=500,
            execution_time_seconds=2.5,
        )

        rag_context = RAGContext(
            similar_incidents=[
                ContextSource(
                    source_type=ContextSourceType.SIMILAR_INCIDENT,
                    document_id="inc-001",
                    similarity_score=0.85,
                    content_summary="Test",
                    metadata={},
                )
            ],
            retrieval_time_ms=100,
        )

        result = RAGAnalysisResult(
            agent_result=agent_result,
            rag_context=rag_context,
            rag_enabled=True,
        )

        metrics = result.get_metrics()

        assert metrics["rag_enabled"] is True
        assert metrics["total_context_sources"] == 1
        assert metrics["retrieval_time_ms"] == 100
        assert metrics["agent_tokens_used"] == 500
        assert metrics["sources_used"]["similar_incidents"] == 1

    def test_success_property(self):
        """Test success property delegation."""
        from tw_ai.agents.react import AgentResult

        successful_result = RAGAnalysisResult(
            agent_result=AgentResult(success=True, tokens_used=0, execution_time_seconds=0),
            rag_context=RAGContext(),
        )
        failed_result = RAGAnalysisResult(
            agent_result=AgentResult(success=False, tokens_used=0, execution_time_seconds=0),
            rag_context=RAGContext(),
        )

        assert successful_result.success is True
        assert failed_result.success is False
