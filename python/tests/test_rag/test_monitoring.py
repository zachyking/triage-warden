"""Tests for RAG monitoring and metrics (Task 2.3.5)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tw_ai.rag.monitoring import (
    AggregatedMetrics,
    AnalysisMetrics,
    ExperimentVariant,
    MetricType,
    RAGMonitor,
    RetrievalMetrics,
    get_rag_monitor,
    reset_rag_monitor,
)


# =============================================================================
# Helper Fixtures
# =============================================================================


@pytest.fixture
def mock_rag_analysis_result():
    """Create a mock RAGAnalysisResult."""
    from tw_ai.agents.models import TriageAnalysis
    from tw_ai.agents.react import AgentResult
    from tw_ai.analysis.rag_analyzer import (
        ContextSource,
        ContextSourceType,
        RAGAnalysisResult,
        RAGContext,
    )

    agent_result = AgentResult(
        success=True,
        analysis=TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Test analysis",
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
                content_summary="Test incident",
                metadata={"verdict": "true_positive"},
            )
        ],
        playbooks=[
            ContextSource(
                source_type=ContextSourceType.PLAYBOOK,
                document_id="pb-001",
                similarity_score=0.75,
                content_summary="Test playbook",
                metadata={"name": "Test"},
            )
        ],
        retrieval_time_ms=100,
    )

    return RAGAnalysisResult(
        agent_result=agent_result,
        rag_context=rag_context,
        rag_enabled=True,
        retrieval_errors=[],
    )


@pytest.fixture
def monitor():
    """Create a fresh RAG monitor for testing."""
    return RAGMonitor(max_history=100, enable_detailed_logging=False)


# =============================================================================
# AnalysisMetrics Tests
# =============================================================================


class TestAnalysisMetrics:
    """Tests for AnalysisMetrics data class."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        now = datetime.now(timezone.utc)
        metrics = AnalysisMetrics(
            timestamp=now,
            analysis_id="test-001",
            rag_enabled=True,
            success=True,
            retrieval_time_ms=100,
            agent_time_ms=2000,
            total_time_ms=2100,
            context_sources=3,
            avg_similarity=0.75,
            verdict="true_positive",
            confidence=85,
            experiment_variant=ExperimentVariant.RAG_ENABLED,
        )

        data = metrics.to_dict()

        assert data["analysis_id"] == "test-001"
        assert data["rag_enabled"] is True
        assert data["success"] is True
        assert data["retrieval_time_ms"] == 100
        assert data["avg_similarity"] == 0.75
        assert data["experiment_variant"] == "rag_enabled"


class TestRetrievalMetrics:
    """Tests for RetrievalMetrics data class."""

    def test_to_dict(self):
        """Test serialization to dictionary."""
        now = datetime.now(timezone.utc)
        metrics = RetrievalMetrics(
            timestamp=now,
            retrieval_time_ms=150,
            sources_retrieved={
                "similar_incidents": 2,
                "playbooks": 1,
            },
            avg_similarity_by_source={
                "similar_incidents": 0.8,
                "playbooks": 0.6,
            },
            total_sources=3,
            errors=[],
        )

        data = metrics.to_dict()

        assert data["retrieval_time_ms"] == 150
        assert data["total_sources"] == 3
        assert data["sources_retrieved"]["similar_incidents"] == 2


# =============================================================================
# AggregatedMetrics Tests
# =============================================================================


class TestAggregatedMetrics:
    """Tests for AggregatedMetrics data class."""

    def test_success_rate_calculation(self):
        """Test success rate property calculation."""
        now = datetime.now(timezone.utc)
        metrics = AggregatedMetrics(
            period_start=now - timedelta(hours=1),
            period_end=now,
            total_analyses=10,
            successful_analyses=8,
        )

        assert metrics.success_rate == 0.8

    def test_success_rate_zero_analyses(self):
        """Test success rate with zero analyses."""
        now = datetime.now(timezone.utc)
        metrics = AggregatedMetrics(
            period_start=now - timedelta(hours=1),
            period_end=now,
            total_analyses=0,
            successful_analyses=0,
        )

        assert metrics.success_rate == 0.0

    def test_rag_usage_rate(self):
        """Test RAG usage rate calculation."""
        now = datetime.now(timezone.utc)
        metrics = AggregatedMetrics(
            period_start=now - timedelta(hours=1),
            period_end=now,
            total_analyses=100,
            rag_enabled_count=75,
        )

        assert metrics.rag_usage_rate == 0.75

    def test_to_dict(self):
        """Test serialization to dictionary."""
        now = datetime.now(timezone.utc)
        metrics = AggregatedMetrics(
            period_start=now - timedelta(hours=1),
            period_end=now,
            total_analyses=10,
            successful_analyses=8,
            rag_enabled_count=9,
            avg_retrieval_time_ms=150.5,
            avg_context_sources=2.5,
            avg_similarity=0.756,
            sources_by_type={"similar_incidents": 15},
            verdict_distribution={"true_positive": 5, "false_positive": 3},
            error_count=2,
        )

        data = metrics.to_dict()

        assert data["total_analyses"] == 10
        assert data["success_rate"] == 0.8
        assert data["rag_usage_rate"] == 0.9
        assert data["avg_similarity"] == 0.756


# =============================================================================
# RAGMonitor Tests
# =============================================================================


class TestRAGMonitor:
    """Tests for RAGMonitor class."""

    def test_initialization(self):
        """Test monitor initialization."""
        monitor = RAGMonitor(max_history=500, enable_detailed_logging=True)

        assert monitor._max_history == 500
        assert monitor._enable_detailed_logging is True
        assert monitor._total_analyses == 0

    def test_record_analysis(self, monitor, mock_rag_analysis_result):
        """Test recording an analysis result."""
        metrics = monitor.record_analysis(
            result=mock_rag_analysis_result,
            analysis_id="test-001",
        )

        assert metrics.analysis_id == "test-001"
        assert metrics.rag_enabled is True
        assert metrics.success is True
        assert metrics.context_sources == 2
        assert metrics.retrieval_time_ms == 100

        # Verify counters updated
        assert monitor._total_analyses == 1
        assert monitor._successful_analyses == 1
        assert monitor._rag_enabled_count == 1

    def test_record_multiple_analyses(self, monitor, mock_rag_analysis_result):
        """Test recording multiple analyses."""
        for i in range(5):
            monitor.record_analysis(
                result=mock_rag_analysis_result,
                analysis_id=f"test-{i:03d}",
            )

        current = monitor.get_current_metrics()

        assert current["total_analyses"] == 5
        assert current["successful_analyses"] == 5
        assert current["success_rate"] == 1.0

    def test_record_analysis_with_experiment_variant(self, monitor, mock_rag_analysis_result):
        """Test recording analysis with A/B test variant."""
        metrics = monitor.record_analysis(
            result=mock_rag_analysis_result,
            analysis_id="test-001",
            experiment_variant=ExperimentVariant.RAG_ENABLED,
        )

        assert metrics.experiment_variant == ExperimentVariant.RAG_ENABLED

    def test_get_current_metrics(self, monitor, mock_rag_analysis_result):
        """Test getting current running metrics."""
        # Record some analyses
        for i in range(3):
            monitor.record_analysis(
                result=mock_rag_analysis_result,
                analysis_id=f"test-{i}",
            )

        metrics = monitor.get_current_metrics()

        assert metrics["total_analyses"] == 3
        assert metrics["rag_enabled_count"] == 3
        assert "avg_retrieval_time_ms" in metrics
        assert "avg_context_sources" in metrics
        assert "avg_similarity" in metrics

    def test_get_aggregated_metrics(self, monitor, mock_rag_analysis_result):
        """Test getting aggregated metrics."""
        # Record some analyses
        for i in range(5):
            monitor.record_analysis(
                result=mock_rag_analysis_result,
                analysis_id=f"test-{i}",
            )

        agg = monitor.get_aggregated_metrics()

        assert agg.total_analyses == 5
        assert agg.successful_analyses == 5
        assert agg.rag_enabled_count == 5
        assert agg.avg_context_sources > 0

    def test_get_aggregated_metrics_with_time_filter(self, monitor, mock_rag_analysis_result):
        """Test aggregated metrics with time filter."""
        monitor.record_analysis(
            result=mock_rag_analysis_result,
            analysis_id="test-001",
        )

        # Get metrics for future time range (should be empty)
        future_start = datetime.now(timezone.utc) + timedelta(hours=1)
        agg = monitor.get_aggregated_metrics(since=future_start)

        assert agg.total_analyses == 0

    def test_get_experiment_comparison(self, monitor, mock_rag_analysis_result):
        """Test A/B experiment comparison."""
        # Record some with RAG enabled
        for i in range(3):
            monitor.record_analysis(
                result=mock_rag_analysis_result,
                analysis_id=f"rag-{i}",
                experiment_variant=ExperimentVariant.RAG_ENABLED,
            )

        # Create a disabled result
        from tw_ai.agents.react import AgentResult
        from tw_ai.analysis.rag_analyzer import RAGAnalysisResult, RAGContext

        disabled_result = RAGAnalysisResult(
            agent_result=AgentResult(
                success=True,
                analysis=None,
                tokens_used=300,
                execution_time_seconds=1.5,
            ),
            rag_context=RAGContext(),
            rag_enabled=False,
        )

        for i in range(2):
            monitor.record_analysis(
                result=disabled_result,
                analysis_id=f"no-rag-{i}",
                experiment_variant=ExperimentVariant.RAG_DISABLED,
            )

        comparison = monitor.get_experiment_comparison()

        assert "rag_enabled" in comparison
        assert "rag_disabled" in comparison
        assert comparison["rag_enabled"]["total_analyses"] == 3
        assert comparison["rag_disabled"]["total_analyses"] == 2

    def test_history_limit(self):
        """Test that history is limited to max_history."""
        from tw_ai.agents.react import AgentResult
        from tw_ai.analysis.rag_analyzer import RAGAnalysisResult, RAGContext

        monitor = RAGMonitor(max_history=5)

        result = RAGAnalysisResult(
            agent_result=AgentResult(
                success=True,
                analysis=None,
                tokens_used=100,
                execution_time_seconds=1.0,
            ),
            rag_context=RAGContext(retrieval_time_ms=50),
            rag_enabled=True,
        )

        # Record more than max_history
        for i in range(10):
            monitor.record_analysis(result=result, analysis_id=f"test-{i}")

        # History should be limited
        assert len(monitor._analysis_history) == 5
        # But counters should reflect all
        assert monitor._total_analyses == 10

    def test_export_metrics_json(self, monitor, mock_rag_analysis_result, tmp_path):
        """Test exporting metrics to JSON file."""
        # Record some data
        for i in range(3):
            monitor.record_analysis(
                result=mock_rag_analysis_result,
                analysis_id=f"test-{i}",
            )

        filepath = tmp_path / "metrics.json"
        monitor.export_metrics_json(filepath)

        assert filepath.exists()

        import json

        with open(filepath) as f:
            data = json.load(f)

        assert "exported_at" in data
        assert "current_metrics" in data
        assert "aggregated_metrics" in data
        assert "recent_analyses" in data

    def test_reset(self, monitor, mock_rag_analysis_result):
        """Test resetting the monitor."""
        monitor.record_analysis(
            result=mock_rag_analysis_result,
            analysis_id="test-001",
        )

        assert monitor._total_analyses == 1

        monitor.reset()

        assert monitor._total_analyses == 0
        assert len(monitor._analysis_history) == 0
        assert len(monitor._retrieval_history) == 0


# =============================================================================
# Global Monitor Tests
# =============================================================================


class TestGlobalMonitor:
    """Tests for global monitor singleton."""

    def test_get_rag_monitor_singleton(self):
        """Test that get_rag_monitor returns singleton."""
        reset_rag_monitor()

        monitor1 = get_rag_monitor()
        monitor2 = get_rag_monitor()

        assert monitor1 is monitor2

    def test_reset_rag_monitor(self):
        """Test resetting the global monitor."""
        reset_rag_monitor()

        monitor1 = get_rag_monitor()
        reset_rag_monitor()
        monitor2 = get_rag_monitor()

        # Should be different instances after reset
        assert monitor1 is not monitor2

    def test_get_rag_monitor_with_options(self):
        """Test creating monitor with options."""
        reset_rag_monitor()

        monitor = get_rag_monitor(max_history=200, enable_detailed_logging=True)

        assert monitor._max_history == 200
        assert monitor._enable_detailed_logging is True

        reset_rag_monitor()


# =============================================================================
# MetricType and ExperimentVariant Tests
# =============================================================================


class TestEnums:
    """Tests for metric enums."""

    def test_metric_type_values(self):
        """Test MetricType enum values."""
        assert MetricType.RETRIEVAL_COUNT == "retrieval_count"
        assert MetricType.RETRIEVAL_LATENCY == "retrieval_latency_ms"
        assert MetricType.ANALYSIS_SUCCESS == "analysis_success_rate"

    def test_experiment_variant_values(self):
        """Test ExperimentVariant enum values."""
        assert ExperimentVariant.RAG_ENABLED == "rag_enabled"
        assert ExperimentVariant.RAG_DISABLED == "rag_disabled"
        assert ExperimentVariant.CONTROL == "control"
