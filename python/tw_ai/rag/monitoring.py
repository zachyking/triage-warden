"""RAG monitoring and metrics for quality tracking.

This module provides monitoring capabilities for RAG-enhanced analysis:

1. Track retrieval relevance metrics
2. Log retrieved context for debugging
3. A/B test framework for RAG vs non-RAG analysis
4. Performance benchmarking

Part of Task 2.3.5: RAG Quality Monitoring
"""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from tw_ai.analysis.rag_analyzer import RAGAnalysisResult, RAGContext

logger = structlog.get_logger()


# =============================================================================
# Metric Types
# =============================================================================


class MetricType(str, Enum):
    """Types of RAG metrics tracked."""

    RETRIEVAL_COUNT = "retrieval_count"
    RETRIEVAL_LATENCY = "retrieval_latency_ms"
    CONTEXT_SOURCES = "context_sources_used"
    SIMILARITY_SCORE = "avg_similarity_score"
    ANALYSIS_SUCCESS = "analysis_success_rate"
    RAG_ENABLED = "rag_enabled_rate"
    CONTEXT_TOKENS = "context_tokens_estimated"


class ExperimentVariant(str, Enum):
    """A/B test variants."""

    RAG_ENABLED = "rag_enabled"
    RAG_DISABLED = "rag_disabled"
    CONTROL = "control"


# =============================================================================
# Metric Data Classes
# =============================================================================


@dataclass
class RetrievalMetrics:
    """Metrics for a single RAG retrieval operation."""

    timestamp: datetime
    retrieval_time_ms: int
    sources_retrieved: dict[str, int]
    avg_similarity_by_source: dict[str, float]
    total_sources: int
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "retrieval_time_ms": self.retrieval_time_ms,
            "sources_retrieved": self.sources_retrieved,
            "avg_similarity_by_source": self.avg_similarity_by_source,
            "total_sources": self.total_sources,
            "errors": self.errors,
        }


@dataclass
class AnalysisMetrics:
    """Metrics for a single RAG-enhanced analysis."""

    timestamp: datetime
    analysis_id: str
    rag_enabled: bool
    success: bool
    retrieval_time_ms: int
    agent_time_ms: int
    total_time_ms: int
    context_sources: int
    avg_similarity: float
    verdict: str | None = None
    confidence: int | None = None
    experiment_variant: ExperimentVariant | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "analysis_id": self.analysis_id,
            "rag_enabled": self.rag_enabled,
            "success": self.success,
            "retrieval_time_ms": self.retrieval_time_ms,
            "agent_time_ms": self.agent_time_ms,
            "total_time_ms": self.total_time_ms,
            "context_sources": self.context_sources,
            "avg_similarity": round(self.avg_similarity, 3),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "experiment_variant": (
                self.experiment_variant.value if self.experiment_variant else None
            ),
        }


@dataclass
class AggregatedMetrics:
    """Aggregated metrics over a time period."""

    period_start: datetime
    period_end: datetime
    total_analyses: int = 0
    successful_analyses: int = 0
    rag_enabled_count: int = 0
    avg_retrieval_time_ms: float = 0.0
    avg_context_sources: float = 0.0
    avg_similarity: float = 0.0
    sources_by_type: dict[str, int] = field(default_factory=dict)
    verdict_distribution: dict[str, int] = field(default_factory=dict)
    error_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total_analyses == 0:
            return 0.0
        return self.successful_analyses / self.total_analyses

    @property
    def rag_usage_rate(self) -> float:
        """Calculate RAG usage rate."""
        if self.total_analyses == 0:
            return 0.0
        return self.rag_enabled_count / self.total_analyses

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "total_analyses": self.total_analyses,
            "successful_analyses": self.successful_analyses,
            "success_rate": round(self.success_rate, 3),
            "rag_enabled_count": self.rag_enabled_count,
            "rag_usage_rate": round(self.rag_usage_rate, 3),
            "avg_retrieval_time_ms": round(self.avg_retrieval_time_ms, 1),
            "avg_context_sources": round(self.avg_context_sources, 2),
            "avg_similarity": round(self.avg_similarity, 3),
            "sources_by_type": self.sources_by_type,
            "verdict_distribution": self.verdict_distribution,
            "error_count": self.error_count,
        }


# =============================================================================
# RAG Monitor
# =============================================================================


class RAGMonitor:
    """Monitor for RAG-enhanced analysis metrics.

    Collects and aggregates metrics from RAG analysis operations
    for quality monitoring and debugging.

    Usage:
        monitor = RAGMonitor()

        # Record analysis metrics
        monitor.record_analysis(result, analysis_id="incident-123")

        # Get aggregated metrics
        metrics = monitor.get_aggregated_metrics()

        # Export for dashboards
        monitor.export_metrics_json("rag_metrics.json")
    """

    def __init__(
        self,
        max_history: int = 10000,
        enable_detailed_logging: bool = False,
    ) -> None:
        """Initialize the RAG monitor.

        Args:
            max_history: Maximum number of analysis records to keep in memory.
            enable_detailed_logging: Whether to log detailed retrieval info.
        """
        self._analysis_history: list[AnalysisMetrics] = []
        self._retrieval_history: list[RetrievalMetrics] = []
        self._max_history = max_history
        self._enable_detailed_logging = enable_detailed_logging

        # Running counters for real-time metrics
        self._total_analyses = 0
        self._successful_analyses = 0
        self._rag_enabled_count = 0
        self._total_retrieval_time_ms = 0
        self._total_context_sources = 0
        self._total_similarity_sum = 0.0
        self._similarity_count = 0

        logger.info(
            "rag_monitor_initialized",
            max_history=max_history,
            detailed_logging=enable_detailed_logging,
        )

    def record_analysis(
        self,
        result: RAGAnalysisResult,
        analysis_id: str,
        experiment_variant: ExperimentVariant | None = None,
    ) -> AnalysisMetrics:
        """Record metrics from a RAG analysis result.

        Args:
            result: The RAG analysis result.
            analysis_id: Unique identifier for this analysis.
            experiment_variant: Optional A/B test variant.

        Returns:
            The recorded AnalysisMetrics.
        """
        now = datetime.now(timezone.utc)

        # Calculate metrics
        avg_similarity = self._calculate_avg_similarity(result.rag_context)
        agent_time_ms = int(result.agent_result.execution_time_seconds * 1000)
        total_time_ms = result.rag_context.retrieval_time_ms + agent_time_ms

        # Extract verdict and confidence if available
        verdict = None
        confidence = None
        if result.analysis:
            verdict = result.analysis.verdict
            confidence = result.analysis.confidence

        metrics = AnalysisMetrics(
            timestamp=now,
            analysis_id=analysis_id,
            rag_enabled=result.rag_enabled,
            success=result.success,
            retrieval_time_ms=result.rag_context.retrieval_time_ms,
            agent_time_ms=agent_time_ms,
            total_time_ms=total_time_ms,
            context_sources=result.rag_context.total_sources,
            avg_similarity=avg_similarity,
            verdict=verdict,
            confidence=confidence,
            experiment_variant=experiment_variant,
        )

        # Update running counters
        self._total_analyses += 1
        if result.success:
            self._successful_analyses += 1
        if result.rag_enabled:
            self._rag_enabled_count += 1
            self._total_retrieval_time_ms += result.rag_context.retrieval_time_ms
            self._total_context_sources += result.rag_context.total_sources
            if avg_similarity > 0:
                self._total_similarity_sum += avg_similarity
                self._similarity_count += 1

        # Add to history
        self._analysis_history.append(metrics)
        if len(self._analysis_history) > self._max_history:
            self._analysis_history.pop(0)

        # Record retrieval metrics
        if result.rag_enabled:
            self._record_retrieval(result.rag_context, result.retrieval_errors)

        # Log if detailed logging enabled
        if self._enable_detailed_logging:
            logger.info(
                "rag_analysis_recorded",
                analysis_id=analysis_id,
                rag_enabled=result.rag_enabled,
                success=result.success,
                context_sources=result.rag_context.total_sources,
                retrieval_time_ms=result.rag_context.retrieval_time_ms,
                avg_similarity=round(avg_similarity, 3),
            )

        return metrics

    def _record_retrieval(
        self,
        context: RAGContext,
        errors: list[str],
    ) -> None:
        """Record retrieval-specific metrics."""
        now = datetime.now(timezone.utc)

        sources_retrieved = {
            "similar_incidents": len(context.similar_incidents),
            "playbooks": len(context.playbooks),
            "mitre_techniques": len(context.mitre_techniques),
            "threat_intel": len(context.threat_intel),
        }

        avg_similarity_by_source = {
            "similar_incidents": self._avg_similarity_for_sources(context.similar_incidents),
            "playbooks": self._avg_similarity_for_sources(context.playbooks),
            "mitre_techniques": self._avg_similarity_for_sources(context.mitre_techniques),
            "threat_intel": self._avg_similarity_for_sources(context.threat_intel),
        }

        metrics = RetrievalMetrics(
            timestamp=now,
            retrieval_time_ms=context.retrieval_time_ms,
            sources_retrieved=sources_retrieved,
            avg_similarity_by_source=avg_similarity_by_source,
            total_sources=context.total_sources,
            errors=errors,
        )

        self._retrieval_history.append(metrics)
        if len(self._retrieval_history) > self._max_history:
            self._retrieval_history.pop(0)

    def _calculate_avg_similarity(self, context: RAGContext) -> float:
        """Calculate average similarity across all context sources."""
        all_sources = context.all_sources()
        if not all_sources:
            return 0.0
        return sum(s.similarity_score for s in all_sources) / len(all_sources)

    def _avg_similarity_for_sources(self, sources: list[Any]) -> float:
        """Calculate average similarity for a list of sources."""
        if not sources:
            return 0.0
        total: float = sum(s.similarity_score for s in sources)
        return total / len(sources)

    def get_current_metrics(self) -> dict[str, Any]:
        """Get current running metrics.

        Returns:
            Dictionary with current metric values.
        """
        avg_retrieval_time = 0.0
        avg_context_sources = 0.0
        avg_similarity = 0.0

        if self._rag_enabled_count > 0:
            avg_retrieval_time = self._total_retrieval_time_ms / self._rag_enabled_count
            avg_context_sources = self._total_context_sources / self._rag_enabled_count

        if self._similarity_count > 0:
            avg_similarity = self._total_similarity_sum / self._similarity_count

        return {
            "total_analyses": self._total_analyses,
            "successful_analyses": self._successful_analyses,
            "success_rate": (
                self._successful_analyses / self._total_analyses
                if self._total_analyses > 0
                else 0.0
            ),
            "rag_enabled_count": self._rag_enabled_count,
            "rag_usage_rate": (
                self._rag_enabled_count / self._total_analyses if self._total_analyses > 0 else 0.0
            ),
            "avg_retrieval_time_ms": round(avg_retrieval_time, 1),
            "avg_context_sources": round(avg_context_sources, 2),
            "avg_similarity": round(avg_similarity, 3),
        }

    def get_aggregated_metrics(
        self,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> AggregatedMetrics:
        """Get aggregated metrics for a time period.

        Args:
            since: Start of time period (inclusive). If None, uses all history.
            until: End of time period (inclusive). If None, uses current time.

        Returns:
            Aggregated metrics for the period.
        """
        now = datetime.now(timezone.utc)
        since = since or (self._analysis_history[0].timestamp if self._analysis_history else now)
        until = until or now

        # Filter analyses in range
        analyses = [a for a in self._analysis_history if since <= a.timestamp <= until]

        if not analyses:
            return AggregatedMetrics(
                period_start=since,
                period_end=until,
            )

        # Calculate aggregates
        total = len(analyses)
        successful = sum(1 for a in analyses if a.success)
        rag_enabled = sum(1 for a in analyses if a.rag_enabled)

        rag_analyses = [a for a in analyses if a.rag_enabled]
        avg_retrieval_time = (
            sum(a.retrieval_time_ms for a in rag_analyses) / len(rag_analyses)
            if rag_analyses
            else 0.0
        )
        avg_sources = (
            sum(a.context_sources for a in rag_analyses) / len(rag_analyses)
            if rag_analyses
            else 0.0
        )
        similarity_values = [a.avg_similarity for a in rag_analyses if a.avg_similarity > 0]
        avg_similarity = (
            sum(similarity_values) / len(similarity_values) if similarity_values else 0.0
        )

        # Count by source type from retrieval history
        retrievals_in_range = [r for r in self._retrieval_history if since <= r.timestamp <= until]
        sources_by_type: dict[str, int] = defaultdict(int)
        for r in retrievals_in_range:
            for source_type, count in r.sources_retrieved.items():
                sources_by_type[source_type] += count

        # Verdict distribution
        verdict_dist: dict[str, int] = defaultdict(int)
        for a in analyses:
            if a.verdict:
                verdict_dist[a.verdict] += 1

        # Error count
        error_count = sum(len(r.errors) for r in retrievals_in_range)

        return AggregatedMetrics(
            period_start=since,
            period_end=until,
            total_analyses=total,
            successful_analyses=successful,
            rag_enabled_count=rag_enabled,
            avg_retrieval_time_ms=avg_retrieval_time,
            avg_context_sources=avg_sources,
            avg_similarity=avg_similarity,
            sources_by_type=dict(sources_by_type),
            verdict_distribution=dict(verdict_dist),
            error_count=error_count,
        )

    def get_experiment_comparison(
        self,
        since: datetime | None = None,
    ) -> dict[str, Any]:
        """Compare metrics between A/B test variants.

        Args:
            since: Start time for comparison. If None, uses all history.

        Returns:
            Comparison metrics by variant.
        """
        since = since or (
            self._analysis_history[0].timestamp
            if self._analysis_history
            else datetime.now(timezone.utc)
        )

        analyses = [
            a
            for a in self._analysis_history
            if a.timestamp >= since and a.experiment_variant is not None
        ]

        variants: dict[str, list[AnalysisMetrics]] = defaultdict(list)
        for a in analyses:
            if a.experiment_variant:
                variants[a.experiment_variant.value].append(a)

        comparison: dict[str, Any] = {}
        for variant_name, variant_analyses in variants.items():
            total = len(variant_analyses)
            successful = sum(1 for a in variant_analyses if a.success)
            avg_time = sum(a.total_time_ms for a in variant_analyses) / total if total > 0 else 0.0
            avg_confidence = sum(a.confidence for a in variant_analyses if a.confidence is not None)
            confidence_count = sum(1 for a in variant_analyses if a.confidence is not None)

            comparison[variant_name] = {
                "total_analyses": total,
                "success_rate": successful / total if total > 0 else 0.0,
                "avg_total_time_ms": round(avg_time, 1),
                "avg_confidence": (
                    round(avg_confidence / confidence_count, 1) if confidence_count > 0 else None
                ),
            }

        return comparison

    def export_metrics_json(self, filepath: str | Path) -> None:
        """Export all metrics to a JSON file.

        Args:
            filepath: Path to output file.
        """
        data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "current_metrics": self.get_current_metrics(),
            "aggregated_metrics": self.get_aggregated_metrics().to_dict(),
            "recent_analyses": [a.to_dict() for a in self._analysis_history[-100:]],
            "recent_retrievals": [r.to_dict() for r in self._retrieval_history[-100:]],
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        logger.info("rag_metrics_exported", filepath=str(filepath))

    def reset(self) -> None:
        """Reset all metrics and history."""
        self._analysis_history.clear()
        self._retrieval_history.clear()
        self._total_analyses = 0
        self._successful_analyses = 0
        self._rag_enabled_count = 0
        self._total_retrieval_time_ms = 0
        self._total_context_sources = 0
        self._total_similarity_sum = 0.0
        self._similarity_count = 0

        logger.info("rag_monitor_reset")


# =============================================================================
# Global Monitor Instance
# =============================================================================

# Singleton monitor for application-wide metrics
_global_monitor: RAGMonitor | None = None


def get_rag_monitor(
    max_history: int = 10000,
    enable_detailed_logging: bool = False,
) -> RAGMonitor:
    """Get the global RAG monitor instance.

    Creates a new instance if one doesn't exist.

    Args:
        max_history: Maximum analysis records to keep.
        enable_detailed_logging: Whether to enable detailed logging.

    Returns:
        The global RAGMonitor instance.
    """
    global _global_monitor
    if _global_monitor is None:
        _global_monitor = RAGMonitor(
            max_history=max_history,
            enable_detailed_logging=enable_detailed_logging,
        )
    return _global_monitor


def reset_rag_monitor() -> None:
    """Reset the global RAG monitor."""
    global _global_monitor
    if _global_monitor is not None:
        _global_monitor.reset()
    _global_monitor = None


__all__ = [
    # Classes
    "RAGMonitor",
    "AnalysisMetrics",
    "RetrievalMetrics",
    "AggregatedMetrics",
    # Enums
    "MetricType",
    "ExperimentVariant",
    # Functions
    "get_rag_monitor",
    "reset_rag_monitor",
]
