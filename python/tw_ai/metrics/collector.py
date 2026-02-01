"""Thread-safe metrics collection for phishing triage pipeline.

This module provides:
- MetricsCollector: Collects triage, action, latency, and error metrics
- Thread-safe operations using threading.Lock
- Optional export to Rust Prometheus endpoint via MetricsBridge
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from tw_bridge import MetricsBridge

logger = logging.getLogger(__name__)


@dataclass
class MetricsData:
    """Container for all collected metrics data.

    Attributes:
        triage_count: Counter of triages by verdict
        triage_confidence: List of confidence values per verdict
        triage_duration_ms: List of triage durations in milliseconds
        action_count: Counter of actions by type
        action_success: Counter of successful actions by type
        stage_latency_ms: Latency lists by stage name
        error_count: Counter of errors by type
        start_time: When metrics collection started
    """

    triage_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    triage_confidence: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    triage_duration_ms: list[int] = field(default_factory=list)
    action_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    action_success: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    stage_latency_ms: dict[str, list[int]] = field(default_factory=lambda: defaultdict(list))
    error_count: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    start_time: float = field(default_factory=time.time)


class MetricsCollector:
    """Thread-safe metrics collector for phishing triage pipeline.

    Collects metrics for:
    - Triage operations (count, confidence, duration by verdict)
    - Actions performed (count, success rate by action type)
    - Stage latencies (duration by stage name)
    - Errors (count by error type)

    All operations are thread-safe using a threading.Lock.

    Optionally exports metrics to the Rust Prometheus endpoint via MetricsBridge
    for unified metrics collection.

    Example:
        # Basic usage (local metrics only)
        collector = MetricsCollector()
        collector.record_triage("malicious", 0.95, 150)
        collector.record_action("quarantine_email", True)
        collector.record_stage_latency("email_parsing", 25)
        metrics = collector.get_metrics()

        # With Rust Prometheus export
        from tw_bridge import MetricsBridge
        bridge = MetricsBridge()
        collector = MetricsCollector(metrics_bridge=bridge)
        collector.record_triage("malicious", 0.95, 150)  # Also exports to Prometheus
    """

    def __init__(
        self,
        metrics_bridge: MetricsBridge | None = None,
        enable_bridge_export: bool = True,
    ) -> None:
        """Initialize the metrics collector.

        Args:
            metrics_bridge: Optional MetricsBridge instance for exporting metrics
                to the Rust Prometheus endpoint. If None, metrics are only
                collected locally.
            enable_bridge_export: Whether to export metrics to the bridge.
                Can be toggled at runtime via set_bridge_export_enabled().
        """
        self._lock = threading.Lock()
        self._data = MetricsData()
        self._metrics_bridge = metrics_bridge
        self._bridge_export_enabled = enable_bridge_export

    @property
    def metrics_bridge(self) -> MetricsBridge | None:
        """Get the current metrics bridge."""
        return self._metrics_bridge

    def set_metrics_bridge(self, bridge: MetricsBridge | None) -> None:
        """Set or replace the metrics bridge.

        Args:
            bridge: The MetricsBridge instance to use, or None to disable bridge export
        """
        with self._lock:
            self._metrics_bridge = bridge

    def set_bridge_export_enabled(self, enabled: bool) -> None:
        """Enable or disable bridge export.

        Args:
            enabled: Whether to export metrics to the bridge
        """
        with self._lock:
            self._bridge_export_enabled = enabled

    def is_bridge_export_enabled(self) -> bool:
        """Check if bridge export is enabled.

        Returns:
            True if bridge export is enabled and a bridge is configured
        """
        with self._lock:
            return self._bridge_export_enabled and self._metrics_bridge is not None

    def _push_to_bridge(self, method_name: str, *args: Any) -> None:
        """Push a metric to the Rust bridge if available.

        This is a helper method that safely calls the bridge method,
        catching any exceptions to prevent metrics export from
        affecting the main application flow.

        Args:
            method_name: Name of the MetricsBridge method to call
            *args: Arguments to pass to the method
        """
        if not self._bridge_export_enabled or self._metrics_bridge is None:
            return

        try:
            method = getattr(self._metrics_bridge, method_name)
            method(*args)
        except Exception as e:
            # Log but don't raise - metrics export should not affect main flow
            logger.debug("Failed to push metric to bridge: %s", e)

    def record_triage(
        self,
        verdict: str,
        confidence: float,
        duration_ms: int,
        severity: str = "medium",
        status: str = "resolved",
    ) -> None:
        """Record a triage operation.

        Args:
            verdict: The triage verdict (malicious, suspicious, benign, inconclusive)
            confidence: Confidence score between 0 and 1
            duration_ms: Duration of the triage operation in milliseconds
            severity: Incident severity for Prometheus export (default: "medium")
            status: Incident status for Prometheus export (default: "resolved")
        """
        with self._lock:
            self._data.triage_count[verdict] += 1
            self._data.triage_confidence[verdict].append(confidence)
            self._data.triage_duration_ms.append(duration_ms)

        # Push to Rust Prometheus endpoint
        duration_seconds = duration_ms / 1000.0
        self._push_to_bridge("record_triage_duration", duration_seconds)
        self._push_to_bridge("record_triage_verdict", verdict, confidence)
        self._push_to_bridge("record_incident", severity, status)

    def record_action(self, action_type: str, success: bool) -> None:
        """Record an action performed during triage.

        Args:
            action_type: Type of action (e.g., quarantine_email, block_sender)
            success: Whether the action succeeded
        """
        with self._lock:
            self._data.action_count[action_type] += 1
            if success:
                self._data.action_success[action_type] += 1

        # Push to Rust Prometheus endpoint
        status = "success" if success else "failure"
        self._push_to_bridge("record_action", action_type, status)

    def record_stage_latency(self, stage: str, duration_ms: int) -> None:
        """Record latency for a pipeline stage.

        Args:
            stage: Name of the pipeline stage
            duration_ms: Duration of the stage in milliseconds
        """
        with self._lock:
            self._data.stage_latency_ms[stage].append(duration_ms)

        # Push to Rust Prometheus endpoint
        duration_seconds = duration_ms / 1000.0
        self._push_to_bridge("record_stage_latency", stage, duration_seconds)

    def record_error(self, error_type: str) -> None:
        """Record an error occurrence.

        Args:
            error_type: Type of error (e.g., parse_error, llm_timeout)
        """
        with self._lock:
            self._data.error_count[error_type] += 1

        # Push to Rust Prometheus endpoint
        self._push_to_bridge("record_error", error_type)

    def record_incident(self, severity: str, status: str) -> None:
        """Record an incident directly to the Prometheus endpoint.

        This method is for recording incidents that may not be part of
        the standard triage flow but should still be tracked.

        Args:
            severity: Incident severity (critical, high, medium, low, info)
            status: Incident status (new, resolved, false_positive, etc.)
        """
        self._push_to_bridge("record_incident", severity, status)

    def get_metrics(self) -> dict[str, Any]:
        """Get all current metrics as a dictionary.

        Returns:
            Dictionary containing all collected metrics:
            - triage_count: Dict of verdict -> count
            - triage_confidence: Dict of verdict -> list of confidence values
            - triage_duration_ms: List of all triage durations
            - action_count: Dict of action_type -> count
            - action_success_rate: Dict of action_type -> success rate (0-1)
            - stage_latency_ms: Dict of stage -> list of durations
            - error_count: Dict of error_type -> count
            - collection_duration_seconds: Time since collector was created
            - bridge_export_enabled: Whether bridge export is enabled
        """
        with self._lock:
            # Calculate action success rates
            action_success_rate: dict[str, float] = {}
            for action_type, total in self._data.action_count.items():
                successes = self._data.action_success.get(action_type, 0)
                action_success_rate[action_type] = successes / total if total > 0 else 0.0

            return {
                "triage_count": dict(self._data.triage_count),
                "triage_confidence": {k: list(v) for k, v in self._data.triage_confidence.items()},
                "triage_duration_ms": list(self._data.triage_duration_ms),
                "action_count": dict(self._data.action_count),
                "action_success_rate": action_success_rate,
                "stage_latency_ms": {k: list(v) for k, v in self._data.stage_latency_ms.items()},
                "error_count": dict(self._data.error_count),
                "collection_duration_seconds": time.time() - self._data.start_time,
                "bridge_export_enabled": self._bridge_export_enabled
                and self._metrics_bridge is not None,
            }

    def reset(self) -> None:
        """Reset all collected metrics."""
        with self._lock:
            self._data = MetricsData()


def create_metrics_collector_with_bridge(
    enable_bridge: bool = True,
) -> MetricsCollector:
    """Factory function to create a MetricsCollector with optional bridge.

    This function handles the optional import of tw_bridge and creates
    a MetricsCollector with the appropriate configuration.

    Args:
        enable_bridge: Whether to enable the Rust Prometheus bridge.
            If True and tw_bridge is available, metrics will be exported
            to the Rust Prometheus endpoint at /metrics.

    Returns:
        MetricsCollector instance configured with or without bridge export

    Example:
        # Auto-detect bridge availability
        collector = create_metrics_collector_with_bridge()

        # Force disable bridge even if available
        collector = create_metrics_collector_with_bridge(enable_bridge=False)
    """
    metrics_bridge = None

    if enable_bridge:
        try:
            from tw_bridge import MetricsBridge

            metrics_bridge = MetricsBridge()
            logger.info("MetricsBridge initialized for Prometheus export")
        except ImportError:
            logger.debug("tw_bridge not available, metrics will only be collected locally")
        except Exception as e:
            logger.warning("Failed to initialize MetricsBridge: %s", e)

    return MetricsCollector(
        metrics_bridge=metrics_bridge,
        enable_bridge_export=enable_bridge,
    )
