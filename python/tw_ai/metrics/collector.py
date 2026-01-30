"""Thread-safe metrics collection for phishing triage pipeline.

This module provides:
- MetricsCollector: Collects triage, action, latency, and error metrics
- Thread-safe operations using threading.Lock
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


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

    Example:
        collector = MetricsCollector()
        collector.record_triage("malicious", 0.95, 150)
        collector.record_action("quarantine_email", True)
        collector.record_stage_latency("email_parsing", 25)
        metrics = collector.get_metrics()
    """

    def __init__(self) -> None:
        """Initialize the metrics collector."""
        self._lock = threading.Lock()
        self._data = MetricsData()

    def record_triage(
        self,
        verdict: str,
        confidence: float,
        duration_ms: int,
    ) -> None:
        """Record a triage operation.

        Args:
            verdict: The triage verdict (malicious, suspicious, benign, inconclusive)
            confidence: Confidence score between 0 and 1
            duration_ms: Duration of the triage operation in milliseconds
        """
        with self._lock:
            self._data.triage_count[verdict] += 1
            self._data.triage_confidence[verdict].append(confidence)
            self._data.triage_duration_ms.append(duration_ms)

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

    def record_stage_latency(self, stage: str, duration_ms: int) -> None:
        """Record latency for a pipeline stage.

        Args:
            stage: Name of the pipeline stage
            duration_ms: Duration of the stage in milliseconds
        """
        with self._lock:
            self._data.stage_latency_ms[stage].append(duration_ms)

    def record_error(self, error_type: str) -> None:
        """Record an error occurrence.

        Args:
            error_type: Type of error (e.g., parse_error, llm_timeout)
        """
        with self._lock:
            self._data.error_count[error_type] += 1

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
            }

    def reset(self) -> None:
        """Reset all collected metrics."""
        with self._lock:
            self._data = MetricsData()
