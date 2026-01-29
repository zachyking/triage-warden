"""Unit tests for the metrics collection and reporting module.

Tests cover:
- MetricsCollector thread-safe operations
- Recording of triage, action, stage latency, and error metrics
- MetricsReporter summary generation
- Text and JSON report formatting
- Percentile calculations
"""

from __future__ import annotations

import json
import sys
import threading
import time
from unittest.mock import MagicMock

import pytest


# =============================================================================
# Mock setup to avoid full tw_ai import chain
# =============================================================================

class MockStructlog:
    """Mock structlog module."""
    @staticmethod
    def get_logger():
        logger = MagicMock()
        logger.info = MagicMock()
        logger.warning = MagicMock()
        logger.error = MagicMock()
        logger.debug = MagicMock()
        return logger

# Install mock structlog if not available
if "structlog" not in sys.modules:
    sys.modules["structlog"] = MockStructlog()

# Mock tw_ai package to prevent full import chain
class MockTwAi:
    pass

if "tw_ai" not in sys.modules:
    sys.modules["tw_ai"] = MockTwAi()

# Load modules directly
import os
import importlib.util

def load_module_directly(name: str, file_path: str):
    """Load a module directly from file without going through package."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

metrics_base = os.path.join(os.path.dirname(__file__), "..", "tw_ai", "metrics")

collector_module = load_module_directly(
    "tw_ai.metrics.collector",
    os.path.join(metrics_base, "collector.py")
)
MetricsCollector = collector_module.MetricsCollector
MetricsData = collector_module.MetricsData

reporter_module = load_module_directly(
    "tw_ai.metrics.reporter",
    os.path.join(metrics_base, "reporter.py")
)
MetricsReporter = reporter_module.MetricsReporter


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def collector() -> MetricsCollector:
    """Create a fresh MetricsCollector instance."""
    return MetricsCollector()


@pytest.fixture
def populated_collector() -> MetricsCollector:
    """Create a MetricsCollector with sample data."""
    collector = MetricsCollector()

    # Record some triages
    collector.record_triage("malicious", 0.95, 150)
    collector.record_triage("malicious", 0.88, 200)
    collector.record_triage("benign", 0.75, 100)
    collector.record_triage("suspicious", 0.65, 180)
    collector.record_triage("inconclusive", 0.45, 250)

    # Record some actions
    collector.record_action("quarantine_email", True)
    collector.record_action("quarantine_email", True)
    collector.record_action("quarantine_email", False)
    collector.record_action("block_sender", True)
    collector.record_action("notify_user", True)

    # Record stage latencies
    collector.record_stage_latency("email_parsing", 25)
    collector.record_stage_latency("email_parsing", 30)
    collector.record_stage_latency("indicator_detection", 50)
    collector.record_stage_latency("indicator_detection", 55)
    collector.record_stage_latency("llm_analysis", 100)

    # Record some errors
    collector.record_error("parse_error")
    collector.record_error("llm_timeout")
    collector.record_error("llm_timeout")

    return collector


@pytest.fixture
def reporter(populated_collector: MetricsCollector) -> MetricsReporter:
    """Create a MetricsReporter with populated collector."""
    return MetricsReporter(populated_collector)


# =============================================================================
# MetricsCollector Tests
# =============================================================================


class TestMetricsCollector:
    """Tests for MetricsCollector class."""

    def test_initial_state(self, collector: MetricsCollector) -> None:
        """Test that a new collector has empty metrics."""
        metrics = collector.get_metrics()

        assert metrics["triage_count"] == {}
        assert metrics["triage_confidence"] == {}
        assert metrics["triage_duration_ms"] == []
        assert metrics["action_count"] == {}
        assert metrics["action_success_rate"] == {}
        assert metrics["stage_latency_ms"] == {}
        assert metrics["error_count"] == {}
        assert metrics["collection_duration_seconds"] >= 0

    def test_record_triage(self, collector: MetricsCollector) -> None:
        """Test recording triage operations."""
        collector.record_triage("malicious", 0.95, 150)
        collector.record_triage("malicious", 0.88, 200)
        collector.record_triage("benign", 0.75, 100)

        metrics = collector.get_metrics()

        assert metrics["triage_count"]["malicious"] == 2
        assert metrics["triage_count"]["benign"] == 1
        assert metrics["triage_confidence"]["malicious"] == [0.95, 0.88]
        assert metrics["triage_confidence"]["benign"] == [0.75]
        assert sorted(metrics["triage_duration_ms"]) == [100, 150, 200]

    def test_record_action(self, collector: MetricsCollector) -> None:
        """Test recording actions with success/failure tracking."""
        collector.record_action("quarantine_email", True)
        collector.record_action("quarantine_email", True)
        collector.record_action("quarantine_email", False)
        collector.record_action("block_sender", True)

        metrics = collector.get_metrics()

        assert metrics["action_count"]["quarantine_email"] == 3
        assert metrics["action_count"]["block_sender"] == 1
        # 2 successes out of 3 = 0.666...
        assert abs(metrics["action_success_rate"]["quarantine_email"] - 2/3) < 0.01
        assert metrics["action_success_rate"]["block_sender"] == 1.0

    def test_record_stage_latency(self, collector: MetricsCollector) -> None:
        """Test recording stage latencies."""
        collector.record_stage_latency("email_parsing", 25)
        collector.record_stage_latency("email_parsing", 30)
        collector.record_stage_latency("indicator_detection", 50)

        metrics = collector.get_metrics()

        assert metrics["stage_latency_ms"]["email_parsing"] == [25, 30]
        assert metrics["stage_latency_ms"]["indicator_detection"] == [50]

    def test_record_error(self, collector: MetricsCollector) -> None:
        """Test recording errors."""
        collector.record_error("parse_error")
        collector.record_error("llm_timeout")
        collector.record_error("llm_timeout")

        metrics = collector.get_metrics()

        assert metrics["error_count"]["parse_error"] == 1
        assert metrics["error_count"]["llm_timeout"] == 2

    def test_reset(self, populated_collector: MetricsCollector) -> None:
        """Test that reset clears all metrics."""
        # Verify metrics exist
        metrics_before = populated_collector.get_metrics()
        assert metrics_before["triage_count"]
        assert metrics_before["action_count"]

        # Reset
        populated_collector.reset()

        # Verify empty
        metrics_after = populated_collector.get_metrics()
        assert metrics_after["triage_count"] == {}
        assert metrics_after["action_count"] == {}
        assert metrics_after["triage_duration_ms"] == []
        assert metrics_after["error_count"] == {}

    def test_thread_safety(self, collector: MetricsCollector) -> None:
        """Test that concurrent access is handled safely."""
        errors = []
        num_threads = 10
        ops_per_thread = 100

        def worker(thread_id: int) -> None:
            try:
                for i in range(ops_per_thread):
                    collector.record_triage(
                        "malicious" if i % 2 == 0 else "benign",
                        0.5 + (i % 50) / 100,
                        100 + i
                    )
                    collector.record_action(f"action_{thread_id}", i % 3 == 0)
                    collector.record_stage_latency(f"stage_{thread_id % 3}", i)
                    collector.record_error(f"error_{i % 5}")
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(num_threads)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # No errors should have occurred
        assert errors == []

        # Verify expected counts
        metrics = collector.get_metrics()
        total_triages = sum(metrics["triage_count"].values())
        assert total_triages == num_threads * ops_per_thread

        total_durations = len(metrics["triage_duration_ms"])
        assert total_durations == num_threads * ops_per_thread

    def test_all_verdicts_tracked(self, collector: MetricsCollector) -> None:
        """Test that all verdict types are properly tracked."""
        verdicts = ["malicious", "suspicious", "benign", "inconclusive"]

        for verdict in verdicts:
            collector.record_triage(verdict, 0.8, 100)

        metrics = collector.get_metrics()

        for verdict in verdicts:
            assert verdict in metrics["triage_count"]
            assert metrics["triage_count"][verdict] == 1


# =============================================================================
# MetricsReporter Tests
# =============================================================================


class TestMetricsReporter:
    """Tests for MetricsReporter class."""

    def test_generate_summary_structure(self, reporter: MetricsReporter) -> None:
        """Test that generate_summary returns expected structure."""
        summary = reporter.generate_summary()

        assert "time_range_hours" in summary
        assert "total_triages" in summary
        assert "verdicts" in summary
        assert "triage_time" in summary
        assert "action_success_rates" in summary
        assert "stage_latency" in summary
        assert "error_rates" in summary
        assert "timestamp" in summary

    def test_generate_summary_totals(self, reporter: MetricsReporter) -> None:
        """Test that summary contains correct totals."""
        summary = reporter.generate_summary()

        # 5 triages recorded in fixture
        assert summary["total_triages"] == 5

        # Check verdict breakdown
        assert summary["verdicts"]["malicious"]["count"] == 2
        assert summary["verdicts"]["benign"]["count"] == 1
        assert summary["verdicts"]["suspicious"]["count"] == 1
        assert summary["verdicts"]["inconclusive"]["count"] == 1

    def test_generate_summary_percentages(self, reporter: MetricsReporter) -> None:
        """Test that verdict percentages are calculated correctly."""
        summary = reporter.generate_summary()

        # malicious: 2/5 = 40%
        assert abs(summary["verdicts"]["malicious"]["percentage"] - 40.0) < 0.1
        # benign: 1/5 = 20%
        assert abs(summary["verdicts"]["benign"]["percentage"] - 20.0) < 0.1

    def test_generate_summary_triage_time_stats(self, reporter: MetricsReporter) -> None:
        """Test triage time statistics calculation."""
        summary = reporter.generate_summary()

        triage_time = summary["triage_time"]

        # Durations: 150, 200, 100, 180, 250
        # Mean: (150+200+100+180+250)/5 = 176
        assert abs(triage_time["mean_ms"] - 176) < 1

        # Median: sorted [100, 150, 180, 200, 250] -> 180
        assert abs(triage_time["median_ms"] - 180) < 1

        # P95 should be close to 250
        assert triage_time["p95_ms"] >= 200

    def test_generate_summary_action_success_rates(self, reporter: MetricsReporter) -> None:
        """Test action success rate calculations."""
        summary = reporter.generate_summary()

        rates = summary["action_success_rates"]

        # quarantine_email: 2/3 successful
        assert abs(rates["quarantine_email"]["success_rate"] - 2/3) < 0.01
        assert rates["quarantine_email"]["total_count"] == 3

        # block_sender: 1/1 successful
        assert rates["block_sender"]["success_rate"] == 1.0
        assert rates["block_sender"]["total_count"] == 1

    def test_generate_summary_stage_latency(self, reporter: MetricsReporter) -> None:
        """Test stage latency statistics."""
        summary = reporter.generate_summary()

        stage_latency = summary["stage_latency"]

        # email_parsing: [25, 30] -> mean 27.5
        assert abs(stage_latency["email_parsing"]["mean_ms"] - 27.5) < 0.1

        # indicator_detection: [50, 55] -> mean 52.5
        assert abs(stage_latency["indicator_detection"]["mean_ms"] - 52.5) < 0.1

        # llm_analysis: [100] -> mean 100
        assert stage_latency["llm_analysis"]["mean_ms"] == 100

    def test_generate_summary_error_rates(self, reporter: MetricsReporter) -> None:
        """Test error rate reporting."""
        summary = reporter.generate_summary()

        error_rates = summary["error_rates"]

        assert error_rates["total"] == 3
        assert error_rates["by_type"]["parse_error"] == 1
        assert error_rates["by_type"]["llm_timeout"] == 2

    def test_generate_summary_time_range(self, reporter: MetricsReporter) -> None:
        """Test that time_range_hours is passed through."""
        summary_24 = reporter.generate_summary(time_range_hours=24)
        summary_1 = reporter.generate_summary(time_range_hours=1)

        assert summary_24["time_range_hours"] == 24
        assert summary_1["time_range_hours"] == 1

    def test_format_text_report(self, reporter: MetricsReporter) -> None:
        """Test text report formatting."""
        report = reporter.format_text_report()

        # Check key sections exist
        assert "TRIAGE WARDEN METRICS REPORT" in report
        assert "TRIAGE SUMMARY" in report
        assert "Total Triages: 5" in report

        # Check verdict breakdown
        assert "malicious" in report
        assert "benign" in report

        # Check triage time stats
        assert "Triage Time (ms):" in report
        assert "Mean:" in report
        assert "Median:" in report
        assert "P95:" in report

        # Check action success rates
        assert "ACTION SUCCESS RATES" in report
        assert "quarantine_email" in report

        # Check stage latency
        assert "STAGE LATENCY" in report
        assert "email_parsing" in report

        # Check errors
        assert "ERRORS" in report
        assert "Total Errors: 3" in report

    def test_export_json(self, reporter: MetricsReporter) -> None:
        """Test JSON export."""
        json_str = reporter.export_json()

        # Should be valid JSON
        data = json.loads(json_str)

        # Should have all expected fields
        assert "total_triages" in data
        assert "verdicts" in data
        assert "triage_time" in data
        assert "action_success_rates" in data
        assert "stage_latency" in data
        assert "error_rates" in data
        assert "timestamp" in data

    def test_export_json_is_serializable(self, reporter: MetricsReporter) -> None:
        """Test that export_json produces serializable output."""
        json_str = reporter.export_json()

        # Should be able to parse and re-serialize
        data = json.loads(json_str)
        reserialized = json.dumps(data)
        assert reserialized


class TestMetricsReporterEmptyCollector:
    """Tests for MetricsReporter with empty collector."""

    def test_empty_collector_summary(self) -> None:
        """Test that empty collector produces valid summary."""
        collector = MetricsCollector()
        reporter = MetricsReporter(collector)

        summary = reporter.generate_summary()

        assert summary["total_triages"] == 0
        assert summary["verdicts"] == {}
        assert summary["triage_time"]["mean_ms"] == 0
        assert summary["triage_time"]["median_ms"] == 0
        assert summary["triage_time"]["p95_ms"] == 0
        assert summary["error_rates"]["total"] == 0

    def test_empty_collector_text_report(self) -> None:
        """Test text report with empty collector."""
        collector = MetricsCollector()
        reporter = MetricsReporter(collector)

        report = reporter.format_text_report()

        assert "Total Triages: 0" in report
        assert "Total Errors: 0" in report

    def test_empty_collector_json_export(self) -> None:
        """Test JSON export with empty collector."""
        collector = MetricsCollector()
        reporter = MetricsReporter(collector)

        json_str = reporter.export_json()
        data = json.loads(json_str)

        assert data["total_triages"] == 0
        assert data["verdicts"] == {}


class TestPercentileCalculation:
    """Tests for percentile calculation edge cases."""

    def test_percentile_single_value(self) -> None:
        """Test percentile calculation with single value."""
        collector = MetricsCollector()
        collector.record_triage("malicious", 0.9, 100)

        reporter = MetricsReporter(collector)
        summary = reporter.generate_summary()

        # With single value, all percentiles should be that value
        assert summary["triage_time"]["mean_ms"] == 100
        assert summary["triage_time"]["median_ms"] == 100
        assert summary["triage_time"]["p95_ms"] == 100

    def test_percentile_two_values(self) -> None:
        """Test percentile calculation with two values."""
        collector = MetricsCollector()
        collector.record_triage("malicious", 0.9, 100)
        collector.record_triage("benign", 0.8, 200)

        reporter = MetricsReporter(collector)
        summary = reporter.generate_summary()

        assert summary["triage_time"]["mean_ms"] == 150
        assert summary["triage_time"]["median_ms"] == 150
        # P95 should be close to 200
        assert summary["triage_time"]["p95_ms"] >= 150

    def test_percentile_many_values(self) -> None:
        """Test percentile calculation with many values."""
        collector = MetricsCollector()

        # Record 100 triages with durations 1-100
        for i in range(1, 101):
            collector.record_triage("malicious", 0.5, i)

        reporter = MetricsReporter(collector)
        summary = reporter.generate_summary()

        # Mean should be 50.5
        assert abs(summary["triage_time"]["mean_ms"] - 50.5) < 1

        # Median should be 50.5
        assert abs(summary["triage_time"]["median_ms"] - 50.5) < 1

        # P95 should be around 95
        assert 94 <= summary["triage_time"]["p95_ms"] <= 96
