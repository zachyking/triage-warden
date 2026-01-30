"""Metrics reporting for phishing triage pipeline.

This module provides:
- MetricsReporter: Generates summaries and reports from collected metrics
- Support for text and JSON output formats
"""

from __future__ import annotations

import json
import statistics
from datetime import datetime
from typing import Any

from tw_ai.metrics.collector import MetricsCollector


class MetricsReporter:
    """Reporter for generating summaries and formatted reports from metrics.

    Takes a MetricsCollector instance and provides methods to generate
    summaries, text reports, and JSON exports.

    Example:
        collector = MetricsCollector()
        # ... record metrics ...
        reporter = MetricsReporter(collector)
        summary = reporter.generate_summary()
        print(reporter.format_text_report())
    """

    def __init__(self, collector: MetricsCollector) -> None:
        """Initialize the reporter with a metrics collector.

        Args:
            collector: MetricsCollector instance to report on
        """
        self._collector = collector

    def _calculate_percentile(self, values: list[int | float], percentile: float) -> float:
        """Calculate a percentile value from a list.

        Args:
            values: List of numeric values
            percentile: Percentile to calculate (0-100)

        Returns:
            The percentile value, or 0 if list is empty
        """
        if not values:
            return 0.0
        sorted_values = sorted(values)
        n = len(sorted_values)
        k = (n - 1) * (percentile / 100)
        f = int(k)
        c = f + 1 if f + 1 < n else f
        return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])

    def generate_summary(self, time_range_hours: int = 24) -> dict[str, Any]:
        """Generate a summary of collected metrics.

        Args:
            time_range_hours: Time range for the summary (for labeling purposes)

        Returns:
            Dictionary containing:
            - time_range_hours: Requested time range
            - total_triages: Total number of triages
            - verdicts: Breakdown by verdict with counts and percentages
            - triage_time: Mean, median, and p95 triage time stats
            - action_success_rates: Success rate per action type
            - stage_latency: Mean latency per stage
            - error_rates: Error counts and total
            - timestamp: When summary was generated
        """
        metrics = self._collector.get_metrics()

        # Triage counts and percentages
        triage_count = metrics["triage_count"]
        total_triages = sum(triage_count.values())

        verdicts: dict[str, dict[str, Any]] = {}
        for verdict, count in triage_count.items():
            verdicts[verdict] = {
                "count": count,
                "percentage": (count / total_triages * 100) if total_triages > 0 else 0,
            }

        # Triage time statistics
        durations = metrics["triage_duration_ms"]
        triage_time: dict[str, float] = {
            "mean_ms": statistics.mean(durations) if durations else 0,
            "median_ms": statistics.median(durations) if durations else 0,
            "p95_ms": self._calculate_percentile(durations, 95),
        }

        # Action success rates
        action_success_rates: dict[str, dict[str, Any]] = {}
        action_count = metrics["action_count"]
        action_rates = metrics["action_success_rate"]
        for action_type, rate in action_rates.items():
            action_success_rates[action_type] = {
                "success_rate": rate,
                "total_count": action_count.get(action_type, 0),
            }

        # Stage latency
        stage_latency: dict[str, dict[str, float]] = {}
        for stage, latencies in metrics["stage_latency_ms"].items():
            stage_latency[stage] = {
                "mean_ms": statistics.mean(latencies) if latencies else 0,
                "median_ms": statistics.median(latencies) if latencies else 0,
                "p95_ms": self._calculate_percentile(latencies, 95),
            }

        # Error rates
        error_count = metrics["error_count"]
        total_errors = sum(error_count.values())
        error_rates: dict[str, Any] = {
            "by_type": dict(error_count),
            "total": total_errors,
        }

        return {
            "time_range_hours": time_range_hours,
            "total_triages": total_triages,
            "verdicts": verdicts,
            "triage_time": triage_time,
            "action_success_rates": action_success_rates,
            "stage_latency": stage_latency,
            "error_rates": error_rates,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def format_text_report(self) -> str:
        """Generate a human-readable text report.

        Returns:
            Formatted text report string
        """
        summary = self.generate_summary()

        lines = [
            "=" * 60,
            "TRIAGE WARDEN METRICS REPORT",
            "=" * 60,
            f"Generated: {summary['timestamp']}",
            "",
            "--- TRIAGE SUMMARY ---",
            f"Total Triages: {summary['total_triages']}",
            "",
        ]

        # Verdict breakdown
        if summary["verdicts"]:
            lines.append("Verdict Breakdown:")
            for verdict, data in sorted(summary["verdicts"].items()):
                lines.append(f"  {verdict:15} {data['count']:6d} ({data['percentage']:5.1f}%)")
            lines.append("")

        # Triage time stats
        triage_time = summary["triage_time"]
        lines.extend(
            [
                "Triage Time (ms):",
                f"  Mean:   {triage_time['mean_ms']:8.1f}",
                f"  Median: {triage_time['median_ms']:8.1f}",
                f"  P95:    {triage_time['p95_ms']:8.1f}",
                "",
            ]
        )

        # Action success rates
        if summary["action_success_rates"]:
            lines.append("--- ACTION SUCCESS RATES ---")
            for action_type, data in sorted(summary["action_success_rates"].items()):
                lines.append(
                    f"  {action_type:25} {data['success_rate']*100:5.1f}% "
                    f"(n={data['total_count']})"
                )
            lines.append("")

        # Stage latency
        if summary["stage_latency"]:
            lines.append("--- STAGE LATENCY (ms) ---")
            lines.append(f"  {'Stage':25} {'Mean':>8} {'Median':>8} {'P95':>8}")
            lines.append("  " + "-" * 53)
            for stage, data in sorted(summary["stage_latency"].items()):
                lines.append(
                    f"  {stage:25} {data['mean_ms']:8.1f} "
                    f"{data['median_ms']:8.1f} {data['p95_ms']:8.1f}"
                )
            lines.append("")

        # Error rates
        error_rates = summary["error_rates"]
        lines.append("--- ERRORS ---")
        lines.append(f"Total Errors: {error_rates['total']}")
        if error_rates["by_type"]:
            for error_type, count in sorted(error_rates["by_type"].items()):
                lines.append(f"  {error_type:25} {count:6d}")
        lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)

    def export_json(self) -> str:
        """Export metrics summary as JSON for dashboards.

        Returns:
            JSON string of the metrics summary
        """
        summary = self.generate_summary()
        return json.dumps(summary, indent=2)
