"""A/B testing framework for few-shot vs zero-shot performance (Stage 2.4.2).

Provides infrastructure for running controlled experiments comparing
dynamic few-shot example selection against static/zero-shot baselines.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

import structlog

from tw_ai.few_shot.config import FewShotConfig

logger = structlog.get_logger()


class ExperimentVariant(str, Enum):
    """Experiment variants for A/B testing."""

    ZERO_SHOT = "zero_shot"  # No examples in prompt
    STATIC = "static"  # Hardcoded examples from prompt files
    DYNAMIC = "dynamic"  # Similarity-selected examples
    HYBRID = "hybrid"  # Mix of static and dynamic


class AssignmentStrategy(str, Enum):
    """Strategies for assigning incidents to variants."""

    RANDOM = "random"  # Pure random assignment
    HASH = "hash"  # Consistent hashing (same incident -> same variant)
    ROUND_ROBIN = "round_robin"  # Alternate between variants
    MANUAL = "manual"  # Explicit assignment via incident metadata


@dataclass
class ExperimentConfig:
    """Configuration for an A/B experiment."""

    name: str
    description: str
    variants: list[ExperimentVariant]
    weights: list[float]  # Weight for each variant (must sum to 1.0)
    assignment_strategy: AssignmentStrategy = AssignmentStrategy.HASH
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: datetime | None = None
    alert_types: list[str] | None = None  # Filter to specific alert types
    enabled: bool = True

    def __post_init__(self) -> None:
        """Validate configuration."""
        if not self.variants:
            raise ValueError("At least one variant required")
        if len(self.variants) != len(self.weights):
            raise ValueError("Number of variants must match number of weights")
        if abs(sum(self.weights) - 1.0) > 0.001:
            raise ValueError("Weights must sum to 1.0")


@dataclass
class TrialResult:
    """Result of a single trial in the experiment."""

    trial_id: str
    incident_id: str
    variant: ExperimentVariant
    timestamp: datetime

    # Input metrics
    alert_type: str
    incident_text_length: int
    examples_provided: int

    # Output metrics (filled after analysis)
    verdict: str | None = None
    confidence: int | None = None
    analysis_latency_ms: int | None = None

    # Quality metrics (filled after human review)
    verdict_correct: bool | None = None
    confidence_calibrated: bool | None = None
    reasoning_quality: int | None = None  # 1-5 rating
    analyst_feedback: str | None = None

    # Example selection metrics (for dynamic/hybrid variants)
    example_selection_time_ms: int | None = None
    example_similarity_scores: list[float] = field(default_factory=list)
    example_ids_used: list[str] = field(default_factory=list)


@dataclass
class ExperimentMetrics:
    """Aggregated metrics for an experiment."""

    experiment_name: str
    variant: ExperimentVariant
    trial_count: int

    # Accuracy metrics
    verdict_accuracy: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None

    # Confidence calibration
    mean_confidence: float | None = None
    confidence_calibration_error: float | None = None

    # Quality metrics
    mean_reasoning_quality: float | None = None

    # Performance metrics
    mean_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    mean_example_selection_ms: float | None = None


class ABTestManager:
    """Manages A/B testing experiments for few-shot selection.

    Handles variant assignment, trial tracking, and metrics computation.
    """

    def __init__(self, config: FewShotConfig | None = None) -> None:
        """Initialize the A/B test manager.

        Args:
            config: Few-shot configuration.
        """
        self._config = config or FewShotConfig()
        self._experiments: dict[str, ExperimentConfig] = {}
        self._trials: dict[str, list[TrialResult]] = {}
        self._assignment_counter: dict[str, int] = {}

    def register_experiment(self, experiment: ExperimentConfig) -> None:
        """Register a new experiment.

        Args:
            experiment: Experiment configuration.
        """
        self._experiments[experiment.name] = experiment
        self._trials[experiment.name] = []
        self._assignment_counter[experiment.name] = 0

        logger.info(
            "experiment_registered",
            name=experiment.name,
            variants=[v.value for v in experiment.variants],
            weights=experiment.weights,
        )

    def get_active_experiment(
        self,
        alert_type: str | None = None,
    ) -> ExperimentConfig | None:
        """Get the currently active experiment.

        Args:
            alert_type: Optional alert type to filter experiments.

        Returns:
            Active experiment config or None.
        """
        now = datetime.utcnow()

        for experiment in self._experiments.values():
            if not experiment.enabled:
                continue

            # Check time window
            if experiment.end_time and now > experiment.end_time:
                continue

            # Check alert type filter
            if experiment.alert_types and alert_type:
                if alert_type not in experiment.alert_types:
                    continue

            return experiment

        return None

    def assign_variant(
        self,
        experiment_name: str,
        incident_id: str,
        incident_text: str,
    ) -> ExperimentVariant:
        """Assign an incident to an experiment variant.

        Args:
            experiment_name: Name of the experiment.
            incident_id: Unique incident identifier.
            incident_text: Incident text for hash-based assignment.

        Returns:
            Assigned variant.
        """
        experiment = self._experiments.get(experiment_name)
        if not experiment:
            raise ValueError(f"Unknown experiment: {experiment_name}")

        strategy = experiment.assignment_strategy

        if strategy == AssignmentStrategy.RANDOM:
            return self._assign_random(experiment)
        elif strategy == AssignmentStrategy.HASH:
            return self._assign_hash(experiment, incident_id, incident_text)
        elif strategy == AssignmentStrategy.ROUND_ROBIN:
            return self._assign_round_robin(experiment)
        else:  # MANUAL - requires explicit specification
            raise ValueError("Manual assignment requires explicit variant")

    def _assign_random(self, experiment: ExperimentConfig) -> ExperimentVariant:
        """Randomly assign variant based on weights."""
        r = random.random()
        cumulative = 0.0

        for variant, weight in zip(experiment.variants, experiment.weights):
            cumulative += weight
            if r < cumulative:
                return variant

        return experiment.variants[-1]

    def _assign_hash(
        self,
        experiment: ExperimentConfig,
        incident_id: str,
        incident_text: str,
    ) -> ExperimentVariant:
        """Assign variant using consistent hashing."""
        # Combine experiment name with incident for deterministic assignment
        hash_input = f"{experiment.name}:{incident_id}:{incident_text[:100]}"
        hash_val = int(hashlib.md5(hash_input.encode()).hexdigest(), 16)
        bucket = hash_val % 1000

        cumulative = 0.0
        for variant, weight in zip(experiment.variants, experiment.weights):
            cumulative += weight
            if bucket < cumulative * 1000:
                return variant

        return experiment.variants[-1]

    def _assign_round_robin(self, experiment: ExperimentConfig) -> ExperimentVariant:
        """Assign variant using round-robin."""
        counter = self._assignment_counter.get(experiment.name, 0)
        variant_index = counter % len(experiment.variants)
        self._assignment_counter[experiment.name] = counter + 1
        return experiment.variants[variant_index]

    def record_trial(
        self,
        experiment_name: str,
        trial: TrialResult,
    ) -> None:
        """Record the result of a trial.

        Args:
            experiment_name: Name of the experiment.
            trial: Trial result to record.
        """
        if experiment_name not in self._trials:
            self._trials[experiment_name] = []

        self._trials[experiment_name].append(trial)

        logger.debug(
            "trial_recorded",
            experiment=experiment_name,
            trial_id=trial.trial_id,
            variant=trial.variant.value,
            verdict=trial.verdict,
        )

    def record_feedback(
        self,
        experiment_name: str,
        trial_id: str,
        verdict_correct: bool,
        confidence_calibrated: bool | None = None,
        reasoning_quality: int | None = None,
        feedback: str | None = None,
    ) -> bool:
        """Record analyst feedback for a trial.

        Args:
            experiment_name: Name of the experiment.
            trial_id: ID of the trial.
            verdict_correct: Whether the verdict was correct.
            confidence_calibrated: Whether confidence matched outcome.
            reasoning_quality: 1-5 quality rating.
            feedback: Free-text feedback.

        Returns:
            True if trial was found and updated.
        """
        trials = self._trials.get(experiment_name, [])

        for trial in trials:
            if trial.trial_id == trial_id:
                trial.verdict_correct = verdict_correct
                trial.confidence_calibrated = confidence_calibrated
                trial.reasoning_quality = reasoning_quality
                trial.analyst_feedback = feedback

                logger.info(
                    "trial_feedback_recorded",
                    experiment=experiment_name,
                    trial_id=trial_id,
                    verdict_correct=verdict_correct,
                )
                return True

        return False

    def compute_metrics(
        self,
        experiment_name: str,
    ) -> dict[ExperimentVariant, ExperimentMetrics]:
        """Compute metrics for an experiment.

        Args:
            experiment_name: Name of the experiment.

        Returns:
            Dictionary mapping variants to their metrics.
        """
        trials = self._trials.get(experiment_name, [])
        experiment = self._experiments.get(experiment_name)

        if not experiment or not trials:
            return {}

        # Group trials by variant
        by_variant: dict[ExperimentVariant, list[TrialResult]] = {}
        for variant in experiment.variants:
            by_variant[variant] = [t for t in trials if t.variant == variant]

        # Compute metrics per variant
        results = {}
        for variant, variant_trials in by_variant.items():
            if not variant_trials:
                continue

            # Count trials with feedback
            with_feedback = [t for t in variant_trials if t.verdict_correct is not None]
            with_latency = [t for t in variant_trials if t.analysis_latency_ms is not None]
            with_quality = [t for t in variant_trials if t.reasoning_quality is not None]

            metrics = ExperimentMetrics(
                experiment_name=experiment_name,
                variant=variant,
                trial_count=len(variant_trials),
            )

            # Accuracy metrics
            if with_feedback:
                correct = sum(1 for t in with_feedback if t.verdict_correct)
                metrics.verdict_accuracy = correct / len(with_feedback)

                # FP/FN rates (for true_positive/false_positive verdicts)
                tp_trials = [t for t in with_feedback if t.verdict == "malicious"]
                fp_trials = [t for t in with_feedback if t.verdict == "benign"]

                if tp_trials:
                    fn = sum(1 for t in tp_trials if not t.verdict_correct)
                    metrics.false_negative_rate = fn / len(tp_trials)

                if fp_trials:
                    fp = sum(1 for t in fp_trials if not t.verdict_correct)
                    metrics.false_positive_rate = fp / len(fp_trials)

            # Confidence metrics
            confidence_values = [t.confidence for t in variant_trials if t.confidence is not None]
            if confidence_values:
                metrics.mean_confidence = sum(confidence_values) / len(confidence_values)

            # Quality metrics
            quality_values = [
                t.reasoning_quality for t in with_quality if t.reasoning_quality is not None
            ]
            if quality_values:
                metrics.mean_reasoning_quality = sum(quality_values) / len(quality_values)

            # Latency metrics
            latency_values = [
                t.analysis_latency_ms for t in with_latency if t.analysis_latency_ms is not None
            ]
            if latency_values:
                metrics.mean_latency_ms = sum(latency_values) / len(latency_values)
                sorted_latencies = sorted(latency_values)
                p95_idx = int(len(sorted_latencies) * 0.95)
                p95_latency_idx = min(p95_idx, len(sorted_latencies) - 1)
                metrics.p95_latency_ms = float(sorted_latencies[p95_latency_idx])

            # Example selection metrics (for dynamic/hybrid)
            selection_times = [
                t.example_selection_time_ms
                for t in variant_trials
                if t.example_selection_time_ms is not None
            ]
            if selection_times:
                metrics.mean_example_selection_ms = sum(selection_times) / len(selection_times)

            results[variant] = metrics

        return results

    def get_experiment_summary(self, experiment_name: str) -> dict[str, Any]:
        """Get a summary of experiment results.

        Args:
            experiment_name: Name of the experiment.

        Returns:
            Dictionary with experiment summary.
        """
        metrics_by_variant = self.compute_metrics(experiment_name)
        experiment = self._experiments.get(experiment_name)

        if not experiment:
            return {"error": "Unknown experiment"}

        summary: dict[str, Any] = {
            "experiment": experiment_name,
            "description": experiment.description,
            "enabled": experiment.enabled,
            "variants": {},
        }

        for variant, metrics in metrics_by_variant.items():
            summary["variants"][variant.value] = {
                "trial_count": metrics.trial_count,
                "verdict_accuracy": metrics.verdict_accuracy,
                "false_positive_rate": metrics.false_positive_rate,
                "false_negative_rate": metrics.false_negative_rate,
                "mean_confidence": metrics.mean_confidence,
                "mean_reasoning_quality": metrics.mean_reasoning_quality,
                "mean_latency_ms": metrics.mean_latency_ms,
                "p95_latency_ms": metrics.p95_latency_ms,
            }

        return summary


def create_default_experiment() -> ExperimentConfig:
    """Create the default few-shot A/B experiment.

    Compares static hardcoded examples (50%) vs dynamic
    similarity-selected examples (50%).

    Returns:
        Default experiment configuration.
    """
    return ExperimentConfig(
        name="few_shot_v1",
        description="Compare static vs dynamic few-shot example selection",
        variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
        weights=[0.5, 0.5],
        assignment_strategy=AssignmentStrategy.HASH,
    )


def create_zero_shot_experiment() -> ExperimentConfig:
    """Create an experiment comparing zero-shot vs few-shot.

    Useful for measuring the value of examples at all.

    Returns:
        Zero-shot baseline experiment configuration.
    """
    return ExperimentConfig(
        name="few_shot_baseline",
        description="Compare zero-shot baseline vs dynamic few-shot",
        variants=[ExperimentVariant.ZERO_SHOT, ExperimentVariant.DYNAMIC],
        weights=[0.5, 0.5],
        assignment_strategy=AssignmentStrategy.HASH,
    )
