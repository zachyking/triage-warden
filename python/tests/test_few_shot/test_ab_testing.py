"""Tests for A/B testing framework (Stage 2.4.2)."""

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from tw_ai.few_shot.ab_testing import (
    ABTestManager,
    AssignmentStrategy,
    ExperimentConfig,
    ExperimentMetrics,
    ExperimentVariant,
    TrialResult,
    create_default_experiment,
    create_zero_shot_experiment,
)


class TestExperimentVariant:
    """Tests for ExperimentVariant enum."""

    def test_variant_values(self) -> None:
        """Test variant values."""
        assert ExperimentVariant.ZERO_SHOT.value == "zero_shot"
        assert ExperimentVariant.STATIC.value == "static"
        assert ExperimentVariant.DYNAMIC.value == "dynamic"
        assert ExperimentVariant.HYBRID.value == "hybrid"


class TestExperimentConfig:
    """Tests for ExperimentConfig."""

    def test_valid_config(self) -> None:
        """Test creating valid experiment config."""
        config = ExperimentConfig(
            name="test_experiment",
            description="Test description",
            variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
            weights=[0.5, 0.5],
        )

        assert config.name == "test_experiment"
        assert len(config.variants) == 2
        assert sum(config.weights) == 1.0
        assert config.enabled is True

    def test_weights_must_sum_to_one(self) -> None:
        """Test that weights must sum to 1.0."""
        with pytest.raises(ValueError, match="must sum to 1.0"):
            ExperimentConfig(
                name="test",
                description="test",
                variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
                weights=[0.3, 0.5],  # Sums to 0.8
            )

    def test_variants_and_weights_must_match(self) -> None:
        """Test variants and weights count must match."""
        with pytest.raises(ValueError, match="must match"):
            ExperimentConfig(
                name="test",
                description="test",
                variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
                weights=[1.0],  # Only one weight
            )

    def test_at_least_one_variant_required(self) -> None:
        """Test at least one variant is required."""
        with pytest.raises(ValueError, match="At least one"):
            ExperimentConfig(
                name="test",
                description="test",
                variants=[],
                weights=[],
            )


class TestTrialResult:
    """Tests for TrialResult."""

    def test_create_trial(self) -> None:
        """Test creating a trial result."""
        trial = TrialResult(
            trial_id="trial_001",
            incident_id="INC-12345",
            variant=ExperimentVariant.DYNAMIC,
            timestamp=datetime.utcnow(),
            alert_type="phishing",
            incident_text_length=500,
            examples_provided=3,
            verdict="malicious",
            confidence=85,
            analysis_latency_ms=1200,
        )

        assert trial.trial_id == "trial_001"
        assert trial.variant == ExperimentVariant.DYNAMIC
        assert trial.examples_provided == 3

    def test_trial_feedback_fields(self) -> None:
        """Test trial feedback fields."""
        trial = TrialResult(
            trial_id="trial_001",
            incident_id="INC-12345",
            variant=ExperimentVariant.STATIC,
            timestamp=datetime.utcnow(),
            alert_type="phishing",
            incident_text_length=500,
            examples_provided=3,
            verdict_correct=True,
            confidence_calibrated=True,
            reasoning_quality=4,
            analyst_feedback="Good analysis",
        )

        assert trial.verdict_correct is True
        assert trial.reasoning_quality == 4


class TestABTestManager:
    """Tests for ABTestManager."""

    @pytest.fixture
    def manager(self) -> ABTestManager:
        """Create an A/B test manager."""
        return ABTestManager()

    @pytest.fixture
    def sample_experiment(self) -> ExperimentConfig:
        """Create a sample experiment."""
        return ExperimentConfig(
            name="test_exp",
            description="Test experiment",
            variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
            weights=[0.5, 0.5],
            assignment_strategy=AssignmentStrategy.HASH,
        )

    def test_register_experiment(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test registering an experiment."""
        manager.register_experiment(sample_experiment)

        assert "test_exp" in manager._experiments
        assert "test_exp" in manager._trials

    def test_get_active_experiment(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test getting active experiment."""
        manager.register_experiment(sample_experiment)

        active = manager.get_active_experiment()
        assert active is not None
        assert active.name == "test_exp"

    def test_get_active_experiment_with_alert_type_filter(
        self,
        manager: ABTestManager,
    ) -> None:
        """Test experiment filtering by alert type."""
        experiment = ExperimentConfig(
            name="phishing_only",
            description="Phishing experiment",
            variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
            weights=[0.5, 0.5],
            alert_types=["phishing"],
        )
        manager.register_experiment(experiment)

        # Should match phishing
        assert manager.get_active_experiment("phishing") is not None

        # Should not match malware
        assert manager.get_active_experiment("malware") is None

    def test_assign_variant_hash_consistent(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test hash-based assignment is consistent."""
        manager.register_experiment(sample_experiment)

        # Same input should always get same variant
        variant1 = manager.assign_variant(
            "test_exp",
            "INC-001",
            "Suspicious email content",
        )
        variant2 = manager.assign_variant(
            "test_exp",
            "INC-001",
            "Suspicious email content",
        )

        assert variant1 == variant2

    def test_assign_variant_different_inputs(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test different inputs can get different variants."""
        manager.register_experiment(sample_experiment)

        variants = set()
        for i in range(100):
            variant = manager.assign_variant(
                "test_exp",
                f"INC-{i:04d}",
                f"Different content {i}",
            )
            variants.add(variant)

        # With 50/50 split and 100 samples, should see both variants
        assert len(variants) == 2

    def test_assign_variant_round_robin(
        self,
        manager: ABTestManager,
    ) -> None:
        """Test round-robin assignment."""
        experiment = ExperimentConfig(
            name="rr_exp",
            description="Round robin test",
            variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
            weights=[0.5, 0.5],
            assignment_strategy=AssignmentStrategy.ROUND_ROBIN,
        )
        manager.register_experiment(experiment)

        v1 = manager.assign_variant("rr_exp", "INC-001", "text1")
        v2 = manager.assign_variant("rr_exp", "INC-002", "text2")
        v3 = manager.assign_variant("rr_exp", "INC-003", "text3")
        v4 = manager.assign_variant("rr_exp", "INC-004", "text4")

        # Should alternate
        assert v1 == v3
        assert v2 == v4
        assert v1 != v2

    def test_record_trial(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test recording trial results."""
        manager.register_experiment(sample_experiment)

        trial = TrialResult(
            trial_id="trial_001",
            incident_id="INC-001",
            variant=ExperimentVariant.DYNAMIC,
            timestamp=datetime.utcnow(),
            alert_type="phishing",
            incident_text_length=500,
            examples_provided=3,
            verdict="malicious",
            confidence=85,
        )

        manager.record_trial("test_exp", trial)

        assert len(manager._trials["test_exp"]) == 1

    def test_record_feedback(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test recording analyst feedback."""
        manager.register_experiment(sample_experiment)

        trial = TrialResult(
            trial_id="trial_001",
            incident_id="INC-001",
            variant=ExperimentVariant.DYNAMIC,
            timestamp=datetime.utcnow(),
            alert_type="phishing",
            incident_text_length=500,
            examples_provided=3,
        )
        manager.record_trial("test_exp", trial)

        success = manager.record_feedback(
            "test_exp",
            "trial_001",
            verdict_correct=True,
            reasoning_quality=4,
        )

        assert success is True
        assert manager._trials["test_exp"][0].verdict_correct is True
        assert manager._trials["test_exp"][0].reasoning_quality == 4

    def test_compute_metrics(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test computing experiment metrics."""
        manager.register_experiment(sample_experiment)

        # Record some trials with feedback
        for i in range(10):
            trial = TrialResult(
                trial_id=f"trial_{i:03d}",
                incident_id=f"INC-{i:03d}",
                variant=ExperimentVariant.STATIC if i < 5 else ExperimentVariant.DYNAMIC,
                timestamp=datetime.utcnow(),
                alert_type="phishing",
                incident_text_length=500,
                examples_provided=3,
                verdict="malicious",
                confidence=80 + i,
                analysis_latency_ms=1000 + (i * 100),
                verdict_correct=i % 2 == 0,  # Half correct
                reasoning_quality=3 + (i % 3),
            )
            manager.record_trial("test_exp", trial)

        metrics = manager.compute_metrics("test_exp")

        assert ExperimentVariant.STATIC in metrics
        assert ExperimentVariant.DYNAMIC in metrics
        assert metrics[ExperimentVariant.STATIC].trial_count == 5
        assert metrics[ExperimentVariant.DYNAMIC].trial_count == 5

    def test_get_experiment_summary(
        self,
        manager: ABTestManager,
        sample_experiment: ExperimentConfig,
    ) -> None:
        """Test getting experiment summary."""
        manager.register_experiment(sample_experiment)

        # Add some trials
        trial = TrialResult(
            trial_id="trial_001",
            incident_id="INC-001",
            variant=ExperimentVariant.DYNAMIC,
            timestamp=datetime.utcnow(),
            alert_type="phishing",
            incident_text_length=500,
            examples_provided=3,
            verdict="malicious",
            confidence=85,
            verdict_correct=True,
        )
        manager.record_trial("test_exp", trial)

        summary = manager.get_experiment_summary("test_exp")

        assert summary["experiment"] == "test_exp"
        assert "variants" in summary
        assert "dynamic" in summary["variants"]


class TestFactoryFunctions:
    """Tests for factory functions."""

    def test_create_default_experiment(self) -> None:
        """Test creating default experiment."""
        experiment = create_default_experiment()

        assert experiment.name == "few_shot_v1"
        assert ExperimentVariant.STATIC in experiment.variants
        assert ExperimentVariant.DYNAMIC in experiment.variants
        assert experiment.weights == [0.5, 0.5]

    def test_create_zero_shot_experiment(self) -> None:
        """Test creating zero-shot baseline experiment."""
        experiment = create_zero_shot_experiment()

        assert experiment.name == "few_shot_baseline"
        assert ExperimentVariant.ZERO_SHOT in experiment.variants
        assert ExperimentVariant.DYNAMIC in experiment.variants
