"""Tests for DynamicPromptBuilder (Stage 2.4.2).

Comprehensive tests for the prompt builder that integrates few-shot
examples with triage prompt templates.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tw_ai.few_shot.ab_testing import (
    ABTestManager,
    AssignmentStrategy,
    ExperimentConfig,
    ExperimentVariant,
)
from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.models import (
    Example,
    ExampleMetadata,
    ExampleQuality,
    ExampleSet,
    FormattedExamples,
)
from tw_ai.few_shot.prompt_builder import (
    DynamicPromptBuilder,
    build_prompt_with_dynamic_examples,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_selector() -> MagicMock:
    """Create a mock FewShotSelector."""
    selector = MagicMock()
    selector.select_examples = AsyncMock()
    selector.format_for_prompt = MagicMock()
    return selector


@pytest.fixture
def mock_ab_manager() -> ABTestManager:
    """Create an ABTestManager with a registered experiment."""
    manager = ABTestManager()
    experiment = ExperimentConfig(
        name="test_exp",
        description="Test experiment",
        variants=[ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC],
        weights=[0.5, 0.5],
        assignment_strategy=AssignmentStrategy.HASH,
    )
    manager.register_experiment(experiment)
    return manager


@pytest.fixture
def sample_example_set() -> ExampleSet:
    """Create a sample ExampleSet for mock returns."""
    return ExampleSet(
        examples=[
            Example(
                id="ex_001",
                alert_context="Phishing email with suspicious attachment",
                analysis_output='{"verdict": "true_positive"}',
                reasoning_explanation="Clear phishing indicators",
                embedding_text="phishing email suspicious attachment",
                metadata=ExampleMetadata(
                    quality=ExampleQuality.HIGH,
                    alert_type="phishing",
                    verdict="malicious",
                    severity="high",
                ),
            ),
        ],
        selection_method="similarity",
        query_text="test alert",
    )


@pytest.fixture
def sample_formatted_examples() -> FormattedExamples:
    """Create sample FormattedExamples for mock returns."""
    return FormattedExamples(
        formatted_text="## Example Analyses\n\n### Example 1\nPhishing example content",
        example_count=1,
        example_ids=["ex_001"],
        total_tokens_estimate=100,
        alert_types_covered=["phishing"],
        verdicts_covered=["malicious"],
    )


@pytest.fixture
def builder(mock_selector: MagicMock) -> DynamicPromptBuilder:
    """Create a DynamicPromptBuilder with mock selector and no AB manager."""
    return DynamicPromptBuilder(selector=mock_selector)


@pytest.fixture
def builder_with_ab(
    mock_selector: MagicMock,
    mock_ab_manager: ABTestManager,
) -> DynamicPromptBuilder:
    """Create a DynamicPromptBuilder with AB testing enabled."""
    return DynamicPromptBuilder(
        selector=mock_selector,
        ab_manager=mock_ab_manager,
    )


# =============================================================================
# DynamicPromptBuilder Initialization Tests
# =============================================================================


class TestDynamicPromptBuilderInit:
    """Tests for DynamicPromptBuilder initialization."""

    def test_init_with_defaults(self, mock_selector: MagicMock) -> None:
        """Test initialization with default config."""
        builder = DynamicPromptBuilder(selector=mock_selector)
        assert builder._selector is mock_selector
        assert builder._ab_manager is None
        assert isinstance(builder._config, FewShotConfig)

    def test_init_with_custom_config(self, mock_selector: MagicMock) -> None:
        """Test initialization with custom config."""
        config = FewShotConfig(default_k=5, min_similarity_threshold=0.5)
        builder = DynamicPromptBuilder(selector=mock_selector, config=config)
        assert builder._config.default_k == 5
        assert builder._config.min_similarity_threshold == 0.5

    def test_init_with_ab_manager(
        self, mock_selector: MagicMock, mock_ab_manager: ABTestManager
    ) -> None:
        """Test initialization with AB test manager."""
        builder = DynamicPromptBuilder(
            selector=mock_selector, ab_manager=mock_ab_manager
        )
        assert builder._ab_manager is mock_ab_manager


# =============================================================================
# Variant Determination Tests
# =============================================================================


class TestVariantDetermination:
    """Tests for _determine_variant method."""

    def test_no_ab_manager_returns_dynamic(self, builder: DynamicPromptBuilder) -> None:
        """Without AB manager, should default to DYNAMIC."""
        variant = builder._determine_variant(
            alert_type="phishing",
            alert_context="test alert",
            incident_id=None,
            experiment_name=None,
        )
        assert variant == ExperimentVariant.DYNAMIC

    def test_ab_manager_no_experiment_returns_dynamic(
        self, mock_selector: MagicMock
    ) -> None:
        """With AB manager but no matching experiment, should return DYNAMIC."""
        manager = ABTestManager()
        builder = DynamicPromptBuilder(selector=mock_selector, ab_manager=manager)
        variant = builder._determine_variant(
            alert_type="phishing",
            alert_context="test alert",
            incident_id=None,
            experiment_name=None,
        )
        assert variant == ExperimentVariant.DYNAMIC

    def test_ab_manager_assigns_variant(
        self, builder_with_ab: DynamicPromptBuilder
    ) -> None:
        """With AB manager and active experiment, should assign a variant."""
        variant = builder_with_ab._determine_variant(
            alert_type="phishing",
            alert_context="test alert",
            incident_id="INC-001",
            experiment_name="test_exp",
        )
        assert variant in (ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC)

    def test_ab_manager_consistent_assignment(
        self, builder_with_ab: DynamicPromptBuilder
    ) -> None:
        """Hash-based assignment should be consistent for same inputs."""
        variant1 = builder_with_ab._determine_variant(
            alert_type="phishing",
            alert_context="same alert context",
            incident_id="INC-001",
            experiment_name="test_exp",
        )
        variant2 = builder_with_ab._determine_variant(
            alert_type="phishing",
            alert_context="same alert context",
            incident_id="INC-001",
            experiment_name="test_exp",
        )
        assert variant1 == variant2

    def test_ab_manager_uses_active_experiment_when_no_name(
        self, builder_with_ab: DynamicPromptBuilder
    ) -> None:
        """Should use get_active_experiment when no experiment_name given."""
        variant = builder_with_ab._determine_variant(
            alert_type="phishing",
            alert_context="test alert",
            incident_id="INC-001",
            experiment_name=None,
        )
        assert variant in (ExperimentVariant.STATIC, ExperimentVariant.DYNAMIC)


# =============================================================================
# Base Prompt Tests
# =============================================================================


class TestGetBasePrompt:
    """Tests for _get_base_prompt method."""

    def test_phishing_base_prompt(self, builder: DynamicPromptBuilder) -> None:
        """Test phishing base prompt contains expected content."""
        prompt = builder._get_base_prompt("phishing")
        assert "Phishing Triage" in prompt
        assert "T1566" in prompt
        assert "Spearphishing" in prompt
        assert "JSON" in prompt

    def test_malware_base_prompt(self, builder: DynamicPromptBuilder) -> None:
        """Test malware base prompt contains expected content."""
        prompt = builder._get_base_prompt("malware")
        assert "Malware" in prompt or "EDR" in prompt
        assert "JSON" in prompt

    def test_suspicious_login_base_prompt(self, builder: DynamicPromptBuilder) -> None:
        """Test suspicious login base prompt contains expected content."""
        prompt = builder._get_base_prompt("suspicious_login")
        assert "Login" in prompt or "Authentication" in prompt or "login" in prompt
        assert "JSON" in prompt

    def test_unknown_alert_type_base_prompt(
        self, builder: DynamicPromptBuilder
    ) -> None:
        """Test unknown alert type gets generic prompt."""
        prompt = builder._get_base_prompt("network_anomaly")
        assert "Network_Anomaly Triage" in prompt
        assert "JSON" in prompt


# =============================================================================
# Static Examples Tests
# =============================================================================


class TestGetStaticExamples:
    """Tests for _get_static_examples method."""

    def test_phishing_static_examples(self, builder: DynamicPromptBuilder) -> None:
        """Test phishing static examples are returned."""
        examples = builder._get_static_examples("phishing")
        assert len(examples) > 0

    def test_malware_static_examples(self, builder: DynamicPromptBuilder) -> None:
        """Test malware static examples are returned."""
        examples = builder._get_static_examples("malware")
        assert len(examples) > 0

    def test_suspicious_login_static_examples(
        self, builder: DynamicPromptBuilder
    ) -> None:
        """Test suspicious login static examples are returned."""
        examples = builder._get_static_examples("suspicious_login")
        assert len(examples) > 0

    def test_unknown_type_returns_empty(self, builder: DynamicPromptBuilder) -> None:
        """Test unknown alert type returns empty string."""
        examples = builder._get_static_examples("unknown_type")
        assert examples == ""


# =============================================================================
# Build Prompt Tests (async)
# =============================================================================


class TestBuildPhishingPrompt:
    """Tests for build_phishing_prompt method."""

    @pytest.mark.asyncio
    async def test_dynamic_variant_uses_selector(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test that dynamic variant calls selector."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples, variant = await builder.build_phishing_prompt(
            alert_context="Suspicious email from unknown sender",
        )

        assert variant == ExperimentVariant.DYNAMIC
        mock_selector.select_examples.assert_called_once()
        mock_selector.format_for_prompt.assert_called_once()
        assert examples is not None
        assert examples.example_count == 1
        assert "Suspicious email from unknown sender" in prompt

    @pytest.mark.asyncio
    async def test_prompt_includes_alert_context(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test that prompt includes the alert context."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, _, _ = await builder.build_phishing_prompt(
            alert_context="Test phishing alert data here",
        )

        assert "Test phishing alert data here" in prompt

    @pytest.mark.asyncio
    async def test_prompt_includes_org_context(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test that organization context is included when provided."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, _, _ = await builder.build_phishing_prompt(
            alert_context="Alert data",
            organization_context="ACME Corp uses Office 365",
        )

        assert "Organization Context" in prompt
        assert "ACME Corp uses Office 365" in prompt


class TestBuildMalwarePrompt:
    """Tests for build_malware_prompt method."""

    @pytest.mark.asyncio
    async def test_malware_prompt_builds(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test malware prompt builds successfully."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples, variant = await builder.build_malware_prompt(
            alert_context="Suspicious process execution detected",
        )

        assert "Suspicious process execution detected" in prompt
        assert variant == ExperimentVariant.DYNAMIC


class TestBuildSuspiciousLoginPrompt:
    """Tests for build_suspicious_login_prompt method."""

    @pytest.mark.asyncio
    async def test_suspicious_login_prompt_builds(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test suspicious login prompt builds successfully."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples, variant = await builder.build_suspicious_login_prompt(
            alert_context="Login from unusual location",
        )

        assert "Login from unusual location" in prompt
        assert variant == ExperimentVariant.DYNAMIC


# =============================================================================
# Variant-Specific Prompt Building Tests
# =============================================================================


class TestVariantSpecificBuilding:
    """Tests for different variant behaviors in _build_specialized_prompt."""

    @pytest.mark.asyncio
    async def test_zero_shot_variant_no_examples(
        self,
        mock_selector: MagicMock,
        mock_ab_manager: ABTestManager,
    ) -> None:
        """Test ZERO_SHOT variant includes no examples."""
        # Create experiment that always assigns ZERO_SHOT
        manager = ABTestManager()
        experiment = ExperimentConfig(
            name="zero_exp",
            description="Zero shot only",
            variants=[ExperimentVariant.ZERO_SHOT],
            weights=[1.0],
        )
        manager.register_experiment(experiment)

        builder = DynamicPromptBuilder(
            selector=mock_selector, ab_manager=manager
        )

        prompt, examples, variant = await builder.build_phishing_prompt(
            alert_context="Test alert",
            experiment_name="zero_exp",
        )

        assert variant == ExperimentVariant.ZERO_SHOT
        assert examples is None
        mock_selector.select_examples.assert_not_called()

    @pytest.mark.asyncio
    async def test_static_variant_uses_static_examples(
        self,
        mock_selector: MagicMock,
    ) -> None:
        """Test STATIC variant uses static examples from prompt files."""
        manager = ABTestManager()
        experiment = ExperimentConfig(
            name="static_exp",
            description="Static only",
            variants=[ExperimentVariant.STATIC],
            weights=[1.0],
        )
        manager.register_experiment(experiment)

        builder = DynamicPromptBuilder(
            selector=mock_selector, ab_manager=manager
        )

        prompt, examples, variant = await builder.build_phishing_prompt(
            alert_context="Test alert",
            experiment_name="static_exp",
        )

        assert variant == ExperimentVariant.STATIC
        assert examples is None
        mock_selector.select_examples.assert_not_called()
        # Static examples should be in the prompt (from phishing prompt file)
        assert len(prompt) > 0

    @pytest.mark.asyncio
    async def test_dynamic_variant_calls_selector(
        self,
        builder: DynamicPromptBuilder,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test DYNAMIC variant selects examples via selector."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples, variant = await builder.build_phishing_prompt(
            alert_context="Test alert",
        )

        assert variant == ExperimentVariant.DYNAMIC
        assert examples is not None
        assert examples.example_count == 1
        mock_selector.select_examples.assert_called_once()

    @pytest.mark.asyncio
    async def test_hybrid_variant_calls_selector(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test HYBRID variant also calls the selector."""
        manager = ABTestManager()
        experiment = ExperimentConfig(
            name="hybrid_exp",
            description="Hybrid only",
            variants=[ExperimentVariant.HYBRID],
            weights=[1.0],
        )
        manager.register_experiment(experiment)

        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        builder = DynamicPromptBuilder(
            selector=mock_selector, ab_manager=manager
        )

        prompt, examples, variant = await builder.build_phishing_prompt(
            alert_context="Test alert",
            experiment_name="hybrid_exp",
        )

        assert variant == ExperimentVariant.HYBRID
        assert examples is not None
        mock_selector.select_examples.assert_called_once()


# =============================================================================
# build_prompt_with_dynamic_examples Standalone Function Tests
# =============================================================================


class TestBuildPromptWithDynamicExamples:
    """Tests for the standalone convenience function."""

    @pytest.mark.asyncio
    async def test_phishing_type(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function with phishing alert type."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples = await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="phishing",
            alert_context="Phishing alert data",
        )

        assert "Phishing alert data" in prompt
        assert examples is not None

    @pytest.mark.asyncio
    async def test_malware_type(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function with malware alert type."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples = await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="malware",
            alert_context="Malware alert data",
        )

        assert "Malware alert data" in prompt

    @pytest.mark.asyncio
    async def test_suspicious_login_type(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function with suspicious_login alert type."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples = await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="suspicious_login",
            alert_context="Login from new IP",
        )

        assert "Login from new IP" in prompt

    @pytest.mark.asyncio
    async def test_generic_type_builds_simple_prompt(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function with unknown alert type uses generic path."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples = await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="network_anomaly",
            alert_context="Unusual network traffic",
        )

        assert "Unusual network traffic" in prompt
        assert examples is not None

    @pytest.mark.asyncio
    async def test_with_organization_context(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function passes organization context."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        prompt, examples = await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="phishing",
            alert_context="Alert data",
            organization_context="Uses Google Workspace",
        )

        assert "Organization Context" in prompt
        assert "Uses Google Workspace" in prompt

    @pytest.mark.asyncio
    async def test_custom_k_parameter(
        self,
        mock_selector: MagicMock,
        sample_example_set: ExampleSet,
        sample_formatted_examples: FormattedExamples,
    ) -> None:
        """Test convenience function passes custom k for generic type."""
        mock_selector.select_examples.return_value = sample_example_set
        mock_selector.format_for_prompt.return_value = sample_formatted_examples

        await build_prompt_with_dynamic_examples(
            selector=mock_selector,
            alert_type="custom_type",
            alert_context="Custom alert",
            k=7,
        )

        # Verify k=7 was passed to select_examples
        mock_selector.select_examples.assert_called_once_with(
            incident_text="Custom alert",
            alert_type="custom_type",
            k=7,
        )
