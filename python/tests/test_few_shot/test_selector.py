"""Tests for FewShotSelector (Stage 2.4.2)."""

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.models import (
    Example,
    ExampleMetadata,
    ExampleQuality,
    ExampleSet,
)
from tw_ai.few_shot.selector import FewShotSelector, create_few_shot_selector


class TestFewShotConfig:
    """Tests for FewShotConfig."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = FewShotConfig()

        assert config.examples_collection == "few_shot_examples"
        assert config.default_k == 3
        assert config.min_similarity_threshold == 0.4
        assert config.quality_filter == "high"
        assert config.require_labeled is True
        assert config.max_example_tokens == 3000

    def test_custom_config(self) -> None:
        """Test custom configuration."""
        config = FewShotConfig(
            default_k=5,
            min_similarity_threshold=0.5,
            quality_filter="all",
            ab_test_enabled=True,
            ab_test_dynamic_percentage=75.0,
        )

        assert config.default_k == 5
        assert config.min_similarity_threshold == 0.5
        assert config.quality_filter == "all"
        assert config.ab_test_enabled is True
        assert config.ab_test_dynamic_percentage == 75.0

    def test_get_quality_filters(self) -> None:
        """Test quality filter generation."""
        # High quality filter
        config_high = FewShotConfig(quality_filter="high")
        assert config_high.get_quality_filters() == {"quality": "high"}

        # No filter for "all"
        config_all = FewShotConfig(quality_filter="all")
        assert config_all.get_quality_filters() is None

    def test_estimate_tokens(self) -> None:
        """Test token estimation."""
        config = FewShotConfig(tokens_per_char_estimate=0.25)

        # 100 chars * 0.25 = 25 tokens
        assert config.estimate_tokens("a" * 100) == 25
        assert config.estimate_tokens("") == 0


class TestFewShotSelector:
    """Tests for FewShotSelector."""

    @pytest.fixture
    def mock_rag_service(self) -> MagicMock:
        """Create a mock RAG service."""
        rag = MagicMock()
        rag.retrieval = MagicMock()
        rag.vector_store = MagicMock()
        return rag

    @pytest.fixture
    def selector(self, mock_rag_service: MagicMock) -> FewShotSelector:
        """Create a selector with mock RAG service."""
        config = FewShotConfig(
            ab_test_enabled=False,
            fallback_to_static=True,
        )
        return FewShotSelector(rag_service=mock_rag_service, config=config)

    @pytest.fixture
    def sample_static_examples(self) -> list[Example]:
        """Create sample static examples."""
        return [
            Example(
                id="static_001",
                alert_context="Static phishing example 1",
                analysis_output='{"verdict": "malicious"}',
                reasoning_explanation="Test reasoning",
                embedding_text="test",
                metadata=ExampleMetadata(
                    quality=ExampleQuality.HIGH,
                    alert_type="phishing",
                    verdict="malicious",
                    severity="high",
                ),
            ),
            Example(
                id="static_002",
                alert_context="Static phishing example 2",
                analysis_output='{"verdict": "benign"}',
                reasoning_explanation="Test reasoning",
                embedding_text="test",
                metadata=ExampleMetadata(
                    quality=ExampleQuality.HIGH,
                    alert_type="phishing",
                    verdict="benign",
                    severity="info",
                ),
            ),
        ]

    def test_create_selector(self, mock_rag_service: MagicMock) -> None:
        """Test selector creation via factory."""
        selector = create_few_shot_selector(mock_rag_service)

        assert selector is not None
        assert selector._rag == mock_rag_service

    def test_register_static_examples(
        self,
        selector: FewShotSelector,
        sample_static_examples: list[Example],
    ) -> None:
        """Test registering static fallback examples."""
        selector.register_static_examples("phishing", sample_static_examples)

        assert "phishing" in selector._static_examples
        assert len(selector._static_examples["phishing"]) == 2

    @pytest.mark.asyncio
    async def test_select_examples_similarity(
        self,
        selector: FewShotSelector,
        mock_rag_service: MagicMock,
    ) -> None:
        """Test selecting examples via similarity search."""
        # Mock the search response
        mock_result = MagicMock()
        mock_result.id = "ex_001"
        mock_result.content = "phishing email test"
        mock_result.similarity = 0.85
        mock_result.metadata = {
            "quality": "high",
            "labeled": True,
            "alert_type": "phishing",
            "verdict": "malicious",
            "severity": "high",
            "confidence_min": 80,
            "confidence_max": 95,
            "technique_ids": "T1566.001",
            "alert_context": "Test phishing context",
            "analysis_output": '{"verdict": "malicious"}',
            "reasoning_explanation": "Test reasoning",
        }

        mock_response = MagicMock()
        mock_response.results = [mock_result]

        mock_rag_service.retrieval.search.return_value = mock_response

        # Execute
        result = await selector.select_examples(
            incident_text="Suspicious email from unknown sender",
            alert_type="phishing",
            k=1,
        )

        # Verify
        assert isinstance(result, ExampleSet)
        assert result.selection_method == "similarity"
        assert len(result.examples) == 1
        assert result.examples[0].id == "ex_001"
        assert result.examples[0].metadata.alert_type == "phishing"

    @pytest.mark.asyncio
    async def test_select_examples_fallback_to_static(
        self,
        selector: FewShotSelector,
        mock_rag_service: MagicMock,
        sample_static_examples: list[Example],
    ) -> None:
        """Test fallback to static examples on search failure."""
        # Register static examples
        selector.register_static_examples("phishing", sample_static_examples)

        # Mock search failure
        mock_rag_service.retrieval.search.side_effect = Exception("Search failed")

        # Execute
        result = await selector.select_examples(
            incident_text="Test incident",
            alert_type="phishing",
            k=2,
        )

        # Verify fallback to static
        assert result.selection_method == "static"
        assert len(result.examples) <= 2

    @pytest.mark.asyncio
    async def test_select_examples_ab_testing(
        self,
        mock_rag_service: MagicMock,
        sample_static_examples: list[Example],
    ) -> None:
        """Test A/B testing variant assignment."""
        config = FewShotConfig(
            ab_test_enabled=True,
            ab_test_dynamic_percentage=0.0,  # Always use static
        )
        selector = FewShotSelector(rag_service=mock_rag_service, config=config)
        selector.register_static_examples("phishing", sample_static_examples)

        result = await selector.select_examples(
            incident_text="Test incident",
            alert_type="phishing",
        )

        # Should use static because dynamic percentage is 0
        assert result.selection_method == "static"

    def test_format_for_prompt(
        self,
        selector: FewShotSelector,
        sample_static_examples: list[Example],
    ) -> None:
        """Test formatting examples for prompt injection."""
        example_set = ExampleSet(
            examples=sample_static_examples,
            selection_method="static",
            query_text="test",
        )

        formatted = selector.format_for_prompt(example_set)

        # Verify formatting
        assert "## Example Analyses" in formatted.formatted_text
        assert "Example 1" in formatted.formatted_text
        assert "Example 2" in formatted.formatted_text
        assert formatted.example_count == 2
        assert "static_001" in formatted.example_ids
        assert "phishing" in formatted.alert_types_covered

    def test_format_for_prompt_with_token_limit(
        self,
        selector: FewShotSelector,
    ) -> None:
        """Test formatting respects token limit."""
        # Create examples that would exceed token limit
        large_context = "A" * 5000  # Very large context
        examples = [
            Example(
                id=f"ex_{i}",
                alert_context=large_context,
                analysis_output="{}",
                reasoning_explanation="Test",
                embedding_text="test",
                metadata=ExampleMetadata(
                    alert_type="phishing",
                    verdict="malicious",
                    severity="high",
                ),
            )
            for i in range(5)
        ]

        example_set = ExampleSet(
            examples=examples,
            selection_method="similarity",
            query_text="test",
        )

        # Format with small token limit
        formatted = selector.format_for_prompt(example_set, max_tokens=500)

        # Should include fewer examples than provided
        assert formatted.example_count < 5

    @pytest.mark.asyncio
    async def test_diverse_selection(
        self,
        selector: FewShotSelector,
        mock_rag_service: MagicMock,
    ) -> None:
        """Test diverse example selection (different verdicts)."""
        # Mock results with same verdict
        results = []
        for i in range(5):
            mock_result = MagicMock()
            mock_result.id = f"ex_{i:03d}"
            mock_result.content = f"test content {i}"
            mock_result.similarity = 0.9 - (i * 0.05)
            mock_result.metadata = {
                "quality": "high",
                "labeled": True,
                "alert_type": "phishing",
                "verdict": "malicious" if i % 2 == 0 else "benign",
                "severity": "high",
                "confidence_min": 80,
                "confidence_max": 95,
                "technique_ids": "",
                "alert_context": f"Test context {i}",
                "analysis_output": "{}",
                "reasoning_explanation": "Test",
            }
            results.append(mock_result)

        mock_response = MagicMock()
        mock_response.results = results

        mock_rag_service.retrieval.search.return_value = mock_response

        # Configure selector for diversity
        selector._config = FewShotConfig(require_verdict_diversity=True)

        result = await selector.select_examples(
            incident_text="Test",
            alert_type="phishing",
            k=3,
        )

        # Should have diverse verdicts
        verdicts = {ex.metadata.verdict for ex in result.examples}
        assert len(verdicts) >= 2  # At least 2 different verdicts


class TestFewShotSelectorFilters:
    """Tests for filter building in FewShotSelector."""

    @pytest.fixture
    def selector(self) -> FewShotSelector:
        """Create selector with mock RAG."""
        mock_rag = MagicMock()
        return FewShotSelector(
            rag_service=mock_rag,
            config=FewShotConfig(
                quality_filter="high",
                require_labeled=True,
            ),
        )

    def test_build_filters_basic(self, selector: FewShotSelector) -> None:
        """Test basic filter building."""
        filters = selector._build_filters(
            alert_type="phishing",
            verdict_filter=None,
            technique_filter=None,
        )

        assert filters is not None
        assert filters["quality"] == "high"
        assert filters["labeled"] is True
        assert filters["alert_type"] == "phishing"

    def test_build_filters_with_verdict(self, selector: FewShotSelector) -> None:
        """Test filter with verdict."""
        filters = selector._build_filters(
            alert_type="malware",
            verdict_filter="malicious",
            technique_filter=None,
        )

        assert filters["verdict"] == "malicious"

    def test_build_filters_no_alert_type(self, selector: FewShotSelector) -> None:
        """Test filter without alert type."""
        filters = selector._build_filters(
            alert_type=None,
            verdict_filter=None,
            technique_filter=None,
        )

        assert "alert_type" not in filters
        assert filters["quality"] == "high"
