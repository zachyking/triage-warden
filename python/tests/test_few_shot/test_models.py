"""Tests for few-shot models (Stage 2.4.2)."""

from datetime import datetime

import pytest

from tw_ai.few_shot.models import (
    Example,
    ExampleDocument,
    ExampleMetadata,
    ExampleQuality,
    ExampleSet,
    FormattedExamples,
)


class TestExampleQuality:
    """Tests for ExampleQuality enum."""

    def test_quality_values(self) -> None:
        """Test quality tier values."""
        assert ExampleQuality.HIGH.value == "high"
        assert ExampleQuality.MEDIUM.value == "medium"
        assert ExampleQuality.LOW.value == "low"

    def test_quality_from_string(self) -> None:
        """Test creating quality from string."""
        assert ExampleQuality("high") == ExampleQuality.HIGH
        assert ExampleQuality("medium") == ExampleQuality.MEDIUM
        assert ExampleQuality("low") == ExampleQuality.LOW


class TestExampleMetadata:
    """Tests for ExampleMetadata model."""

    def test_default_values(self) -> None:
        """Test default metadata values."""
        metadata = ExampleMetadata(
            alert_type="phishing",
            verdict="malicious",
            severity="high",
        )

        assert metadata.quality == ExampleQuality.MEDIUM
        assert metadata.labeled is True
        assert metadata.curator is None
        assert metadata.confidence_range == (0, 100)
        assert metadata.technique_ids == []
        assert metadata.usage_count == 0

    def test_full_metadata(self) -> None:
        """Test metadata with all fields."""
        metadata = ExampleMetadata(
            quality=ExampleQuality.HIGH,
            labeled=True,
            curator="analyst1",
            curated_at=datetime(2024, 1, 1),
            alert_type="phishing",
            verdict="malicious",
            severity="critical",
            confidence_range=(85, 95),
            technique_ids=["T1566.001", "T1566.002"],
            usage_count=5,
            positive_feedback=3,
            negative_feedback=1,
        )

        assert metadata.quality == ExampleQuality.HIGH
        assert metadata.curator == "analyst1"
        assert metadata.technique_ids == ["T1566.001", "T1566.002"]
        assert metadata.positive_feedback == 3


class TestExample:
    """Tests for Example model."""

    @pytest.fixture
    def sample_metadata(self) -> ExampleMetadata:
        """Create sample metadata."""
        return ExampleMetadata(
            quality=ExampleQuality.HIGH,
            alert_type="phishing",
            verdict="malicious",
            severity="high",
            technique_ids=["T1566.001"],
        )

    def test_create_example(self, sample_metadata: ExampleMetadata) -> None:
        """Test creating an example."""
        example = Example(
            id="phishing_001",
            alert_context="User received suspicious email from support@micros0ft.com",
            analysis_output='{"verdict": "malicious", "confidence": 92}',
            reasoning_explanation="Typosquatted domain indicates phishing attempt",
            embedding_text="phishing email typosquatting microsoft",
            metadata=sample_metadata,
        )

        assert example.id == "phishing_001"
        assert "micros0ft.com" in example.alert_context
        assert example.metadata.alert_type == "phishing"

    def test_example_with_source_incident(self, sample_metadata: ExampleMetadata) -> None:
        """Test example linked to source incident."""
        example = Example(
            id="phishing_001",
            alert_context="Test context",
            analysis_output="{}",
            reasoning_explanation="Test reasoning",
            embedding_text="test",
            metadata=sample_metadata,
            source_incident_id="INC-12345",
        )

        assert example.source_incident_id == "INC-12345"


class TestExampleDocument:
    """Tests for ExampleDocument model."""

    def test_to_metadata(self) -> None:
        """Test converting document to ChromaDB metadata."""
        doc = ExampleDocument(
            id="doc_001",
            content="test embedding text",
            alert_context="Test alert context",
            analysis_output='{"verdict": "malicious"}',
            reasoning_explanation="Test reasoning",
            quality="high",
            labeled=True,
            alert_type="phishing",
            verdict="malicious",
            severity="high",
            confidence_min=80,
            confidence_max=95,
            technique_ids="T1566.001,T1566.002",
        )

        metadata = doc.to_metadata()

        assert metadata["quality"] == "high"
        assert metadata["labeled"] is True
        assert metadata["alert_type"] == "phishing"
        assert metadata["verdict"] == "malicious"
        assert metadata["confidence_min"] == 80
        assert metadata["technique_ids"] == "T1566.001,T1566.002"

    def test_from_example(self) -> None:
        """Test creating document from Example."""
        example = Example(
            id="ex_001",
            alert_context="Test context",
            analysis_output='{"verdict": "benign"}',
            reasoning_explanation="Test reasoning",
            embedding_text="test embedding",
            metadata=ExampleMetadata(
                quality=ExampleQuality.HIGH,
                alert_type="malware",
                verdict="benign",
                severity="low",
                confidence_range=(90, 100),
                technique_ids=["T1059.001"],
            ),
        )

        doc = ExampleDocument.from_example(example)

        assert doc.id == "ex_001"
        assert doc.content == "test embedding"
        assert doc.quality == "high"
        assert doc.alert_type == "malware"
        assert doc.confidence_min == 90
        assert doc.confidence_max == 100
        assert doc.technique_ids == "T1059.001"


class TestExampleSet:
    """Tests for ExampleSet model."""

    @pytest.fixture
    def sample_examples(self) -> list[Example]:
        """Create sample examples."""
        return [
            Example(
                id="ex_001",
                alert_context="Phishing email",
                analysis_output="{}",
                reasoning_explanation="",
                embedding_text="test",
                metadata=ExampleMetadata(
                    alert_type="phishing",
                    verdict="malicious",
                    severity="high",
                ),
            ),
            Example(
                id="ex_002",
                alert_context="Legitimate email",
                analysis_output="{}",
                reasoning_explanation="",
                embedding_text="test",
                metadata=ExampleMetadata(
                    alert_type="phishing",
                    verdict="benign",
                    severity="info",
                ),
            ),
        ]

    def test_example_set_properties(self, sample_examples: list[Example]) -> None:
        """Test ExampleSet computed properties."""
        example_set = ExampleSet(
            examples=sample_examples,
            selection_method="similarity",
            query_text="test query",
            execution_time_ms=50,
        )

        assert example_set.count == 2
        assert example_set.alert_types == {"phishing"}
        assert example_set.verdicts == {"malicious", "benign"}

    def test_empty_example_set(self) -> None:
        """Test empty ExampleSet."""
        example_set = ExampleSet(
            examples=[],
            selection_method="similarity",
            query_text="test",
        )

        assert example_set.count == 0
        assert example_set.alert_types == set()


class TestFormattedExamples:
    """Tests for FormattedExamples model."""

    def test_formatted_examples(self) -> None:
        """Test FormattedExamples model."""
        formatted = FormattedExamples(
            formatted_text="## Example 1\n\nTest example",
            example_count=1,
            example_ids=["ex_001"],
            total_tokens_estimate=50,
            alert_types_covered=["phishing"],
            verdicts_covered=["malicious"],
        )

        assert formatted.example_count == 1
        assert "ex_001" in formatted.example_ids
        assert "phishing" in formatted.alert_types_covered
