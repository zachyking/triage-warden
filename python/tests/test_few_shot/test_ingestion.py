"""Tests for example ingestion (Stage 2.4.2)."""

import json
import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.ingestion import ExampleCurator, ExampleIngester
from tw_ai.few_shot.models import (
    Example,
    ExampleMetadata,
    ExampleQuality,
)


class TestExampleIngester:
    """Tests for ExampleIngester."""

    @pytest.fixture
    def mock_rag_service(self) -> MagicMock:
        """Create mock RAG service."""
        rag = MagicMock()
        rag.vector_store = MagicMock()
        return rag

    @pytest.fixture
    def ingester(self, mock_rag_service: MagicMock) -> ExampleIngester:
        """Create ingester with mock RAG."""
        return ExampleIngester(
            rag_service=mock_rag_service,
            config=FewShotConfig(),
        )

    @pytest.fixture
    def sample_example(self) -> Example:
        """Create a sample example."""
        return Example(
            id="ex_001",
            alert_context="User received email from support@micros0ft.com",
            analysis_output='{"verdict": "malicious", "confidence": 92}',
            reasoning_explanation="Typosquatted domain indicates phishing",
            embedding_text="phishing email typosquatting microsoft",
            metadata=ExampleMetadata(
                quality=ExampleQuality.HIGH,
                alert_type="phishing",
                verdict="malicious",
                severity="high",
                technique_ids=["T1566.001"],
            ),
        )

    @pytest.mark.asyncio
    async def test_ingest_example(
        self,
        ingester: ExampleIngester,
        mock_rag_service: MagicMock,
        sample_example: Example,
    ) -> None:
        """Test ingesting a single example."""
        doc_id = await ingester.ingest_example(sample_example)

        assert doc_id == "ex_001"
        mock_rag_service.vector_store.add.assert_called_once()

        # Verify call arguments
        call_args = mock_rag_service.vector_store.add.call_args
        assert call_args.kwargs["collection_name"] == "few_shot_examples"
        assert call_args.kwargs["ids"] == ["ex_001"]

    @pytest.mark.asyncio
    async def test_ingest_examples_batch(
        self,
        ingester: ExampleIngester,
        mock_rag_service: MagicMock,
    ) -> None:
        """Test batch ingestion of examples."""
        examples = [
            Example(
                id=f"ex_{i:03d}",
                alert_context=f"Test context {i}",
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

        doc_ids = await ingester.ingest_examples(examples)

        assert len(doc_ids) == 5
        mock_rag_service.vector_store.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_ingest_empty_list(
        self,
        ingester: ExampleIngester,
        mock_rag_service: MagicMock,
    ) -> None:
        """Test ingesting empty list returns empty."""
        doc_ids = await ingester.ingest_examples([])

        assert doc_ids == []
        mock_rag_service.vector_store.add.assert_not_called()

    @pytest.mark.asyncio
    async def test_ingest_from_file(
        self,
        ingester: ExampleIngester,
        mock_rag_service: MagicMock,
    ) -> None:
        """Test ingesting from JSON file."""
        # Create temp file with examples
        examples_data = {
            "examples": [
                {
                    "id": "file_ex_001",
                    "alert_context": "Test phishing context",
                    "analysis_output": '{"verdict": "malicious"}',
                    "reasoning_explanation": "Test reasoning",
                    "metadata": {
                        "quality": "high",
                        "alert_type": "phishing",
                        "verdict": "malicious",
                        "severity": "high",
                        "technique_ids": ["T1566.001"],
                    },
                },
                {
                    "id": "file_ex_002",
                    "alert_context": "Test benign context",
                    "analysis_output": '{"verdict": "benign"}',
                    "reasoning_explanation": "Test reasoning",
                    "metadata": {
                        "quality": "medium",
                        "alert_type": "phishing",
                        "verdict": "benign",
                        "severity": "info",
                    },
                },
            ]
        }

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
        ) as f:
            json.dump(examples_data, f)
            temp_path = Path(f.name)

        try:
            doc_ids = await ingester.ingest_from_file(temp_path)

            assert len(doc_ids) == 2
            assert "file_ex_001" in doc_ids
            assert "file_ex_002" in doc_ids
        finally:
            temp_path.unlink()

    def test_parse_example_dict(self, ingester: ExampleIngester) -> None:
        """Test parsing example from dictionary."""
        data = {
            "id": "parsed_001",
            "alert_context": "Test context",
            "analysis_output": '{"verdict": "suspicious"}',
            "reasoning_explanation": "Test reasoning",
            "metadata": {
                "quality": "high",
                "labeled": True,
                "curator": "analyst1",
                "alert_type": "malware",
                "verdict": "suspicious",
                "severity": "medium",
                "confidence_range": [50, 70],
                "technique_ids": ["T1059.001"],
            },
        }

        example = ingester._parse_example_dict(data)

        assert example.id == "parsed_001"
        assert example.metadata.quality == ExampleQuality.HIGH
        assert example.metadata.curator == "analyst1"
        assert example.metadata.confidence_range == (50, 70)
        assert example.metadata.technique_ids == ["T1059.001"]

    def test_generate_embedding_text(self, ingester: ExampleIngester) -> None:
        """Test embedding text generation."""
        metadata = ExampleMetadata(
            alert_type="phishing",
            verdict="malicious",
            severity="high",
            technique_ids=["T1566.001", "T1566.002"],
        )

        embedding_text = ingester._generate_embedding_text(
            "Test alert context",
            metadata,
        )

        assert "Alert Type: phishing" in embedding_text
        assert "Verdict: malicious" in embedding_text
        assert "Severity: high" in embedding_text
        assert "T1566.001" in embedding_text
        assert "Test alert context" in embedding_text


class TestExampleCurator:
    """Tests for ExampleCurator."""

    @pytest.fixture
    def mock_rag_service(self) -> MagicMock:
        """Create mock RAG service."""
        return MagicMock()

    @pytest.fixture
    def curator(self, mock_rag_service: MagicMock) -> ExampleCurator:
        """Create curator with mock RAG."""
        return ExampleCurator(
            rag_service=mock_rag_service,
            config=FewShotConfig(),
        )

    @pytest.mark.asyncio
    async def test_promote_to_high_quality(
        self,
        curator: ExampleCurator,
    ) -> None:
        """Test promoting example to high quality."""
        result = await curator.promote_to_high_quality(
            example_id="ex_001",
            curator="analyst1",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_demote_to_low_quality(
        self,
        curator: ExampleCurator,
    ) -> None:
        """Test demoting example to low quality."""
        result = await curator.demote_to_low_quality(
            example_id="ex_001",
            curator="analyst1",
        )

        assert result is True

    @pytest.mark.asyncio
    async def test_record_feedback(
        self,
        curator: ExampleCurator,
    ) -> None:
        """Test recording analyst feedback."""
        result = await curator.record_feedback(
            example_id="ex_001",
            positive=True,
            analyst="analyst1",
        )

        assert result is True

    def test_create_example_from_incident(
        self,
        curator: ExampleCurator,
    ) -> None:
        """Test creating example from completed incident."""
        example = curator.create_example_from_incident(
            incident_id="INC-12345",
            alert_context="Suspicious email from unknown sender",
            analysis_output='{"verdict": "malicious", "confidence": 85}',
            alert_type="phishing",
            verdict="malicious",
            severity="high",
            confidence=85,
            reasoning="Typosquatted domain and suspicious attachment",
            technique_ids=["T1566.001"],
            curator="analyst1",
        )

        assert example.id == "example_phishing_INC-12345"
        assert example.source_incident_id == "INC-12345"
        assert example.metadata.quality == ExampleQuality.MEDIUM
        assert example.metadata.curator == "analyst1"
        assert example.metadata.confidence_range == (80, 100)  # 85 falls in high bracket

    def test_create_example_confidence_ranges(
        self,
        curator: ExampleCurator,
    ) -> None:
        """Test confidence range bracketing."""
        # High confidence
        high_example = curator.create_example_from_incident(
            incident_id="INC-001",
            alert_context="Test",
            analysis_output="{}",
            alert_type="malware",
            verdict="malicious",
            severity="critical",
            confidence=95,
            reasoning="Test",
        )
        assert high_example.metadata.confidence_range == (80, 100)

        # Medium confidence
        med_example = curator.create_example_from_incident(
            incident_id="INC-002",
            alert_context="Test",
            analysis_output="{}",
            alert_type="malware",
            verdict="suspicious",
            severity="medium",
            confidence=60,
            reasoning="Test",
        )
        assert med_example.metadata.confidence_range == (50, 79)

        # Low confidence
        low_example = curator.create_example_from_incident(
            incident_id="INC-003",
            alert_context="Test",
            analysis_output="{}",
            alert_type="malware",
            verdict="inconclusive",
            severity="low",
            confidence=30,
            reasoning="Test",
        )
        assert low_example.metadata.confidence_range == (0, 49)
