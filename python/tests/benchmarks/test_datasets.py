"""Unit tests for benchmark datasets module.

Tests cover:
- BenchmarkExample creation and validation
- BenchmarkDataset operations
- SecurityBenchmark aggregation
- YAML loading/saving
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

# Mock structlog before imports
class MockStructlog:
    @staticmethod
    def get_logger():
        logger = MagicMock()
        logger.info = MagicMock()
        logger.warning = MagicMock()
        logger.error = MagicMock()
        logger.debug = MagicMock()
        return logger

sys.modules["structlog"] = MockStructlog()

# Direct module loading to avoid full package imports
import importlib.util
import os

def load_module_directly(name: str, file_path: str):
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

base_path = os.path.join(os.path.dirname(__file__), "..", "..", "tw_ai", "benchmarks")

datasets_module = load_module_directly(
    "tw_ai.benchmarks.datasets",
    os.path.join(base_path, "datasets.py")
)

BenchmarkExample = datasets_module.BenchmarkExample
BenchmarkDataset = datasets_module.BenchmarkDataset
SecurityBenchmark = datasets_module.SecurityBenchmark
TaskType = datasets_module.TaskType


class TestBenchmarkExample:
    """Tests for BenchmarkExample dataclass."""

    def test_create_example(self):
        """Test basic example creation."""
        example = BenchmarkExample(
            id="test_001",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            input_data={"alert_type": "email", "subject": "Test"},
            expected_output={"verdict": "true_positive", "confidence": 90},
            difficulty="medium",
            category="phishing",
            tags=["email", "credential-theft"],
        )

        assert example.id == "test_001"
        assert example.task_type == TaskType.VERDICT_CLASSIFICATION
        assert example.difficulty == "medium"
        assert "email" in example.tags

    def test_create_example_with_string_task_type(self):
        """Test example creation with string task type."""
        example = BenchmarkExample(
            id="test_002",
            task_type="verdict_classification",
            input_data={"data": "test"},
            expected_output={"verdict": "benign"},
        )

        assert example.task_type == TaskType.VERDICT_CLASSIFICATION

    def test_example_validation_empty_id(self):
        """Test that empty ID raises ValueError."""
        with pytest.raises(ValueError, match="id cannot be empty"):
            BenchmarkExample(
                id="",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"data": "test"},
                expected_output={"verdict": "benign"},
            )

    def test_example_validation_empty_input(self):
        """Test that empty input_data raises ValueError."""
        with pytest.raises(ValueError, match="input_data cannot be empty"):
            BenchmarkExample(
                id="test_001",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={},
                expected_output={"verdict": "benign"},
            )

    def test_example_validation_empty_expected(self):
        """Test that empty expected_output raises ValueError."""
        with pytest.raises(ValueError, match="expected_output cannot be empty"):
            BenchmarkExample(
                id="test_001",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"data": "test"},
                expected_output={},
            )

    def test_example_validation_invalid_difficulty(self):
        """Test that invalid difficulty raises ValueError."""
        with pytest.raises(ValueError, match="Invalid difficulty"):
            BenchmarkExample(
                id="test_001",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"data": "test"},
                expected_output={"verdict": "benign"},
                difficulty="impossible",
            )

    def test_from_dict(self):
        """Test creating example from dictionary."""
        data = {
            "id": "test_001",
            "task_type": "severity_rating",
            "input": {"alert_type": "ransomware"},
            "expected": {"severity": "critical"},
            "difficulty": "hard",
            "category": "ransomware",
            "tags": ["encryption"],
        }

        example = BenchmarkExample.from_dict(data)

        assert example.id == "test_001"
        assert example.task_type == TaskType.SEVERITY_RATING
        assert example.difficulty == "hard"
        assert example.category == "ransomware"

    def test_to_dict(self):
        """Test converting example to dictionary."""
        example = BenchmarkExample(
            id="test_001",
            task_type=TaskType.MITRE_MAPPING,
            input_data={"description": "Attack"},
            expected_output={"techniques": []},
            difficulty="easy",
            category="lateral-movement",
        )

        result = example.to_dict()

        assert result["id"] == "test_001"
        assert result["task_type"] == "mitre_mapping"
        assert result["difficulty"] == "easy"


class TestBenchmarkDataset:
    """Tests for BenchmarkDataset class."""

    @pytest.fixture
    def sample_examples(self) -> list[BenchmarkExample]:
        """Create sample examples for testing."""
        return [
            BenchmarkExample(
                id="ex_001",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"alert": "phishing"},
                expected_output={"verdict": "true_positive"},
                difficulty="easy",
                category="phishing",
                tags=["email"],
            ),
            BenchmarkExample(
                id="ex_002",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"alert": "malware"},
                expected_output={"verdict": "true_positive"},
                difficulty="medium",
                category="malware",
                tags=["endpoint"],
            ),
            BenchmarkExample(
                id="ex_003",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                input_data={"alert": "benign"},
                expected_output={"verdict": "false_positive"},
                difficulty="hard",
                category="legitimate",
                tags=["email"],
            ),
        ]

    def test_create_dataset(self, sample_examples):
        """Test basic dataset creation."""
        dataset = BenchmarkDataset(
            name="Test Dataset",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="A test dataset",
            examples=sample_examples,
        )

        assert dataset.name == "Test Dataset"
        assert len(dataset) == 3
        assert dataset.task_type == TaskType.VERDICT_CLASSIFICATION

    def test_dataset_validation_empty_examples(self):
        """Test that empty examples raises ValueError."""
        with pytest.raises(ValueError, match="must have at least one example"):
            BenchmarkDataset(
                name="Empty",
                task_type=TaskType.VERDICT_CLASSIFICATION,
                description="Empty dataset",
                examples=[],
            )

    def test_filter_by_difficulty(self, sample_examples):
        """Test filtering by difficulty level."""
        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=sample_examples,
        )

        easy = dataset.filter_by_difficulty("easy")
        assert len(easy) == 1
        assert easy[0].id == "ex_001"

        medium = dataset.filter_by_difficulty("medium")
        assert len(medium) == 1

    def test_filter_by_category(self, sample_examples):
        """Test filtering by category."""
        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=sample_examples,
        )

        phishing = dataset.filter_by_category("phishing")
        assert len(phishing) == 1
        assert phishing[0].category == "phishing"

    def test_filter_by_tags(self, sample_examples):
        """Test filtering by tags."""
        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=sample_examples,
        )

        email_examples = dataset.filter_by_tags(["email"])
        assert len(email_examples) == 2

    def test_get_statistics(self, sample_examples):
        """Test getting dataset statistics."""
        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=sample_examples,
        )

        stats = dataset.get_statistics()

        assert stats["name"] == "Test"
        assert stats["total_examples"] == 3
        assert stats["by_difficulty"]["easy"] == 1
        assert stats["by_difficulty"]["medium"] == 1
        assert stats["by_difficulty"]["hard"] == 1
        assert "phishing" in stats["by_category"]

    def test_iterate_dataset(self, sample_examples):
        """Test iterating over dataset examples."""
        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=sample_examples,
        )

        ids = [ex.id for ex in dataset]
        assert ids == ["ex_001", "ex_002", "ex_003"]

    def test_yaml_save_and_load(self, sample_examples):
        """Test saving and loading from YAML."""
        dataset = BenchmarkDataset(
            name="Test Dataset",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="A test dataset",
            examples=sample_examples,
            version="1.0",
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            dataset.to_yaml(f.name)
            loaded = BenchmarkDataset.from_yaml(f.name)

        assert loaded.name == dataset.name
        assert loaded.task_type == dataset.task_type
        assert len(loaded) == len(dataset)
        assert loaded.examples[0].id == dataset.examples[0].id


class TestSecurityBenchmark:
    """Tests for SecurityBenchmark class."""

    def test_create_empty_benchmark(self):
        """Test creating an empty benchmark."""
        benchmark = SecurityBenchmark()
        assert len(benchmark.tasks) == 0

    def test_add_dataset(self):
        """Test adding a dataset."""
        benchmark = SecurityBenchmark()

        dataset = BenchmarkDataset(
            name="Test",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            description="Test",
            examples=[
                BenchmarkExample(
                    id="ex_001",
                    task_type=TaskType.VERDICT_CLASSIFICATION,
                    input_data={"data": "test"},
                    expected_output={"verdict": "true_positive"},
                )
            ],
        )

        benchmark.add_dataset(dataset)

        assert TaskType.VERDICT_CLASSIFICATION in benchmark.tasks
        assert benchmark.get_dataset(TaskType.VERDICT_CLASSIFICATION) == dataset

    def test_with_builtin_datasets(self):
        """Test creating benchmark with built-in datasets."""
        benchmark = SecurityBenchmark.with_builtin_datasets()

        assert len(benchmark.tasks) > 0
        assert TaskType.VERDICT_CLASSIFICATION in benchmark.tasks
        assert TaskType.SEVERITY_RATING in benchmark.tasks
        assert TaskType.MITRE_MAPPING in benchmark.tasks

    def test_get_total_examples(self):
        """Test getting total example count."""
        benchmark = SecurityBenchmark.with_builtin_datasets()
        total = benchmark.get_total_examples()
        assert total > 0

    def test_get_summary(self):
        """Test getting benchmark summary."""
        benchmark = SecurityBenchmark.with_builtin_datasets()
        summary = benchmark.get_summary()

        assert "total_tasks" in summary
        assert "total_examples" in summary
        assert "tasks" in summary
        assert len(summary["tasks"]) > 0

    def test_load_datasets_from_directory(self):
        """Test loading datasets from a directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test dataset file
            dataset_data = {
                "name": "Test Dataset",
                "task_type": "verdict_classification",
                "description": "A test dataset",
                "version": "1.0",
                "examples": [
                    {
                        "id": "test_001",
                        "task_type": "verdict_classification",
                        "input": {"data": "test"},
                        "expected": {"verdict": "true_positive"},
                    }
                ],
            }

            yaml_path = Path(temp_dir) / "verdict_classification.yaml"
            with open(yaml_path, "w") as f:
                yaml.dump(dataset_data, f)

            benchmark = SecurityBenchmark()
            benchmark.load_datasets(temp_dir)

            assert TaskType.VERDICT_CLASSIFICATION in benchmark.tasks


class TestTaskType:
    """Tests for TaskType enum."""

    def test_all_task_types(self):
        """Test that all expected task types exist."""
        expected = [
            "incident_summarization",
            "severity_rating",
            "verdict_classification",
            "mitre_mapping",
            "ioc_query_generation",
            "action_recommendation",
        ]

        for task_name in expected:
            assert TaskType(task_name) is not None

    def test_task_type_values(self):
        """Test task type string values."""
        assert TaskType.VERDICT_CLASSIFICATION.value == "verdict_classification"
        assert TaskType.SEVERITY_RATING.value == "severity_rating"
        assert TaskType.MITRE_MAPPING.value == "mitre_mapping"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
