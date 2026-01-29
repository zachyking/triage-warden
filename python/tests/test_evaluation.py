"""Unit tests for the evaluation framework.

Tests cover:
- TestCase dataclass and validation
- YAML loading from files and directories
- Metric calculations (accuracy, precision, recall, F1)
- Confusion matrix generation
- EvaluationRunner with mock agents
- EvaluationReport generation
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import yaml


# =============================================================================
# Mock setup to avoid full tw_ai import chain
# =============================================================================

# Create mock modules to avoid importing full tw_ai package which needs openai, etc.
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

# Install mock structlog if not available or force our mock
sys.modules["structlog"] = MockStructlog()

# Mock tw_ai package to prevent full import chain
class MockTwAi:
    pass

# Install mock tw_ai before importing evaluation
if "tw_ai" not in sys.modules:
    sys.modules["tw_ai"] = MockTwAi()

# Add tw_ai to path for direct imports
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tw_ai"))

# Now import evaluation modules directly using relative path hack
# This avoids triggering tw_ai.__init__ which imports LLM providers
import importlib.util

def load_module_directly(name: str, file_path: str):
    """Load a module directly from file without going through package."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

eval_base = os.path.join(os.path.dirname(__file__), "..", "tw_ai", "evaluation")

dataset_module = load_module_directly(
    "tw_ai.evaluation.dataset",
    os.path.join(eval_base, "dataset.py")
)
TestCase = dataset_module.TestCase
load_test_cases = dataset_module.load_test_cases
save_test_cases = dataset_module.save_test_cases

metrics_module = load_module_directly(
    "tw_ai.evaluation.metrics",
    os.path.join(eval_base, "metrics.py")
)
EvaluationReport = metrics_module.EvaluationReport
VerdictMetrics = metrics_module.VerdictMetrics
calculate_verdict_metrics = metrics_module.calculate_verdict_metrics
calculate_severity_accuracy = metrics_module.calculate_severity_accuracy
generate_confusion_matrix = metrics_module.generate_confusion_matrix
calculate_technique_recall = metrics_module.calculate_technique_recall
format_confusion_matrix = metrics_module.format_confusion_matrix

runner_module = load_module_directly(
    "tw_ai.evaluation.runner",
    os.path.join(eval_base, "runner.py")
)
EvaluationRunner = runner_module.EvaluationRunner
EvaluationConfig = runner_module.EvaluationConfig
CaseResult = runner_module.CaseResult


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_test_case() -> TestCase:
    """Create a sample test case."""
    return TestCase(
        id="test_001",
        name="Sample phishing test",
        alert_data={
            "type": "email_security",
            "subject": "Your account compromised",
            "sender": "support@paypa1.com",
        },
        expected_verdict="malicious",
        expected_severity="high",
        expected_techniques=["T1566.001"],
        category="phishing",
        tags=["email", "credential-theft"],
    )


@pytest.fixture
def sample_test_cases() -> list[TestCase]:
    """Create a list of sample test cases."""
    return [
        TestCase(
            id="phishing_001",
            name="Obvious phishing",
            alert_data={"type": "email", "sender": "bad@evil.com"},
            expected_verdict="malicious",
            expected_severity="high",
            expected_techniques=["T1566.001"],
        ),
        TestCase(
            id="phishing_002",
            name="Legitimate email",
            alert_data={"type": "email", "sender": "hr@company.com"},
            expected_verdict="benign",
            expected_severity="informational",
            expected_techniques=[],
        ),
        TestCase(
            id="malware_001",
            name="Ransomware detected",
            alert_data={"type": "endpoint", "process": "encrypt.exe"},
            expected_verdict="malicious",
            expected_severity="critical",
            expected_techniques=["T1486"],
        ),
    ]


@pytest.fixture
def yaml_content() -> str:
    """Sample YAML content for test cases."""
    return """
- id: test_001
  name: "Phishing email test"
  alert:
    type: email_security
    subject: "Account locked"
    sender: "support@fake-bank.com"
  expected:
    verdict: malicious
    severity: high
    techniques: [T1566.001]

- id: test_002
  name: "Legitimate notification"
  alert:
    type: email_security
    subject: "Monthly newsletter"
    sender: "newsletter@company.com"
  expected:
    verdict: benign
    severity: informational
    techniques: []
"""


@pytest.fixture
def temp_yaml_file(yaml_content: str) -> Path:
    """Create a temporary YAML file."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False
    ) as f:
        f.write(yaml_content)
        return Path(f.name)


@pytest.fixture
def temp_yaml_dir(yaml_content: str) -> Path:
    """Create a temporary directory with YAML files."""
    import os

    temp_dir = tempfile.mkdtemp()

    # Write phishing cases
    phishing_yaml = """
- id: phishing_001
  name: "Phishing test"
  alert:
    type: email
    sender: "bad@evil.com"
  expected:
    verdict: malicious
    severity: high
    techniques: [T1566.001]
"""
    with open(os.path.join(temp_dir, "phishing.yaml"), "w") as f:
        f.write(phishing_yaml)

    # Write malware cases
    malware_yaml = """
- id: malware_001
  name: "Malware test"
  alert:
    type: endpoint
    process: "bad.exe"
  expected:
    verdict: malicious
    severity: critical
    techniques: [T1486]
"""
    with open(os.path.join(temp_dir, "malware.yaml"), "w") as f:
        f.write(malware_yaml)

    return Path(temp_dir)


# =============================================================================
# TestCase Tests
# =============================================================================


class TestTestCase:
    """Tests for TestCase dataclass."""

    def test_create_test_case(self, sample_test_case: TestCase):
        """Test basic TestCase creation."""
        assert sample_test_case.id == "test_001"
        assert sample_test_case.name == "Sample phishing test"
        assert sample_test_case.expected_verdict == "malicious"
        assert sample_test_case.expected_severity == "high"
        assert sample_test_case.expected_techniques == ["T1566.001"]
        assert sample_test_case.category == "phishing"

    def test_test_case_validation_empty_id(self):
        """Test that empty ID raises ValueError."""
        with pytest.raises(ValueError, match="id cannot be empty"):
            TestCase(
                id="",
                name="Test",
                alert_data={"type": "test"},
                expected_verdict="malicious",
            )

    def test_test_case_validation_empty_name(self):
        """Test that empty name raises ValueError."""
        with pytest.raises(ValueError, match="name cannot be empty"):
            TestCase(
                id="test_001",
                name="",
                alert_data={"type": "test"},
                expected_verdict="malicious",
            )

    def test_test_case_validation_empty_alert_data(self):
        """Test that empty alert_data raises ValueError."""
        with pytest.raises(ValueError, match="alert_data cannot be empty"):
            TestCase(
                id="test_001",
                name="Test",
                alert_data={},
                expected_verdict="malicious",
            )

    def test_from_dict_with_nested_expected(self):
        """Test creating TestCase from dict with nested expected structure."""
        data = {
            "id": "test_001",
            "name": "Test case",
            "alert": {"type": "email"},
            "expected": {
                "verdict": "malicious",
                "severity": "high",
                "techniques": ["T1566.001"],
            },
        }
        tc = TestCase.from_dict(data)
        assert tc.expected_verdict == "malicious"
        assert tc.expected_severity == "high"
        assert tc.expected_techniques == ["T1566.001"]

    def test_from_dict_with_flat_structure(self):
        """Test creating TestCase from dict with flat structure."""
        data = {
            "id": "test_001",
            "name": "Test case",
            "alert_data": {"type": "email"},
            "expected_verdict": "benign",
            "expected_severity": "low",
        }
        tc = TestCase.from_dict(data)
        assert tc.expected_verdict == "benign"
        assert tc.expected_severity == "low"

    def test_to_dict(self, sample_test_case: TestCase):
        """Test converting TestCase to dict."""
        result = sample_test_case.to_dict()
        assert result["id"] == "test_001"
        assert result["expected_verdict"] == "malicious"
        assert result["category"] == "phishing"


# =============================================================================
# Dataset Loading Tests
# =============================================================================


class TestLoadTestCases:
    """Tests for load_test_cases function."""

    def test_load_from_file(self, temp_yaml_file: Path):
        """Test loading test cases from a single YAML file."""
        cases = load_test_cases(str(temp_yaml_file))
        assert len(cases) == 2
        assert cases[0].id == "test_001"
        assert cases[1].id == "test_002"

    def test_load_from_directory(self, temp_yaml_dir: Path):
        """Test loading test cases from a directory."""
        cases = load_test_cases(str(temp_yaml_dir))
        assert len(cases) == 2
        # Check that category is inferred from filename
        phishing_case = next(c for c in cases if c.id == "phishing_001")
        assert phishing_case.category == "phishing"
        malware_case = next(c for c in cases if c.id == "malware_001")
        assert malware_case.category == "malware"

    def test_load_nonexistent_path(self):
        """Test that loading from nonexistent path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_test_cases("/nonexistent/path")

    def test_load_real_test_cases(self):
        """Test loading the actual test case files."""
        import os

        test_cases_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "tw_ai",
            "evaluation",
            "test_cases",
        )
        if os.path.exists(test_cases_dir):
            cases = load_test_cases(test_cases_dir)
            assert len(cases) > 0
            # Verify we have the expected mix of verdicts
            malicious_count = sum(1 for c in cases if c.expected_verdict == "malicious")
            benign_count = sum(1 for c in cases if c.expected_verdict == "benign")
            assert malicious_count >= 5  # 5 true positives
            assert benign_count >= 5  # 3 FP + 2 TN


class TestSaveTestCases:
    """Tests for save_test_cases function."""

    def test_save_and_reload(self, sample_test_cases: list[TestCase]):
        """Test saving and reloading test cases."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            save_test_cases(sample_test_cases, f.name)
            reloaded = load_test_cases(f.name)

        assert len(reloaded) == len(sample_test_cases)
        for original, loaded in zip(sample_test_cases, reloaded):
            assert original.id == loaded.id
            assert original.expected_verdict == loaded.expected_verdict


# =============================================================================
# Metrics Tests
# =============================================================================


class TestCalculateVerdictMetrics:
    """Tests for calculate_verdict_metrics function."""

    def test_perfect_predictions(self):
        """Test metrics with perfect predictions."""
        predictions = ["malicious", "benign", "malicious", "benign"]
        labels = ["malicious", "benign", "malicious", "benign"]

        metrics = calculate_verdict_metrics(predictions, labels)

        assert metrics.accuracy == 1.0
        assert metrics.precision == 1.0
        assert metrics.recall == 1.0
        assert metrics.f1_score == 1.0

    def test_all_wrong_predictions(self):
        """Test metrics with all wrong predictions."""
        predictions = ["benign", "malicious", "benign", "malicious"]
        labels = ["malicious", "benign", "malicious", "benign"]

        metrics = calculate_verdict_metrics(predictions, labels)

        assert metrics.accuracy == 0.0
        assert metrics.precision == 0.0
        assert metrics.recall == 0.0

    def test_mixed_predictions(self):
        """Test metrics with mixed predictions."""
        # 2 TP, 1 FP, 1 FN, 1 TN
        predictions = ["malicious", "malicious", "malicious", "benign", "benign"]
        labels = ["malicious", "malicious", "benign", "malicious", "benign"]

        metrics = calculate_verdict_metrics(predictions, labels)

        # Accuracy: 3/5 = 0.6
        assert metrics.accuracy == pytest.approx(0.6)
        # Precision: 2/(2+1) = 0.667
        assert metrics.precision == pytest.approx(2 / 3)
        # Recall: 2/(2+1) = 0.667
        assert metrics.recall == pytest.approx(2 / 3)

    def test_empty_inputs(self):
        """Test metrics with empty inputs."""
        metrics = calculate_verdict_metrics([], [])
        assert metrics.accuracy == 0.0

    def test_length_mismatch(self):
        """Test that mismatched lengths raise ValueError."""
        with pytest.raises(ValueError, match="Length mismatch"):
            calculate_verdict_metrics(["malicious"], ["malicious", "benign"])

    def test_per_class_metrics(self):
        """Test per-class metrics are calculated."""
        predictions = ["malicious", "benign", "suspicious"]
        labels = ["malicious", "benign", "suspicious"]

        metrics = calculate_verdict_metrics(predictions, labels)

        assert "malicious" in metrics.per_class_metrics
        assert "benign" in metrics.per_class_metrics
        assert "suspicious" in metrics.per_class_metrics
        assert metrics.per_class_metrics["malicious"]["precision"] == 1.0


class TestCalculateSeverityAccuracy:
    """Tests for calculate_severity_accuracy function."""

    def test_perfect_severity_predictions(self):
        """Test with perfect severity predictions."""
        predictions = ["high", "low", "critical"]
        labels = ["high", "low", "critical"]

        accuracy = calculate_severity_accuracy(predictions, labels)
        assert accuracy == 1.0

    def test_partial_severity_predictions(self):
        """Test with partial matches."""
        predictions = ["high", "medium", "critical"]
        labels = ["high", "low", "critical"]

        accuracy = calculate_severity_accuracy(predictions, labels)
        assert accuracy == pytest.approx(2 / 3)

    def test_with_none_values(self):
        """Test handling of None values."""
        predictions = ["high", None, "critical"]
        labels = ["high", "low", None]

        # Only first pair is valid
        accuracy = calculate_severity_accuracy(predictions, labels)
        assert accuracy == 1.0

    def test_empty_inputs(self):
        """Test with empty inputs."""
        accuracy = calculate_severity_accuracy([], [])
        assert accuracy == 0.0


class TestGenerateConfusionMatrix:
    """Tests for generate_confusion_matrix function."""

    def test_basic_confusion_matrix(self):
        """Test basic confusion matrix generation."""
        predictions = ["malicious", "benign", "malicious", "benign"]
        labels = ["malicious", "benign", "benign", "malicious"]

        matrix = generate_confusion_matrix(predictions, labels)

        # matrix[actual][predicted]
        assert matrix["malicious"]["malicious"] == 1  # TP
        assert matrix["malicious"]["benign"] == 1  # FN
        assert matrix["benign"]["malicious"] == 1  # FP
        assert matrix["benign"]["benign"] == 1  # TN

    def test_three_class_confusion_matrix(self):
        """Test confusion matrix with three classes."""
        predictions = ["malicious", "benign", "suspicious"]
        labels = ["malicious", "suspicious", "benign"]

        matrix = generate_confusion_matrix(predictions, labels)

        assert "malicious" in matrix
        assert "benign" in matrix
        assert "suspicious" in matrix

    def test_empty_inputs(self):
        """Test with empty inputs."""
        matrix = generate_confusion_matrix([], [])
        assert matrix == {}


class TestCalculateTechniqueRecall:
    """Tests for calculate_technique_recall function."""

    def test_perfect_technique_recall(self):
        """Test perfect recall of techniques."""
        predicted = [["T1566.001", "T1486"], ["T1078"]]
        expected = [["T1566.001"], ["T1078"]]

        recall = calculate_technique_recall(predicted, expected)
        assert recall == 1.0

    def test_partial_technique_recall(self):
        """Test partial recall of techniques."""
        predicted = [["T1566.001"], []]
        expected = [["T1566.001", "T1486"], ["T1078"]]

        # Found 1 of 3 expected
        recall = calculate_technique_recall(predicted, expected)
        assert recall == pytest.approx(1 / 3)

    def test_no_expected_techniques(self):
        """Test when no techniques are expected."""
        predicted = [["T1566.001"], []]
        expected = [[], []]

        recall = calculate_technique_recall(predicted, expected)
        assert recall == 0.0  # No expected, so 0/0 = 0


class TestFormatConfusionMatrix:
    """Tests for format_confusion_matrix function."""

    def test_format_basic_matrix(self):
        """Test formatting a basic confusion matrix."""
        matrix = {
            "malicious": {"malicious": 5, "benign": 1},
            "benign": {"malicious": 2, "benign": 7},
        }

        formatted = format_confusion_matrix(matrix)

        assert "Confusion Matrix" in formatted
        assert "malicious" in formatted
        assert "benign" in formatted

    def test_format_empty_matrix(self):
        """Test formatting an empty matrix."""
        formatted = format_confusion_matrix({})
        assert "Empty" in formatted


# =============================================================================
# EvaluationRunner Tests
# =============================================================================


class TestEvaluationRunner:
    """Tests for EvaluationRunner class."""

    @pytest.fixture
    def mock_agent(self):
        """Create a mock agent that returns predictable results."""

        class MockAgent:
            def __init__(self):
                self.responses = {}

            def set_response(self, case_id: str, verdict: str, severity: str):
                self.responses[case_id] = (verdict, severity)

            async def run(self, request: Any) -> MagicMock:
                # Extract case ID from request
                if hasattr(request, "alert_data"):
                    alert_data = request.alert_data
                else:
                    alert_data = request

                # Find matching response by checking alert data patterns
                for case_id, (verdict, severity) in self.responses.items():
                    if case_id in str(alert_data):
                        result = MagicMock()
                        result.analysis = MagicMock()
                        result.analysis.verdict = verdict
                        result.analysis.severity = severity
                        result.analysis.mitre_techniques = []
                        return result

                # Default response
                result = MagicMock()
                result.analysis = MagicMock()
                result.analysis.verdict = "true_positive"
                result.analysis.severity = "high"
                result.analysis.mitre_techniques = []
                return result

        return MockAgent()

    @pytest.fixture
    def simple_mock_agent(self):
        """Create a simple mock agent."""

        class SimpleAgent:
            async def run(self, request: Any) -> MagicMock:
                result = MagicMock()
                result.analysis = MagicMock()
                result.analysis.verdict = "true_positive"
                result.analysis.severity = "high"
                result.analysis.mitre_techniques = []
                return result

        return SimpleAgent()

    async def test_evaluate_empty_cases(self, simple_mock_agent):
        """Test evaluating empty case list."""
        runner = EvaluationRunner(agent=simple_mock_agent)
        report = await runner.evaluate([])

        assert report.total_cases == 0
        assert report.accuracy == 0.0

    async def test_evaluate_single_case(self, simple_mock_agent, sample_test_case):
        """Test evaluating a single test case."""
        runner = EvaluationRunner(agent=simple_mock_agent)
        report = await runner.evaluate([sample_test_case])

        assert report.total_cases == 1
        assert len(report.results) == 1

    async def test_evaluate_with_matching_verdict(self, simple_mock_agent):
        """Test evaluation when verdict matches expected."""
        # Agent returns true_positive which normalizes to malicious
        test_case = TestCase(
            id="test_001",
            name="Test",
            alert_data={"type": "test"},
            expected_verdict="malicious",
        )

        runner = EvaluationRunner(agent=simple_mock_agent)
        report = await runner.evaluate([test_case])

        assert report.passed_cases == 1
        assert report.failed_cases == 0
        assert report.accuracy == 1.0

    async def test_evaluate_with_mismatched_verdict(self, simple_mock_agent):
        """Test evaluation when verdict doesn't match expected."""
        # Agent returns true_positive (malicious), but we expect benign
        test_case = TestCase(
            id="test_001",
            name="Test",
            alert_data={"type": "test"},
            expected_verdict="benign",
        )

        runner = EvaluationRunner(agent=simple_mock_agent)
        report = await runner.evaluate([test_case])

        assert report.passed_cases == 0
        assert report.failed_cases == 1

    async def test_evaluate_parallel(self, simple_mock_agent, sample_test_cases):
        """Test parallel evaluation."""
        runner = EvaluationRunner(
            agent=simple_mock_agent,
            config=EvaluationConfig(max_concurrent=2),
        )
        report = await runner.evaluate(sample_test_cases, parallel=True)

        assert report.total_cases == len(sample_test_cases)

    async def test_evaluate_with_timeout(self):
        """Test evaluation with timeout handling."""

        class SlowAgent:
            async def run(self, request: Any):
                await asyncio.sleep(10)  # Simulate slow agent
                return MagicMock()

        runner = EvaluationRunner(
            agent=SlowAgent(),
            config=EvaluationConfig(timeout_per_case=0.1),
        )

        test_case = TestCase(
            id="test_001",
            name="Test",
            alert_data={"type": "test"},
            expected_verdict="malicious",
        )

        report = await runner.evaluate([test_case])

        assert report.failed_cases == 1
        assert "Timeout" in report.results[0].get("error", "")

    async def test_evaluate_with_agent_error(self):
        """Test evaluation when agent raises an error."""

        class ErrorAgent:
            async def run(self, request: Any):
                raise RuntimeError("Agent failed")

        runner = EvaluationRunner(
            agent=ErrorAgent(),
            config=EvaluationConfig(retry_failed=False),
        )

        test_case = TestCase(
            id="test_001",
            name="Test",
            alert_data={"type": "test"},
            expected_verdict="malicious",
        )

        report = await runner.evaluate([test_case])

        assert report.failed_cases == 1
        assert "Agent failed" in report.results[0].get("error", "")

    async def test_config_defaults(self):
        """Test EvaluationConfig default values."""
        config = EvaluationConfig()

        assert config.max_concurrent == 5
        assert config.timeout_per_case == 120.0
        assert config.retry_failed is True
        assert config.max_retries == 2


class TestCaseResult:
    """Tests for CaseResult dataclass."""

    def test_case_result_creation(self):
        """Test creating a CaseResult."""
        result = CaseResult(
            test_case_id="test_001",
            test_case_name="Test case",
            passed=True,
            predicted_verdict="malicious",
            expected_verdict="malicious",
            execution_time=1.5,
        )

        assert result.passed is True
        assert result.execution_time == 1.5

    def test_case_result_to_dict(self):
        """Test converting CaseResult to dict."""
        result = CaseResult(
            test_case_id="test_001",
            test_case_name="Test case",
            passed=False,
            error="Timeout",
        )

        d = result.to_dict()
        assert d["test_case_id"] == "test_001"
        assert d["error"] == "Timeout"


# =============================================================================
# EvaluationReport Tests
# =============================================================================


class TestEvaluationReport:
    """Tests for EvaluationReport dataclass."""

    def test_report_creation(self):
        """Test creating an EvaluationReport."""
        report = EvaluationReport(
            total_cases=10,
            passed_cases=8,
            failed_cases=2,
            accuracy=0.8,
            precision=0.9,
            recall=0.85,
            f1_score=0.87,
            severity_accuracy=0.75,
            confusion_matrix={
                "malicious": {"malicious": 7, "benign": 1},
                "benign": {"malicious": 1, "benign": 1},
            },
        )

        assert report.total_cases == 10
        assert report.accuracy == 0.8
        assert report.verdict_metrics is not None

    def test_report_to_dict(self):
        """Test converting report to dict."""
        report = EvaluationReport(
            total_cases=5,
            passed_cases=4,
            failed_cases=1,
            accuracy=0.8,
            precision=0.75,
            recall=0.9,
            f1_score=0.82,
            severity_accuracy=0.7,
            confusion_matrix={},
        )

        d = report.to_dict()
        assert d["total_cases"] == 5
        assert d["accuracy"] == 0.8

    def test_report_summary(self):
        """Test generating report summary."""
        report = EvaluationReport(
            total_cases=10,
            passed_cases=8,
            failed_cases=2,
            accuracy=0.8,
            precision=0.9,
            recall=0.85,
            f1_score=0.87,
            severity_accuracy=0.75,
            confusion_matrix={},
        )

        summary = report.summary()

        assert "EVALUATION REPORT" in summary
        assert "80.00%" in summary  # accuracy
        assert "Total Cases: 10" in summary


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the evaluation framework."""

    async def test_full_evaluation_workflow(self):
        """Test the complete evaluation workflow."""

        # Create a mock agent with deterministic responses
        class DeterministicAgent:
            def __init__(self, verdict_map: dict[str, str]):
                self.verdict_map = verdict_map

            async def run(self, request: Any) -> MagicMock:
                if hasattr(request, "alert_data"):
                    alert_type = request.alert_data.get("type", "")
                else:
                    alert_type = request.get("type", "")

                verdict = self.verdict_map.get(alert_type, "suspicious")

                result = MagicMock()
                result.analysis = MagicMock()
                result.analysis.verdict = verdict
                result.analysis.severity = "high"
                result.analysis.mitre_techniques = []
                return result

        # Map email -> malicious, endpoint -> malicious (true_positive)
        agent = DeterministicAgent({
            "email": "true_positive",
            "endpoint": "true_positive",
        })

        # Create test cases
        cases = [
            TestCase(
                id="case_001",
                name="Phishing email",
                alert_data={"type": "email"},
                expected_verdict="malicious",
            ),
            TestCase(
                id="case_002",
                name="Malware endpoint",
                alert_data={"type": "endpoint"},
                expected_verdict="malicious",
            ),
            TestCase(
                id="case_003",
                name="Benign activity",
                alert_data={"type": "unknown"},
                expected_verdict="benign",
            ),
        ]

        # Run evaluation
        runner = EvaluationRunner(agent=agent)
        report = await runner.evaluate(cases)

        # Verify report
        assert report.total_cases == 3
        assert report.passed_cases == 2  # Two malicious cases pass
        assert report.failed_cases == 1  # One benign case fails

    def test_load_and_validate_project_test_cases(self):
        """Test loading actual project test case files."""
        import os

        test_cases_dir = os.path.join(
            os.path.dirname(__file__),
            "..",
            "tw_ai",
            "evaluation",
            "test_cases",
        )

        if not os.path.exists(test_cases_dir):
            pytest.skip("Test cases directory not found")

        cases = load_test_cases(test_cases_dir)

        # Verify we have test cases
        assert len(cases) > 0

        # Verify all cases have required fields
        for case in cases:
            assert case.id
            assert case.name
            assert case.alert_data
            assert case.expected_verdict in ("malicious", "benign", "suspicious")

        # Verify we have the expected distribution
        verdicts = [c.expected_verdict for c in cases]
        assert verdicts.count("malicious") >= 5  # True positives
        assert verdicts.count("benign") >= 5  # False positives + True negatives


# =============================================================================
# Run tests
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
