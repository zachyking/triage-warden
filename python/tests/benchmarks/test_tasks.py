"""Unit tests for benchmark tasks module.

Tests cover:
- Task prompt formatting
- Output parsing
- Evaluation logic for each task type
"""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

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

# Direct module loading
import importlib.util
import os

def load_module_directly(name: str, file_path: str):
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

base_path = os.path.join(os.path.dirname(__file__), "..", "..", "tw_ai", "benchmarks")

# Load datasets first (dependency)
datasets_module = load_module_directly(
    "tw_ai.benchmarks.datasets",
    os.path.join(base_path, "datasets.py")
)
BenchmarkExample = datasets_module.BenchmarkExample
TaskType = datasets_module.TaskType

# Load tasks module
tasks_module = load_module_directly(
    "tw_ai.benchmarks.tasks",
    os.path.join(base_path, "tasks.py")
)

VerdictClassificationTask = tasks_module.VerdictClassificationTask
SeverityRatingTask = tasks_module.SeverityRatingTask
MitreMappingTask = tasks_module.MitreMappingTask
IncidentSummarizationTask = tasks_module.IncidentSummarizationTask
ActionRecommendationTask = tasks_module.ActionRecommendationTask
IoCQueryGenerationTask = tasks_module.IoCQueryGenerationTask
get_task = tasks_module.get_task
TaskResult = tasks_module.TaskResult


class TestVerdictClassificationTask:
    """Tests for VerdictClassificationTask."""

    @pytest.fixture
    def task(self):
        return VerdictClassificationTask()

    @pytest.fixture
    def sample_example(self):
        return BenchmarkExample(
            id="vc_001",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            input_data={
                "alert_type": "email_security",
                "subject": "Urgent: Account compromised",
                "sender": "security@paypa1.com",
            },
            expected_output={"verdict": "true_positive", "confidence": 90},
        )

    def test_format_prompt(self, task, sample_example):
        """Test prompt formatting."""
        prompt = task.format_prompt(sample_example)

        assert "ALERT DATA:" in prompt
        assert "email_security" in prompt
        assert "paypa1.com" in prompt
        assert "true_positive" in prompt.lower() or "verdict" in prompt.lower()

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "verdict": "true_positive",
            "confidence": 85,
            "reasoning": "Test reasoning",
        })

        result = task.parse_output(output)

        assert result["verdict"] == "true_positive"
        assert result["confidence"] == 85

    def test_parse_output_json_with_markdown(self, task):
        """Test parsing JSON wrapped in markdown code block."""
        output = """```json
{
    "verdict": "false_positive",
    "confidence": 95,
    "reasoning": "Legitimate email"
}
```"""
        result = task.parse_output(output)

        assert result["verdict"] == "false_positive"
        assert result["confidence"] == 95

    def test_parse_output_fallback(self, task):
        """Test fallback parsing for invalid JSON."""
        output = "This is a true_positive alert because..."

        result = task.parse_output(output)

        assert result["verdict"] == "true_positive"

    def test_evaluate_exact_match(self, task):
        """Test evaluation with exact match."""
        predicted = {"verdict": "true_positive", "confidence": 85}
        expected = {"verdict": "true_positive", "confidence": 90}

        scores = task.evaluate(predicted, expected)

        assert scores["verdict_accuracy"] == 1.0
        assert scores["primary"] == 1.0

    def test_evaluate_mismatch(self, task):
        """Test evaluation with mismatched verdict."""
        predicted = {"verdict": "false_positive", "confidence": 80}
        expected = {"verdict": "true_positive", "confidence": 90}

        scores = task.evaluate(predicted, expected)

        assert scores["verdict_accuracy"] == 0.0
        assert scores["primary"] == 0.0


class TestSeverityRatingTask:
    """Tests for SeverityRatingTask."""

    @pytest.fixture
    def task(self):
        return SeverityRatingTask()

    def test_format_prompt(self, task):
        """Test prompt formatting."""
        example = BenchmarkExample(
            id="sr_001",
            task_type=TaskType.SEVERITY_RATING,
            input_data={
                "alert_type": "ransomware",
                "affected_systems": 10,
            },
            expected_output={"severity": "critical"},
        )

        prompt = task.format_prompt(example)

        assert "ransomware" in prompt
        assert "critical" in prompt.lower() or "severity" in prompt.lower()

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "severity": "high",
            "justification": "Significant risk",
        })

        result = task.parse_output(output)

        assert result["severity"] == "high"

    def test_parse_output_fallback(self, task):
        """Test fallback parsing."""
        output = "This is a critical severity incident"

        result = task.parse_output(output)

        assert result["severity"] == "critical"

    def test_evaluate_exact_match(self, task):
        """Test evaluation with exact match."""
        predicted = {"severity": "high"}
        expected = {"severity": "high"}

        scores = task.evaluate(predicted, expected)

        assert scores["exact_match"] == 1.0
        assert scores["distance_score"] == 1.0

    def test_evaluate_one_off(self, task):
        """Test evaluation when one level off."""
        predicted = {"severity": "medium"}
        expected = {"severity": "high"}

        scores = task.evaluate(predicted, expected)

        assert scores["exact_match"] == 0.0
        assert scores["distance_score"] == 0.75  # 1 - 0.25

    def test_evaluate_two_off(self, task):
        """Test evaluation when two levels off."""
        predicted = {"severity": "low"}
        expected = {"severity": "high"}

        scores = task.evaluate(predicted, expected)

        assert scores["distance_score"] == 0.5  # 1 - 0.5


class TestMitreMappingTask:
    """Tests for MitreMappingTask."""

    @pytest.fixture
    def task(self):
        return MitreMappingTask()

    def test_format_prompt(self, task):
        """Test prompt formatting."""
        example = BenchmarkExample(
            id="mm_001",
            task_type=TaskType.MITRE_MAPPING,
            input_data={
                "description": "Attacker used spearphishing",
                "indicators": ["malicious.xlsm", "powershell.exe"],
            },
            expected_output={"techniques": [{"id": "T1566.001", "name": "Spearphishing", "tactic": "Initial Access"}]},
        )

        prompt = task.format_prompt(example)

        assert "spearphishing" in prompt.lower()
        assert "MITRE" in prompt

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "techniques": [
                {"id": "T1566.001", "name": "Spearphishing", "tactic": "Initial Access"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
            ]
        })

        result = task.parse_output(output)

        assert len(result["techniques"]) == 2
        assert result["techniques"][0]["id"] == "T1566.001"

    def test_parse_output_fallback(self, task):
        """Test fallback parsing extracts technique IDs."""
        output = "The attack used T1566.001 and T1059.001 techniques"

        result = task.parse_output(output)

        assert len(result["techniques"]) == 2

    def test_evaluate_perfect_match(self, task):
        """Test evaluation with perfect technique match."""
        predicted = {"techniques": [{"id": "T1566.001"}, {"id": "T1059"}]}
        expected = {"techniques": [{"id": "T1566.001"}, {"id": "T1059"}]}

        scores = task.evaluate(predicted, expected)

        assert scores["precision"] == 1.0
        assert scores["recall"] == 1.0
        assert scores["f1"] == 1.0

    def test_evaluate_partial_match(self, task):
        """Test evaluation with partial technique match."""
        predicted = {"techniques": [{"id": "T1566.001"}]}
        expected = {"techniques": [{"id": "T1566.001"}, {"id": "T1059"}]}

        scores = task.evaluate(predicted, expected)

        assert scores["precision"] == 1.0  # 1/1
        assert scores["recall"] == 0.5  # 1/2


class TestIncidentSummarizationTask:
    """Tests for IncidentSummarizationTask."""

    @pytest.fixture
    def task(self):
        return IncidentSummarizationTask()

    def test_format_prompt(self, task):
        """Test prompt formatting."""
        example = BenchmarkExample(
            id="is_001",
            task_type=TaskType.INCIDENT_SUMMARIZATION,
            input_data={
                "title": "Phishing campaign",
                "alerts": [{"type": "email", "detail": "Suspicious email"}],
            },
            expected_output={"summary": "Phishing campaign targeted users", "key_findings": ["Finding 1"]},
        )

        prompt = task.format_prompt(example)

        assert "Phishing" in prompt
        assert "summary" in prompt.lower()

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "summary": "A phishing attack was detected.",
            "key_findings": ["Malicious email", "Credential harvesting"],
        })

        result = task.parse_output(output)

        assert "phishing" in result["summary"].lower()
        assert len(result["key_findings"]) == 2

    def test_evaluate_findings_coverage(self, task):
        """Test evaluation of findings coverage."""
        predicted = {
            "summary": "Phishing attack with credential harvesting detected.",
            "key_findings": ["Malicious email detected", "Credentials entered"],
        }
        expected = {
            "summary": "Expected summary",
            "key_findings": ["Malicious email", "Credential harvesting"],
        }

        scores = task.evaluate(predicted, expected)

        # Should have some coverage of expected findings
        assert scores["findings_coverage"] > 0


class TestActionRecommendationTask:
    """Tests for ActionRecommendationTask."""

    @pytest.fixture
    def task(self):
        return ActionRecommendationTask()

    def test_format_prompt(self, task):
        """Test prompt formatting."""
        example = BenchmarkExample(
            id="ar_001",
            task_type=TaskType.ACTION_RECOMMENDATION,
            input_data={
                "incident_type": "ransomware",
                "severity": "critical",
            },
            expected_output={"actions": [{"action": "Isolate system", "priority": "immediate"}]},
        )

        prompt = task.format_prompt(example)

        assert "ransomware" in prompt
        assert "action" in prompt.lower()

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "actions": [
                {"action": "Isolate the system", "priority": "immediate"},
                {"action": "Reset credentials", "priority": "high"},
            ]
        })

        result = task.parse_output(output)

        assert len(result["actions"]) == 2
        assert result["actions"][0]["priority"] == "immediate"

    def test_evaluate_action_coverage(self, task):
        """Test evaluation of action coverage."""
        predicted = {
            "actions": [
                {"action": "Isolate the affected system from network", "priority": "immediate"},
            ]
        }
        expected = {
            "actions": [
                {"action": "Isolate affected system from network immediately", "priority": "immediate"},
            ]
        }

        scores = task.evaluate(predicted, expected)

        # Should have some coverage
        assert scores["action_coverage"] > 0


class TestIoCQueryGenerationTask:
    """Tests for IoCQueryGenerationTask."""

    @pytest.fixture
    def task(self):
        return IoCQueryGenerationTask()

    def test_format_prompt(self, task):
        """Test prompt formatting."""
        example = BenchmarkExample(
            id="iq_001",
            task_type=TaskType.IOC_QUERY_GENERATION,
            input_data={
                "ioc_type": "ip_address",
                "ioc_value": "185.234.72.14",
                "query_target": "splunk",
            },
            expected_output={"query": 'index=* src_ip="185.234.72.14"'},
        )

        prompt = task.format_prompt(example)

        assert "185.234.72.14" in prompt
        assert "splunk" in prompt.lower()

    def test_parse_output_json(self, task):
        """Test parsing valid JSON output."""
        output = json.dumps({
            "query": 'index=* src_ip="1.2.3.4"',
            "description": "Search for IP",
        })

        result = task.parse_output(output)

        assert "index=" in result["query"]


class TestGetTask:
    """Tests for get_task function."""

    def test_get_verdict_task(self):
        """Test getting verdict classification task."""
        task = get_task(TaskType.VERDICT_CLASSIFICATION)
        assert isinstance(task, VerdictClassificationTask)

    def test_get_severity_task(self):
        """Test getting severity rating task."""
        task = get_task(TaskType.SEVERITY_RATING)
        assert isinstance(task, SeverityRatingTask)

    def test_get_mitre_task(self):
        """Test getting MITRE mapping task."""
        task = get_task(TaskType.MITRE_MAPPING)
        assert isinstance(task, MitreMappingTask)

    def test_get_all_tasks(self):
        """Test that all task types can be retrieved."""
        for task_type in TaskType:
            task = get_task(task_type)
            assert task is not None
            assert task.task_type == task_type


class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_create_result(self):
        """Test creating a task result."""
        result = TaskResult(
            example_id="test_001",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            predicted={"verdict": "true_positive"},
            expected={"verdict": "true_positive"},
            scores={"primary": 1.0, "accuracy": 1.0},
        )

        assert result.example_id == "test_001"
        assert result.passed is True

    def test_result_failed(self):
        """Test result with low primary score."""
        result = TaskResult(
            example_id="test_002",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            predicted={"verdict": "false_positive"},
            expected={"verdict": "true_positive"},
            scores={"primary": 0.0},
        )

        assert result.passed is False

    def test_result_with_error(self):
        """Test result with error."""
        result = TaskResult(
            example_id="test_003",
            task_type=TaskType.VERDICT_CLASSIFICATION,
            predicted={},
            expected={"verdict": "true_positive"},
            error="LLM timeout",
        )

        assert result.passed is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
