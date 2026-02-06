"""Comprehensive tests for the playbook loader and executor."""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

# Direct module loading to avoid Python 3.10+ syntax in tw_ai/__init__.py
# This allows running tests on Python 3.9 while the rest of the codebase requires 3.10+
_base_path = Path(__file__).parent.parent / "tw_ai" / "playbook"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load loader module
_loader = _load_module("tw_ai.playbook.loader", _base_path / "loader.py")
PlaybookLoader = _loader.PlaybookLoader
Playbook = _loader.Playbook
Stage = _loader.Stage
Step = _loader.Step
Branch = _loader.Branch
Condition = _loader.Condition
ValidationResult = _loader.ValidationResult
PlaybookValidationError = _loader.PlaybookValidationError

# Load executor module
_executor = _load_module("tw_ai.playbook.executor", _base_path / "executor.py")
PlaybookExecutor = _executor.PlaybookExecutor
ExecutionResult = _executor.ExecutionResult
StageResult = _executor.StageResult
StepResult = _executor.StepResult
ExecutionContext = _executor.ExecutionContext


# =============================================================================
# Test Fixtures
# =============================================================================


MINIMAL_PLAYBOOK_YAML = """
name: minimal-playbook
version: "1.0"
description: "A minimal playbook for testing"

stages:
  - name: test_stage
    description: "A test stage"
    steps:
      - action: test_action
        input:
          key: "value"
        output:
          - result
"""

COMPLETE_PLAYBOOK_YAML = """
name: phishing-triage
version: "1.0"
description: "Automated triage workflow for phishing emails"

trigger:
  sources:
    - email_security_gateway
    - user_reported
  alert_types:
    - suspected_phishing
    - user_reported_phishing

input:
  required:
    - message_id
    - recipient
    - sender
  optional:
    - subject
    - received_time

stages:
  - name: extraction
    description: "Extract indicators from the email"
    steps:
      - action: parse_email
        input:
          message_id: "{{ input.message_id }}"
        output:
          - headers
          - body
          - urls

  - name: enrichment
    description: "Gather threat intelligence"
    parallel: true
    steps:
      - action: lookup_sender_reputation
        input:
          sender: "{{ input.sender }}"
        output:
          - sender_ti

      - action: lookup_urls
        input:
          urls: "{{ extraction.urls }}"
        output:
          - url_ti

  - name: ai_analysis
    description: "AI-powered analysis"
    steps:
      - action: run_triage_agent
        input:
          context:
            headers: "{{ extraction.headers }}"
            urls: "{{ enrichment.url_ti }}"
        output:
          - verdict
          - confidence
          - summary

  - name: decision
    description: "Execute response based on analysis"
    branches:
      true_positive:
        conditions:
          - verdict: true_positive
          - confidence_above: 0.8
        steps:
          - action: quarantine_email
            input:
              message_id: "{{ input.message_id }}"
            requires_approval: false
          - action: create_ticket
            input:
              title: "Phishing Alert"
              priority: high

      suspicious:
        conditions:
          - verdict: suspicious
        steps:
          - action: create_ticket
            input:
              title: "Suspicious Email"
              priority: medium

      false_positive:
        conditions:
          - verdict: false_positive
          - confidence_above: 0.9
        steps:
          - action: log_false_positive
            input:
              reason: "{{ ai_analysis.summary }}"

sla:
  time_to_triage: 5m
  time_to_respond: 15m
  escalation_on_breach: true

metrics:
  - name: phishing_detection_rate
    description: "Percentage of phishing emails detected"
  - name: false_positive_rate
    description: "False positive rate"
"""

PLAYBOOK_WITH_CONDITIONS_YAML = """
name: conditional-playbook
version: "1.0"
description: "Playbook with conditional steps"

stages:
  - name: analysis
    steps:
      - action: analyze_data
        input:
          data: "test"
        output:
          - verdict
          - confidence

  - name: response
    steps:
      - action: high_confidence_action
        input:
          type: "auto"
        conditions:
          - confidence_above: 0.9
      - action: low_confidence_action
        input:
          type: "manual"
        conditions:
          - confidence_below: 0.5
"""


@pytest.fixture
def loader() -> PlaybookLoader:
    """Create a playbook loader instance."""
    return PlaybookLoader()


@pytest.fixture
def minimal_playbook(loader: PlaybookLoader) -> Playbook:
    """Load the minimal playbook."""
    return loader.load_from_string(MINIMAL_PLAYBOOK_YAML)


@pytest.fixture
def complete_playbook(loader: PlaybookLoader) -> Playbook:
    """Load the complete playbook."""
    return loader.load_from_string(COMPLETE_PLAYBOOK_YAML)


@pytest.fixture
def mock_action_handler():
    """Create a mock action handler that records calls."""
    calls: list[tuple[str, dict[str, Any]]] = []

    async def handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
        calls.append((action, input_data))
        # Return mock outputs based on action
        if action == "parse_email":
            return {
                "headers": {"From": "test@example.com"},
                "body": "Test email body",
                "urls": ["https://suspicious.com"],
            }
        elif action == "lookup_sender_reputation":
            return {"sender_ti": {"reputation": "unknown"}}
        elif action == "lookup_urls":
            return {"url_ti": [{"url": "https://suspicious.com", "verdict": "suspicious"}]}
        elif action == "run_triage_agent":
            return {
                "verdict": "true_positive",
                "confidence": 85,
                "summary": "Phishing email detected",
            }
        elif action == "analyze_data":
            return {"verdict": "positive", "confidence": 0.95}
        return {"status": "ok", "action": action}

    handler.calls = calls
    return handler


# =============================================================================
# PlaybookLoader Tests
# =============================================================================


class TestPlaybookLoader:
    """Tests for PlaybookLoader class."""

    def test_load_from_string_minimal(self, loader: PlaybookLoader) -> None:
        """Test loading a minimal playbook from string."""
        playbook = loader.load_from_string(MINIMAL_PLAYBOOK_YAML)

        assert playbook.name == "minimal-playbook"
        assert playbook.version == "1.0"
        assert len(playbook.stages) == 1
        assert playbook.stages[0].name == "test_stage"

    def test_load_from_string_complete(self, loader: PlaybookLoader) -> None:
        """Test loading a complete playbook with all features."""
        playbook = loader.load_from_string(COMPLETE_PLAYBOOK_YAML)

        assert playbook.name == "phishing-triage"
        assert len(playbook.stages) == 4
        assert len(playbook.trigger.sources) == 2
        assert len(playbook.input.required) == 3
        assert playbook.stages[1].parallel is True
        assert len(playbook.stages[3].branches) == 3

    def test_load_from_file(self, loader: PlaybookLoader, tmp_path: Path) -> None:
        """Test loading a playbook from file."""
        playbook_path = tmp_path / "test-playbook.yaml"
        playbook_path.write_text(MINIMAL_PLAYBOOK_YAML)

        playbook = loader.load(playbook_path)
        assert playbook.name == "minimal-playbook"

    def test_load_nonexistent_file(self, loader: PlaybookLoader) -> None:
        """Test loading a nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            loader.load("/nonexistent/path/playbook.yaml")

    def test_load_invalid_yaml(self, loader: PlaybookLoader) -> None:
        """Test loading invalid YAML raises PlaybookValidationError."""
        invalid_yaml = "name: test\ninvalid: [unclosed"
        with pytest.raises(PlaybookValidationError) as exc_info:
            loader.load_from_string(invalid_yaml)
        assert "Invalid YAML" in str(exc_info.value)

    def test_load_empty_yaml(self, loader: PlaybookLoader) -> None:
        """Test loading empty YAML raises PlaybookValidationError."""
        with pytest.raises(PlaybookValidationError):
            loader.load_from_string("")

    def test_validate_minimal_playbook(
        self, loader: PlaybookLoader, minimal_playbook: Playbook
    ) -> None:
        """Test validating a minimal valid playbook."""
        result = loader.validate(minimal_playbook)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_complete_playbook(
        self, loader: PlaybookLoader, complete_playbook: Playbook
    ) -> None:
        """Test validating a complete playbook."""
        result = loader.validate(complete_playbook)
        assert result.valid is True
        assert len(result.errors) == 0

    def test_validate_empty_stages(self, loader: PlaybookLoader) -> None:
        """Test validation fails for playbook with no stages."""
        playbook_yaml = """
name: empty-playbook
version: "1.0"
stages: []
"""
        playbook = loader.load_from_string(playbook_yaml)
        result = loader.validate(playbook)
        assert result.valid is False
        assert any("at least one stage" in e for e in result.errors)

    def test_validate_duplicate_stage_names(self, loader: PlaybookLoader) -> None:
        """Test validation fails for duplicate stage names."""
        playbook_yaml = """
name: duplicate-stages
version: "1.0"
stages:
  - name: stage1
    steps:
      - action: test
  - name: stage1
    steps:
      - action: test2
"""
        playbook = loader.load_from_string(playbook_yaml)
        result = loader.validate(playbook)
        assert result.valid is False
        assert any("Duplicate stage names" in e for e in result.errors)

    def test_validate_stage_without_steps_or_branches(self, loader: PlaybookLoader) -> None:
        """Test validation fails for empty stage."""
        playbook_yaml = """
name: empty-stage
version: "1.0"
stages:
  - name: empty_stage
    description: "This stage has no steps"
"""
        playbook = loader.load_from_string(playbook_yaml)
        result = loader.validate(playbook)
        assert result.valid is False
        assert any("no steps or branches" in e for e in result.errors)

    def test_get_stage_by_name(self, complete_playbook: Playbook) -> None:
        """Test getting a stage by name."""
        stage = complete_playbook.get_stage("extraction")
        assert stage is not None
        assert stage.name == "extraction"

        missing = complete_playbook.get_stage("nonexistent")
        assert missing is None


# =============================================================================
# Condition Tests
# =============================================================================


class TestCondition:
    """Tests for Condition evaluation."""

    def test_evaluate_verdict_match(self) -> None:
        """Test condition evaluates verdict correctly."""
        condition = Condition(verdict="true_positive")
        context = {"ai_analysis": {"verdict": "true_positive", "confidence": 90}}
        assert condition.evaluate(context) is True

        context = {"ai_analysis": {"verdict": "false_positive", "confidence": 90}}
        assert condition.evaluate(context) is False

    def test_evaluate_confidence_above(self) -> None:
        """Test confidence_above condition."""
        condition = Condition(confidence_above=0.8)

        # Confidence as 0-100 scale (should be converted)
        context = {"ai_analysis": {"confidence": 85}}
        assert condition.evaluate(context) is True

        context = {"ai_analysis": {"confidence": 75}}
        assert condition.evaluate(context) is False

        # Confidence as 0-1 scale
        context = {"ai_analysis": {"confidence": 0.85}}
        assert condition.evaluate(context) is True

    def test_evaluate_confidence_below(self) -> None:
        """Test confidence_below condition."""
        condition = Condition(confidence_below=0.5)

        context = {"ai_analysis": {"confidence": 40}}
        assert condition.evaluate(context) is True

        context = {"ai_analysis": {"confidence": 60}}
        assert condition.evaluate(context) is False

    def test_evaluate_confidence_between(self) -> None:
        """Test confidence_between condition."""
        condition = Condition(confidence_between=[0.6, 0.8])

        context = {"ai_analysis": {"confidence": 70}}
        assert condition.evaluate(context) is True

        context = {"ai_analysis": {"confidence": 50}}
        assert condition.evaluate(context) is False

        context = {"ai_analysis": {"confidence": 90}}
        assert condition.evaluate(context) is False

    def test_evaluate_combined_conditions(self) -> None:
        """Test multiple conditions combined."""
        condition = Condition(verdict="true_positive", confidence_above=0.8)

        # Both match
        context = {"ai_analysis": {"verdict": "true_positive", "confidence": 90}}
        assert condition.evaluate(context) is True

        # Verdict matches, confidence doesn't
        context = {"ai_analysis": {"verdict": "true_positive", "confidence": 70}}
        assert condition.evaluate(context) is False

        # Confidence matches, verdict doesn't
        context = {"ai_analysis": {"verdict": "suspicious", "confidence": 90}}
        assert condition.evaluate(context) is False

    def test_evaluate_expression_is_not_null(self) -> None:
        """Test 'is not null' expression evaluation."""
        condition = Condition(expression="input.reported_by is not null")

        context = {"input": {"reported_by": "user@example.com"}}
        assert condition.evaluate(context) is True

        context = {"input": {"reported_by": None}}
        assert condition.evaluate(context) is False

        context = {"input": {}}
        assert condition.evaluate(context) is False

    def test_evaluate_expression_is_null(self) -> None:
        """Test 'is null' expression evaluation."""
        condition = Condition(expression="input.optional_field is null")

        context = {"input": {"optional_field": None}}
        assert condition.evaluate(context) is True

        context = {"input": {}}
        assert condition.evaluate(context) is True

        context = {"input": {"optional_field": "value"}}
        assert condition.evaluate(context) is False

    def test_confidence_validation(self) -> None:
        """Test confidence validation raises for invalid values."""
        with pytest.raises(ValueError):
            Condition(confidence_above=1.5)

        with pytest.raises(ValueError):
            Condition(confidence_below=-0.1)

    def test_confidence_between_validation(self) -> None:
        """Test confidence_between validation."""
        with pytest.raises(ValueError):
            Condition(confidence_between=[0.8, 0.6])  # Wrong order

        with pytest.raises(ValueError):
            Condition(confidence_between=[0.5])  # Only one value


# =============================================================================
# ExecutionContext Tests
# =============================================================================


class TestExecutionContext:
    """Tests for ExecutionContext."""

    def test_get_input_value(self) -> None:
        """Test getting values from input."""
        context = ExecutionContext(input={"message_id": "123", "sender": "test@example.com"})

        assert context.get("input.message_id") == "123"
        assert context.get("input.sender") == "test@example.com"
        assert context.get("input.missing") is None
        assert context.get("input.missing", "default") == "default"

    def test_get_stage_value(self) -> None:
        """Test getting values from stage outputs."""
        context = ExecutionContext()
        context.set_stage_output("extraction", {"urls": ["http://test.com"]})

        assert context.get("extraction.urls") == ["http://test.com"]
        assert context.get("extraction.missing") is None

    def test_get_nested_value(self) -> None:
        """Test getting nested values."""
        context = ExecutionContext(
            input={"config": {"timeout": 30, "nested": {"deep": "value"}}}
        )

        assert context.get("input.config.timeout") == 30
        assert context.get("input.config.nested.deep") == "value"

    def test_set_stage_output(self) -> None:
        """Test setting stage outputs."""
        context = ExecutionContext()
        context.set_stage_output("stage1", {"key1": "value1"})
        context.set_stage_output("stage1", {"key2": "value2"})

        assert context.get("stage1.key1") == "value1"
        assert context.get("stage1.key2") == "value2"

    def test_to_dict(self) -> None:
        """Test converting context to dictionary."""
        context = ExecutionContext(
            input={"key": "value"},
            trigger={"source": "test"},
        )
        context.set_stage_output("stage1", {"output": "data"})

        result = context.to_dict()
        assert result["input"] == {"key": "value"}
        assert result["trigger"] == {"source": "test"}
        assert result["stage1"] == {"output": "data"}


# =============================================================================
# PlaybookExecutor Tests
# =============================================================================


class TestPlaybookExecutor:
    """Tests for PlaybookExecutor class."""

    @pytest.mark.asyncio
    async def test_execute_minimal_playbook(
        self, minimal_playbook: Playbook, mock_action_handler
    ) -> None:
        """Test executing a minimal playbook."""
        executor = PlaybookExecutor(action_handler=mock_action_handler)
        result = await executor.execute(minimal_playbook, {"key": "value"})

        assert result.success is True
        assert result.stages_completed == 1
        assert result.total_stages == 1
        assert len(result.actions_taken) == 1
        assert result.actions_taken[0]["action"] == "test_action"

    @pytest.mark.asyncio
    async def test_execute_with_parallel_steps(
        self, loader: PlaybookLoader, mock_action_handler
    ) -> None:
        """Test executing a playbook with parallel steps."""
        playbook_yaml = """
name: parallel-test
version: "1.0"
stages:
  - name: parallel_stage
    parallel: true
    steps:
      - action: action_a
        output: [result_a]
      - action: action_b
        output: [result_b]
      - action: action_c
        output: [result_c]
"""
        playbook = loader.load_from_string(playbook_yaml)
        executor = PlaybookExecutor(action_handler=mock_action_handler)
        result = await executor.execute(playbook, {})

        assert result.success is True
        assert len(result.actions_taken) == 3
        actions = {a["action"] for a in result.actions_taken}
        assert actions == {"action_a", "action_b", "action_c"}

    @pytest.mark.asyncio
    async def test_execute_with_template_resolution(
        self, loader: PlaybookLoader
    ) -> None:
        """Test template variable resolution during execution."""
        playbook_yaml = """
name: template-test
version: "1.0"
stages:
  - name: first_stage
    steps:
      - action: produce_data
        input:
          key: "{{ input.source }}"
        output: [data]
  - name: second_stage
    steps:
      - action: consume_data
        input:
          data: "{{ first_stage.data }}"
"""
        playbook = loader.load_from_string(playbook_yaml)

        resolved_inputs: list[dict] = []

        async def tracking_handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            resolved_inputs.append({"action": action, "input": input_data.copy()})
            if action == "produce_data":
                return {"data": "produced_value"}
            return {}

        executor = PlaybookExecutor(action_handler=tracking_handler)
        result = await executor.execute(playbook, {"source": "test_source"})

        assert result.success is True
        assert resolved_inputs[0]["input"]["key"] == "test_source"
        assert resolved_inputs[1]["input"]["data"] == "produced_value"

    @pytest.mark.asyncio
    async def test_execute_with_conditional_steps(
        self, loader: PlaybookLoader
    ) -> None:
        """Test conditional step execution."""
        playbook = loader.load_from_string(PLAYBOOK_WITH_CONDITIONS_YAML)

        async def handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            if action == "analyze_data":
                return {"verdict": "positive", "confidence": 0.95}
            return {"status": "executed"}

        executor = PlaybookExecutor(action_handler=handler)
        result = await executor.execute(playbook, {})

        assert result.success is True
        # high_confidence_action should execute (0.95 > 0.9)
        # low_confidence_action should be skipped (0.95 > 0.5)
        executed_actions = [a["action"] for a in result.actions_taken]
        assert "high_confidence_action" in executed_actions
        assert "low_confidence_action" not in executed_actions

    @pytest.mark.asyncio
    async def test_execute_with_branching(
        self, complete_playbook: Playbook, mock_action_handler
    ) -> None:
        """Test branch execution based on conditions."""
        executor = PlaybookExecutor(action_handler=mock_action_handler)
        result = await executor.execute(
            complete_playbook,
            {"message_id": "123", "recipient": "user@test.com", "sender": "attacker@phish.com"},
        )

        assert result.success is True
        # Should take true_positive branch (confidence 85 > 80, verdict true_positive)
        decision_stage = result.stage_results[3]
        assert decision_stage.branch_taken == "true_positive"

    @pytest.mark.asyncio
    async def test_execute_with_approval_handler(
        self, loader: PlaybookLoader
    ) -> None:
        """Test execution with approval handler."""
        playbook_yaml = """
name: approval-test
version: "1.0"
stages:
  - name: approval_stage
    steps:
      - action: dangerous_action
        requires_approval: true
        input:
          target: "system"
"""
        playbook = loader.load_from_string(playbook_yaml)

        approval_requests: list[tuple[str, dict]] = []

        async def approval_handler(action: str, input_data: dict[str, Any]) -> bool:
            approval_requests.append((action, input_data))
            return True  # Approve

        async def action_handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            return {"status": "completed"}

        executor = PlaybookExecutor(
            action_handler=action_handler,
            approval_handler=approval_handler,
        )
        result = await executor.execute(playbook, {})

        assert result.success is True
        assert len(approval_requests) == 1
        assert approval_requests[0][0] == "dangerous_action"

    @pytest.mark.asyncio
    async def test_execute_with_approval_denied(
        self, loader: PlaybookLoader
    ) -> None:
        """Test execution when approval is denied."""
        playbook_yaml = """
name: approval-denied-test
version: "1.0"
stages:
  - name: approval_stage
    steps:
      - action: dangerous_action
        requires_approval: true
"""
        playbook = loader.load_from_string(playbook_yaml)

        async def approval_handler(action: str, input_data: dict[str, Any]) -> bool:
            return False  # Deny

        async def action_handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            return {"status": "completed"}

        executor = PlaybookExecutor(
            action_handler=action_handler,
            approval_handler=approval_handler,
        )
        result = await executor.execute(playbook, {})

        # Step should be skipped but playbook succeeds
        assert result.success is True
        assert result.stage_results[0].steps[0].skipped is True
        assert result.stage_results[0].steps[0].approved is False

    @pytest.mark.asyncio
    async def test_execute_action_failure(self, loader: PlaybookLoader) -> None:
        """Test handling of action failures."""
        playbook_yaml = """
name: failure-test
version: "1.0"
stages:
  - name: failing_stage
    steps:
      - action: failing_action
"""
        playbook = loader.load_from_string(playbook_yaml)

        async def failing_handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            raise RuntimeError("Action failed!")

        executor = PlaybookExecutor(action_handler=failing_handler)
        result = await executor.execute(playbook, {})

        assert result.success is False
        assert result.stages_completed == 0
        assert "failing_stage" in result.error
        assert result.stage_results[0].steps[0].error == "Action failed!"

    @pytest.mark.asyncio
    async def test_execute_default_handler(self, minimal_playbook: Playbook) -> None:
        """Test execution with default (simulation) handler."""
        executor = PlaybookExecutor()  # No handler provided
        result = await executor.execute(minimal_playbook, {"key": "value"})

        assert result.success is True
        assert result.actions_taken[0]["output"]["status"] == "simulated"

    @pytest.mark.asyncio
    async def test_execute_preserves_final_state(
        self, complete_playbook: Playbook, mock_action_handler
    ) -> None:
        """Test that final state contains all stage outputs."""
        executor = PlaybookExecutor(action_handler=mock_action_handler)
        result = await executor.execute(
            complete_playbook,
            {"message_id": "123", "recipient": "user@test.com", "sender": "attacker@phish.com"},
        )

        assert result.success is True
        assert "extraction" in result.final_state
        assert "enrichment" in result.final_state
        assert "ai_analysis" in result.final_state
        assert "input" in result.final_state

    @pytest.mark.asyncio
    async def test_execute_no_matching_branch(self, loader: PlaybookLoader) -> None:
        """Test execution when no branch conditions match."""
        playbook_yaml = """
name: no-match-test
version: "1.0"
stages:
  - name: analysis
    steps:
      - action: analyze
        output: [verdict, confidence]
  - name: decision
    branches:
      high_confidence:
        conditions:
          - confidence_above: 0.99
        steps:
          - action: auto_action
"""
        playbook = loader.load_from_string(playbook_yaml)

        async def handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            if action == "analyze":
                return {"verdict": "suspicious", "confidence": 0.5}
            return {}

        executor = PlaybookExecutor(action_handler=handler)
        result = await executor.execute(playbook, {})

        # Should succeed even with no branch match
        assert result.success is True
        assert result.stage_results[1].branch_taken is None


# =============================================================================
# Branch Tests
# =============================================================================


class TestBranch:
    """Tests for Branch model."""

    def test_evaluate_conditions_all_match(self) -> None:
        """Test branch evaluation when all conditions match."""
        branch = Branch(
            conditions=[
                Condition(verdict="true_positive"),
                Condition(confidence_above=0.8),
            ],
            steps=[Step(action="test_action")],
        )

        context = {"ai_analysis": {"verdict": "true_positive", "confidence": 90}}
        assert branch.evaluate_conditions(context) is True

    def test_evaluate_conditions_partial_match(self) -> None:
        """Test branch evaluation when only some conditions match."""
        branch = Branch(
            conditions=[
                Condition(verdict="true_positive"),
                Condition(confidence_above=0.8),
            ],
            steps=[],
        )

        context = {"ai_analysis": {"verdict": "true_positive", "confidence": 70}}
        assert branch.evaluate_conditions(context) is False

    def test_evaluate_conditions_empty(self) -> None:
        """Test branch with no conditions always matches."""
        branch = Branch(conditions=[], steps=[])
        assert branch.evaluate_conditions({}) is True


# =============================================================================
# StageResult Tests
# =============================================================================


class TestStageResult:
    """Tests for StageResult."""

    def test_get_outputs_from_successful_steps(self) -> None:
        """Test aggregating outputs from successful steps."""
        stage_result = StageResult(
            name="test_stage",
            success=True,
            steps=[
                StepResult(action="action1", success=True, output={"key1": "value1"}),
                StepResult(action="action2", success=True, output={"key2": "value2"}),
                StepResult(action="action3", success=False, error="failed"),
            ],
        )

        outputs = stage_result.get_outputs()
        assert outputs == {"key1": "value1", "key2": "value2"}

    def test_get_outputs_excludes_skipped(self) -> None:
        """Test that skipped steps are excluded from outputs."""
        stage_result = StageResult(
            name="test_stage",
            success=True,
            steps=[
                StepResult(action="action1", success=True, output={"key1": "value1"}),
                StepResult(action="action2", success=True, skipped=True, output={"key2": "value2"}),
            ],
        )

        outputs = stage_result.get_outputs()
        assert outputs == {"key1": "value1"}

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        stage_result = StageResult(
            name="test_stage",
            success=True,
            steps=[StepResult(action="test", success=True)],
            branch_taken="main",
            execution_time_ms=100,
        )

        result_dict = stage_result.to_dict()
        assert result_dict["name"] == "test_stage"
        assert result_dict["success"] is True
        assert result_dict["branch_taken"] == "main"
        assert len(result_dict["steps"]) == 1


# =============================================================================
# Integration Tests
# =============================================================================


class TestPlaybookIntegration:
    """Integration tests for the complete playbook workflow."""

    @pytest.mark.asyncio
    async def test_full_phishing_workflow(self, loader: PlaybookLoader) -> None:
        """Test a complete phishing triage workflow end-to-end."""
        playbook = loader.load_from_string(COMPLETE_PLAYBOOK_YAML)

        # Validate the playbook
        validation_result = loader.validate(playbook)
        assert validation_result.valid is True

        # Track all actions
        executed_actions: list[str] = []

        async def tracking_handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            executed_actions.append(action)
            if action == "parse_email":
                return {"headers": {}, "body": "suspicious content", "urls": []}
            elif action == "lookup_sender_reputation":
                return {"sender_ti": {"reputation": "bad"}}
            elif action == "lookup_urls":
                return {"url_ti": []}
            elif action == "run_triage_agent":
                return {"verdict": "true_positive", "confidence": 92, "summary": "Phishing detected"}
            return {"status": "completed"}

        executor = PlaybookExecutor(action_handler=tracking_handler)
        result = await executor.execute(
            playbook,
            {
                "message_id": "msg-123",
                "recipient": "victim@company.com",
                "sender": "attacker@phishing.com",
            },
        )

        assert result.success is True
        assert result.stages_completed == 4
        assert "parse_email" in executed_actions
        assert "lookup_sender_reputation" in executed_actions
        assert "run_triage_agent" in executed_actions
        assert "quarantine_email" in executed_actions  # From true_positive branch
        assert "create_ticket" in executed_actions  # From true_positive branch

    @pytest.mark.asyncio
    async def test_workflow_with_low_confidence(self, loader: PlaybookLoader) -> None:
        """Test workflow when AI analysis has low confidence."""
        playbook_yaml = """
name: low-confidence-test
version: "1.0"
stages:
  - name: analysis
    steps:
      - action: analyze
        output: [verdict, confidence]
  - name: decision
    branches:
      high_confidence:
        conditions:
          - verdict: true_positive
          - confidence_above: 0.8
        steps:
          - action: auto_remediate
      low_confidence:
        conditions:
          - confidence_below: 0.6
        steps:
          - action: escalate_to_human
"""
        playbook = loader.load_from_string(playbook_yaml)

        async def handler(action: str, input_data: dict[str, Any]) -> dict[str, Any]:
            if action == "analyze":
                return {"verdict": "suspicious", "confidence": 0.45}
            return {"status": "ok"}

        executor = PlaybookExecutor(action_handler=handler)
        result = await executor.execute(playbook, {})

        assert result.success is True
        decision_stage = result.stage_results[1]
        assert decision_stage.branch_taken == "low_confidence"
        assert any(a["action"] == "escalate_to_human" for a in result.actions_taken)
