"""Unit tests for the production ReAct agent implementation.

Tests cover:
- Basic agent initialization and configuration
- Token counting and budget enforcement
- Tool execution with retry logic
- Timeout handling
- Execution trace and state persistence
- Streaming callbacks
- TriageRequest dataclass
- AgentResult structure
"""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


# =============================================================================
# Mock setup for imports
# =============================================================================


@dataclass
class MockToolDefinition:
    """Mock ToolDefinition for testing."""
    name: str
    description: str
    parameters: dict


class _MockLLMBase:
    """Mock tw_ai.llm.base module."""
    ToolDefinition = MockToolDefinition

    class Role:
        SYSTEM = "system"
        USER = "user"
        ASSISTANT = "assistant"
        TOOL = "tool"

    @dataclass
    class Message:
        role: str
        content: str
        name: str | None = None
        tool_call_id: str | None = None

        @classmethod
        def system(cls, content: str) -> "Message":
            return cls(role="system", content=content)

        @classmethod
        def user(cls, content: str) -> "Message":
            return cls(role="user", content=content)

        @classmethod
        def assistant(cls, content: str) -> "Message":
            return cls(role="assistant", content=content)

        @classmethod
        def tool_result(cls, content: str, tool_call_id: str) -> "Message":
            return cls(role="tool", content=content, tool_call_id=tool_call_id)

    @dataclass
    class ToolCall:
        id: str
        name: str
        arguments: dict

    @dataclass
    class LLMResponse:
        content: str | None
        tool_calls: list = None
        finish_reason: str = "stop"
        usage: dict = None
        model: str = ""
        raw_response: Any = None

        def __post_init__(self):
            if self.tool_calls is None:
                self.tool_calls = []
            if self.usage is None:
                self.usage = {}

        @property
        def has_tool_calls(self) -> bool:
            return len(self.tool_calls) > 0

    class LLMProvider:
        @property
        def name(self) -> str:
            return "mock"

        async def complete(self, messages, tools=None, temperature=0.1, max_tokens=4096):
            pass

        async def health_check(self) -> bool:
            return True


# Pre-register mock modules
sys.modules["tw_ai.llm.base"] = _MockLLMBase
sys.modules["tw_ai.llm"] = MagicMock()


# Mock models module
class MockTriageAnalysis:
    def __init__(self, **kwargs):
        self.verdict = kwargs.get("verdict", "suspicious")
        self.confidence = kwargs.get("confidence", 75)
        self.severity = kwargs.get("severity", "medium")
        self.summary = kwargs.get("summary", "Test summary")
        self.indicators = kwargs.get("indicators", [])
        self.mitre_techniques = kwargs.get("mitre_techniques", [])
        self.recommended_actions = kwargs.get("recommended_actions", [])
        self.reasoning = kwargs.get("reasoning", "Test reasoning")

    def model_dump(self):
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "reasoning": self.reasoning,
        }


class _MockModels:
    TriageAnalysis = MockTriageAnalysis


sys.modules["tw_ai.agents.models"] = _MockModels


# Mock output_parser module
class MockParseError(Exception):
    pass


def mock_parse_triage_analysis(text: str):
    """Mock parser that extracts JSON from text."""
    import json
    import re

    # Try to extract JSON from code block
    json_match = re.search(r"```json\s*([\s\S]*?)\s*```", text)
    if json_match:
        json_str = json_match.group(1)
    else:
        # Try to find raw JSON
        json_match = re.search(r"\{[\s\S]*\}", text)
        if json_match:
            json_str = json_match.group(0)
        else:
            raise MockParseError("No JSON found in response")

    try:
        data = json.loads(json_str)
        return MockTriageAnalysis(**data)
    except json.JSONDecodeError as e:
        raise MockParseError(f"Invalid JSON: {e}")


class _MockOutputParser:
    ParseError = MockParseError
    parse_triage_analysis = staticmethod(mock_parse_triage_analysis)


sys.modules["tw_ai.agents.output_parser"] = _MockOutputParser


# Mock tools module
@dataclass
class MockTool:
    name: str
    description: str
    parameters: dict
    handler: Any
    requires_confirmation: bool = False

    def to_definition(self):
        return MockToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )


class MockToolRegistry:
    def __init__(self):
        self._tools: dict[str, MockTool] = {}

    def register(self, tool: MockTool):
        self._tools[tool.name] = tool

    def get(self, name: str):
        return self._tools.get(name)

    def list_tools(self):
        return list(self._tools.keys())

    def get_tool_definitions(self):
        return [tool.to_definition() for tool in self._tools.values()]

    async def execute(self, name: str, arguments: dict):
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")
        return await tool.handler(**arguments)


class _MockTools:
    Tool = MockTool
    ToolRegistry = MockToolRegistry


sys.modules["tw_ai.agents.tools"] = _MockTools


# Now import the react module
import importlib.util

_base_path = Path(__file__).parent.parent / "tw_ai" / "agents"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_react = _load_module("tw_ai.agents.react", _base_path / "react.py")
ReActAgent = _react.ReActAgent
AgentResult = _react.AgentResult
TriageRequest = _react.TriageRequest
Step = _react.Step
StepType = _react.StepType
TokenCounter = _react.TokenCounter


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def mock_llm():
    """Create a mock LLM provider."""
    llm = MagicMock()
    llm.name = "mock-llm"
    llm.complete = AsyncMock()
    return llm


@pytest.fixture
def mock_registry():
    """Create a mock tool registry with sample tools."""
    registry = MockToolRegistry()

    async def mock_lookup_ip(ip: str):
        return {
            "indicator": ip,
            "verdict": "clean" if ip.startswith("192.168") else "suspicious",
            "score": 0 if ip.startswith("192.168") else 50,
        }

    async def mock_lookup_hash(hash: str):
        return {
            "indicator": hash,
            "verdict": "unknown",
            "score": 0,
        }

    async def mock_failing_tool(**kwargs):
        raise RuntimeError("Tool execution failed")

    registry.register(MockTool(
        name="lookup_ip",
        description="Look up IP reputation",
        parameters={"type": "object", "properties": {"ip": {"type": "string"}}},
        handler=mock_lookup_ip,
    ))

    registry.register(MockTool(
        name="lookup_hash",
        description="Look up file hash",
        parameters={"type": "object", "properties": {"hash": {"type": "string"}}},
        handler=mock_lookup_hash,
    ))

    registry.register(MockTool(
        name="failing_tool",
        description="A tool that always fails",
        parameters={"type": "object", "properties": {}},
        handler=mock_failing_tool,
    ))

    return registry


@pytest.fixture
def sample_triage_request():
    """Create a sample triage request."""
    return TriageRequest(
        alert_type="phishing",
        alert_data={
            "subject": "Urgent: Verify your account",
            "sender": "security@example-typo.com",
            "recipient": "user@company.com",
            "links": ["https://evil.example.com/login"],
        },
        context={"user_department": "Finance"},
        priority="high",
    )


@pytest.fixture
def sample_analysis_json():
    """Return a valid analysis JSON response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 85,
        "severity": "high",
        "summary": "Phishing email detected with malicious link",
        "indicators": [
            {"type": "domain", "value": "evil.example.com", "verdict": "malicious"}
        ],
        "mitre_techniques": [
            {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "relevance": "Email-based attack"}
        ],
        "recommended_actions": [
            {"action": "Block sender domain", "priority": "immediate", "reason": "Known phishing source"}
        ],
        "reasoning": "The email exhibits classic phishing characteristics..."
    })


# =============================================================================
# Token Counter Tests
# =============================================================================


class TestTokenCounter:
    """Tests for TokenCounter class."""

    def test_count_empty_string(self):
        """Test counting tokens in empty string."""
        counter = TokenCounter()
        assert counter.count("") == 0

    def test_count_simple_text(self):
        """Test counting tokens in simple text."""
        counter = TokenCounter()
        # Should return a reasonable estimate
        count = counter.count("Hello, world!")
        assert count > 0
        assert count < 100  # Reasonable upper bound

    def test_count_long_text(self):
        """Test counting tokens in longer text."""
        counter = TokenCounter()
        text = "This is a test sentence. " * 100
        count = counter.count(text)
        assert count > 100  # Should be substantial

    def test_count_messages(self):
        """Test counting tokens in message list."""
        counter = TokenCounter()
        messages = [
            _MockLLMBase.Message.system("You are a helpful assistant."),
            _MockLLMBase.Message.user("Hello!"),
            _MockLLMBase.Message.assistant("Hi there!"),
        ]
        count = counter.count_messages(messages)
        assert count > 0


# =============================================================================
# TriageRequest Tests
# =============================================================================


class TestTriageRequest:
    """Tests for TriageRequest dataclass."""

    def test_basic_creation(self):
        """Test creating a basic TriageRequest."""
        request = TriageRequest(
            alert_type="malware",
            alert_data={"file_hash": "abc123"},
        )
        assert request.alert_type == "malware"
        assert request.alert_data == {"file_hash": "abc123"}
        assert request.context is None
        assert request.priority is None

    def test_full_creation(self, sample_triage_request):
        """Test creating a full TriageRequest."""
        assert sample_triage_request.alert_type == "phishing"
        assert "sender" in sample_triage_request.alert_data
        assert sample_triage_request.context == {"user_department": "Finance"}
        assert sample_triage_request.priority == "high"

    def test_to_task_string(self, sample_triage_request):
        """Test converting request to task string."""
        task_str = sample_triage_request.to_task_string()

        assert "phishing" in task_str
        assert "security@example-typo.com" in task_str
        assert "Finance" in task_str
        assert "high" in task_str.lower()

    def test_to_task_string_minimal(self):
        """Test task string with minimal data."""
        request = TriageRequest(
            alert_type="test",
            alert_data={"key": "value"},
        )
        task_str = request.to_task_string()

        assert "test" in task_str
        assert "value" in task_str


# =============================================================================
# Step Tests
# =============================================================================


class TestStep:
    """Tests for Step dataclass."""

    def test_thought_step(self):
        """Test creating a thought step."""
        step = Step(
            step_type=StepType.THOUGHT,
            content="Analyzing the alert...",
            tokens_used=50,
        )
        assert step.step_type == StepType.THOUGHT
        assert step.content == "Analyzing the alert..."
        assert step.tokens_used == 50

    def test_action_step(self):
        """Test creating an action step."""
        step = Step(
            step_type=StepType.ACTION,
            content="Calling tool: lookup_ip",
            tool_name="lookup_ip",
            tool_arguments={"ip": "192.168.1.1"},
        )
        assert step.step_type == StepType.ACTION
        assert step.tool_name == "lookup_ip"
        assert step.tool_arguments == {"ip": "192.168.1.1"}

    def test_observation_step(self):
        """Test creating an observation step."""
        step = Step(
            step_type=StepType.OBSERVATION,
            content="Tool completed",
            tool_name="lookup_ip",
            tool_result={"verdict": "clean"},
            duration_ms=150,
        )
        assert step.step_type == StepType.OBSERVATION
        assert step.tool_result == {"verdict": "clean"}
        assert step.duration_ms == 150

    def test_error_step(self):
        """Test creating an error step."""
        step = Step(
            step_type=StepType.ERROR,
            content="Tool failed",
            error="Connection timeout",
            retry_count=2,
        )
        assert step.step_type == StepType.ERROR
        assert step.error == "Connection timeout"
        assert step.retry_count == 2

    def test_to_dict(self):
        """Test converting step to dictionary."""
        step = Step(
            step_type=StepType.ACTION,
            content="Test action",
            tool_name="test_tool",
            tool_arguments={"arg": "value"},
        )
        step_dict = step.to_dict()

        assert step_dict["step_type"] == "action"
        assert step_dict["content"] == "Test action"
        assert step_dict["tool_name"] == "test_tool"
        assert step_dict["tool_arguments"] == {"arg": "value"}


# =============================================================================
# AgentResult Tests
# =============================================================================


class TestAgentResult:
    """Tests for AgentResult dataclass."""

    def test_successful_result(self):
        """Test creating a successful result."""
        analysis = MockTriageAnalysis(
            verdict="true_positive",
            summary="Malware detected",
        )
        result = AgentResult(
            success=True,
            analysis=analysis,
            tokens_used=1500,
            execution_time_seconds=5.5,
        )

        assert result.success is True
        assert result.analysis.verdict == "true_positive"
        assert result.tokens_used == 1500
        assert result.execution_time_seconds == 5.5
        assert result.error is None

    def test_failed_result(self):
        """Test creating a failed result."""
        result = AgentResult(
            success=False,
            tokens_used=500,
            execution_time_seconds=2.0,
            error="Max iterations reached",
        )

        assert result.success is False
        assert result.analysis is None
        assert result.error == "Max iterations reached"

    def test_legacy_fields(self):
        """Test that legacy fields are populated."""
        trace = [
            Step(
                step_type=StepType.ACTION,
                content="Calling lookup_ip",
                tool_name="lookup_ip",
                tool_arguments={"ip": "1.2.3.4"},
            ),
            Step(
                step_type=StepType.OBSERVATION,
                content="Tool completed",
                tool_name="lookup_ip",
                tool_result={"verdict": "clean"},
            ),
        ]
        analysis = MockTriageAnalysis(summary="Test summary", reasoning="Test reasoning")

        result = AgentResult(
            success=True,
            analysis=analysis,
            execution_trace=trace,
            tokens_used=1000,
        )

        # Check legacy fields
        assert result.output == "Test summary"
        assert result.reasoning == ["Test reasoning"]
        assert result.tool_calls == 1
        assert result.total_tokens == 1000
        assert len(result.actions_taken) == 1


# =============================================================================
# ReActAgent Initialization Tests
# =============================================================================


class TestReActAgentInit:
    """Tests for ReActAgent initialization."""

    def test_default_init(self, mock_llm, mock_registry):
        """Test agent initialization with defaults."""
        agent = ReActAgent(llm=mock_llm, tools=mock_registry)

        assert agent.max_iterations == 10
        assert agent.max_tokens == 8000
        assert agent.timeout_seconds == 120
        assert agent.tool_retries == 2

    def test_custom_config(self, mock_llm, mock_registry):
        """Test agent initialization with custom config."""
        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            max_iterations=5,
            max_tokens=4000,
            timeout_seconds=60,
            tool_retries=3,
        )

        assert agent.max_iterations == 5
        assert agent.max_tokens == 4000
        assert agent.timeout_seconds == 60
        assert agent.tool_retries == 3

    def test_custom_system_prompt(self, mock_llm, mock_registry):
        """Test agent initialization with custom system prompt."""
        custom_prompt = "You are a security analyst."
        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            system_prompt=custom_prompt,
        )

        assert agent.system_prompt == custom_prompt


# =============================================================================
# ReActAgent Run Tests
# =============================================================================


class TestReActAgentRun:
    """Tests for ReActAgent.run() method."""

    @pytest.mark.asyncio
    async def test_simple_completion(self, mock_llm, mock_registry, sample_analysis_json):
        """Test a simple run that completes immediately."""
        # Mock LLM to return final analysis directly
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 500},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run(TriageRequest(
            alert_type="test",
            alert_data={"key": "value"},
        ))

        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.verdict == "true_positive"
        assert result.tokens_used > 0

    @pytest.mark.asyncio
    async def test_run_with_tool_call(self, mock_llm, mock_registry, sample_analysis_json):
        """Test a run that makes tool calls."""
        # First call: LLM wants to call a tool
        tool_call_response = _MockLLMBase.LLMResponse(
            content="Let me look up this IP address.",
            tool_calls=[
                _MockLLMBase.ToolCall(
                    id="call_123",
                    name="lookup_ip",
                    arguments={"ip": "192.168.1.1"},
                )
            ],
            usage={"total_tokens": 200},
        )

        # Second call: LLM provides final analysis
        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 300},
        )

        mock_llm.complete.side_effect = [tool_call_response, final_response]

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Analyze IP 192.168.1.1")

        assert result.success is True
        assert mock_llm.complete.call_count == 2

        # Check execution trace
        action_steps = [s for s in result.execution_trace if s.step_type == StepType.ACTION]
        assert len(action_steps) == 1
        assert action_steps[0].tool_name == "lookup_ip"

    @pytest.mark.asyncio
    async def test_run_with_string_task(self, mock_llm, mock_registry, sample_analysis_json):
        """Test running with a string task instead of TriageRequest."""
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 400},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Analyze this suspicious email")

        assert result.success is True

    @pytest.mark.asyncio
    async def test_max_iterations_reached(self, mock_llm, mock_registry):
        """Test that max iterations limit is enforced."""
        # Always return tool calls to force iterations
        tool_call_response = _MockLLMBase.LLMResponse(
            content="Checking another thing...",
            tool_calls=[
                _MockLLMBase.ToolCall(
                    id="call_999",
                    name="lookup_ip",
                    arguments={"ip": "1.2.3.4"},
                )
            ],
            usage={"total_tokens": 100},
        )
        mock_llm.complete.return_value = tool_call_response

        agent = ReActAgent(llm=mock_llm, tools=mock_registry, max_iterations=3)
        result = await agent.run("Test task")

        assert result.success is False
        assert "max_iterations" in result.error

    @pytest.mark.asyncio
    async def test_token_budget_exceeded(self, mock_llm, mock_registry):
        """Test that token budget limit is enforced."""
        # Return response with many tokens
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content="Processing..." * 1000,  # Lots of content
            tool_calls=[
                _MockLLMBase.ToolCall(
                    id="call_1",
                    name="lookup_ip",
                    arguments={"ip": "1.1.1.1"},
                )
            ],
            usage={"total_tokens": 5000},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry, max_tokens=100)
        result = await agent.run("Test task")

        assert result.success is False
        assert "budget" in result.error.lower() or "token" in result.error.lower()

    @pytest.mark.asyncio
    async def test_timeout_handling(self, mock_llm, mock_registry):
        """Test that timeout is enforced."""
        async def slow_complete(*args, **kwargs):
            await asyncio.sleep(5)
            return _MockLLMBase.LLMResponse(content="Done", usage={})

        mock_llm.complete = slow_complete

        agent = ReActAgent(llm=mock_llm, tools=mock_registry, timeout_seconds=0.1)
        result = await agent.run("Test task")

        assert result.success is False
        assert "timed out" in result.error.lower() or "timeout" in result.error.lower()

    @pytest.mark.asyncio
    async def test_parse_error_handling(self, mock_llm, mock_registry):
        """Test handling of parse errors in final response."""
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content="This is not valid JSON at all",
            tool_calls=[],
            usage={"total_tokens": 100},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Test task")

        assert result.success is False
        assert result.raw_output == "This is not valid JSON at all"
        assert result.error is not None


# =============================================================================
# Tool Retry Tests
# =============================================================================


class TestToolRetry:
    """Tests for tool retry logic."""

    @pytest.mark.asyncio
    async def test_tool_retry_on_failure(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that failed tools are retried."""
        call_count = 0

        async def flaky_tool(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise RuntimeError("Temporary failure")
            return {"result": "success"}

        mock_registry._tools["flaky_tool"] = MockTool(
            name="flaky_tool",
            description="A flaky tool",
            parameters={"type": "object", "properties": {}},
            handler=flaky_tool,
        )

        # First call: use flaky tool
        tool_response = _MockLLMBase.LLMResponse(
            content="Trying the tool",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="flaky_tool", arguments={})
            ],
            usage={"total_tokens": 100},
        )

        # Second call: final response
        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            tool_retries=2,
            retry_base_delay=0.01,  # Fast retry for tests
        )
        result = await agent.run("Test task")

        assert result.success is True
        assert call_count == 2  # Called twice due to retry

    @pytest.mark.asyncio
    async def test_tool_retry_exhausted(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that retries are eventually exhausted."""
        # First call: use failing tool
        tool_response = _MockLLMBase.LLMResponse(
            content="Trying the failing tool",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="failing_tool", arguments={})
            ],
            usage={"total_tokens": 100},
        )

        # Second call: final response (agent continues with partial results)
        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            tool_retries=1,
            retry_base_delay=0.01,
        )
        result = await agent.run("Test task")

        # Agent should continue even if tool fails
        assert result.success is True

        # Check that error was recorded
        error_steps = [s for s in result.execution_trace if s.step_type == StepType.ERROR]
        assert len(error_steps) == 1
        assert "failed" in error_steps[0].content.lower()


# =============================================================================
# Callback Tests
# =============================================================================


class TestCallbacks:
    """Tests for streaming callbacks."""

    @pytest.mark.asyncio
    async def test_on_thought_callback(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that on_thought callback is invoked."""
        thoughts = []

        async def on_thought(thought: str, step: Step):
            thoughts.append(thought)

        # LLM makes a tool call with thought
        tool_response = _MockLLMBase.LLMResponse(
            content="I need to investigate this IP address.",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="lookup_ip", arguments={"ip": "1.1.1.1"})
            ],
            usage={"total_tokens": 100},
        )

        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            on_thought=on_thought,
        )
        await agent.run("Test task")

        assert len(thoughts) == 1
        assert "investigate" in thoughts[0].lower()

    @pytest.mark.asyncio
    async def test_on_action_callback(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that on_action callback is invoked."""
        actions = []

        async def on_action(tool_name: str, arguments: dict, step: Step):
            actions.append((tool_name, arguments))

        tool_response = _MockLLMBase.LLMResponse(
            content="Looking up IP",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="lookup_ip", arguments={"ip": "8.8.8.8"})
            ],
            usage={"total_tokens": 100},
        )

        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            on_action=on_action,
        )
        await agent.run("Test task")

        assert len(actions) == 1
        assert actions[0][0] == "lookup_ip"
        assert actions[0][1] == {"ip": "8.8.8.8"}

    @pytest.mark.asyncio
    async def test_on_observation_callback(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that on_observation callback is invoked."""
        observations = []

        async def on_observation(result: Any, step: Step):
            observations.append(result)

        tool_response = _MockLLMBase.LLMResponse(
            content="Checking IP",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="lookup_ip", arguments={"ip": "192.168.1.1"})
            ],
            usage={"total_tokens": 100},
        )

        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            on_observation=on_observation,
        )
        await agent.run("Test task")

        assert len(observations) == 1
        assert observations[0]["verdict"] == "clean"


# =============================================================================
# Execution Trace Tests
# =============================================================================


class TestExecutionTrace:
    """Tests for execution trace and state persistence."""

    @pytest.mark.asyncio
    async def test_execution_trace_recorded(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that execution trace is properly recorded."""
        tool_response = _MockLLMBase.LLMResponse(
            content="Analyzing...",
            tool_calls=[
                _MockLLMBase.ToolCall(id="call_1", name="lookup_ip", arguments={"ip": "1.2.3.4"})
            ],
            usage={"total_tokens": 100},
        )

        final_response = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 200},
        )

        mock_llm.complete.side_effect = [tool_response, final_response]

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Test task")

        # Should have thought, action, observation, and final steps
        assert len(result.execution_trace) >= 3

        # Check step types
        step_types = [s.step_type for s in result.execution_trace]
        assert StepType.THOUGHT in step_types
        assert StepType.ACTION in step_types
        assert StepType.OBSERVATION in step_types
        assert StepType.FINAL in step_types

    @pytest.mark.asyncio
    async def test_save_execution_trace(self, mock_llm, mock_registry, sample_analysis_json):
        """Test saving execution trace to file."""
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 500},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Test task")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            filepath = f.name

        try:
            agent.save_execution_trace(result, filepath)

            # Verify file was created and contains valid JSON
            with open(filepath) as f:
                trace_data = json.load(f)

            assert trace_data["success"] is True
            assert trace_data["tokens_used"] > 0
            assert "steps" in trace_data
            assert trace_data["analysis"] is not None
        finally:
            Path(filepath).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_step_timestamps(self, mock_llm, mock_registry, sample_analysis_json):
        """Test that steps have timestamps."""
        mock_llm.complete.return_value = _MockLLMBase.LLMResponse(
            content=f"```json\n{sample_analysis_json}\n```",
            tool_calls=[],
            usage={"total_tokens": 500},
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run("Test task")

        for step in result.execution_trace:
            assert step.timestamp > 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestIntegration:
    """Integration tests for the full ReAct loop."""

    @pytest.mark.asyncio
    async def test_full_triage_flow(self, mock_llm, mock_registry):
        """Test a complete triage flow with multiple tool calls."""
        analysis_json = json.dumps({
            "verdict": "true_positive",
            "confidence": 90,
            "severity": "high",
            "summary": "Confirmed phishing attack with malicious infrastructure",
            "indicators": [
                {"type": "ip", "value": "203.0.113.100", "verdict": "malicious"},
                {"type": "domain", "value": "evil.example.com", "verdict": "malicious"},
            ],
            "mitre_techniques": [
                {"id": "T1566", "name": "Phishing", "tactic": "Initial Access", "relevance": "Email attack vector"}
            ],
            "recommended_actions": [
                {"action": "Block IP at firewall", "priority": "immediate", "reason": "Active C2 server"},
                {"action": "Reset user credentials", "priority": "high", "reason": "Potential compromise"},
            ],
            "reasoning": "Multiple indicators confirm malicious activity..."
        })

        # Simulate multiple tool calls
        responses = [
            _MockLLMBase.LLMResponse(
                content="I'll check the IP address first.",
                tool_calls=[
                    _MockLLMBase.ToolCall(id="call_1", name="lookup_ip", arguments={"ip": "203.0.113.100"})
                ],
                usage={"total_tokens": 150},
            ),
            _MockLLMBase.LLMResponse(
                content="Now checking the file hash.",
                tool_calls=[
                    _MockLLMBase.ToolCall(id="call_2", name="lookup_hash", arguments={"hash": "abc123"})
                ],
                usage={"total_tokens": 150},
            ),
            _MockLLMBase.LLMResponse(
                content=f"Based on my analysis:\n```json\n{analysis_json}\n```",
                tool_calls=[],
                usage={"total_tokens": 400},
            ),
        ]
        mock_llm.complete.side_effect = responses

        request = TriageRequest(
            alert_type="phishing",
            alert_data={
                "sender_ip": "203.0.113.100",
                "attachment_hash": "abc123",
                "subject": "Urgent action required",
            },
            priority="high",
        )

        agent = ReActAgent(llm=mock_llm, tools=mock_registry)
        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.verdict == "true_positive"
        assert result.analysis.confidence == 90
        assert len(result.analysis.recommended_actions) == 2

        # Verify tool calls were made
        action_steps = [s for s in result.execution_trace if s.step_type == StepType.ACTION]
        assert len(action_steps) == 2

    @pytest.mark.asyncio
    async def test_graceful_degradation(self, mock_llm, mock_registry):
        """Test that agent continues when tools fail."""
        analysis_json = json.dumps({
            "verdict": "inconclusive",
            "confidence": 40,
            "severity": "medium",
            "summary": "Could not gather full context due to tool failures",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "Manual investigation required", "priority": "high", "reason": "Automated tools unavailable"}
            ],
            "reasoning": "Tool failures prevented complete analysis..."
        })

        responses = [
            _MockLLMBase.LLMResponse(
                content="Checking the tool",
                tool_calls=[
                    _MockLLMBase.ToolCall(id="call_1", name="failing_tool", arguments={})
                ],
                usage={"total_tokens": 100},
            ),
            _MockLLMBase.LLMResponse(
                content=f"```json\n{analysis_json}\n```",
                tool_calls=[],
                usage={"total_tokens": 200},
            ),
        ]
        mock_llm.complete.side_effect = responses

        agent = ReActAgent(
            llm=mock_llm,
            tools=mock_registry,
            tool_retries=1,
            retry_base_delay=0.01,
        )
        result = await agent.run("Test with failing tools")

        # Agent should still complete successfully
        assert result.success is True
        assert result.analysis.verdict == "inconclusive"

        # Error should be in trace
        error_steps = [s for s in result.execution_trace if s.step_type == StepType.ERROR]
        assert len(error_steps) == 1
