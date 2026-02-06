"""End-to-end integration tests for phishing email triage.

Tests the complete triage pipeline for phishing-related alerts,
verifying correct verdicts, confidence levels, MITRE techniques,
and recommended actions.
"""

from __future__ import annotations

import json
import sys
import types
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# =============================================================================
# Mock module setup (must be before imports from tw_ai)
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


sys.modules["tw_ai.llm.base"] = _MockLLMBase
sys.modules["tw_ai.llm"] = MagicMock()

# Prevent tw_ai/__init__.py from running its imports when react.py is loaded
sys.modules.setdefault("tw_ai", MagicMock())
_mock_san = types.ModuleType("tw_ai.sanitization")
_mock_san.PromptInjectionError = type("PromptInjectionError", (Exception,), {})


class _StubRedactionMode:
    STRICT = "strict"
    PERMISSIVE = "permissive"


class _StubPIIRedactor:
    def __init__(self, **kwargs):
        pass

    def redact_dict(self, data, **kwargs):
        return data, []

    def redact_text(self, text, **kwargs):
        return text, []


class _StubPromptSanitizer:
    def sanitize_dict(self, data, **kwargs):
        return data, []

    def sanitize_text(self, text, **kwargs):
        return text, []


_mock_san.RedactionMode = _StubRedactionMode
_mock_san.RedactionRecord = MagicMock()
_mock_san.PIIRedactor = _StubPIIRedactor
_mock_san.PromptSanitizer = _StubPromptSanitizer
_mock_san.create_security_analysis_redactor = lambda: _StubPIIRedactor()
sys.modules.setdefault("tw_ai.sanitization", _mock_san)


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
    import re

    json_match = re.search(r"```json\s*([\s\S]*?)\s*```", text)
    if json_match:
        json_str = json_match.group(1)
    else:
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


@dataclass
class MockToolResult:
    """Mock ToolResult for testing."""
    success: bool
    data: dict = field(default_factory=dict)
    error: str | None = None
    execution_time_ms: int = 0

    @classmethod
    def ok(cls, data: dict, execution_time_ms: int = 0) -> "MockToolResult":
        return cls(success=True, data=data, execution_time_ms=execution_time_ms)

    @classmethod
    def fail(cls, error: str, execution_time_ms: int = 0) -> "MockToolResult":
        return cls(success=False, error=error, execution_time_ms=execution_time_ms)


def _mock_create_triage_tools():
    return MockToolRegistry()


def _mock_get_policy_bridge():
    return None


def _mock_is_policy_bridge_available():
    return False


def _mock_is_action_allowed(action_type: str, target: str, confidence: float = 0.0):
    return True


def _mock_check_action(action_type: str, target: str, confidence: float) -> dict:
    return {"decision": "allowed", "reason": None, "approval_level": None}


def _mock_get_operation_mode() -> str:
    return "autonomous"


def _mock_is_kill_switch_active() -> bool:
    return False


def _mock_submit_approval_request(action_type: str, target: str, reason: str, level: str = "standard") -> dict:
    import uuid
    return {
        "request_id": str(uuid.uuid4()),
        "status": "pending",
        "expires_at": "2025-01-30T12:00:00Z",
    }


def _mock_check_approval_status(request_id: str) -> dict:
    return {"status": "pending", "approved_by": None, "approved_at": None}


_mock_approval_requests = {}


class _MockTools:
    Tool = MockTool
    ToolResult = MockToolResult
    ToolRegistry = MockToolRegistry
    create_triage_tools = staticmethod(_mock_create_triage_tools)
    get_policy_bridge = staticmethod(_mock_get_policy_bridge)
    is_policy_bridge_available = staticmethod(_mock_is_policy_bridge_available)
    is_action_allowed = staticmethod(_mock_is_action_allowed)
    _mock_check_action = staticmethod(_mock_check_action)
    _mock_get_operation_mode = staticmethod(_mock_get_operation_mode)
    _mock_is_kill_switch_active = staticmethod(_mock_is_kill_switch_active)
    _mock_submit_approval_request = staticmethod(_mock_submit_approval_request)
    _mock_check_approval_status = staticmethod(_mock_check_approval_status)
    _mock_approval_requests = _mock_approval_requests


sys.modules["tw_ai.agents.tools"] = _MockTools


# Now import the actual react module
import importlib.util

_base_path = Path(__file__).parent.parent.parent / "tw_ai" / "agents"


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
StepType = _react.StepType


# =============================================================================
# Test Helper Functions
# =============================================================================


def create_mock_llm_for_phishing(response_json: str):
    """Create a mock LLM that returns the given response."""
    from unittest.mock import AsyncMock

    llm = MagicMock()
    llm.name = "mock-llm"
    llm.complete = AsyncMock(return_value=_MockLLMBase.LLMResponse(
        content=f"```json\n{response_json}\n```",
        tool_calls=[],
        usage={"total_tokens": 500},
    ))
    return llm


def get_phishing_malicious_response() -> str:
    """Get a malicious phishing analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 92,
        "severity": "high",
        "summary": "Credential harvesting phishing attempt using typosquatted domain. "
                   "Sender domain 'paypa1.com' impersonates PayPal with '1' instead of 'l'.",
        "indicators": [
            {"type": "domain", "value": "paypa1.com", "verdict": "malicious - typosquatting"},
            {"type": "url", "value": "http://paypa1-verify.com/login", "verdict": "malicious - credential harvesting"},
        ],
        "mitre_techniques": [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "relevance": "Email contains link to credential harvesting page",
            },
        ],
        "recommended_actions": [
            {
                "action": "Quarantine email and block sender domain",
                "priority": "immediate",
                "reason": "Prevent credential theft",
            },
            {
                "action": "Block sender domain at email gateway",
                "priority": "immediate",
                "reason": "Stop similar phishing attempts",
            },
        ],
        "reasoning": "Clear phishing attempt with typosquatted domain and credential harvesting link.",
    })


def get_phishing_benign_response() -> str:
    """Get a benign email analysis response."""
    return json.dumps({
        "verdict": "false_positive",
        "confidence": 88,
        "severity": "informational",
        "summary": "Legitimate internal email from company reports system.",
        "indicators": [
            {"type": "domain", "value": "company.com", "verdict": "benign - internal domain"},
        ],
        "mitre_techniques": [],
        "recommended_actions": [
            {
                "action": "Release email from quarantine",
                "priority": "high",
                "reason": "Legitimate business communication",
            },
        ],
        "reasoning": "Legitimate internal email with passing authentication and internal URLs.",
    })


# =============================================================================
# Integration Tests
# =============================================================================


class TestPhishingTriageMalicious:
    """Tests for obvious phishing email detection."""

    @pytest.mark.asyncio
    async def test_obvious_phishing_verdict_is_malicious(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that obvious phishing email gets malicious verdict."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())

        # Create mock tool registry from conftest
        registry = MockToolRegistry()
        async def mock_lookup_domain(domain: str):
            if "paypa1" in domain:
                return {"verdict": "malicious", "categories": ["phishing"]}
            return {"verdict": "unknown"}

        registry.register(MockTool(
            name="lookup_domain",
            description="Look up domain reputation",
            parameters={"type": "object", "properties": {"domain": {"type": "string"}}},
            handler=mock_lookup_domain,
        ))

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.verdict == "true_positive"

    @pytest.mark.asyncio
    async def test_obvious_phishing_high_confidence(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that obvious phishing gets high confidence score."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.confidence >= 80

    @pytest.mark.asyncio
    async def test_phishing_identifies_correct_mitre_techniques(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that phishing analysis identifies appropriate MITRE techniques."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.mitre_techniques) > 0

        # Check for phishing-related techniques (T1566.*)
        technique_ids = [t["id"] for t in result.analysis.mitre_techniques]
        has_phishing_technique = any(
            tid.startswith("T1566") or tid.startswith("T1598")
            for tid in technique_ids
        )
        assert has_phishing_technique, f"Expected phishing technique, got: {technique_ids}"

    @pytest.mark.asyncio
    async def test_phishing_recommends_quarantine_action(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that phishing analysis recommends quarantine and blocking."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.recommended_actions) > 0

        # Check for containment actions
        action_texts = [a["action"].lower() for a in result.analysis.recommended_actions]
        has_containment = any(
            "quarantine" in text or "block" in text
            for text in action_texts
        )
        assert has_containment, f"Expected containment action, got: {action_texts}"

    @pytest.mark.asyncio
    async def test_phishing_includes_typosquat_indicator(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that phishing analysis identifies typosquatted domain."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.indicators) > 0

        # Check that typosquatted domain is identified
        indicator_values = [i["value"] for i in result.analysis.indicators]
        assert "paypa1.com" in indicator_values or any(
            "paypa1" in v for v in indicator_values
        ), f"Expected typosquatted domain indicator, got: {indicator_values}"


class TestPhishingTriageBenign:
    """Tests for legitimate email detection (false positive)."""

    @pytest.mark.asyncio
    async def test_legitimate_email_verdict_is_benign(
        self,
        mock_tool_registry,
        legitimate_email_alert,
    ):
        """Test that legitimate email gets benign/false_positive verdict."""
        llm = create_mock_llm_for_phishing(get_phishing_benign_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=legitimate_email_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.verdict in ("false_positive", "benign")

    @pytest.mark.asyncio
    async def test_legitimate_email_low_severity(
        self,
        mock_tool_registry,
        legitimate_email_alert,
    ):
        """Test that legitimate email gets low/informational severity."""
        llm = create_mock_llm_for_phishing(get_phishing_benign_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=legitimate_email_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.severity in ("informational", "low", "info")

    @pytest.mark.asyncio
    async def test_legitimate_email_no_malicious_mitre_techniques(
        self,
        mock_tool_registry,
        legitimate_email_alert,
    ):
        """Test that legitimate email has no malicious MITRE techniques mapped."""
        llm = create_mock_llm_for_phishing(get_phishing_benign_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=legitimate_email_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        # Benign emails should have no attack techniques
        assert len(result.analysis.mitre_techniques) == 0

    @pytest.mark.asyncio
    async def test_legitimate_email_recommends_release(
        self,
        mock_tool_registry,
        legitimate_email_alert,
    ):
        """Test that legitimate email recommends release from quarantine."""
        llm = create_mock_llm_for_phishing(get_phishing_benign_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=legitimate_email_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.recommended_actions) > 0

        # Check for release action
        action_texts = [a["action"].lower() for a in result.analysis.recommended_actions]
        has_release = any(
            "release" in text or "allow" in text or "whitelist" in text
            for text in action_texts
        )
        assert has_release, f"Expected release action, got: {action_texts}"


class TestPhishingTriageEdgeCases:
    """Edge case tests for phishing triage."""

    @pytest.mark.asyncio
    async def test_phishing_with_missing_fields(self, mock_tool_registry):
        """Test handling of alerts with missing optional fields."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        # Minimal alert with only required fields
        minimal_alert = {
            "type": "email_security",
            "sender": "phishing@paypa1.com",
        }

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=minimal_alert,
        )

        result = await agent.run(request)

        # Should still complete successfully
        assert result.success is True

    @pytest.mark.asyncio
    async def test_phishing_with_priority_context(self, mock_tool_registry, phishing_alert):
        """Test that high priority context is included in analysis."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
            priority="critical",
            context={"user_department": "Executive", "user_role": "CEO"},
        )

        result = await agent.run(request)

        assert result.success is True
        # High-priority phishing targeting executive should still be malicious
        assert result.analysis.verdict == "true_positive"

    @pytest.mark.asyncio
    async def test_phishing_agent_result_has_execution_trace(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that agent result includes execution trace."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.execution_trace) > 0
        # Should have at least a final step
        step_types = [s.step_type for s in result.execution_trace]
        assert StepType.FINAL in step_types

    @pytest.mark.asyncio
    async def test_phishing_tokens_tracked(
        self,
        mock_tool_registry,
        phishing_alert,
    ):
        """Test that token usage is tracked."""
        llm = create_mock_llm_for_phishing(get_phishing_malicious_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="phishing",
            alert_data=phishing_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.tokens_used > 0
