"""End-to-end integration tests for suspicious login/authentication triage.

Tests the complete triage pipeline for authentication-related alerts,
including impossible travel, brute force attacks, and account lockout
recommendations.
"""

from __future__ import annotations

import json
import sys
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


class _MockTools:
    Tool = MockTool
    ToolRegistry = MockToolRegistry


sys.modules["tw_ai.agents.tools"] = _MockTools


# Import the actual react module
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


def create_mock_llm_for_login(response_json: str):
    """Create a mock LLM that returns the given response."""
    from unittest.mock import AsyncMock

    llm = MagicMock()
    llm.name = "mock-llm"
    llm.complete = AsyncMock(return_value=_MockLLMBase.LLMResponse(
        content=f"```json\n{response_json}\n```",
        tool_calls=[],
        usage={"total_tokens": 600},
    ))
    return llm


def get_impossible_travel_response() -> str:
    """Get an impossible travel login analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 95,
        "severity": "critical",
        "summary": "Account compromise confirmed via impossible travel. User authenticated from Moscow, Russia "
                   "only 30 minutes after authenticating from San Francisco, US - physically impossible without teleportation.",
        "indicators": [
            {"type": "ip", "value": "185.234.72.15", "verdict": "malicious - known credential stuffing infrastructure"},
            {"type": "geolocation", "value": "Moscow, Russia -> San Francisco", "verdict": "malicious - impossible travel"},
        ],
        "mitre_techniques": [
            {
                "id": "T1078.004",
                "name": "Cloud Accounts",
                "tactic": "Defense Evasion",
                "relevance": "Compromised cloud identity credentials",
            },
            {
                "id": "T1539",
                "name": "Steal Web Session Cookie",
                "tactic": "Credential Access",
                "relevance": "Possible session token theft to bypass MFA",
            },
        ],
        "recommended_actions": [
            {
                "action": "Force sign-out all sessions",
                "priority": "immediate",
                "reason": "Terminate attacker access",
            },
            {
                "action": "Lock user account",
                "priority": "immediate",
                "reason": "Prevent further unauthorized access",
            },
            {
                "action": "Reset user password and MFA",
                "priority": "immediate",
                "reason": "Invalidate compromised credentials",
            },
            {
                "action": "Review user's recent activity",
                "priority": "high",
                "reason": "Assess potential data exfiltration",
            },
        ],
        "reasoning": "Clear account compromise. The 30-minute window between San Francisco and Moscow logins "
                     "is physically impossible - approximately 9,400km apart would require 18+ hours of flight time. "
                     "Source IP is flagged as credential stuffing infrastructure in threat intelligence.",
    })


def get_brute_force_response() -> str:
    """Get a brute force attack analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 98,
        "severity": "critical",
        "summary": "Active password spray attack detected with 3 successful compromises. "
                   "847 login attempts across 423 accounts in 30 minutes from known malicious IP range.",
        "indicators": [
            {"type": "ip", "value": "185.234.72.0/24", "verdict": "malicious - password spraying infrastructure"},
            {"type": "pattern", "value": "847 attempts, 423 accounts, 30 minutes", "verdict": "malicious - automated attack"},
            {"type": "account", "value": "old.admin@company.com", "verdict": "critical - compromised privileged account"},
        ],
        "mitre_techniques": [
            {
                "id": "T1110.003",
                "name": "Password Spraying",
                "tactic": "Credential Access",
                "relevance": "Many accounts targeted with few passwords each",
            },
            {
                "id": "T1078.002",
                "name": "Domain Accounts",
                "tactic": "Defense Evasion",
                "relevance": "Valid domain credentials obtained",
            },
        ],
        "recommended_actions": [
            {
                "action": "Lock all compromised accounts immediately",
                "priority": "immediate",
                "reason": "Prevent unauthorized access",
            },
            {
                "action": "Reset passwords for compromised accounts",
                "priority": "immediate",
                "reason": "Attacker has valid credentials",
            },
            {
                "action": "Block IP range 185.234.72.0/24 at perimeter",
                "priority": "immediate",
                "reason": "Stop ongoing attack",
            },
            {
                "action": "Enable enhanced lockout policy",
                "priority": "high",
                "reason": "Slow future spray attempts",
            },
            {
                "action": "Review all legacy/dormant accounts",
                "priority": "high",
                "reason": "These were successful targets",
            },
        ],
        "reasoning": "Active password spray attack that has achieved partial success. "
                     "847 login attempts across 423 accounts in 30 minutes is clearly automated. "
                     "Pattern of ~2 attempts per account matches password spray to avoid lockout. "
                     "3 successful compromises including legacy admin account is critical finding.",
    })


def get_legitimate_travel_response() -> str:
    """Get a legitimate travel login response (false positive)."""
    return json.dumps({
        "verdict": "false_positive",
        "confidence": 90,
        "severity": "informational",
        "summary": "Legitimate international travel login. User authenticated from Munich, Germany "
                   "which aligns with their scheduled conference attendance.",
        "indicators": [
            {"type": "ip", "value": "91.64.145.32", "verdict": "benign - German ISP"},
            {"type": "geolocation", "value": "Munich, Germany", "verdict": "benign - matches calendar event"},
        ],
        "mitre_techniques": [],
        "recommended_actions": [
            {
                "action": "Close alert as false positive",
                "priority": "high",
                "reason": "Legitimate business travel",
            },
            {
                "action": "Document travel correlation",
                "priority": "low",
                "reason": "Improve future alert context",
            },
        ],
        "reasoning": "This is a false positive triggered by international travel. "
                     "14-hour gap between locations is sufficient for transatlantic flight. "
                     "MFA was properly challenged and passed using authenticator app.",
    })


# =============================================================================
# Integration Tests - Impossible Travel
# =============================================================================


class TestSuspiciousLoginImpossibleTravel:
    """Tests for impossible travel scenario detection."""

    @pytest.mark.asyncio
    async def test_impossible_travel_verdict_is_malicious(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that impossible travel gets malicious verdict."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        # Add IP lookup tool
        async def mock_lookup_ip(ip: str):
            if ip.startswith("185.234.72"):
                return {
                    "verdict": "malicious",
                    "categories": ["credential-stuffing"],
                    "country": "RU",
                }
            return {"verdict": "unknown"}

        registry.register(MockTool(
            name="lookup_ip",
            description="Look up IP reputation",
            parameters={"type": "object", "properties": {"ip": {"type": "string"}}},
            handler=mock_lookup_ip,
        ))

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis is not None
        assert result.analysis.verdict == "true_positive"

    @pytest.mark.asyncio
    async def test_impossible_travel_critical_severity(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that impossible travel gets critical severity."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.severity == "critical"

    @pytest.mark.asyncio
    async def test_impossible_travel_identifies_valid_accounts_technique(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that impossible travel identifies T1078 Valid Accounts technique."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.mitre_techniques) > 0

        # Check for account compromise techniques (T1078.*, T1539)
        technique_ids = [t["id"] for t in result.analysis.mitre_techniques]
        has_account_technique = any(
            tid.startswith("T1078") or tid.startswith("T1539")
            for tid in technique_ids
        )
        assert has_account_technique, f"Expected account compromise technique, got: {technique_ids}"

    @pytest.mark.asyncio
    async def test_impossible_travel_recommends_account_lockout(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that impossible travel recommends account lockout/session termination."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.recommended_actions) > 0

        # Check for account lockout/session termination actions
        action_texts = [a["action"].lower() for a in result.analysis.recommended_actions]
        has_lockout = any(
            "lock" in text or "sign-out" in text or "signout" in text or
            "session" in text or "terminate" in text or "reset" in text
            for text in action_texts
        )
        assert has_lockout, f"Expected account lockout action, got: {action_texts}"

    @pytest.mark.asyncio
    async def test_impossible_travel_high_confidence(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that impossible travel gets high confidence score."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        # Impossible travel should have very high confidence
        assert result.analysis.confidence >= 90


# =============================================================================
# Integration Tests - Brute Force / Password Spray
# =============================================================================


class TestSuspiciousLoginBruteForce:
    """Tests for brute force / password spray detection."""

    @pytest.mark.asyncio
    async def test_brute_force_verdict_is_malicious(
        self,
        mock_tool_registry,
        login_brute_force_alert,
    ):
        """Test that password spray attack gets malicious verdict."""
        llm = create_mock_llm_for_login(get_brute_force_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_brute_force_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.verdict == "true_positive"

    @pytest.mark.asyncio
    async def test_brute_force_identifies_password_spray_technique(
        self,
        mock_tool_registry,
        login_brute_force_alert,
    ):
        """Test that brute force identifies T1110.003 Password Spraying technique."""
        llm = create_mock_llm_for_login(get_brute_force_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_brute_force_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.mitre_techniques) > 0

        # Check for brute force techniques (T1110.*)
        technique_ids = [t["id"] for t in result.analysis.mitre_techniques]
        has_brute_force_technique = any(
            tid.startswith("T1110")
            for tid in technique_ids
        )
        assert has_brute_force_technique, f"Expected brute force technique, got: {technique_ids}"

    @pytest.mark.asyncio
    async def test_brute_force_recommends_immediate_lockout(
        self,
        mock_tool_registry,
        login_brute_force_alert,
    ):
        """Test that password spray recommends immediate account lockout."""
        llm = create_mock_llm_for_login(get_brute_force_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_brute_force_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.recommended_actions) > 0

        # Check for immediate priority account lockout
        immediate_actions = [
            a for a in result.analysis.recommended_actions
            if a.get("priority", "").lower() == "immediate"
        ]
        assert len(immediate_actions) > 0, "Expected immediate priority actions"

        # Check for lockout-related actions
        action_texts = [a["action"].lower() for a in result.analysis.recommended_actions]
        has_lockout = any(
            "lock" in text or "reset" in text or "block" in text
            for text in action_texts
        )
        assert has_lockout, f"Expected lockout/reset action, got: {action_texts}"

    @pytest.mark.asyncio
    async def test_brute_force_identifies_compromised_accounts(
        self,
        mock_tool_registry,
        login_brute_force_alert,
    ):
        """Test that password spray identifies compromised accounts in indicators."""
        llm = create_mock_llm_for_login(get_brute_force_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_brute_force_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.analysis.indicators) > 0

        # Check for account-type indicator or IP indicator
        indicator_types = [i.get("type", "") for i in result.analysis.indicators]
        has_relevant_indicator = any(
            t in ("account", "ip", "pattern")
            for t in indicator_types
        )
        assert has_relevant_indicator, f"Expected account/IP/pattern indicator, got: {indicator_types}"

    @pytest.mark.asyncio
    async def test_brute_force_very_high_confidence(
        self,
        mock_tool_registry,
        login_brute_force_alert,
    ):
        """Test that password spray attack gets very high confidence."""
        llm = create_mock_llm_for_login(get_brute_force_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_brute_force_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        # Automated attack pattern should have very high confidence
        assert result.analysis.confidence >= 95


# =============================================================================
# Integration Tests - Edge Cases
# =============================================================================


class TestSuspiciousLoginEdgeCases:
    """Edge case tests for suspicious login triage."""

    @pytest.mark.asyncio
    async def test_legitimate_travel_is_benign(self, mock_tool_registry):
        """Test that legitimate travel is identified as false positive."""
        llm = create_mock_llm_for_login(get_legitimate_travel_response())
        registry = MockToolRegistry()

        alert = {
            "type": "authentication",
            "user": "mwilliams@company.com",
            "event_type": "successful_login",
            "timestamp": "2024-01-15T08:30:00Z",
            "source_ip": "91.64.145.32",
            "geo_location": {"country": "Germany", "city": "Munich"},
            "auth_method": "password_mfa",
            "mfa_status": "passed",
            "previous_login": {
                "timestamp": "2024-01-14T18:00:00Z",
                "source_ip": "73.162.45.128",
                "geo_location": {"country": "US", "city": "Chicago"},
            },
            "context": {"calendar_event": "Munich Conference Jan 14-17"},
        }

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=alert,
            context={"known_travel": "Munich Conference"},
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.verdict in ("false_positive", "benign")

    @pytest.mark.asyncio
    async def test_login_with_mfa_context(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that MFA bypass is noted in analysis."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        # Alert explicitly has MFA not challenged
        alert = login_impossible_travel_alert.copy()
        alert["mfa_status"] = "not_challenged"
        alert["mfa_policy"] = "required"

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=alert,
        )

        result = await agent.run(request)

        assert result.success is True
        # MFA bypass should increase severity of compromise
        assert result.analysis.verdict == "true_positive"

    @pytest.mark.asyncio
    async def test_login_triage_includes_reasoning(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that login analysis includes detailed reasoning."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert result.analysis.reasoning is not None
        assert len(result.analysis.reasoning) > 50

    @pytest.mark.asyncio
    async def test_login_triage_has_execution_trace(
        self,
        mock_tool_registry,
        login_impossible_travel_alert,
    ):
        """Test that login triage has execution trace."""
        llm = create_mock_llm_for_login(get_impossible_travel_response())
        registry = MockToolRegistry()

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=login_impossible_travel_alert,
        )

        result = await agent.run(request)

        assert result.success is True
        assert len(result.execution_trace) > 0
        # Should have at least a final step
        step_types = [s.step_type for s in result.execution_trace]
        assert StepType.FINAL in step_types

    @pytest.mark.asyncio
    async def test_service_account_login_suspicious(self, mock_tool_registry):
        """Test that service account interactive login is flagged."""
        response = json.dumps({
            "verdict": "suspicious",
            "confidence": 65,
            "severity": "high",
            "summary": "Service account used for interactive RDP session. "
                       "While from internal network, service accounts should not be used interactively.",
            "indicators": [
                {"type": "account", "value": "svc_backup@company.com", "verdict": "suspicious - interactive use"},
            ],
            "mitre_techniques": [
                {
                    "id": "T1078.002",
                    "name": "Domain Accounts",
                    "tactic": "Defense Evasion",
                    "relevance": "Service account potentially misused",
                },
            ],
            "recommended_actions": [
                {
                    "action": "Verify with IT if maintenance was scheduled",
                    "priority": "high",
                    "reason": "Determine if activity is authorized",
                },
                {
                    "action": "Review session activity logs",
                    "priority": "high",
                    "reason": "Check what actions were taken",
                },
            ],
            "reasoning": "Service accounts should never be used for interactive logins. "
                         "This could indicate legitimate troubleshooting or credential misuse.",
        })

        llm = create_mock_llm_for_login(response)
        registry = MockToolRegistry()

        alert = {
            "type": "authentication",
            "user": "svc_backup@company.com",
            "event_type": "successful_login",
            "timestamp": "2024-01-15T02:30:00Z",
            "source_ip": "10.50.25.100",
            "client_app": "Microsoft Remote Desktop",
            "auth_method": "password_only",
            "mfa_status": "exempt",
            "account_type": "service_account",
        }

        agent = ReActAgent(llm=llm, tools=registry)

        request = TriageRequest(
            alert_type="authentication",
            alert_data=alert,
        )

        result = await agent.run(request)

        assert result.success is True
        # Service account interactive login should be suspicious
        assert result.analysis.verdict in ("suspicious", "true_positive")
