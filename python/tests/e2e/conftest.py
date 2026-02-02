"""Pytest fixtures for E2E phishing pipeline tests.

Provides:
- mock_llm_provider: Returns scripted responses for deterministic tests
- mock_tool_registry: Uses mock connectors for threat intel lookups
- phishing_workflow: Configured PhishingTriageWorkflow
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest

# Import sample email fixtures
from .fixtures.sample_emails import (
    OBVIOUS_PHISHING,
    SOPHISTICATED_PHISHING,
    LEGITIMATE_EMAIL,
    FALSE_POSITIVE,
)


# =============================================================================
# Mock Module Setup
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
        def system(cls, content: str) -> "_MockLLMBase.Message":
            return cls(role="system", content=content)

        @classmethod
        def user(cls, content: str) -> "_MockLLMBase.Message":
            return cls(role="user", content=content)

        @classmethod
        def assistant(cls, content: str) -> "_MockLLMBase.Message":
            return cls(role="assistant", content=content)

        @classmethod
        def tool_result(cls, content: str, tool_call_id: str) -> "_MockLLMBase.Message":
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


# Install mock modules before importing from tw_ai
sys.modules["tw_ai.llm.base"] = _MockLLMBase
sys.modules["tw_ai.llm"] = MagicMock()


# =============================================================================
# Mock Models
# =============================================================================


class MockIndicator:
    """Mock Indicator for testing."""
    def __init__(self, type: str, value: str, verdict: str, context: str = None):
        self.type = type
        self.value = value
        self.verdict = verdict
        self.context = context


class MockMITRETechnique:
    """Mock MITRETechnique for testing."""
    def __init__(self, id: str, name: str, tactic: str, relevance: str):
        self.id = id
        self.name = name
        self.tactic = tactic
        self.relevance = relevance


class MockRecommendedAction:
    """Mock RecommendedAction for testing."""
    def __init__(self, action: str, priority: str, reason: str, requires_approval: bool = False):
        self.action = action
        self.priority = priority
        self.reason = reason
        self.requires_approval = requires_approval


class MockTriageAnalysis:
    """Mock TriageAnalysis for testing."""
    def __init__(self, **kwargs):
        self.verdict = kwargs.get("verdict", "suspicious")
        self.confidence = kwargs.get("confidence", 75)
        self.severity = kwargs.get("severity", "medium")
        self.summary = kwargs.get("summary", "Test summary")
        self.indicators = kwargs.get("indicators", [])
        self.mitre_techniques = kwargs.get("mitre_techniques", [])

        # Convert recommended_actions to objects
        raw_actions = kwargs.get("recommended_actions", [])
        self.recommended_actions = []
        for action in raw_actions:
            if isinstance(action, dict):
                self.recommended_actions.append(MockRecommendedAction(
                    action=action.get("action", ""),
                    priority=action.get("priority", "medium"),
                    reason=action.get("reason", ""),
                    requires_approval=action.get("requires_approval", False),
                ))
            else:
                self.recommended_actions.append(action)

        self.reasoning = kwargs.get("reasoning", "Test reasoning")

    def model_dump(self):
        return {
            "verdict": self.verdict,
            "confidence": self.confidence,
            "severity": self.severity,
            "summary": self.summary,
            "indicators": self.indicators,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": [
                {"action": a.action, "priority": a.priority, "reason": a.reason, "requires_approval": a.requires_approval}
                for a in self.recommended_actions
            ],
            "reasoning": self.reasoning,
        }


class _MockModels:
    TriageAnalysis = MockTriageAnalysis
    Indicator = MockIndicator
    MITRETechnique = MockMITRETechnique
    RecommendedAction = MockRecommendedAction


sys.modules["tw_ai.agents.models"] = _MockModels


# =============================================================================
# Mock Output Parser
# =============================================================================


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


# =============================================================================
# Mock Tools
# =============================================================================


@dataclass
class MockTool:
    """Mock tool implementation."""
    name: str
    description: str
    parameters: dict
    handler: Callable
    requires_confirmation: bool = False

    def to_definition(self):
        return MockToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )


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


class MockToolRegistry:
    """Mock tool registry with test implementations."""

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


# Mock functions for policy bridge compatibility
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


# =============================================================================
# Load Real Modules
# =============================================================================

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
# LLM Response Templates
# =============================================================================


def create_obvious_phishing_response() -> str:
    """Create response for obvious phishing detection."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 95,
        "severity": "critical",
        "summary": "Obvious phishing attempt detected. Typosquatted domain 'paypa1.com' impersonates PayPal. "
                   "Email contains urgency language, credential request, and failed authentication.",
        "indicators": [
            {"type": "domain", "value": "paypa1.com", "verdict": "malicious - typosquatting paypal.com"},
            {"type": "domain", "value": "paypa1-secure.com", "verdict": "malicious - phishing infrastructure"},
            {"type": "url", "value": "http://paypa1-secure.com/verify/login", "verdict": "malicious - credential harvesting"},
            {"type": "email", "value": "security@paypa1.com", "verdict": "malicious - spoofed sender"},
        ],
        "mitre_techniques": [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "relevance": "Phishing email with malicious link",
            },
            {
                "id": "T1598.003",
                "name": "Spearphishing for Information",
                "tactic": "Reconnaissance",
                "relevance": "Attempting to harvest credentials",
            },
        ],
        "recommended_actions": [
            {
                "action": "Quarantine email immediately",
                "priority": "immediate",
                "reason": "Clear phishing attempt",
                "requires_approval": False,
            },
            {
                "action": "Block sender domain paypa1.com",
                "priority": "immediate",
                "reason": "Typosquatting domain",
                "requires_approval": False,
            },
            {
                "action": "Block URL domain paypa1-secure.com",
                "priority": "immediate",
                "reason": "Phishing infrastructure",
                "requires_approval": False,
            },
            {
                "action": "Notify recipient about phishing attempt",
                "priority": "high",
                "reason": "Security awareness",
                "requires_approval": False,
            },
        ],
        "reasoning": "Multiple clear phishing indicators: (1) Typosquatted domain 'paypa1.com' using '1' instead of 'l' "
                     "to impersonate PayPal, (2) Urgency language ('URGENT', 'immediately', '24 hours'), "
                     "(3) Credential harvesting request ('verify your account'), (4) All authentication failed "
                     "(SPF/DKIM/DMARC). High confidence malicious.",
    })


def create_sophisticated_phishing_response() -> str:
    """Create response for sophisticated phishing that needs review."""
    return json.dumps({
        "verdict": "suspicious",
        "confidence": 72,
        "severity": "high",
        "summary": "Likely phishing attempt using lookalike domain 'micros0ft-security.com'. "
                   "Professional appearance but domain uses '0' instead of 'o'. Recommend manual review.",
        "indicators": [
            {"type": "domain", "value": "micros0ft-security.com", "verdict": "suspicious - possible homoglyph attack"},
            {"type": "url", "value": "https://micros0ft-security.com/account/review", "verdict": "suspicious - lookalike domain"},
        ],
        "mitre_techniques": [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "relevance": "Email contains link to suspicious domain",
            },
        ],
        "recommended_actions": [
            {
                "action": "Escalate to analyst for manual review",
                "priority": "high",
                "reason": "Sophisticated attack requires human verification",
                "requires_approval": False,
            },
            {
                "action": "Hold email in quarantine pending review",
                "priority": "high",
                "reason": "Prevent potential credential theft",
                "requires_approval": False,
            },
            {
                "action": "Investigate domain registration for micros0ft-security.com",
                "priority": "medium",
                "reason": "Determine if domain is malicious",
                "requires_approval": False,
            },
        ],
        "reasoning": "The email appears professionally crafted with legitimate Microsoft branding, but the domain "
                     "'micros0ft-security.com' contains a homoglyph (0 instead of o). While this could be a "
                     "sophisticated phishing attempt, the lack of obvious urgency language and partial authentication "
                     "pass (SPF) makes this borderline. Recommend escalation for manual review.",
    })


def create_legitimate_email_response() -> str:
    """Create response for legitimate email."""
    return json.dumps({
        "verdict": "false_positive",
        "confidence": 92,
        "severity": "informational",
        "summary": "Legitimate internal business email from Finance team. "
                   "All authentication passes, sender is internal domain, content is normal business communication.",
        "indicators": [
            {"type": "domain", "value": "company.com", "verdict": "benign - internal domain"},
            {"type": "url", "value": "https://company.sharepoint.com/sites/finance/reports/Q4-2024", "verdict": "benign - internal SharePoint"},
        ],
        "mitre_techniques": [],
        "recommended_actions": [
            {
                "action": "Release email to recipient",
                "priority": "high",
                "reason": "Legitimate business communication",
                "requires_approval": False,
            },
            {
                "action": "Add sender to trusted list",
                "priority": "low",
                "reason": "Reduce future false positives",
                "requires_approval": False,
            },
        ],
        "reasoning": "This is a legitimate internal email. Evidence: (1) Sender domain is company.com (internal), "
                     "(2) All authentication passes (SPF/DKIM/DMARC), (3) URL points to internal SharePoint, "
                     "(4) Content matches normal business communication pattern (quarterly report). No phishing indicators present.",
    })


def create_false_positive_response() -> str:
    """Create response for false positive (legitimate security notification)."""
    return json.dumps({
        "verdict": "false_positive",
        "confidence": 88,
        "severity": "informational",
        "summary": "Legitimate security notification from Okta (known security vendor). "
                   "Despite 'suspicious' language in subject, this is a real security alert about a blocked login.",
        "indicators": [
            {"type": "domain", "value": "okta.com", "verdict": "benign - known security vendor"},
            {"type": "url", "value": "https://company.okta.com/password/reset", "verdict": "benign - legitimate password reset"},
            {"type": "url", "value": "https://support.okta.com", "verdict": "benign - vendor support site"},
        ],
        "mitre_techniques": [],
        "recommended_actions": [
            {
                "action": "Deliver email to recipient",
                "priority": "high",
                "reason": "Legitimate security notification",
                "requires_approval": False,
            },
            {
                "action": "Whitelist Okta notification emails",
                "priority": "medium",
                "reason": "Prevent future false positives on security alerts",
                "requires_approval": False,
            },
        ],
        "reasoning": "This is a legitimate security notification from Okta, a known identity provider. Evidence: "
                     "(1) Sender domain okta.com is a recognized security vendor, (2) All authentication passes, "
                     "(3) URLs point to legitimate Okta infrastructure (company.okta.com, support.okta.com), "
                     "(4) Content describes a blocked suspicious login which is expected Okta behavior. "
                     "The 'suspicious' language in subject refers to the detected threat, not phishing characteristics.",
    })


# =============================================================================
# Mock LLM Provider Class
# =============================================================================


class MockLLMProvider:
    """Mock LLM provider that returns scripted responses based on email content."""

    def __init__(self, response_map: dict[str, str] | None = None):
        self._response_map = response_map or {}
        self._call_count = 0
        self._call_history: list[dict] = []

        # Default response patterns based on email characteristics
        self._default_patterns = {
            "paypa1": create_obvious_phishing_response,
            "paypa1-secure": create_obvious_phishing_response,
            "micros0ft": create_sophisticated_phishing_response,
            "micros0ft-security": create_sophisticated_phishing_response,
            "company.sharepoint.com": create_legitimate_email_response,
            "finance@company.com": create_legitimate_email_response,
            "Q4 2024 Financial Report": create_legitimate_email_response,
            "okta.com": create_false_positive_response,
            "noreply@okta.com": create_false_positive_response,
            "Suspicious login detected": create_false_positive_response,
        }

    @property
    def name(self) -> str:
        return "mock-llm"

    @property
    def call_count(self) -> int:
        return self._call_count

    def _find_matching_response(self, messages: list) -> str:
        """Find matching response based on message content."""
        combined = ""
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                combined += msg.content.lower() + " "
            elif isinstance(msg, dict) and "content" in msg:
                combined += str(msg["content"]).lower() + " "

        # Check custom response map
        for pattern, response in self._response_map.items():
            if pattern.lower() in combined:
                return response

        # Check default patterns
        for pattern, response_fn in self._default_patterns.items():
            if pattern.lower() in combined:
                return response_fn()

        # Default fallback
        return json.dumps({
            "verdict": "inconclusive",
            "confidence": 50,
            "severity": "medium",
            "summary": "Unable to determine verdict with available information.",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {"action": "Escalate for manual review", "priority": "medium", "reason": "Insufficient evidence"}
            ],
            "reasoning": "Could not make a determination based on available evidence.",
        })

    async def complete(
        self,
        messages: list,
        tools: list | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> _MockLLMBase.LLMResponse:
        """Generate mock completion response."""
        self._call_count += 1
        self._call_history.append({
            "messages": messages,
            "tools": tools,
        })

        response_content = self._find_matching_response(messages)
        return _MockLLMBase.LLMResponse(
            content=f"```json\n{response_content}\n```",
            tool_calls=[],
            usage={"total_tokens": 800, "prompt_tokens": 600, "completion_tokens": 200},
        )

    async def health_check(self) -> bool:
        return True


# =============================================================================
# Pytest Fixtures
# =============================================================================


@pytest.fixture
def mock_llm_provider() -> MockLLMProvider:
    """Create a mock LLM provider with scripted responses."""
    return MockLLMProvider()


@pytest.fixture
def mock_tool_registry() -> MockToolRegistry:
    """Create a mock tool registry with test implementations."""
    registry = MockToolRegistry()

    async def mock_lookup_domain(domain: str) -> dict:
        """Mock domain lookup."""
        domain_lower = domain.lower()

        # Typosquatting domains
        if "paypa1" in domain_lower or "micros0ft" in domain_lower:
            return {
                "success": True,
                "data": {
                    "indicator": domain,
                    "indicator_type": "domain",
                    "verdict": "malicious",
                    "score": 90,
                    "categories": ["phishing", "typosquatting"],
                },
            }

        # Known good domains
        if "company.com" in domain_lower or "okta.com" in domain_lower:
            return {
                "success": True,
                "data": {
                    "indicator": domain,
                    "indicator_type": "domain",
                    "verdict": "benign",
                    "score": 0,
                    "categories": ["internal" if "company" in domain_lower else "security-vendor"],
                },
            }

        return {
            "success": True,
            "data": {
                "indicator": domain,
                "indicator_type": "domain",
                "verdict": "unknown",
                "score": 0,
                "categories": [],
            },
        }

    async def mock_lookup_url(url: str) -> dict:
        """Mock URL lookup."""
        url_lower = url.lower()

        if "paypa1" in url_lower or "micros0ft" in url_lower:
            return {
                "success": True,
                "data": {
                    "indicator": url,
                    "indicator_type": "url",
                    "verdict": "malicious",
                    "score": 90,
                    "categories": ["phishing"],
                },
            }

        if "company.com" in url_lower or "okta.com" in url_lower:
            return {
                "success": True,
                "data": {
                    "indicator": url,
                    "indicator_type": "url",
                    "verdict": "benign",
                    "score": 0,
                    "categories": [],
                },
            }

        return {
            "success": True,
            "data": {
                "indicator": url,
                "indicator_type": "url",
                "verdict": "unknown",
                "score": 0,
                "categories": [],
            },
        }

    registry.register(MockTool(
        name="lookup_domain",
        description="Look up a domain in threat intelligence databases",
        parameters={
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
        handler=mock_lookup_domain,
    ))

    registry.register(MockTool(
        name="lookup_url",
        description="Look up a URL in threat intelligence databases",
        parameters={
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
        handler=mock_lookup_url,
    ))

    return registry


@pytest.fixture
def phishing_workflow(mock_llm_provider, mock_tool_registry):
    """Create a configured PhishingTriageWorkflow for testing."""
    from tw_ai.workflows.phishing import PhishingTriageWorkflow

    agent = ReActAgent(llm=mock_llm_provider, tools=mock_tool_registry)

    def mock_policy_checker(action: dict) -> dict:
        """Mock policy checker that allows most actions."""
        action_type = action.get("action_type", "")
        confidence = action.get("confidence", 0)

        # Block actions with very low confidence
        if confidence < 0.5:
            return {"decision": "denied", "reason": "Low confidence"}

        # Require approval for blocking actions
        if "block" in action_type.lower():
            return {"decision": "requires_approval", "reason": "Blocking actions require approval"}

        return {"decision": "allowed"}

    workflow = PhishingTriageWorkflow(
        agent=agent,
        tools=mock_tool_registry,
        policy_checker=mock_policy_checker,
    )

    return workflow


@pytest.fixture
def obvious_phishing() -> dict:
    """Return obvious phishing email fixture."""
    return OBVIOUS_PHISHING.copy()


@pytest.fixture
def sophisticated_phishing() -> dict:
    """Return sophisticated phishing email fixture."""
    return SOPHISTICATED_PHISHING.copy()


@pytest.fixture
def legitimate_email() -> dict:
    """Return legitimate email fixture."""
    return LEGITIMATE_EMAIL.copy()


@pytest.fixture
def false_positive() -> dict:
    """Return false positive email fixture."""
    return FALSE_POSITIVE.copy()


# =============================================================================
# Exported Classes
# =============================================================================

__all__ = [
    "MockLLMProvider",
    "MockToolRegistry",
    "MockTool",
    "MockTriageAnalysis",
    "ReActAgent",
    "AgentResult",
    "TriageRequest",
    "StepType",
]
