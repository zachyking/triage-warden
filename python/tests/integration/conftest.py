"""Pytest fixtures for Triage Warden integration tests.

Provides mock LLM providers with scripted responses and mock tool registries
for deterministic end-to-end testing of the triage pipeline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest

# =============================================================================
# Sample Alerts
# =============================================================================

PHISHING_ALERT = {
    "type": "email_security",
    "subject": "Urgent: Your account has been compromised",
    "sender": "support@paypa1.com",
    "urls": ["http://paypa1-verify.com/login"],
    "recipient": "user@company.com",
    "received_time": "2024-01-15T09:30:00Z",
    "spf_result": "fail",
    "dkim_result": "none",
    "dmarc_result": "fail",
}

LEGITIMATE_EMAIL_ALERT = {
    "type": "email_security",
    "subject": "Monthly Report - December 2024",
    "sender": "reports@company.com",
    "urls": ["https://sharepoint.company.com/reports/december"],
    "recipient": "user@company.com",
    "received_time": "2024-01-15T10:00:00Z",
    "spf_result": "pass",
    "dkim_result": "pass",
    "dmarc_result": "pass",
}

MALWARE_ALERT = {
    "type": "edr_detection",
    "hostname": "workstation-001",
    "process": "powershell.exe",
    "command_line": "-enc SGVsbG8gV29ybGQ=",
    "file_hash": "44d88612fea8a8f36de82e1278abb02f",
    "parent_process": "cmd.exe",
    "user": "DOMAIN\\jsmith",
    "detection_time": "2024-01-15T14:30:00Z",
}

SUSPICIOUS_PROCESS_ALERT = {
    "type": "edr_detection",
    "hostname": "workstation-002",
    "process": "notepad.exe",
    "command_line": "notepad.exe",
    "file_hash": "unknown_hash_12345",
    "parent_process": "powershell.exe",
    "target_process": "lsass.exe",
    "access_mask": "0x1fffff",
    "user": "DOMAIN\\svc_account",
    "detection_time": "2024-01-15T15:00:00Z",
}

LOGIN_ALERT_IMPOSSIBLE_TRAVEL = {
    "type": "authentication",
    "user": "jsmith@company.com",
    "event_type": "successful_login",
    "timestamp": "2024-01-15T14:30:00Z",
    "source_ip": "185.234.72.15",
    "geo_location": {"country": "Russia", "city": "Moscow"},
    "auth_method": "password_only",
    "mfa_status": "not_challenged",
    "previous_login": {
        "timestamp": "2024-01-15T14:00:00Z",
        "source_ip": "104.18.32.12",
        "geo_location": {"country": "US", "city": "San Francisco"},
    },
}

LOGIN_ALERT_BRUTE_FORCE = {
    "type": "authentication",
    "event_type": "aggregated_failures",
    "timeframe": "2024-01-15T10:00:00Z to 2024-01-15T10:30:00Z",
    "source_ips": ["185.234.72.10", "185.234.72.11", "185.234.72.12"],
    "total_attempts": 847,
    "unique_accounts": 423,
    "successful_logins": 3,
    "failure_reasons": {"invalid_password": 812, "account_locked": 32},
    "successful_accounts": [
        "legacy.service@company.com",
        "temp.contractor@company.com",
        "old.admin@company.com",
    ],
}


# =============================================================================
# Mock LLM Response Templates
# =============================================================================


def _create_phishing_malicious_response() -> str:
    """Create a malicious phishing analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 92,
        "severity": "high",
        "summary": "Credential harvesting phishing attempt using typosquatted domain. "
                   "Sender domain 'paypa1.com' impersonates PayPal with '1' instead of 'l'. "
                   "Email authentication fails (SPF/DKIM/DMARC) and URL points to phishing site.",
        "indicators": [
            {"type": "domain", "value": "paypa1.com", "verdict": "malicious - typosquatting PayPal"},
            {"type": "url", "value": "http://paypa1-verify.com/login", "verdict": "malicious - credential harvesting"},
            {"type": "email", "value": "support@paypa1.com", "verdict": "malicious - spoofed sender"},
        ],
        "mitre_techniques": [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
                "relevance": "Email contains link to credential harvesting page",
            },
            {
                "id": "T1598.003",
                "name": "Spearphishing for Information",
                "tactic": "Reconnaissance",
                "relevance": "Attempting to steal user credentials",
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
            {
                "action": "Add paypa1-verify.com to URL blocklist",
                "priority": "high",
                "reason": "Block access to phishing site",
            },
            {
                "action": "Alert user about phishing attempt",
                "priority": "medium",
                "reason": "Security awareness",
            },
        ],
        "reasoning": "This is a clear phishing attempt with multiple red flags: "
                     "(1) Typosquatted domain 'paypa1.com' using '1' instead of 'l' to impersonate PayPal, "
                     "(2) All email authentication checks failed (SPF, DKIM, DMARC), "
                     "(3) URL points to a domain designed to harvest credentials, "
                     "(4) Subject line uses urgency tactics ('Your account has been compromised'). "
                     "Threat intelligence confirms the domain is associated with phishing campaigns.",
    })


def _create_phishing_benign_response() -> str:
    """Create a benign email analysis response."""
    return json.dumps({
        "verdict": "false_positive",
        "confidence": 88,
        "severity": "informational",
        "summary": "Legitimate internal email from company reports system. "
                   "All email authentication passes and URL points to internal SharePoint.",
        "indicators": [
            {"type": "domain", "value": "company.com", "verdict": "benign - internal domain"},
            {"type": "url", "value": "https://sharepoint.company.com/reports/december", "verdict": "benign - internal SharePoint"},
        ],
        "mitre_techniques": [],
        "recommended_actions": [
            {
                "action": "Release email from quarantine",
                "priority": "high",
                "reason": "Legitimate business communication",
            },
            {
                "action": "Tune detection rule to reduce false positives",
                "priority": "medium",
                "reason": "Improve alert quality for internal senders",
            },
        ],
        "reasoning": "This is a legitimate internal email. Evidence: "
                     "(1) Sender domain is company.com - our internal domain, "
                     "(2) All email authentication passes (SPF, DKIM, DMARC), "
                     "(3) URL points to internal SharePoint site, "
                     "(4) Subject matches normal business communication patterns. "
                     "This was flagged due to external link detection rules that should be tuned for internal resources.",
    })


def _create_malware_malicious_response() -> str:
    """Create a malicious malware analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 95,
        "severity": "critical",
        "summary": "Confirmed malware execution detected. EICAR test file hash identified, "
                   "encoded PowerShell command execution indicates malicious payload delivery.",
        "indicators": [
            {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f", "verdict": "malicious - EICAR test file"},
            {"type": "process", "value": "powershell.exe -enc", "verdict": "malicious - encoded command execution"},
        ],
        "mitre_techniques": [
            {
                "id": "T1059.001",
                "name": "PowerShell",
                "tactic": "Execution",
                "relevance": "Encoded PowerShell used for payload execution",
            },
            {
                "id": "T1027",
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion",
                "relevance": "Base64 encoded command to evade detection",
            },
        ],
        "recommended_actions": [
            {
                "action": "Isolate host immediately",
                "priority": "immediate",
                "reason": "Contain active malware infection",
            },
            {
                "action": "Block file hash at endpoint",
                "priority": "immediate",
                "reason": "Prevent execution on other hosts",
            },
            {
                "action": "Acquire memory dump for forensics",
                "priority": "high",
                "reason": "Preserve evidence of malicious activity",
            },
            {
                "action": "Reset user credentials",
                "priority": "high",
                "reason": "Assume credential compromise",
            },
        ],
        "reasoning": "Critical malware detection with high confidence. Evidence: "
                     "(1) File hash matches known malware signature (EICAR test file), "
                     "(2) Encoded PowerShell execution is a classic evasion technique, "
                     "(3) Process spawned from cmd.exe suggests execution chain, "
                     "(4) Threat intelligence confirms hash as malicious. "
                     "Immediate containment required to prevent lateral movement.",
    })


def _create_malware_suspicious_process_response() -> str:
    """Create a suspicious process behavior analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 98,
        "severity": "critical",
        "summary": "Credential dumping attack detected. Notepad.exe accessing LSASS with full access rights "
                   "is a strong indicator of Mimikatz or similar credential harvesting tool using process hollowing.",
        "indicators": [
            {"type": "process", "value": "notepad.exe -> lsass.exe", "verdict": "malicious - abnormal access pattern"},
            {"type": "hash", "value": "unknown_hash_12345", "verdict": "suspicious - not in baseline"},
        ],
        "mitre_techniques": [
            {
                "id": "T1003.001",
                "name": "LSASS Memory",
                "tactic": "Credential Access",
                "relevance": "Direct credential extraction from LSASS",
            },
            {
                "id": "T1055.012",
                "name": "Process Hollowing",
                "tactic": "Defense Evasion",
                "relevance": "Notepad likely hollowed to host malicious code",
            },
        ],
        "recommended_actions": [
            {
                "action": "Isolate host immediately",
                "priority": "immediate",
                "reason": "Active credential theft in progress",
            },
            {
                "action": "Disable service account svc_account",
                "priority": "immediate",
                "reason": "Prevent lateral movement with compromised credentials",
            },
            {
                "action": "Force password reset for all accounts on host",
                "priority": "immediate",
                "reason": "LSASS contains cached credentials",
            },
        ],
        "reasoning": "Unambiguous credential dumping attack. Critical indicators: "
                     "(1) Notepad.exe should NEVER access LSASS - this is process hollowing/injection, "
                     "(2) Access mask 0x1fffff is PROCESS_ALL_ACCESS - far more than any legitimate need, "
                     "(3) Service account executing this suggests attacker has already compromised that credential. "
                     "This is likely Mimikatz running inside a hollowed notepad process.",
    })


def _create_login_impossible_travel_response() -> str:
    """Create an impossible travel login analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 95,
        "severity": "critical",
        "summary": "Account compromise confirmed via impossible travel. User authenticated from Moscow, Russia "
                   "only 30 minutes after authenticating from San Francisco, US - physically impossible.",
        "indicators": [
            {"type": "ip", "value": "185.234.72.15", "verdict": "malicious - known credential stuffing infrastructure"},
            {"type": "geolocation", "value": "Moscow, Russia", "verdict": "suspicious - impossible travel from San Francisco"},
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
                "action": "Reset user password and MFA",
                "priority": "immediate",
                "reason": "Invalidate compromised credentials",
            },
            {
                "action": "Lock account pending investigation",
                "priority": "immediate",
                "reason": "Prevent further unauthorized access",
            },
            {
                "action": "Review user's recent activity for data access",
                "priority": "high",
                "reason": "Assess potential data exfiltration",
            },
        ],
        "reasoning": "Clear account compromise. The 30-minute window between San Francisco and Moscow logins "
                     "is physically impossible - approximately 9,400km apart would require 18+ hours of flight time. "
                     "MFA was not challenged despite being configured, suggesting session token theft or MFA bypass.",
    })


def _create_login_brute_force_response() -> str:
    """Create a brute force attack analysis response."""
    return json.dumps({
        "verdict": "true_positive",
        "confidence": 98,
        "severity": "critical",
        "summary": "Active password spray attack detected with 3 successful compromises. "
                   "847 login attempts across 423 accounts in 30 minutes from known malicious IP range.",
        "indicators": [
            {"type": "ip", "value": "185.234.72.0/24", "verdict": "malicious - known password spraying infrastructure"},
            {"type": "pattern", "value": "847 attempts, 423 accounts", "verdict": "malicious - automated credential attack"},
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
                "action": "Reset passwords for all 3 compromised accounts",
                "priority": "immediate",
                "reason": "Attacker has valid credentials",
            },
            {
                "action": "Lock compromised accounts",
                "priority": "immediate",
                "reason": "Prevent unauthorized access",
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
        ],
        "reasoning": "Active password spray attack that has achieved partial success. "
                     "847 login attempts across 423 accounts in 30 minutes is clearly automated. "
                     "Pattern of ~2 attempts per account matches password spray to avoid lockout. "
                     "3 successful compromises including legacy admin account is critical.",
    })


# =============================================================================
# Mock LLM Provider
# =============================================================================


@dataclass
class MockToolCall:
    """Mock tool call for testing."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class MockLLMResponse:
    """Mock LLM response for testing."""
    content: str | None
    tool_calls: list[MockToolCall] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: dict[str, int] = field(default_factory=dict)
    model: str = "mock-model"
    raw_response: Any = None

    def __post_init__(self):
        if not self.usage:
            self.usage = {"total_tokens": 500}

    @property
    def has_tool_calls(self) -> bool:
        return len(self.tool_calls) > 0


class MockLLMProvider:
    """
    Mock LLM provider that returns scripted responses based on input patterns.

    Responses are determined by analyzing the alert content in the messages
    and returning appropriate pre-defined responses.
    """

    def __init__(self, response_map: dict[str, str] | None = None):
        """
        Initialize mock LLM provider.

        Args:
            response_map: Optional mapping of patterns to response JSON strings.
        """
        self._response_map = response_map or {}
        self._call_count = 0
        self._call_history: list[dict[str, Any]] = []

        # Default response patterns
        self._default_patterns = {
            "paypa1": _create_phishing_malicious_response,
            "paypal": _create_phishing_malicious_response,
            "typosquat": _create_phishing_malicious_response,
            "sharepoint.company.com": _create_phishing_benign_response,
            "reports@company.com": _create_phishing_benign_response,
            "44d88612fea8a8f36de82e1278abb02f": _create_malware_malicious_response,
            "eicar": _create_malware_malicious_response,
            "lsass": _create_malware_suspicious_process_response,
            "process_hollowing": _create_malware_suspicious_process_response,
            "impossible_travel": _create_login_impossible_travel_response,
            "moscow": _create_login_impossible_travel_response,
            "san francisco": _create_login_impossible_travel_response,
            "password_spray": _create_login_brute_force_response,
            "847 attempts": _create_login_brute_force_response,
            "aggregated_failures": _create_login_brute_force_response,
        }

    @property
    def name(self) -> str:
        return "mock-llm"

    @property
    def call_count(self) -> int:
        return self._call_count

    @property
    def call_history(self) -> list[dict[str, Any]]:
        return self._call_history

    def _find_matching_response(self, messages: list) -> str:
        """Find a matching response based on message content."""
        # Combine all message content for pattern matching
        combined_content = ""
        for msg in messages:
            if hasattr(msg, "content") and msg.content:
                combined_content += msg.content.lower() + " "
            elif isinstance(msg, dict) and "content" in msg:
                combined_content += str(msg["content"]).lower() + " "

        # Check custom response map first
        for pattern, response in self._response_map.items():
            if pattern.lower() in combined_content:
                return response

        # Check default patterns
        for pattern, response_fn in self._default_patterns.items():
            if pattern.lower() in combined_content:
                return response_fn()

        # Default response
        return json.dumps({
            "verdict": "inconclusive",
            "confidence": 50,
            "severity": "medium",
            "summary": "Unable to determine verdict with available information.",
            "indicators": [],
            "mitre_techniques": [],
            "recommended_actions": [
                {
                    "action": "Escalate to senior analyst",
                    "priority": "medium",
                    "reason": "Requires manual investigation",
                }
            ],
            "reasoning": "Insufficient evidence to make a determination.",
        })

    async def complete(
        self,
        messages: list,
        tools: list | None = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ) -> MockLLMResponse:
        """
        Generate a mock completion response.

        Args:
            messages: Conversation messages.
            tools: Optional tool definitions.
            temperature: Sampling temperature (ignored in mock).
            max_tokens: Max tokens (ignored in mock).

        Returns:
            MockLLMResponse with scripted content.
        """
        self._call_count += 1
        self._call_history.append({
            "messages": messages,
            "tools": tools,
            "temperature": temperature,
            "max_tokens": max_tokens,
        })

        response_content = self._find_matching_response(messages)

        return MockLLMResponse(
            content=f"```json\n{response_content}\n```",
            tool_calls=[],
            usage={"total_tokens": 800, "prompt_tokens": 600, "completion_tokens": 200},
        )

    async def health_check(self) -> bool:
        return True


# =============================================================================
# Mock Tool Registry
# =============================================================================


@dataclass
class MockToolDefinition:
    """Mock tool definition."""
    name: str
    description: str
    parameters: dict[str, Any]


@dataclass
class MockTool:
    """Mock tool implementation."""
    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable
    requires_confirmation: bool = False

    def to_definition(self) -> MockToolDefinition:
        return MockToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )


class MockToolRegistry:
    """Mock tool registry with test implementations."""

    def __init__(self):
        self._tools: dict[str, MockTool] = {}
        self._setup_default_tools()

    def _setup_default_tools(self):
        """Set up default mock tools."""

        async def mock_lookup_hash(hash: str) -> dict[str, Any]:
            """Mock hash lookup returning deterministic results."""
            # EICAR test file hash
            if hash == "44d88612fea8a8f36de82e1278abb02f":
                return {
                    "success": True,
                    "data": {
                        "indicator": hash,
                        "indicator_type": "md5",
                        "verdict": "malicious",
                        "score": 95,
                        "malware_families": ["EICAR-Test-File"],
                        "categories": ["malware", "test-file"],
                        "malicious_count": 68,
                        "total_engines": 72,
                    },
                }
            return {
                "success": True,
                "data": {
                    "indicator": hash,
                    "indicator_type": "hash",
                    "verdict": "unknown",
                    "score": 0,
                    "malware_families": [],
                    "categories": [],
                },
            }

        async def mock_lookup_ip(ip: str) -> dict[str, Any]:
            """Mock IP lookup returning deterministic results."""
            # Known malicious IP
            if ip.startswith("185.234.72"):
                return {
                    "success": True,
                    "data": {
                        "indicator": ip,
                        "indicator_type": "ip",
                        "verdict": "malicious",
                        "score": 90,
                        "categories": ["credential-stuffing", "password-spray"],
                        "country": "RU",
                    },
                }
            # Internal IPs are clean
            if ip.startswith(("10.", "192.168.", "172.16.")):
                return {
                    "success": True,
                    "data": {
                        "indicator": ip,
                        "indicator_type": "ip",
                        "verdict": "benign",
                        "score": 0,
                        "categories": ["private"],
                        "country": "INTERNAL",
                    },
                }
            return {
                "success": True,
                "data": {
                    "indicator": ip,
                    "indicator_type": "ip",
                    "verdict": "unknown",
                    "score": 0,
                    "categories": [],
                    "country": "XX",
                },
            }

        async def mock_lookup_domain(domain: str) -> dict[str, Any]:
            """Mock domain lookup returning deterministic results."""
            # Typosquatted domains
            if "paypa1" in domain or domain.endswith(".xyz"):
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
            # Company domains are clean
            if "company.com" in domain:
                return {
                    "success": True,
                    "data": {
                        "indicator": domain,
                        "indicator_type": "domain",
                        "verdict": "benign",
                        "score": 0,
                        "categories": ["internal"],
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

        async def mock_get_host_info(hostname: str) -> dict[str, Any]:
            """Mock EDR host info."""
            return {
                "hostname": hostname,
                "host_id": f"host-{hostname}",
                "ip_addresses": ["192.168.1.100"],
                "os": "Windows 10 Enterprise",
                "status": "online",
                "isolated": False,
                "source": "mock",
            }

        async def mock_get_detections(hostname: str, hours: int = 24) -> dict[str, Any]:
            """Mock EDR detections."""
            return {
                "hostname": hostname,
                "timerange_hours": hours,
                "total_count": 0,
                "detections": [],
                "source": "mock",
            }

        async def mock_search_siem(query: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
            """Mock SIEM search."""
            return {
                "events": [],
                "events_raw": [],
                "total_count": 0,
                "search_stats": {
                    "query": query,
                    "timerange_hours": hours,
                    "events_returned": 0,
                },
                "source": "mock",
            }

        # Register tools
        self.register(MockTool(
            name="lookup_hash",
            description="Look up a file hash in threat intelligence databases",
            parameters={
                "type": "object",
                "properties": {"hash": {"type": "string"}},
                "required": ["hash"],
            },
            handler=mock_lookup_hash,
        ))

        self.register(MockTool(
            name="lookup_ip",
            description="Look up an IP address in threat intelligence databases",
            parameters={
                "type": "object",
                "properties": {"ip": {"type": "string"}},
                "required": ["ip"],
            },
            handler=mock_lookup_ip,
        ))

        self.register(MockTool(
            name="lookup_domain",
            description="Look up a domain in threat intelligence databases",
            parameters={
                "type": "object",
                "properties": {"domain": {"type": "string"}},
                "required": ["domain"],
            },
            handler=mock_lookup_domain,
        ))

        self.register(MockTool(
            name="get_host_info",
            description="Get host information from EDR",
            parameters={
                "type": "object",
                "properties": {"hostname": {"type": "string"}},
                "required": ["hostname"],
            },
            handler=mock_get_host_info,
        ))

        self.register(MockTool(
            name="get_detections",
            description="Get EDR detections for a host",
            parameters={
                "type": "object",
                "properties": {
                    "hostname": {"type": "string"},
                    "hours": {"type": "integer", "default": 24},
                },
                "required": ["hostname"],
            },
            handler=mock_get_detections,
        ))

        self.register(MockTool(
            name="search_siem",
            description="Search SIEM logs",
            parameters={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "hours": {"type": "integer", "default": 24},
                    "limit": {"type": "integer", "default": 100},
                },
                "required": ["query"],
            },
            handler=mock_search_siem,
        ))

    def register(self, tool: MockTool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> MockTool | None:
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        return list(self._tools.keys())

    def get_tool_definitions(self) -> list[MockToolDefinition]:
        return [tool.to_definition() for tool in self._tools.values()]

    async def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")
        return await tool.handler(**arguments)


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
    return MockToolRegistry()


@pytest.fixture
def phishing_alert() -> dict[str, Any]:
    """Return sample phishing alert."""
    return PHISHING_ALERT.copy()


@pytest.fixture
def legitimate_email_alert() -> dict[str, Any]:
    """Return sample legitimate email alert."""
    return LEGITIMATE_EMAIL_ALERT.copy()


@pytest.fixture
def malware_alert() -> dict[str, Any]:
    """Return sample malware alert."""
    return MALWARE_ALERT.copy()


@pytest.fixture
def suspicious_process_alert() -> dict[str, Any]:
    """Return sample suspicious process alert."""
    return SUSPICIOUS_PROCESS_ALERT.copy()


@pytest.fixture
def login_impossible_travel_alert() -> dict[str, Any]:
    """Return sample impossible travel login alert."""
    return LOGIN_ALERT_IMPOSSIBLE_TRAVEL.copy()


@pytest.fixture
def login_brute_force_alert() -> dict[str, Any]:
    """Return sample brute force login alert."""
    return LOGIN_ALERT_BRUTE_FORCE.copy()
