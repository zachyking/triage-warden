"""Unit tests for tool argument validation (Security Task 5.4).

Tests Pydantic schema validation for all tool arguments to ensure:
- Unknown/extra arguments are rejected
- Strict type coercion (no implicit conversions)
- Argument size limits are enforced
- Invalid formats are rejected
"""

from __future__ import annotations

import importlib.util
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# =============================================================================
# Setup mocks and direct module loading to avoid tw_ai package initialization
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


# Pre-register mock modules BEFORE any imports
sys.modules["tw_ai.llm.base"] = _MockLLMBase()
sys.modules["tw_ai.llm"] = MagicMock()

# Mock the email analysis modules
_mock_email = MagicMock()
_mock_email.EmailAnalysis = MagicMock
_mock_email.ExtractedURL = MagicMock
_mock_email.extract_urls = MagicMock(return_value=[])
_mock_email.extract_urls_from_html = MagicMock(return_value=[])
_mock_email.parse_email_alert = MagicMock()
sys.modules["tw_ai.analysis.email"] = _mock_email

_mock_phishing = MagicMock()
_mock_phishing.PhishingIndicators = MagicMock
_mock_phishing.analyze_phishing_indicators = MagicMock()
sys.modules["tw_ai.analysis.phishing"] = _mock_phishing


def _load_tools_module():
    """Load tools.py directly without going through tw_ai package."""
    tools_path = Path(__file__).parent.parent / "tw_ai" / "agents" / "tools.py"
    spec = importlib.util.spec_from_file_location("tw_ai.agents.tools", tools_path)
    module = importlib.util.module_from_spec(spec)
    # Register the module BEFORE executing to avoid issues with dataclass
    sys.modules["tw_ai.agents.tools"] = module
    spec.loader.exec_module(module)
    return module


# Load the tools module directly
_tools = _load_tools_module()

# Import what we need from the loaded module
ToolArgumentValidationError = _tools.ToolArgumentValidationError
validate_tool_arguments = _tools.validate_tool_arguments
LookupHashArgs = _tools.LookupHashArgs
LookupIpArgs = _tools.LookupIpArgs
LookupDomainArgs = _tools.LookupDomainArgs
SearchSiemArgs = _tools.SearchSiemArgs
GetRecentAlertsArgs = _tools.GetRecentAlertsArgs
GetHostInfoArgs = _tools.GetHostInfoArgs
GetDetectionsArgs = _tools.GetDetectionsArgs
GetProcessesArgs = _tools.GetProcessesArgs
GetNetworkConnectionsArgs = _tools.GetNetworkConnectionsArgs
MapToMitreArgs = _tools.MapToMitreArgs
CheckPolicyArgs = _tools.CheckPolicyArgs
SubmitApprovalArgs = _tools.SubmitApprovalArgs
GetApprovalStatusArgs = _tools.GetApprovalStatusArgs
AnalyzeEmailArgs = _tools.AnalyzeEmailArgs
CheckPhishingIndicatorsArgs = _tools.CheckPhishingIndicatorsArgs
ExtractEmailUrlsArgs = _tools.ExtractEmailUrlsArgs
CheckSenderReputationArgs = _tools.CheckSenderReputationArgs
QuarantineEmailArgs = _tools.QuarantineEmailArgs
BlockSenderArgs = _tools.BlockSenderArgs
NotifyUserArgs = _tools.NotifyUserArgs
CreateSecurityTicketArgs = _tools.CreateSecurityTicketArgs
MAX_HASH_LENGTH = _tools.MAX_HASH_LENGTH
MAX_IP_LENGTH = _tools.MAX_IP_LENGTH
MAX_DOMAIN_LENGTH = _tools.MAX_DOMAIN_LENGTH
MAX_QUERY_LENGTH = _tools.MAX_QUERY_LENGTH
MAX_DESCRIPTION_LENGTH = _tools.MAX_DESCRIPTION_LENGTH
MAX_EMAIL_LENGTH = _tools.MAX_EMAIL_LENGTH
MAX_TEXT_LENGTH = _tools.MAX_TEXT_LENGTH
MAX_ARRAY_SIZE = _tools.MAX_ARRAY_SIZE
TOOL_ARGUMENT_SCHEMAS = _tools.TOOL_ARGUMENT_SCHEMAS


# =============================================================================
# Test LookupHashArgs
# =============================================================================


class TestLookupHashArgs:
    """Tests for hash lookup argument validation."""

    def test_valid_md5_hash(self):
        """Test valid MD5 hash is accepted."""
        args = LookupHashArgs(hash="d41d8cd98f00b204e9800998ecf8427e")
        assert args.hash == "d41d8cd98f00b204e9800998ecf8427e"

    def test_valid_sha1_hash(self):
        """Test valid SHA1 hash is accepted."""
        args = LookupHashArgs(hash="da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert args.hash == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_valid_sha256_hash(self):
        """Test valid SHA256 hash is accepted."""
        args = LookupHashArgs(hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert args.hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_uppercase_hash_normalized(self):
        """Test uppercase hash is normalized to lowercase."""
        args = LookupHashArgs(hash="D41D8CD98F00B204E9800998ECF8427E")
        assert args.hash == "d41d8cd98f00b204e9800998ecf8427e"

    def test_hash_with_whitespace_stripped(self):
        """Test hash with whitespace is stripped."""
        args = LookupHashArgs(hash="  d41d8cd98f00b204e9800998ecf8427e  ")
        assert args.hash == "d41d8cd98f00b204e9800998ecf8427e"

    def test_invalid_hash_length(self):
        """Test invalid hash length is rejected."""
        with pytest.raises(Exception) as exc_info:
            LookupHashArgs(hash="abc123")
        # Error can be from min_length check ("32 characters") or from custom validator
        assert "Invalid hash length" in str(exc_info.value) or "32 characters" in str(exc_info.value)

    def test_invalid_hash_characters(self):
        """Test non-hexadecimal characters are rejected."""
        with pytest.raises(Exception) as exc_info:
            LookupHashArgs(hash="z41d8cd98f00b204e9800998ecf8427e")
        assert "hexadecimal" in str(exc_info.value).lower() or "invalid" in str(exc_info.value).lower()

    def test_empty_hash_rejected(self):
        """Test empty hash is rejected."""
        with pytest.raises(Exception):
            LookupHashArgs(hash="")

    def test_extra_arguments_rejected(self):
        """Test extra arguments are rejected (extra='forbid')."""
        with pytest.raises(Exception) as exc_info:
            LookupHashArgs(hash="d41d8cd98f00b204e9800998ecf8427e", extra_field="malicious")
        assert "extra" in str(exc_info.value).lower()


# =============================================================================
# Test LookupIpArgs
# =============================================================================


class TestLookupIpArgs:
    """Tests for IP lookup argument validation."""

    def test_valid_ipv4(self):
        """Test valid IPv4 address is accepted."""
        args = LookupIpArgs(ip="192.168.1.100")
        assert args.ip == "192.168.1.100"

    def test_valid_ipv6(self):
        """Test valid IPv6 address is accepted."""
        args = LookupIpArgs(ip="2001:db8::1")
        assert args.ip == "2001:db8::1"

    def test_valid_ipv6_full(self):
        """Test valid full IPv6 address is accepted."""
        args = LookupIpArgs(ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert args.ip == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_invalid_ip_format(self):
        """Test invalid IP format is rejected."""
        with pytest.raises(Exception) as exc_info:
            LookupIpArgs(ip="not-an-ip")
        assert "Invalid IP address" in str(exc_info.value)

    def test_invalid_ipv4_octet(self):
        """Test invalid IPv4 octet is rejected."""
        with pytest.raises(Exception) as exc_info:
            LookupIpArgs(ip="192.168.1.300")
        assert "Invalid IP address" in str(exc_info.value)

    def test_empty_ip_rejected(self):
        """Test empty IP is rejected."""
        with pytest.raises(Exception):
            LookupIpArgs(ip="")

    def test_ip_with_whitespace_stripped(self):
        """Test IP with whitespace is stripped."""
        args = LookupIpArgs(ip="  192.168.1.100  ")
        assert args.ip == "192.168.1.100"


# =============================================================================
# Test LookupDomainArgs
# =============================================================================


class TestLookupDomainArgs:
    """Tests for domain lookup argument validation."""

    def test_valid_domain(self):
        """Test valid domain is accepted."""
        args = LookupDomainArgs(domain="example.com")
        assert args.domain == "example.com"

    def test_valid_subdomain(self):
        """Test valid subdomain is accepted."""
        args = LookupDomainArgs(domain="sub.example.com")
        assert args.domain == "sub.example.com"

    def test_domain_normalized_lowercase(self):
        """Test domain is normalized to lowercase."""
        args = LookupDomainArgs(domain="EXAMPLE.COM")
        assert args.domain == "example.com"

    def test_invalid_domain_format(self):
        """Test invalid domain format is rejected."""
        with pytest.raises(Exception) as exc_info:
            LookupDomainArgs(domain="not a domain")
        assert "Invalid domain" in str(exc_info.value)

    def test_domain_too_long(self):
        """Test domain exceeding max length is rejected."""
        long_domain = "a" * 250 + ".com"
        with pytest.raises(Exception):
            LookupDomainArgs(domain=long_domain)

    def test_empty_domain_rejected(self):
        """Test empty domain is rejected."""
        with pytest.raises(Exception):
            LookupDomainArgs(domain="")


# =============================================================================
# Test SearchSiemArgs
# =============================================================================


class TestSearchSiemArgs:
    """Tests for SIEM search argument validation."""

    def test_valid_search(self):
        """Test valid search arguments are accepted."""
        args = SearchSiemArgs(query="login_failure", hours=24, limit=100)
        assert args.query == "login_failure"
        assert args.hours == 24
        assert args.limit == 100

    def test_defaults_applied(self):
        """Test default values are applied."""
        args = SearchSiemArgs(query="malware")
        assert args.hours == 24
        assert args.limit == 100

    def test_query_too_long(self):
        """Test query exceeding max length is rejected."""
        long_query = "a" * (MAX_QUERY_LENGTH + 1)
        with pytest.raises(Exception):
            SearchSiemArgs(query=long_query)

    def test_hours_out_of_range(self):
        """Test hours outside valid range is rejected."""
        with pytest.raises(Exception):
            SearchSiemArgs(query="test", hours=0)
        with pytest.raises(Exception):
            SearchSiemArgs(query="test", hours=10000)

    def test_limit_out_of_range(self):
        """Test limit outside valid range is rejected."""
        with pytest.raises(Exception):
            SearchSiemArgs(query="test", limit=0)
        with pytest.raises(Exception):
            SearchSiemArgs(query="test", limit=50000)

    def test_empty_query_rejected(self):
        """Test empty query is rejected."""
        with pytest.raises(Exception):
            SearchSiemArgs(query="")


# =============================================================================
# Test GetHostInfoArgs
# =============================================================================


class TestGetHostInfoArgs:
    """Tests for host info argument validation."""

    def test_valid_hostname(self):
        """Test valid hostname is accepted."""
        args = GetHostInfoArgs(hostname="workstation-001")
        assert args.hostname == "workstation-001"

    def test_valid_fqdn(self):
        """Test valid FQDN is accepted."""
        args = GetHostInfoArgs(hostname="server01.example.com")
        assert args.hostname == "server01.example.com"

    def test_hostname_with_whitespace_stripped(self):
        """Test hostname with whitespace is stripped."""
        args = GetHostInfoArgs(hostname="  workstation-001  ")
        assert args.hostname == "workstation-001"

    def test_invalid_hostname_format(self):
        """Test invalid hostname format is rejected."""
        with pytest.raises(Exception) as exc_info:
            GetHostInfoArgs(hostname="invalid hostname!")
        assert "Invalid hostname" in str(exc_info.value)

    def test_empty_hostname_rejected(self):
        """Test empty hostname is rejected."""
        with pytest.raises(Exception):
            GetHostInfoArgs(hostname="")


# =============================================================================
# Test CheckPolicyArgs
# =============================================================================


class TestCheckPolicyArgs:
    """Tests for policy check argument validation."""

    def test_valid_policy_check(self):
        """Test valid policy check arguments are accepted."""
        args = CheckPolicyArgs(action_type="isolate_host", target="workstation-001", confidence=0.95)
        assert args.action_type == "isolate_host"
        assert args.target == "workstation-001"
        assert args.confidence == 0.95

    def test_default_confidence(self):
        """Test default confidence value is applied."""
        args = CheckPolicyArgs(action_type="create_ticket", target="INC-001")
        assert args.confidence == 0.9

    def test_confidence_out_of_range(self):
        """Test confidence outside valid range is rejected."""
        with pytest.raises(Exception):
            CheckPolicyArgs(action_type="test", target="test", confidence=-0.1)
        with pytest.raises(Exception):
            CheckPolicyArgs(action_type="test", target="test", confidence=1.5)

    def test_empty_action_type_rejected(self):
        """Test empty action_type is rejected."""
        with pytest.raises(Exception):
            CheckPolicyArgs(action_type="", target="test")


# =============================================================================
# Test SubmitApprovalArgs
# =============================================================================


class TestSubmitApprovalArgs:
    """Tests for approval submission argument validation."""

    def test_valid_approval_submission(self):
        """Test valid approval submission arguments are accepted."""
        args = SubmitApprovalArgs(action_type="isolate_host", target="server-001", level="senior")
        assert args.action_type == "isolate_host"
        assert args.target == "server-001"
        assert args.level == "senior"

    def test_default_level(self):
        """Test default approval level is applied."""
        args = SubmitApprovalArgs(action_type="test", target="test")
        assert args.level == "analyst"

    def test_invalid_level_rejected(self):
        """Test invalid approval level is rejected."""
        with pytest.raises(Exception):
            SubmitApprovalArgs(action_type="test", target="test", level="invalid")


# =============================================================================
# Test BlockSenderArgs
# =============================================================================


class TestBlockSenderArgs:
    """Tests for block sender argument validation."""

    def test_valid_email_block(self):
        """Test valid email block arguments are accepted."""
        args = BlockSenderArgs(sender="attacker@evil.com", block_type="email", reason="Phishing")
        assert args.sender == "attacker@evil.com"
        assert args.block_type == "email"
        assert args.reason == "Phishing"

    def test_valid_domain_block(self):
        """Test valid domain block arguments are accepted."""
        args = BlockSenderArgs(sender="evil.com", block_type="domain", reason="Malware distribution")
        assert args.sender == "evil.com"
        assert args.block_type == "domain"

    def test_invalid_block_type_rejected(self):
        """Test invalid block type is rejected."""
        with pytest.raises(Exception):
            BlockSenderArgs(sender="test@test.com", block_type="invalid", reason="test")


# =============================================================================
# Test NotifyUserArgs
# =============================================================================


class TestNotifyUserArgs:
    """Tests for user notification argument validation."""

    def test_valid_notification(self):
        """Test valid notification arguments are accepted."""
        args = NotifyUserArgs(
            recipient="user@example.com",
            notification_type="phishing_warning",
            subject="Security Alert",
            body="A suspicious email was detected.",
        )
        assert args.recipient == "user@example.com"
        assert args.notification_type == "phishing_warning"
        assert args.subject == "Security Alert"

    def test_invalid_notification_type_rejected(self):
        """Test invalid notification type is rejected."""
        with pytest.raises(Exception):
            NotifyUserArgs(
                recipient="user@example.com",
                notification_type="invalid_type",
                subject="Test",
                body="Test",
            )

    def test_invalid_email_format_rejected(self):
        """Test invalid email format is rejected."""
        with pytest.raises(Exception):
            NotifyUserArgs(
                recipient="not-an-email",
                notification_type="security_alert",
                subject="Test",
                body="Test",
            )


# =============================================================================
# Test CreateSecurityTicketArgs
# =============================================================================


class TestCreateSecurityTicketArgs:
    """Tests for security ticket creation argument validation."""

    def test_valid_ticket(self):
        """Test valid ticket arguments are accepted."""
        args = CreateSecurityTicketArgs(
            title="Phishing Campaign Detected",
            description="Multiple phishing emails targeting finance department.",
            severity="high",
            indicators=["evil.com", "attacker@evil.com", "192.168.1.100"],
        )
        assert args.title == "Phishing Campaign Detected"
        assert args.severity == "high"
        assert len(args.indicators) == 3

    def test_invalid_severity_rejected(self):
        """Test invalid severity is rejected."""
        with pytest.raises(Exception):
            CreateSecurityTicketArgs(
                title="Test",
                description="Test",
                severity="extreme",
                indicators=[],
            )

    def test_too_many_indicators_rejected(self):
        """Test too many indicators is rejected."""
        with pytest.raises(Exception):
            CreateSecurityTicketArgs(
                title="Test",
                description="Test",
                severity="high",
                indicators=["indicator"] * (MAX_ARRAY_SIZE + 1),
            )


# =============================================================================
# Test CheckSenderReputationArgs
# =============================================================================


class TestCheckSenderReputationArgs:
    """Tests for sender reputation check argument validation."""

    def test_valid_email(self):
        """Test valid email address is accepted."""
        args = CheckSenderReputationArgs(sender_email="user@example.com")
        assert args.sender_email == "user@example.com"

    def test_invalid_email_format(self):
        """Test invalid email format is rejected."""
        with pytest.raises(Exception) as exc_info:
            CheckSenderReputationArgs(sender_email="not-valid")
        assert "Invalid email" in str(exc_info.value)

    def test_email_with_whitespace_stripped(self):
        """Test email with whitespace is stripped."""
        args = CheckSenderReputationArgs(sender_email="  user@example.com  ")
        assert args.sender_email == "user@example.com"


# =============================================================================
# Test AnalyzeEmailArgs
# =============================================================================


class TestAnalyzeEmailArgs:
    """Tests for email analysis argument validation."""

    def test_valid_email_data(self):
        """Test valid email data is accepted."""
        args = AnalyzeEmailArgs(
            email_data={
                "message_id": "test-123",
                "subject": "Test Subject",
                "sender": "sender@example.com",
            }
        )
        assert args.email_data["message_id"] == "test-123"

    def test_email_data_too_large(self):
        """Test email data exceeding size limit is rejected."""
        large_data = {"body": "x" * 2_000_000}  # 2MB
        with pytest.raises(Exception) as exc_info:
            AnalyzeEmailArgs(email_data=large_data)
        assert "exceeds maximum size" in str(exc_info.value)


# =============================================================================
# Test ExtractEmailUrlsArgs
# =============================================================================


class TestExtractEmailUrlsArgs:
    """Tests for URL extraction argument validation."""

    def test_valid_text(self):
        """Test valid text is accepted."""
        args = ExtractEmailUrlsArgs(text="Check this link: https://example.com")
        assert "example.com" in args.text

    def test_defaults_applied(self):
        """Test default include_html is True."""
        args = ExtractEmailUrlsArgs(text="test")
        assert args.include_html is True

    def test_text_too_long(self):
        """Test text exceeding max length is rejected."""
        long_text = "x" * (MAX_TEXT_LENGTH + 1)
        with pytest.raises(Exception):
            ExtractEmailUrlsArgs(text=long_text)


# =============================================================================
# Test validate_tool_arguments function
# =============================================================================


class TestValidateToolArguments:
    """Tests for the validate_tool_arguments function."""

    def test_valid_arguments_pass(self):
        """Test valid arguments pass validation."""
        result = validate_tool_arguments("lookup_hash", {"hash": "d41d8cd98f00b204e9800998ecf8427e"})
        assert result["hash"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_invalid_arguments_raise_error(self):
        """Test invalid arguments raise ToolArgumentValidationError."""
        with pytest.raises(ToolArgumentValidationError) as exc_info:
            validate_tool_arguments("lookup_hash", {"hash": "invalid"})
        assert "validation failed" in exc_info.value.message
        assert len(exc_info.value.errors) > 0

    def test_extra_arguments_rejected(self):
        """Test extra arguments are rejected."""
        with pytest.raises(ToolArgumentValidationError) as exc_info:
            validate_tool_arguments(
                "lookup_hash",
                {"hash": "d41d8cd98f00b204e9800998ecf8427e", "extra": "malicious"},
            )
        assert "extra" in exc_info.value.message.lower()

    def test_unknown_tool_allowed(self):
        """Test unknown tools pass without validation (backward compatibility)."""
        result = validate_tool_arguments("unknown_tool", {"any": "args"})
        assert result == {"any": "args"}

    def test_wrong_type_rejected(self):
        """Test wrong types are rejected (strict mode)."""
        with pytest.raises(ToolArgumentValidationError):
            validate_tool_arguments("search_siem", {"query": "test", "hours": "24"})  # string instead of int

    def test_all_tools_have_schemas(self):
        """Test all expected tools have schemas defined."""
        expected_tools = [
            "lookup_hash",
            "lookup_ip",
            "lookup_domain",
            "search_siem",
            "get_recent_alerts",
            "get_host_info",
            "get_detections",
            "get_processes",
            "get_network_connections",
            "map_to_mitre",
            "check_policy",
            "submit_approval",
            "get_approval_status",
            "analyze_email",
            "check_phishing_indicators",
            "extract_email_urls",
            "check_sender_reputation",
            "quarantine_email",
            "block_sender",
            "notify_user",
            "create_security_ticket",
        ]
        for tool_name in expected_tools:
            assert tool_name in TOOL_ARGUMENT_SCHEMAS, f"Missing schema for tool: {tool_name}"


# =============================================================================
# Test Size Limit Constants
# =============================================================================


class TestSizeLimits:
    """Tests for size limit constants."""

    def test_hash_length_limit(self):
        """Test hash length limit is reasonable."""
        assert MAX_HASH_LENGTH >= 128  # SHA-512

    def test_ip_length_limit(self):
        """Test IP length limit covers IPv6."""
        assert MAX_IP_LENGTH >= 45

    def test_domain_length_limit(self):
        """Test domain length limit follows RFC."""
        assert MAX_DOMAIN_LENGTH == 253

    def test_email_length_limit(self):
        """Test email length limit follows RFC."""
        assert MAX_EMAIL_LENGTH == 254

    def test_query_length_reasonable(self):
        """Test query length limit is reasonable."""
        assert MAX_QUERY_LENGTH >= 1000
        assert MAX_QUERY_LENGTH <= 100000


# =============================================================================
# Test Strict Mode
# =============================================================================


class TestStrictMode:
    """Tests for strict type coercion mode."""

    def test_string_not_coerced_to_int(self):
        """Test string is not implicitly coerced to int."""
        with pytest.raises(ToolArgumentValidationError):
            validate_tool_arguments("search_siem", {"query": "test", "hours": "24"})

    def test_int_not_coerced_to_string(self):
        """Test int is not implicitly coerced to string."""
        with pytest.raises(ToolArgumentValidationError):
            validate_tool_arguments("lookup_hash", {"hash": 12345})

    def test_float_confidence_accepted(self):
        """Test float confidence value is accepted."""
        result = validate_tool_arguments(
            "check_policy",
            {"action_type": "test", "target": "test", "confidence": 0.95},
        )
        assert result["confidence"] == 0.95


# =============================================================================
# Test Security Edge Cases
# =============================================================================


class TestSecurityEdgeCases:
    """Tests for security-related edge cases."""

    def test_command_injection_in_query(self):
        """Test command injection attempts in query are handled safely."""
        # The query is just validated for length, not content - that's handled by the tool
        result = validate_tool_arguments("search_siem", {"query": "; rm -rf /"})
        assert result["query"] == "; rm -rf /"

    def test_null_bytes_in_input(self):
        """Test null bytes in input."""
        # Null bytes might cause issues - they should be handled gracefully
        try:
            validate_tool_arguments("search_siem", {"query": "test\x00malicious"})
        except ToolArgumentValidationError:
            pass  # It's OK if this fails validation

    def test_unicode_in_domain(self):
        """Test unicode in domain (IDN attacks)."""
        # Punycode/IDN domains with actual Cyrillic characters should be rejected
        # Note: "gooole.com" with Cyrillic 'o' (U+043E) looks like ASCII but isn't
        with pytest.raises(ToolArgumentValidationError):
            # This domain contains Cyrillic 'о' (U+043E) instead of Latin 'o'
            validate_tool_arguments("lookup_domain", {"domain": "g\u043eogle.com"})

    def test_oversized_array(self):
        """Test oversized arrays are rejected."""
        with pytest.raises(ToolArgumentValidationError):
            validate_tool_arguments(
                "create_security_ticket",
                {
                    "title": "Test",
                    "description": "Test",
                    "severity": "high",
                    "indicators": ["x"] * 200,  # Over MAX_ARRAY_SIZE
                },
            )
