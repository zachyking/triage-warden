"""Tool definitions and registry for the ReAct agent."""

from __future__ import annotations

import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

# Import email analysis modules
from tw_ai.analysis.email import (
    EmailAnalysis,
    ExtractedURL,
    extract_urls,
    extract_urls_from_html,
    parse_email_alert,
)
from tw_ai.analysis.phishing import (
    PhishingIndicators,
    analyze_phishing_indicators,
)
from tw_ai.llm.base import ToolDefinition

logger = structlog.get_logger()

MOCK_FALLBACK_OVERRIDE_ENV = "TW_ALLOW_MOCK_FALLBACKS"


def _is_production_environment() -> bool:
    """Check if running in a production environment."""
    for var in ("TW_ENV", "NODE_ENV", "ENVIRONMENT"):
        value = os.environ.get(var, "").strip().lower()
        if value in {"production", "prod"}:
            return True
    return False


def _mock_fallbacks_allowed() -> bool:
    """Whether mock fallbacks are allowed for unavailable bridges."""
    if not _is_production_environment():
        return True
    override = os.environ.get(MOCK_FALLBACK_OVERRIDE_ENV, "").strip().lower()
    return override in {"1", "true", "yes", "on"}


# =============================================================================
# Bridge Imports with Graceful Fallback
# =============================================================================

# Try to import bridges from the Rust PyO3 bridge
_THREAT_INTEL_BRIDGE_AVAILABLE = False
_EDR_BRIDGE_AVAILABLE = False
_SIEM_BRIDGE_AVAILABLE = False
_ThreatIntelBridgeClass: type[Any] | None = None
_EDRBridgeClass: type[Any] | None = None
_SIEMBridgeClass: type[Any] | None = None

try:
    from tw_bridge import ThreatIntelBridge as _ThreatIntelBridgeImport

    _ThreatIntelBridgeClass = _ThreatIntelBridgeImport
    _THREAT_INTEL_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.ThreatIntelBridge available")
except ImportError:
    logger.warning("tw_bridge.ThreatIntelBridge not available, using mock fallback")

try:
    from tw_bridge import EDRBridge as _EDRBridgeImport

    _EDRBridgeClass = _EDRBridgeImport
    _EDR_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.EDRBridge available")
except ImportError:
    logger.warning("tw_bridge.EDRBridge not available, using mock fallback")

try:
    from tw_bridge import SIEMBridge as _SIEMBridgeImport

    _SIEMBridgeClass = _SIEMBridgeImport
    _SIEM_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.SIEMBridge available")
except ImportError:
    logger.warning("tw_bridge.SIEMBridge not available, using mock fallback")

# Try to import PolicyBridge from the Rust PyO3 bridge
_POLICY_BRIDGE_AVAILABLE = False
_PolicyBridgeClass: type[Any] | None = None

try:
    from tw_bridge import PolicyBridge as _PolicyBridgeImport

    _PolicyBridgeClass = _PolicyBridgeImport
    _POLICY_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.PolicyBridge available")
except ImportError:
    logger.warning("tw_bridge.PolicyBridge not available, using mock fallback")

# Try to import TicketingBridge from the Rust PyO3 bridge
_TICKETING_BRIDGE_AVAILABLE = False
_TicketingBridgeClass: type[Any] | None = None

try:
    from tw_bridge import TicketingBridge as _TicketingBridgeImport

    _TicketingBridgeClass = _TicketingBridgeImport
    _TICKETING_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.TicketingBridge available")
except ImportError:
    logger.warning("tw_bridge.TicketingBridge not available, using mock fallback")

# Try to import EmailGatewayBridge from the Rust PyO3 bridge
_EMAIL_GATEWAY_BRIDGE_AVAILABLE = False
_EmailGatewayBridgeClass: type[Any] | None = None

try:
    from tw_bridge import EmailGatewayBridge as _EmailGatewayBridgeImport

    _EmailGatewayBridgeClass = _EmailGatewayBridgeImport
    _EMAIL_GATEWAY_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.EmailGatewayBridge available")
except ImportError:
    logger.warning("tw_bridge.EmailGatewayBridge not available, using mock fallback")


# =============================================================================
# ToolResult Dataclass
# =============================================================================


@dataclass
class ToolResult:
    """Result of a tool execution."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    execution_time_ms: int = 0

    @classmethod
    def ok(cls, data: dict[str, Any], execution_time_ms: int = 0) -> ToolResult:
        """Create a successful result."""
        return cls(success=True, data=data, execution_time_ms=execution_time_ms)

    @classmethod
    def fail(cls, error: str, execution_time_ms: int = 0) -> ToolResult:
        """Create a failed result."""
        return cls(success=False, error=error, execution_time_ms=execution_time_ms)


# =============================================================================
# Pydantic Argument Schemas for Tool Validation (Security Task 5.4)
# =============================================================================

# Maximum size limits for string arguments to prevent DoS attacks
MAX_HASH_LENGTH = 128  # SHA-512 is 128 chars
MAX_IP_LENGTH = 45  # IPv6 max length
MAX_DOMAIN_LENGTH = 253  # RFC 1035
MAX_QUERY_LENGTH = 4096  # Reasonable query limit
MAX_DESCRIPTION_LENGTH = 10000  # Limit for long text fields
MAX_EMAIL_LENGTH = 254  # RFC 5321
MAX_TEXT_LENGTH = 100000  # Maximum text content
MAX_ARRAY_SIZE = 100  # Maximum array items


class ToolArgumentValidationError(Exception):
    """Exception raised when tool arguments fail validation."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.message = message
        self.errors = errors or []


class StrictBaseModel(BaseModel):
    """Base model with strict validation settings for all tool arguments.

    Configuration:
    - extra='forbid': Reject unknown/extra arguments
    - strict=True: Strict type coercion (no implicit conversions)
    - validate_default=True: Validate default values
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        validate_default=True,
    )


# Threat Intelligence Tool Schemas
class LookupHashArgs(StrictBaseModel):
    """Arguments for lookup_hash tool."""

    hash: str = Field(
        ...,
        min_length=32,
        max_length=MAX_HASH_LENGTH,
        description="File hash (MD5, SHA1, or SHA256)",
    )

    @field_validator("hash")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        """Validate hash is hexadecimal and correct length."""
        v = v.strip().lower()
        if not v:
            raise ValueError("Hash cannot be empty")
        # Valid hash lengths: MD5=32, SHA1=40, SHA256=64, SHA512=128
        valid_lengths = {32, 40, 64, 128}
        if len(v) not in valid_lengths:
            raise ValueError(
                f"Invalid hash length {len(v)}. "
                "Expected 32 (MD5), 40 (SHA1), 64 (SHA256), or 128 (SHA512)"
            )
        if not all(c in "0123456789abcdef" for c in v):
            raise ValueError("Hash must contain only hexadecimal characters (0-9, a-f)")
        return v


class LookupIpArgs(StrictBaseModel):
    """Arguments for lookup_ip tool."""

    ip: str = Field(
        ...,
        min_length=1,
        max_length=MAX_IP_LENGTH,
        description="IP address (IPv4 or IPv6)",
    )

    @field_validator("ip")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        """Validate IP address format."""
        import ipaddress

        v = v.strip()
        if not v:
            raise ValueError("IP address cannot be empty")
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address format: {v}")
        return v


class LookupDomainArgs(StrictBaseModel):
    """Arguments for lookup_domain tool."""

    domain: str = Field(
        ...,
        min_length=1,
        max_length=MAX_DOMAIN_LENGTH,
        description="Domain to look up",
    )

    @field_validator("domain")
    @classmethod
    def validate_domain_format(cls, v: str) -> str:
        """Validate domain format."""
        import re

        v = v.strip().lower()
        if not v:
            raise ValueError("Domain cannot be empty")
        # Basic domain validation pattern
        domain_pattern = re.compile(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )
        if not domain_pattern.match(v):
            raise ValueError(f"Invalid domain format: {v}")
        return v


# SIEM Tool Schemas
class SearchSiemArgs(StrictBaseModel):
    """Arguments for search_siem tool."""

    query: str = Field(
        ...,
        min_length=1,
        max_length=MAX_QUERY_LENGTH,
        description="Search query string",
    )
    hours: int = Field(
        default=24,
        ge=1,
        le=8760,  # Max 1 year
        description="Number of hours to search back",
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=10000,
        description="Maximum number of events to return",
    )


class GetRecentAlertsArgs(StrictBaseModel):
    """Arguments for get_recent_alerts tool."""

    limit: int = Field(
        default=10,
        ge=1,
        le=1000,
        description="Maximum number of alerts to return",
    )


# EDR Tool Schemas
class GetHostInfoArgs(StrictBaseModel):
    """Arguments for get_host_info tool."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,  # Max hostname length
        description="Hostname to look up",
    )

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Hostname cannot be empty")
        # Allow hostnames with letters, numbers, hyphens, dots
        hostname_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
        if not hostname_pattern.match(v):
            raise ValueError(f"Invalid hostname format: {v}")
        return v


class GetDetectionsArgs(StrictBaseModel):
    """Arguments for get_detections tool."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Hostname to get detections for",
    )
    hours: int = Field(
        default=24,
        ge=1,
        le=8760,
        description="Number of hours to look back",
    )

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Hostname cannot be empty")
        hostname_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
        if not hostname_pattern.match(v):
            raise ValueError(f"Invalid hostname format: {v}")
        return v


class GetProcessesArgs(StrictBaseModel):
    """Arguments for get_processes tool."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Hostname to get processes for",
    )
    hours: int = Field(
        default=24,
        ge=1,
        le=8760,
        description="Number of hours to look back",
    )

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Hostname cannot be empty")
        hostname_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
        if not hostname_pattern.match(v):
            raise ValueError(f"Invalid hostname format: {v}")
        return v


class GetNetworkConnectionsArgs(StrictBaseModel):
    """Arguments for get_network_connections tool."""

    hostname: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Hostname to get network connections for",
    )
    hours: int = Field(
        default=24,
        ge=1,
        le=8760,
        description="Number of hours to look back",
    )

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, v: str) -> str:
        """Validate hostname format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Hostname cannot be empty")
        hostname_pattern = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$")
        if not hostname_pattern.match(v):
            raise ValueError(f"Invalid hostname format: {v}")
        return v


# MITRE Tool Schemas
class MapToMitreArgs(StrictBaseModel):
    """Arguments for map_to_mitre tool."""

    description: str = Field(
        ...,
        min_length=1,
        max_length=MAX_DESCRIPTION_LENGTH,
        description="Description of attack behavior to map",
    )


# Policy Tool Schemas
class CheckPolicyArgs(StrictBaseModel):
    """Arguments for check_policy tool."""

    action_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type of action to check",
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Target of the action",
    )
    confidence: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Confidence score from AI analysis",
    )


class SubmitApprovalArgs(StrictBaseModel):
    """Arguments for submit_approval tool."""

    action_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Type of action requiring approval",
    )
    target: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Target of the action",
    )
    level: Literal["analyst", "senior", "manager", "executive"] = Field(
        default="analyst",
        description="Required approval level",
    )


class GetApprovalStatusArgs(StrictBaseModel):
    """Arguments for get_approval_status tool."""

    request_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="Unique request ID from submit_approval",
    )


# Email Triage Tool Schemas
class AnalyzeEmailArgs(StrictBaseModel):
    """Arguments for analyze_email tool."""

    email_data: dict[str, Any] = Field(
        ...,
        description="Email alert data to analyze",
    )

    @field_validator("email_data")
    @classmethod
    def validate_email_data_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate email data size and structure."""
        import json

        # Check serialized size to prevent DoS
        try:
            serialized = json.dumps(v)
            if len(serialized) > 1_000_000:  # 1MB limit
                raise ValueError("Email data exceeds maximum size (1MB)")
        except (TypeError, ValueError) as e:
            if "exceeds maximum size" in str(e):
                raise
            raise ValueError(f"Email data must be JSON-serializable: {e}")
        return v


class CheckPhishingIndicatorsArgs(StrictBaseModel):
    """Arguments for check_phishing_indicators tool."""

    email_data: dict[str, Any] = Field(
        ...,
        description="Email data to analyze for phishing indicators",
    )

    @field_validator("email_data")
    @classmethod
    def validate_email_data_size(cls, v: dict[str, Any]) -> dict[str, Any]:
        """Validate email data size."""
        import json

        try:
            serialized = json.dumps(v)
            if len(serialized) > 1_000_000:
                raise ValueError("Email data exceeds maximum size (1MB)")
        except (TypeError, ValueError) as e:
            if "exceeds maximum size" in str(e):
                raise
            raise ValueError(f"Email data must be JSON-serializable: {e}")
        return v


class ExtractEmailUrlsArgs(StrictBaseModel):
    """Arguments for extract_email_urls tool."""

    text: str = Field(
        ...,
        min_length=1,
        max_length=MAX_TEXT_LENGTH,
        description="Text content to extract URLs from",
    )
    include_html: bool = Field(
        default=True,
        description="Extract from HTML anchor tags if present",
    )


class CheckSenderReputationArgs(StrictBaseModel):
    """Arguments for check_sender_reputation tool."""

    sender_email: str = Field(
        ...,
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Sender email address to check",
    )

    @field_validator("sender_email")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email address format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Email address cannot be empty")
        # Basic email validation
        email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        if not email_pattern.match(v):
            raise ValueError(f"Invalid email address format: {v}")
        return v


# Phishing Response Action Tool Schemas
class QuarantineEmailArgs(StrictBaseModel):
    """Arguments for quarantine_email tool."""

    message_id: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Unique identifier of the email message",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Reason for quarantining the email",
    )


class BlockSenderArgs(StrictBaseModel):
    """Arguments for block_sender tool."""

    sender: str = Field(
        ...,
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Email address or domain to block",
    )
    block_type: Literal["email", "domain"] = Field(
        ...,
        description="Block type: email for address, domain for entire domain",
    )
    reason: str = Field(
        ...,
        min_length=1,
        max_length=1000,
        description="Reason for blocking the sender",
    )


class NotifyUserArgs(StrictBaseModel):
    """Arguments for notify_user tool."""

    recipient: str = Field(
        ...,
        min_length=1,
        max_length=MAX_EMAIL_LENGTH,
        description="Email address of the notification recipient",
    )
    notification_type: Literal["phishing_warning", "security_alert", "action_taken"] = Field(
        ...,
        description="Type of notification to send",
    )
    subject: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Subject line of the notification",
    )
    body: str = Field(
        ...,
        min_length=1,
        max_length=MAX_DESCRIPTION_LENGTH,
        description="Body content of the notification message",
    )

    @field_validator("recipient")
    @classmethod
    def validate_recipient_email(cls, v: str) -> str:
        """Validate recipient email address format."""
        import re

        v = v.strip()
        if not v:
            raise ValueError("Recipient email cannot be empty")
        email_pattern = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        if not email_pattern.match(v):
            raise ValueError(f"Invalid recipient email format: {v}")
        return v


class CreateSecurityTicketArgs(StrictBaseModel):
    """Arguments for create_security_ticket tool."""

    title: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="Title/summary of the security ticket",
    )
    description: str = Field(
        ...,
        min_length=1,
        max_length=MAX_DESCRIPTION_LENGTH,
        description="Detailed description of the incident",
    )
    severity: Literal["critical", "high", "medium", "low"] = Field(
        ...,
        description="Severity level of the incident",
    )
    indicators: list[str] = Field(
        ...,
        max_length=MAX_ARRAY_SIZE,
        description="List of indicators of compromise (IOCs)",
    )

    @field_validator("indicators")
    @classmethod
    def validate_indicators(cls, v: list[str]) -> list[str]:
        """Validate indicators list."""
        if len(v) > MAX_ARRAY_SIZE:
            raise ValueError(f"Too many indicators (max {MAX_ARRAY_SIZE})")
        validated = []
        for indicator in v:
            if not isinstance(indicator, str):
                raise ValueError(f"Indicator must be a string, got {type(indicator)}")
            indicator = indicator.strip()
            if len(indicator) > 1000:
                raise ValueError("Indicator string too long (max 1000 characters)")
            validated.append(indicator)
        return validated


# Mapping of tool names to their argument schemas
TOOL_ARGUMENT_SCHEMAS: dict[str, type[StrictBaseModel]] = {
    "lookup_hash": LookupHashArgs,
    "lookup_ip": LookupIpArgs,
    "lookup_domain": LookupDomainArgs,
    "search_siem": SearchSiemArgs,
    "get_recent_alerts": GetRecentAlertsArgs,
    "get_host_info": GetHostInfoArgs,
    "get_detections": GetDetectionsArgs,
    "get_processes": GetProcessesArgs,
    "get_network_connections": GetNetworkConnectionsArgs,
    "map_to_mitre": MapToMitreArgs,
    "check_policy": CheckPolicyArgs,
    "submit_approval": SubmitApprovalArgs,
    "get_approval_status": GetApprovalStatusArgs,
    "analyze_email": AnalyzeEmailArgs,
    "check_phishing_indicators": CheckPhishingIndicatorsArgs,
    "extract_email_urls": ExtractEmailUrlsArgs,
    "check_sender_reputation": CheckSenderReputationArgs,
    "quarantine_email": QuarantineEmailArgs,
    "block_sender": BlockSenderArgs,
    "notify_user": NotifyUserArgs,
    "create_security_ticket": CreateSecurityTicketArgs,
}


def validate_tool_arguments(
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Validate tool arguments against Pydantic schema.

    Args:
        tool_name: Name of the tool being called.
        arguments: Raw arguments from LLM output.

    Returns:
        Validated and normalized arguments.

    Raises:
        ToolArgumentValidationError: If validation fails.
    """
    schema_class = TOOL_ARGUMENT_SCHEMAS.get(tool_name)

    if schema_class is None:
        # Tool not in schema registry - log warning and allow (backward compatibility)
        logger.warning(
            "tool_argument_validation_no_schema",
            tool_name=tool_name,
            message="No Pydantic schema defined for tool, skipping validation",
        )
        return arguments

    try:
        validated = schema_class.model_validate(arguments)
        logger.debug(
            "tool_argument_validation_success",
            tool_name=tool_name,
        )
        return validated.model_dump()
    except ValidationError as e:
        error_details = e.errors()
        error_messages = []
        for error in error_details:
            loc = ".".join(str(x) for x in error["loc"])
            msg = error["msg"]
            error_messages.append(f"{loc}: {msg}")

        full_message = f"Tool '{tool_name}' argument validation failed: {'; '.join(error_messages)}"
        logger.error(
            "tool_argument_validation_failed",
            tool_name=tool_name,
            errors=error_details,
            message=full_message,
        )
        raise ToolArgumentValidationError(
            message=full_message,
            errors=[dict(e) for e in error_details],
        )


# =============================================================================
# Singleton Bridge Instances
# =============================================================================

_threat_intel_bridge: Any = None
_edr_bridge: Any = None
_siem_bridge: Any = None


def get_threat_intel_bridge() -> Any:
    """Get or create the ThreatIntel bridge instance."""
    global _threat_intel_bridge
    if (
        _threat_intel_bridge is None
        and _THREAT_INTEL_BRIDGE_AVAILABLE
        and _ThreatIntelBridgeClass is not None
    ):
        try:
            mode = os.environ.get("TW_THREAT_INTEL_MODE", "mock")
            _threat_intel_bridge = _ThreatIntelBridgeClass(mode)
            logger.info("ThreatIntelBridge initialized", mode=mode)
        except Exception as e:
            logger.error("Failed to initialize ThreatIntelBridge", error=str(e))
    return _threat_intel_bridge


def get_edr_bridge() -> Any:
    """Get or create the EDR bridge instance."""
    global _edr_bridge
    if _edr_bridge is None and _EDR_BRIDGE_AVAILABLE and _EDRBridgeClass is not None:
        try:
            mode = os.environ.get("TW_EDR_MODE", "mock")
            with_sample_data = os.environ.get("TW_BRIDGE_SAMPLE_DATA", "true").lower() == "true"
            _edr_bridge = _EDRBridgeClass(mode, with_sample_data=with_sample_data)
            logger.info("EDRBridge initialized", mode=mode, with_sample_data=with_sample_data)
        except Exception as e:
            logger.error("Failed to initialize EDRBridge", error=str(e))
    return _edr_bridge


def get_siem_bridge() -> Any:
    """Get or create the SIEM bridge instance."""
    global _siem_bridge
    if _siem_bridge is None and _SIEM_BRIDGE_AVAILABLE and _SIEMBridgeClass is not None:
        try:
            mode = os.environ.get("TW_SIEM_MODE", "mock")
            with_sample_data = os.environ.get("TW_BRIDGE_SAMPLE_DATA", "true").lower() == "true"
            _siem_bridge = _SIEMBridgeClass(mode, with_sample_data=with_sample_data)
            logger.info("SIEMBridge initialized", mode=mode, with_sample_data=with_sample_data)
        except Exception as e:
            logger.error("Failed to initialize SIEMBridge", error=str(e))
    return _siem_bridge


def is_bridge_available() -> bool:
    """Check if any PyO3 bridge is available."""
    return _THREAT_INTEL_BRIDGE_AVAILABLE or _EDR_BRIDGE_AVAILABLE or _SIEM_BRIDGE_AVAILABLE


def is_threat_intel_bridge_available() -> bool:
    """Check if the ThreatIntel PyO3 bridge is available."""
    return _THREAT_INTEL_BRIDGE_AVAILABLE


def is_siem_bridge_available() -> bool:
    """Check if the SIEM PyO3 bridge is available."""
    return _SIEM_BRIDGE_AVAILABLE


def is_edr_bridge_available() -> bool:
    """Check if the EDR PyO3 bridge is available."""
    return _EDR_BRIDGE_AVAILABLE


def is_policy_bridge_available() -> bool:
    """Check if the Policy PyO3 bridge is available."""
    return _POLICY_BRIDGE_AVAILABLE


def is_ticketing_bridge_available() -> bool:
    """Check if the Ticketing PyO3 bridge is available."""
    return _TICKETING_BRIDGE_AVAILABLE


def is_email_gateway_bridge_available() -> bool:
    """Check if the EmailGateway PyO3 bridge is available."""
    return _EMAIL_GATEWAY_BRIDGE_AVAILABLE


_policy_bridge: Any = None


def get_policy_bridge() -> Any:
    """Get or create the Policy bridge instance."""
    global _policy_bridge
    if _policy_bridge is None and _POLICY_BRIDGE_AVAILABLE and _PolicyBridgeClass is not None:
        try:
            _policy_bridge = _PolicyBridgeClass()
            logger.info("PolicyBridge initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize PolicyBridge", error=str(e))
    return _policy_bridge


_ticketing_bridge: Any = None


def get_ticketing_bridge() -> Any:
    """Get or create the Ticketing bridge instance.

    The bridge mode is controlled by the TW_TICKETING_MODE environment variable:
        - "mock" (default): Uses mock connector for testing
        - "jira": Uses Jira Cloud/Server API

    For "jira" mode, the following environment variables are required:
        - TW_JIRA_URL: Base URL of your Jira instance
        - TW_JIRA_EMAIL: Email address for authentication
        - TW_JIRA_API_TOKEN: API token for authentication
        - TW_JIRA_PROJECT: Project key (e.g., "SEC")

    Returns:
        TicketingBridge instance or None if unavailable
    """
    global _ticketing_bridge
    if (
        _ticketing_bridge is None
        and _TICKETING_BRIDGE_AVAILABLE
        and _TicketingBridgeClass is not None
    ):
        try:
            mode = os.environ.get("TW_TICKETING_MODE", "mock")
            _ticketing_bridge = _TicketingBridgeClass(mode)
            logger.info("TicketingBridge initialized", mode=mode)
        except Exception as e:
            logger.error("Failed to initialize TicketingBridge", error=str(e))
    return _ticketing_bridge


_email_gateway_bridge: Any = None


def get_email_gateway_bridge() -> Any:
    """Get or create the EmailGateway bridge instance.

    The bridge mode is controlled by the TW_EMAIL_GATEWAY_MODE environment variable:
        - "mock" (default): Uses mock connector for testing
        - "m365": Uses Microsoft 365 Graph API

    For "m365" mode, the following environment variables are required:
        - TW_M365_TENANT_ID: Microsoft 365 tenant ID
        - TW_M365_CLIENT_ID: Application client ID
        - TW_M365_CLIENT_SECRET: Application client secret

    Returns:
        EmailGatewayBridge instance or None if unavailable
    """
    global _email_gateway_bridge
    if (
        _email_gateway_bridge is None
        and _EMAIL_GATEWAY_BRIDGE_AVAILABLE
        and _EmailGatewayBridgeClass is not None
    ):
        try:
            mode = os.environ.get("TW_EMAIL_GATEWAY_MODE", "mock")
            _email_gateway_bridge = _EmailGatewayBridgeClass(mode)
            logger.info("EmailGatewayBridge initialized", mode=mode)
        except Exception as e:
            logger.error("Failed to initialize EmailGatewayBridge", error=str(e))
    return _email_gateway_bridge


# =============================================================================
# Mock Fallback Implementations for Threat Intelligence
# =============================================================================


def _mock_hash_lookup(hash_value: str) -> dict[str, Any]:
    """Mock hash lookup for testing when bridge is unavailable."""
    # Known malicious hash (EICAR test file MD5)
    if hash_value == "44d88612fea8a8f36de82e1278abb02f":
        return {
            "indicator_type": "md5",
            "indicator": hash_value,
            "verdict": "malicious",
            "malicious_score": 95,
            "malicious_count": 68,
            "total_engines": 72,
            "categories": ["malware", "test-file"],
            "malware_families": ["EICAR-Test-File"],
            "source": "mock",
        }

    return {
        "indicator_type": "hash",
        "indicator": hash_value,
        "verdict": "unknown",
        "malicious_score": 0,
        "malicious_count": 0,
        "total_engines": 0,
        "categories": [],
        "malware_families": [],
        "source": "mock",
    }


def _mock_ip_lookup(ip: str) -> dict[str, Any]:
    """Mock IP lookup for testing when bridge is unavailable."""
    # Known malicious IP
    if ip == "203.0.113.100":
        return {
            "indicator_type": "ip",
            "indicator": ip,
            "verdict": "malicious",
            "malicious_score": 85,
            "malicious_count": 15,
            "total_engines": 20,
            "categories": ["c2", "botnet"],
            "country": "XX",
            "asn": "AS12345",
            "source": "mock",
        }

    # Private IP ranges are clean
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.")):
        return {
            "indicator_type": "ip",
            "indicator": ip,
            "verdict": "clean",
            "malicious_score": 0,
            "malicious_count": 0,
            "total_engines": 0,
            "categories": ["private"],
            "country": "PRIVATE",
            "asn": None,
            "source": "mock",
        }

    return {
        "indicator_type": "ip",
        "indicator": ip,
        "verdict": "unknown",
        "malicious_score": 0,
        "malicious_count": 0,
        "total_engines": 0,
        "categories": [],
        "country": "XX",
        "asn": None,
        "source": "mock",
    }


def _mock_domain_lookup(domain: str) -> dict[str, Any]:
    """Mock domain lookup for testing when bridge is unavailable."""
    # Known malicious domains
    if domain in ("evil.example.com", "malware.test", "phishing.bad"):
        return {
            "indicator_type": "domain",
            "indicator": domain,
            "verdict": "malicious",
            "malicious_score": 90,
            "malicious_count": 25,
            "total_engines": 30,
            "categories": ["phishing", "malware"],
            "source": "mock",
        }

    # Known clean domains
    if domain in ("google.com", "microsoft.com", "github.com"):
        return {
            "indicator_type": "domain",
            "indicator": domain,
            "verdict": "clean",
            "malicious_score": 0,
            "malicious_count": 0,
            "total_engines": 30,
            "categories": ["technology"],
            "source": "mock",
        }

    return {
        "indicator_type": "domain",
        "indicator": domain,
        "verdict": "unknown",
        "malicious_score": 0,
        "malicious_count": 0,
        "total_engines": 0,
        "categories": [],
        "source": "mock",
    }


# =============================================================================
# Mock Fallback Implementations for Policy
# =============================================================================


def _mock_check_action(action_type: str, target: str, confidence: float) -> dict[str, Any]:
    """Mock policy check for testing when bridge is unavailable.

    Default behavior:
    - Low-risk actions (create_ticket, send_notification) with high confidence: allowed
    - Host isolation: requires approval
    - Dangerous actions (delete_user, wipe_host): denied
    - Everything else: requires approval
    """
    # Dangerous actions are always denied
    if action_type in ("delete_user", "wipe_host", "destroy_data"):
        return {
            "decision": "denied",
            "reason": f"Action '{action_type}' is not allowed by policy",
            "approval_level": None,
        }

    # Low-risk actions with high confidence are allowed
    if (
        action_type in ("create_ticket", "add_ticket_comment", "send_notification")
        and confidence >= 0.9
    ):
        return {
            "decision": "allowed",
            "reason": None,
            "approval_level": None,
        }

    # Phishing response actions: email-level allowed with high confidence
    if action_type in ("quarantine_email", "block_sender_email") and confidence >= 0.9:
        return {
            "decision": "allowed",
            "reason": None,
            "approval_level": None,
        }

    # Domain blocks require senior approval (higher risk of blocking legitimate traffic)
    if action_type == "block_sender_domain":
        return {
            "decision": "requires_approval",
            "reason": "Domain blocks require senior approval",
            "approval_level": "senior",
        }

    # Host isolation requires analyst approval
    if action_type == "isolate_host":
        return {
            "decision": "requires_approval",
            "reason": "Action requires analyst approval",
            "approval_level": "analyst",
        }

    # Protected targets require senior approval
    protected_patterns = ["-prod-", "dc01", "dc02", "admin", "root"]
    if any(pattern in target.lower() for pattern in protected_patterns):
        return {
            "decision": "requires_approval",
            "reason": "Target is protected and requires senior approval",
            "approval_level": "senior",
        }

    # Default: require analyst approval
    return {
        "decision": "requires_approval",
        "reason": "Action requires analyst approval",
        "approval_level": "analyst",
    }


def _mock_get_operation_mode() -> str:
    """Mock operation mode for testing when bridge is unavailable."""
    return "supervised"


def _mock_is_kill_switch_active() -> bool:
    """Mock kill switch status for testing when bridge is unavailable."""
    return False


# Approval request storage for mock fallback
_mock_approval_requests: dict[str, dict[str, Any]] = {}
_mock_approval_counter: int = 0


def _mock_submit_approval_request(action_type: str, target: str, level: str) -> str:
    """Mock approval request submission when bridge is unavailable."""
    global _mock_approval_counter
    import uuid

    request_id = str(uuid.uuid4())
    _mock_approval_requests[request_id] = {
        "action_type": action_type,
        "target": target,
        "level": level,
        "status": "pending",
        "decided_by": None,
    }
    _mock_approval_counter += 1
    return request_id


def _mock_check_approval_status(request_id: str) -> dict[str, Any]:
    """Mock approval status check when bridge is unavailable."""
    if request_id in _mock_approval_requests:
        req = _mock_approval_requests[request_id]
        return {
            "status": req["status"],
            "decided_by": req["decided_by"],
        }
    return {
        "status": "expired",
        "decided_by": None,
    }


# =============================================================================
# Mock Fallback Implementations for Ticketing
# =============================================================================

# Mock ticket storage for testing
_mock_tickets: dict[str, dict[str, Any]] = {}
_mock_ticket_counter: int = 0


def _mock_create_ticket(
    title: str,
    description: str,
    priority: str,
    labels: list[str],
) -> dict[str, Any]:
    """Mock ticket creation when TicketingBridge is unavailable.

    Creates a mock ticket with generated ID and URL for testing.
    """
    global _mock_ticket_counter

    _mock_ticket_counter += 1
    ticket_id = f"MOCK-{_mock_ticket_counter}"
    ticket_key = ticket_id
    ticket_url = f"https://mock-ticketing.example.com/browse/{ticket_key}"

    ticket = {
        "id": ticket_id,
        "key": ticket_key,
        "title": title,
        "description": description,
        "status": "Open",
        "priority": priority,
        "labels": labels,
        "url": ticket_url,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "is_mock": True,
    }

    _mock_tickets[ticket_id] = ticket
    return ticket


# =============================================================================
# Mock Fallback Implementations for Email Gateway
# =============================================================================

# Mock email and block storage for testing
_mock_quarantined_emails: dict[str, dict[str, Any]] = {}
_mock_blocked_senders: dict[str, dict[str, Any]] = {}


def _mock_quarantine_email(message_id: str) -> bool:
    """Mock email quarantine when EmailGatewayBridge is unavailable.

    Simulates quarantining an email for testing purposes.
    """
    _mock_quarantined_emails[message_id] = {
        "quarantined_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "quarantined",
    }
    return True


def _mock_block_sender(sender_address: str) -> bool:
    """Mock sender blocking when EmailGatewayBridge is unavailable.

    Simulates blocking a sender for testing purposes.
    """
    _mock_blocked_senders[sender_address] = {
        "blocked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "blocked",
    }
    return True


# =============================================================================
# Email Triage Helper Functions
# =============================================================================


def _normalize_email_data_for_phishing(email_data: dict[str, Any]) -> dict[str, Any]:
    """Normalize email data to the format expected by analyze_phishing_indicators.

    Handles both raw email alert data and output from analyze_email tool.

    Args:
        email_data: Email data in various formats.

    Returns:
        Normalized dict with expected fields for phishing analysis.
    """
    normalized: dict[str, Any] = {}

    # Subject
    normalized["subject"] = email_data.get("subject", "")

    # Body - try various field names
    body = email_data.get("body", "")
    if not body:
        body = email_data.get("body_text", "") or email_data.get("body_html", "")
    normalized["body"] = body

    # Sender email - try various field names
    sender_email = email_data.get("sender_email", "")
    if not sender_email:
        sender_email = email_data.get("sender", "") or email_data.get("from", "")
    normalized["sender_email"] = sender_email

    # Sender display name
    normalized["sender_display_name"] = email_data.get("sender_display_name", "")

    # Reply-to
    normalized["reply_to"] = email_data.get("reply_to", "")

    # URLs - handle both list of strings and list of dicts
    urls_data = email_data.get("urls", [])
    urls: list[str] = []
    url_display_texts: list[dict[str, str]] = []

    for url_item in urls_data:
        if isinstance(url_item, str):
            urls.append(url_item)
        elif isinstance(url_item, dict):
            url_str = url_item.get("url", "")
            if url_str:
                urls.append(url_str)
                display_text = url_item.get("display_text")
                if display_text:
                    url_display_texts.append(
                        {
                            "url": url_str,
                            "display_text": display_text,
                        }
                    )

    normalized["urls"] = urls
    normalized["url_display_texts"] = url_display_texts

    # Attachments - handle both list of strings and list of dicts
    attachments_data = email_data.get("attachments", [])
    attachments: list[str] = []

    for att_item in attachments_data:
        if isinstance(att_item, str):
            attachments.append(att_item)
        elif isinstance(att_item, dict):
            filename = att_item.get("filename", att_item.get("name", ""))
            if filename:
                attachments.append(filename)

    normalized["attachments"] = attachments

    return normalized


def _mock_check_sender_reputation(sender_email: str) -> dict[str, Any]:
    """Mock sender reputation check for testing when real service is unavailable.

    Provides realistic mock data for known domains and generic responses
    for unknown senders.
    """
    # Extract domain from email
    domain = ""
    if "@" in sender_email:
        domain = sender_email.split("@")[-1].lower().strip()

    # Known trusted domains (high reputation)
    trusted_domains = {
        "google.com": {"score": 95, "domain_age_days": 9500, "category": "technology"},
        "microsoft.com": {"score": 95, "domain_age_days": 10000, "category": "technology"},
        "github.com": {"score": 90, "domain_age_days": 5800, "category": "technology"},
        "amazon.com": {"score": 92, "domain_age_days": 10500, "category": "e-commerce"},
        "apple.com": {"score": 95, "domain_age_days": 10000, "category": "technology"},
    }

    # Known suspicious/malicious domains
    suspicious_domains = {
        "evil.example.com": {"score": 5, "domain_age_days": 7, "category": "malicious"},
        "phishing.bad": {"score": 0, "domain_age_days": 3, "category": "phishing"},
        "malware.test": {"score": 10, "domain_age_days": 14, "category": "malware"},
    }

    # Check trusted domains
    if domain in trusted_domains:
        info = trusted_domains[domain]
        return {
            "sender_email": sender_email,
            "domain": domain,
            "score": info["score"],
            "is_known_sender": True,
            "domain_age_days": info["domain_age_days"],
            "category": info["category"],
            "risk_level": "low",
            "is_mock": True,
        }

    # Check suspicious domains
    if domain in suspicious_domains:
        info = suspicious_domains[domain]
        return {
            "sender_email": sender_email,
            "domain": domain,
            "score": info["score"],
            "is_known_sender": False,
            "domain_age_days": info["domain_age_days"],
            "category": info["category"],
            "risk_level": "high",
            "is_mock": True,
        }

    # Check for newly registered or suspicious patterns
    # Domains with numbers or hyphens mimicking brands
    suspicious_patterns = ["paypa1", "micros0ft", "g00gle", "amaz0n", "app1e"]
    for pattern in suspicious_patterns:
        if pattern in domain:
            return {
                "sender_email": sender_email,
                "domain": domain,
                "score": 15,
                "is_known_sender": False,
                "domain_age_days": 30,
                "category": "suspicious",
                "risk_level": "high",
                "is_mock": True,
            }

    # Default: unknown sender
    return {
        "sender_email": sender_email,
        "domain": domain,
        "score": 50,
        "is_known_sender": False,
        "domain_age_days": None,  # Unknown
        "category": "unknown",
        "risk_level": "medium",
        "is_mock": True,
    }


def _extract_sender_domain(sender_email: str) -> str:
    """Extract and normalize sender domain from an email address."""
    normalized = sender_email.strip().lower()
    if "@" in normalized:
        return normalized.rsplit("@", 1)[1]
    return normalized


def _reputation_from_domain_lookup(
    sender_email: str, lookup_result: dict[str, Any]
) -> dict[str, Any]:
    """Build sender reputation payload from a threat-intel domain lookup result."""
    domain = _extract_sender_domain(sender_email)

    malicious_score_raw = lookup_result.get("malicious_score", 0)
    try:
        malicious_score = int(float(malicious_score_raw))
    except (TypeError, ValueError):
        malicious_score = 0
    malicious_score = max(0, min(100, malicious_score))

    score = max(0, min(100, 100 - malicious_score))
    verdict = str(lookup_result.get("verdict", "unknown")).strip().lower()

    if verdict == "malicious" or score <= 25:
        risk_level = "high"
    elif verdict == "suspicious" or score <= 60:
        risk_level = "medium"
    else:
        risk_level = "low"

    categories = lookup_result.get("categories")
    if isinstance(categories, list) and categories:
        category = str(categories[0])
    elif isinstance(categories, str) and categories:
        category = categories
    else:
        category = verdict if verdict in {"malicious", "suspicious", "clean"} else "unknown"

    domain_age_raw = lookup_result.get("domain_age_days")
    domain_age_days: int | None = None
    if isinstance(domain_age_raw, (int, float)):
        domain_age_days = int(domain_age_raw)

    return {
        "sender_email": sender_email,
        "domain": domain,
        "score": score,
        "is_known_sender": (verdict == "clean" and score >= 85),
        "domain_age_days": domain_age_days,
        "category": category,
        "risk_level": risk_level,
        "is_mock": False,
    }


# =============================================================================
# Policy Helper Functions
# =============================================================================


def is_action_allowed(action_type: str, target: str, confidence: float) -> bool:
    """Check if an action is allowed by the policy engine.

    This is a convenience function that calls check_policy and returns
    a simple boolean indicating whether the action can proceed.

    Args:
        action_type: Type of action (e.g., "isolate_host", "create_ticket")
        target: Target of the action (e.g., hostname, IP address)
        confidence: Confidence score from AI analysis (0.0 to 1.0)

    Returns:
        True if the action is allowed, False if denied or requires approval

    Example:
        if is_action_allowed("create_ticket", "INC-001", 0.95):
            # Proceed with creating ticket
            pass
    """
    bridge = get_policy_bridge()

    if bridge is not None:
        try:
            result = bridge.check_action(action_type, target, confidence)
            return bool(result.get("decision") == "allowed")
        except Exception as e:
            logger.error("Policy check failed", error=str(e))
            return False

    # Mock fallback
    result = _mock_check_action(action_type, target, confidence)
    return bool(result.get("decision") == "allowed")


def _format_event_for_llm(event: dict[str, Any]) -> str:
    """Format a single SIEM event for LLM readability.

    Transforms raw SIEM event data into a human-readable format
    that's easy for the LLM to understand and analyze.
    """
    timestamp = event.get("timestamp", "Unknown time")
    event_type = event.get("event_type", event.get("type", "Unknown"))
    source_ip = event.get("source_ip", event.get("src_ip", "N/A"))
    dest_ip = event.get("destination_ip", event.get("dst_ip", "N/A"))
    user = event.get("user", event.get("username", "N/A"))
    message = event.get("message", event.get("raw_log", "No message"))
    severity = event.get("severity", "info")
    hostname = event.get("hostname", event.get("host", "N/A"))

    lines = [
        f"[{timestamp}] {severity.upper()} - {event_type}",
        f"  Host: {hostname}",
        f"  Source IP: {source_ip} -> Dest IP: {dest_ip}",
        f"  User: {user}",
        f"  Message: {message}",
    ]

    # Add any additional fields that might be relevant
    for key in ["process_name", "file_path", "command_line", "action"]:
        if key in event and event[key]:
            lines.append(f"  {key.replace('_', ' ').title()}: {event[key]}")

    return "\n".join(lines)


def _format_alert_for_llm(alert: dict[str, Any]) -> str:
    """Format a single alert for LLM readability.

    Transforms raw alert data into a human-readable format
    that's easy for the LLM to understand and analyze.
    """
    alert_id = alert.get("id", alert.get("alert_id", "Unknown"))
    name = alert.get("name", alert.get("title", "Unknown Alert"))
    severity = alert.get("severity", "unknown")
    timestamp = alert.get("timestamp", alert.get("created_at", "Unknown time"))
    description = alert.get("description", "")
    details = alert.get("details", {})

    lines = [
        f"Alert ID: {alert_id}",
        f"Name: {name}",
        f"Severity: {severity.upper()}",
        f"Time: {timestamp}",
    ]

    if description:
        lines.append(f"Description: {description}")

    # Add details if present
    if details and isinstance(details, dict):
        lines.append("Details:")
        for key, value in details.items():
            lines.append(f"  - {key}: {value}")

    return "\n".join(lines)


@dataclass
class Tool:
    """A tool that can be called by the agent."""

    name: str
    description: str
    parameters: dict[str, Any]
    handler: Callable[..., Awaitable[Any]]
    requires_confirmation: bool = False

    def to_definition(self) -> ToolDefinition:
        """Convert to a ToolDefinition for the LLM."""
        return ToolDefinition(
            name=self.name,
            description=self.description,
            parameters=self.parameters,
        )


class ToolRegistry:
    """Registry of tools available to the agent."""

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register(self, tool: Tool) -> None:
        """Register a tool."""
        logger.debug("tool_registered", name=tool.name)
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def get_tool_definitions(self) -> list[ToolDefinition]:
        """Get ToolDefinitions for all registered tools."""
        return [tool.to_definition() for tool in self._tools.values()]

    async def execute(self, name: str, arguments: dict[str, Any]) -> Any:
        """Execute a tool by name with the given arguments.

        Validates arguments against Pydantic schema before execution.
        This prevents injection attacks and ensures type safety.

        Args:
            name: Name of the tool to execute.
            arguments: Arguments from LLM output.

        Returns:
            Result of the tool execution.

        Raises:
            ValueError: If tool not found.
            ToolArgumentValidationError: If arguments fail validation.
        """
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")

        # Validate arguments against Pydantic schema (Security Task 5.4)
        # This prevents:
        # - Unknown/extra arguments that could be injection vectors
        # - Incorrect types that could cause unexpected behavior
        # - Oversized inputs that could cause DoS
        validated_arguments = validate_tool_arguments(name, arguments)

        logger.debug("tool_execute", name=name, arguments=validated_arguments)
        return await tool.handler(**validated_arguments)


def create_triage_tools() -> ToolRegistry:
    """Create the default set of tools for security triage."""
    registry = ToolRegistry()

    # ========================================================================
    # Threat Intelligence Tools - Use PyO3 bridge when available
    # ========================================================================

    async def lookup_hash(hash: str) -> ToolResult:
        """Look up a file hash in threat intelligence databases.

        Calls ThreatIntelBridge.lookup_hash() when available, otherwise uses mock.

        Returns:
            ToolResult with verdict, score, malware_families, etc.
        """
        start_time = time.perf_counter()
        bridge = get_threat_intel_bridge()

        try:
            if bridge is not None:
                result = bridge.lookup_hash(hash)
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Hash lookup unavailable: threat intel connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result = _mock_hash_lookup(hash)
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "indicator": result.get("indicator", hash),
                    "indicator_type": result.get("indicator_type", "hash"),
                    "verdict": result.get("verdict", "unknown"),
                    "score": result.get("malicious_score", 0),
                    "malware_families": result.get("malware_families", []),
                    "categories": result.get("categories", []),
                    "malicious_count": result.get("malicious_count", 0),
                    "total_engines": result.get("total_engines", 0),
                    "source": result.get("source", "unknown"),
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("lookup_hash_failed", hash=hash, error=str(e))
            return ToolResult.fail(
                error=f"Hash lookup failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="lookup_hash",
            description=(
                "Look up a file hash (MD5, SHA1, SHA256) in threat intelligence databases. "
                "Returns verdict (malicious/suspicious/clean/unknown), malicious score (0-100), "
                "malware families, and detection counts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "The file hash to look up (MD5, SHA1, or SHA256)",
                    }
                },
                "required": ["hash"],
            },
            handler=lookup_hash,
        )
    )

    async def lookup_ip(ip: str) -> ToolResult:
        """Look up an IP address in threat intelligence databases.

        Calls ThreatIntelBridge.lookup_ip() when available, otherwise uses mock.

        Returns:
            ToolResult with verdict, categories, country, etc.
        """
        start_time = time.perf_counter()
        bridge = get_threat_intel_bridge()

        try:
            if bridge is not None:
                result = bridge.lookup_ip(ip)
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "IP lookup unavailable: threat intel connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result = _mock_ip_lookup(ip)
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "indicator": result.get("indicator", ip),
                    "indicator_type": result.get("indicator_type", "ip"),
                    "verdict": result.get("verdict", "unknown"),
                    "score": result.get("malicious_score", 0),
                    "categories": result.get("categories", []),
                    "country": result.get("country", "XX"),
                    "asn": result.get("asn"),
                    "malicious_count": result.get("malicious_count", 0),
                    "total_engines": result.get("total_engines", 0),
                    "source": result.get("source", "unknown"),
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("lookup_ip_failed", ip=ip, error=str(e))
            return ToolResult.fail(
                error=f"IP lookup failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="lookup_ip",
            description=(
                "Look up an IP address in threat intelligence databases. "
                "Returns verdict (malicious/suspicious/clean/unknown), threat categories, "
                "country, ASN, and detection counts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "The IP address to look up (IPv4 or IPv6)",
                    }
                },
                "required": ["ip"],
            },
            handler=lookup_ip,
        )
    )

    async def lookup_domain(domain: str) -> ToolResult:
        """Look up a domain in threat intelligence databases.

        Calls ThreatIntelBridge.lookup_domain() when available, otherwise uses mock.

        Returns:
            ToolResult with verdict, categories, etc.
        """
        start_time = time.perf_counter()
        bridge = get_threat_intel_bridge()

        try:
            if bridge is not None:
                result = bridge.lookup_domain(domain)
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Domain lookup unavailable: threat intel connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result = _mock_domain_lookup(domain)
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "indicator": result.get("indicator", domain),
                    "indicator_type": result.get("indicator_type", "domain"),
                    "verdict": result.get("verdict", "unknown"),
                    "score": result.get("malicious_score", 0),
                    "categories": result.get("categories", []),
                    "malicious_count": result.get("malicious_count", 0),
                    "total_engines": result.get("total_engines", 0),
                    "source": result.get("source", "unknown"),
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("lookup_domain_failed", domain=domain, error=str(e))
            return ToolResult.fail(
                error=f"Domain lookup failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="lookup_domain",
            description=(
                "Look up a domain in threat intelligence databases. "
                "Returns verdict (malicious/suspicious/clean/unknown), threat categories, "
                "and detection counts."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "domain": {
                        "type": "string",
                        "description": "The domain to look up",
                    }
                },
                "required": ["domain"],
            },
            handler=lookup_domain,
        )
    )

    # ========================================================================
    # SIEM Tools
    # ========================================================================

    async def search_siem(query: str, hours: int = 24, limit: int = 100) -> ToolResult:
        """Search SIEM logs using the bridge or mock fallback.

        Args:
            query: Search query string (supports keywords like 'login_failure', 'malware', etc.)
            hours: Number of hours to search back (default: 24)
            limit: Maximum number of events to return (default: 100)

        Returns:
            ToolResult with data containing:
                - events: List of matching events (formatted for LLM readability)
                - events_raw: List of raw event data
                - total_count: Total number of matching events
                - search_stats: Search execution statistics
                - is_mock: Whether mock data was used
        """
        start_time = time.perf_counter()
        bridge = get_siem_bridge()

        try:
            if bridge is not None:
                logger.debug("search_siem_bridge", query=query, hours=hours, limit=limit)
                result = bridge.search(query, hours)

                # Extract and limit events
                raw_events = result.get("events", [])[:limit]
                total_count = result.get("total_count", len(raw_events))

                # Format events for LLM readability
                formatted_events = [_format_event_for_llm(e) for e in raw_events]

                # Build search stats
                search_stats = {
                    "search_id": result.get("search_id", "unknown"),
                    "execution_time_ms": result.get("stats", {}).get("execution_time_ms", 0),
                    "events_scanned": result.get("stats", {}).get("events_scanned", 0),
                    "query": query,
                    "timerange_hours": hours,
                    "limit_applied": limit,
                    "events_returned": len(raw_events),
                }

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data={
                        "events": formatted_events,
                        "events_raw": raw_events,
                        "total_count": total_count,
                        "search_stats": search_stats,
                        "is_mock": False,
                    },
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback
            logger.debug("search_siem_mock", query=query, hours=hours, limit=limit)
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "events": [],
                    "events_raw": [],
                    "total_count": 0,
                    "search_stats": {
                        "search_id": "mock-search",
                        "execution_time_ms": 0,
                        "events_scanned": 0,
                        "query": query,
                        "timerange_hours": hours,
                        "limit_applied": limit,
                        "events_returned": 0,
                    },
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("search_siem_failed", query=query, error=str(e))
            return ToolResult.fail(
                error=f"SIEM search failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="search_siem",
            description=(
                "Search security logs in the SIEM. Returns events matching the query "
                "within the specified time range. Use this to investigate security "
                "incidents by searching for specific patterns, users, IPs, or event types."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": (
                            "The search query. Supports keywords like 'login_failure', "
                            "'malware', IP addresses, usernames, or event types."
                        ),
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to search back (default 24)",
                        "default": 24,
                    },
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of events to return (default 100)",
                        "default": 100,
                    },
                },
                "required": ["query"],
            },
            handler=search_siem,
        )
    )

    async def get_recent_alerts(limit: int = 10) -> ToolResult:
        """Get recent alerts from the SIEM using the bridge or mock fallback.

        Args:
            limit: Maximum number of alerts to return (default: 10)

        Returns:
            ToolResult with data containing:
                - alerts: List of alert summaries (formatted for LLM readability)
                - alerts_raw: List of raw alert data
                - total_count: Total number of alerts returned
                - is_mock: Whether mock data was used
        """
        start_time = time.perf_counter()
        bridge = get_siem_bridge()

        try:
            if bridge is not None:
                logger.debug("get_recent_alerts_bridge", limit=limit)
                raw_alerts = bridge.get_recent_alerts(limit)

                # Format alerts for LLM readability
                formatted_alerts = [_format_alert_for_llm(a) for a in raw_alerts]

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data={
                        "alerts": formatted_alerts,
                        "alerts_raw": raw_alerts,
                        "total_count": len(raw_alerts),
                        "is_mock": False,
                    },
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback
            logger.debug("get_recent_alerts_mock", limit=limit)
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "alerts": [],
                    "alerts_raw": [],
                    "total_count": 0,
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("get_recent_alerts_failed", error=str(e))
            return ToolResult.fail(
                error=f"Get recent alerts failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="get_recent_alerts",
            description=(
                "Get the most recent security alerts from the SIEM. "
                "Returns alerts sorted by timestamp (newest first). "
                "Use this to quickly see what security events need attention."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "limit": {
                        "type": "integer",
                        "description": "Maximum number of alerts to return (default 10)",
                        "default": 10,
                    },
                },
                "required": [],
            },
            handler=get_recent_alerts,
        )
    )

    # ========================================================================
    # EDR Tools - Use bridge when available, fallback to mock
    # ========================================================================

    async def get_host_info(hostname: str) -> ToolResult:
        """Get host information from EDR.

        Returns host details including OS, status, and isolation state.
        Uses the PyO3 bridge when available, otherwise returns mock data.
        """
        start_time = time.perf_counter()
        bridge = get_edr_bridge()

        try:
            if bridge is not None:
                result = bridge.get_host_info(hostname)
                # Format for LLM readability
                formatted = _format_host_info_for_llm(result)
                formatted["is_mock"] = False

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data=formatted,
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "hostname": hostname,
                    "host_id": f"mock-{hostname}",
                    "ip_addresses": ["192.168.1.100"],
                    "os": "Windows 10 Enterprise",
                    "os_version": "10.0.19044",
                    "status": "online",
                    "isolated": False,
                    "last_seen": "2025-01-29T10:30:00Z",
                    "agent_version": "7.0.0",
                    "tags": ["workstation", "finance"],
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("get_host_info_failed", hostname=hostname, error=str(e))
            return ToolResult.fail(
                error=f"Get host info failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    def _format_host_info_for_llm(data: dict[str, Any]) -> dict[str, Any]:
        """Format host info for LLM readability."""
        # The bridge returns a dict, ensure consistent structure
        result = {
            "hostname": data.get("hostname", "unknown"),
            "host_id": data.get("host_id", ""),
            "ip_addresses": data.get("ip_addresses", []),
            "os": data.get("os", "Unknown"),
            "os_version": data.get("os_version", ""),
            "status": data.get("status", "unknown"),
            "isolated": data.get("isolated", False),
            "last_seen": data.get("last_seen", ""),
            "agent_version": data.get("agent_version", ""),
            "tags": data.get("tags", []),
            "source": "edr_bridge",
        }
        return result

    registry.register(
        Tool(
            name="get_host_info",
            description=(
                "Get detailed information about a host from the EDR. "
                "Returns hostname, OS, status (online/offline), isolation state, "
                "IP addresses, agent version, and tags."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to look up",
                    }
                },
                "required": ["hostname"],
            },
            handler=get_host_info,
        )
    )

    async def get_detections(hostname: str, hours: int = 24) -> ToolResult:
        """Get recent detections/alerts for a host.

        Returns detections with severity, MITRE techniques, and process info.
        """
        start_time = time.perf_counter()
        bridge = get_edr_bridge()

        try:
            if bridge is not None:
                result = bridge.get_detections(hostname)
                formatted = _format_detections_for_llm(result, hostname)
                formatted["timerange_hours"] = hours
                formatted["is_mock"] = False

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data=formatted,
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback with realistic detection data
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "hostname": hostname,
                    "timerange_hours": hours,
                    "total_count": 2,
                    "detections": [
                        {
                            "id": "det-001",
                            "name": "Suspicious PowerShell Execution",
                            "severity": "high",
                            "timestamp": "2025-01-29T09:15:00Z",
                            "description": "PowerShell executing encoded command",
                            "tactic": "Execution",
                            "technique": "T1059.001",
                            "technique_name": "PowerShell",
                            "process_name": "powershell.exe",
                            "file_hash": "abc123def456",
                            "status": "new",
                        },
                        {
                            "id": "det-002",
                            "name": "Credential Access Attempt",
                            "severity": "critical",
                            "timestamp": "2025-01-29T09:20:00Z",
                            "description": "LSASS memory access detected",
                            "tactic": "Credential Access",
                            "technique": "T1003.001",
                            "technique_name": "LSASS Memory",
                            "process_name": "mimikatz.exe",
                            "file_hash": "fed987cba654",
                            "status": "new",
                        },
                    ],
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("get_detections_failed", hostname=hostname, error=str(e))
            return ToolResult.fail(
                error=f"Get detections failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    def _format_detections_for_llm(data: list[dict[str, Any]], hostname: str) -> dict[str, Any]:
        """Format detections for LLM readability."""
        formatted = []
        for det in data:
            formatted.append(
                {
                    "id": det.get("id", ""),
                    "name": det.get("name", "Unknown Detection"),
                    "severity": det.get("severity", "unknown"),
                    "timestamp": det.get("timestamp", ""),
                    "description": det.get("description", ""),
                    "tactic": det.get("tactic", ""),
                    "technique": det.get("technique", ""),
                    "technique_name": det.get("technique_name", ""),
                    "process_name": det.get("process_name", ""),
                    "file_hash": det.get("file_hash", ""),
                    "status": det.get("status", "new"),
                }
            )
        return {
            "hostname": hostname,
            "total_count": len(formatted),
            "detections": formatted,
            "source": "edr_bridge",
        }

    registry.register(
        Tool(
            name="get_detections",
            description=(
                "Get recent security detections/alerts for a host from the EDR. "
                "Returns detections with severity levels (critical, high, medium, low), "
                "MITRE ATT&CK techniques, associated processes, and file hashes."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to get detections for",
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to look back (default 24)",
                        "default": 24,
                    },
                },
                "required": ["hostname"],
            },
            handler=get_detections,
        )
    )

    async def get_processes(hostname: str, hours: int = 24) -> ToolResult:
        """Get process list for a host.

        Returns running processes with name, command line, user, and parent info.
        """
        start_time = time.perf_counter()
        bridge = get_edr_bridge()

        try:
            if bridge is not None:
                result = bridge.get_processes(hostname, hours)
                formatted = _format_processes_for_llm(result, hostname, hours)
                formatted["is_mock"] = False

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data=formatted,
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback with realistic process data
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "hostname": hostname,
                    "timerange_hours": hours,
                    "total_count": 5,
                    "processes": [
                        {
                            "pid": 1234,
                            "name": "powershell.exe",
                            "command_line": "powershell.exe -enc SQBFAFgA...",
                            "user": "DOMAIN\\user1",
                            "parent_pid": 5678,
                            "parent_name": "cmd.exe",
                            "start_time": "2025-01-29T09:14:30Z",
                            "hash": "abc123",
                        },
                        {
                            "pid": 5678,
                            "name": "cmd.exe",
                            "command_line": "cmd.exe /c powershell",
                            "user": "DOMAIN\\user1",
                            "parent_pid": 9999,
                            "parent_name": "explorer.exe",
                            "start_time": "2025-01-29T09:14:00Z",
                            "hash": "def456",
                        },
                        {
                            "pid": 2468,
                            "name": "mimikatz.exe",
                            "command_line": "mimikatz.exe sekurlsa::logonpasswords",
                            "user": "DOMAIN\\user1",
                            "parent_pid": 1234,
                            "parent_name": "powershell.exe",
                            "start_time": "2025-01-29T09:19:00Z",
                            "hash": "fed987",
                        },
                        {
                            "pid": 9999,
                            "name": "explorer.exe",
                            "command_line": "C:\\Windows\\explorer.exe",
                            "user": "DOMAIN\\user1",
                            "parent_pid": 1,
                            "parent_name": "System",
                            "start_time": "2025-01-29T08:00:00Z",
                            "hash": "ghijkl",
                        },
                        {
                            "pid": 3456,
                            "name": "chrome.exe",
                            "command_line": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                            "user": "DOMAIN\\user1",
                            "parent_pid": 9999,
                            "parent_name": "explorer.exe",
                            "start_time": "2025-01-29T08:30:00Z",
                            "hash": "mnopqr",
                        },
                    ],
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("get_processes_failed", hostname=hostname, error=str(e))
            return ToolResult.fail(
                error=f"Get processes failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    def _format_processes_for_llm(
        data: list[dict[str, Any]], hostname: str, hours: int
    ) -> dict[str, Any]:
        """Format process list for LLM readability."""
        formatted = []
        for proc in data:
            formatted.append(
                {
                    "pid": proc.get("pid", 0),
                    "name": proc.get("name", "unknown"),
                    "command_line": proc.get("command_line", ""),
                    "user": proc.get("user", ""),
                    "parent_pid": proc.get("parent_pid", 0),
                    "parent_name": proc.get("parent_name", ""),
                    "start_time": proc.get("start_time", ""),
                    "hash": proc.get("hash", ""),
                }
            )
        return {
            "hostname": hostname,
            "timerange_hours": hours,
            "total_count": len(formatted),
            "processes": formatted,
            "source": "edr_bridge",
        }

    registry.register(
        Tool(
            name="get_processes",
            description=(
                "Get the process list for a host from the EDR. "
                "Returns process name, command line arguments, user context, "
                "parent process info, and file hashes. Useful for process tree analysis."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to get processes for",
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to look back (default 24)",
                        "default": 24,
                    },
                },
                "required": ["hostname"],
            },
            handler=get_processes,
        )
    )

    async def get_network_connections(hostname: str, hours: int = 24) -> ToolResult:
        """Get network connections for a host.

        Returns connections with destination IP, port, and associated process.
        """
        start_time = time.perf_counter()
        bridge = get_edr_bridge()

        try:
            if bridge is not None:
                result = bridge.get_network_connections(hostname, hours)
                formatted = _format_network_connections_for_llm(result, hostname, hours)
                formatted["is_mock"] = False

                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.ok(
                    data=formatted,
                    execution_time_ms=execution_time_ms,
                )

            # Mock fallback with realistic network data
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "hostname": hostname,
                    "timerange_hours": hours,
                    "total_count": 4,
                    "connections": [
                        {
                            "timestamp": "2025-01-29T09:15:30Z",
                            "direction": "outbound",
                            "protocol": "TCP",
                            "local_ip": "192.168.1.100",
                            "local_port": 49152,
                            "remote_ip": "203.0.113.50",
                            "remote_port": 443,
                            "remote_hostname": "c2.evil.com",
                            "process_name": "powershell.exe",
                            "process_pid": 1234,
                            "bytes_sent": 15000,
                            "bytes_received": 250000,
                            "status": "established",
                        },
                        {
                            "timestamp": "2025-01-29T09:16:00Z",
                            "direction": "outbound",
                            "protocol": "TCP",
                            "local_ip": "192.168.1.100",
                            "local_port": 49153,
                            "remote_ip": "198.51.100.25",
                            "remote_port": 8443,
                            "remote_hostname": "exfil.malware.net",
                            "process_name": "mimikatz.exe",
                            "process_pid": 2468,
                            "bytes_sent": 500000,
                            "bytes_received": 1000,
                            "status": "closed",
                        },
                        {
                            "timestamp": "2025-01-29T08:30:00Z",
                            "direction": "outbound",
                            "protocol": "TCP",
                            "local_ip": "192.168.1.100",
                            "local_port": 49100,
                            "remote_ip": "142.250.185.206",
                            "remote_port": 443,
                            "remote_hostname": "www.google.com",
                            "process_name": "chrome.exe",
                            "process_pid": 3456,
                            "bytes_sent": 50000,
                            "bytes_received": 1500000,
                            "status": "established",
                        },
                        {
                            "timestamp": "2025-01-29T09:00:00Z",
                            "direction": "inbound",
                            "protocol": "TCP",
                            "local_ip": "192.168.1.100",
                            "local_port": 445,
                            "remote_ip": "192.168.1.50",
                            "remote_port": 52100,
                            "remote_hostname": "admin-workstation",
                            "process_name": "System",
                            "process_pid": 4,
                            "bytes_sent": 0,
                            "bytes_received": 1500,
                            "status": "closed",
                        },
                    ],
                    "is_mock": True,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("get_network_connections_failed", hostname=hostname, error=str(e))
            return ToolResult.fail(
                error=f"Get network connections failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    def _format_network_connections_for_llm(
        data: list[dict[str, Any]], hostname: str, hours: int
    ) -> dict[str, Any]:
        """Format network connections for LLM readability."""
        formatted = []
        for conn in data:
            formatted.append(
                {
                    "timestamp": conn.get("timestamp", ""),
                    "direction": conn.get("direction", "unknown"),
                    "protocol": conn.get("protocol", "TCP"),
                    "local_ip": conn.get("local_ip", ""),
                    "local_port": conn.get("local_port", 0),
                    "remote_ip": conn.get("remote_ip", ""),
                    "remote_port": conn.get("remote_port", 0),
                    "remote_hostname": conn.get("remote_hostname", ""),
                    "process_name": conn.get("process_name", ""),
                    "process_pid": conn.get("process_pid", 0),
                    "bytes_sent": conn.get("bytes_sent", 0),
                    "bytes_received": conn.get("bytes_received", 0),
                    "status": conn.get("status", "unknown"),
                }
            )
        return {
            "hostname": hostname,
            "timerange_hours": hours,
            "total_count": len(formatted),
            "connections": formatted,
            "source": "edr_bridge",
        }

    registry.register(
        Tool(
            name="get_network_connections",
            description=(
                "Get network connections for a host from the EDR. "
                "Returns connection details including destination IP/port, protocol, "
                "direction (inbound/outbound), associated process, and data transfer stats. "
                "Useful for identifying C2 communications or data exfiltration."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "hostname": {
                        "type": "string",
                        "description": "The hostname to get network connections for",
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Number of hours to look back (default 24)",
                        "default": 24,
                    },
                },
                "required": ["hostname"],
            },
            handler=get_network_connections,
        )
    )

    # ========================================================================
    # End of EDR Tools
    # ========================================================================

    async def map_to_mitre(description: str) -> ToolResult:
        """Map attack behavior to MITRE ATT&CK techniques."""
        start_time = time.perf_counter()

        try:
            from tw_ai.analysis.mitre import map_to_mitre as map_behavior_to_mitre

            mapped = map_behavior_to_mitre(description)
            tactics = sorted({technique.tactic for technique in mapped if technique.tactic})

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            return ToolResult.ok(
                data={
                    "techniques": [
                        {
                            "id": technique.id,
                            "name": technique.name,
                            "tactic": technique.tactic,
                            "relevance": technique.relevance,
                        }
                        for technique in mapped
                    ],
                    "tactics": tactics,
                    "description": description,
                    "match_count": len(mapped),
                    "is_mock": False,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("map_to_mitre_failed", description=description, error=str(e))
            return ToolResult.fail(
                error=f"Map to MITRE failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="map_to_mitre",
            description="Map attack behavior description to MITRE ATT&CK techniques",
            parameters={
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Description of the attack behavior to map",
                    }
                },
                "required": ["description"],
            },
            handler=map_to_mitre,
        )
    )

    # ========================================================================
    # Policy Tools - Check actions against policy engine
    # ========================================================================

    async def check_policy(action_type: str, target: str, confidence: float = 0.9) -> ToolResult:
        """Check if an action is allowed by the policy engine.

        Evaluates the proposed action against the policy engine rules,
        considering the current operation mode and kill switch status.

        Args:
            action_type: Type of action (e.g., "isolate_host", "create_ticket")
            target: Target of the action (e.g., hostname, IP address)
            confidence: Confidence score from AI analysis (0.0 to 1.0, default 0.9)

        Returns:
            ToolResult with:
                - decision: "allowed", "denied", or "requires_approval"
                - reason: Explanation for the decision
                - approval_level: Required approval level (if requires_approval)
                - operation_mode: Current operation mode
                - kill_switch_active: Whether kill switch is engaged
        """
        start_time = time.perf_counter()
        bridge = get_policy_bridge()

        try:
            if bridge is not None:
                result = bridge.check_action(action_type, target, confidence)
                operation_mode = bridge.get_operation_mode()
                kill_switch_active = bridge.is_kill_switch_active()
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Policy check unavailable: policy connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result = _mock_check_action(action_type, target, confidence)
                operation_mode = _mock_get_operation_mode()
                kill_switch_active = _mock_is_kill_switch_active()
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "decision": result.get("decision", "denied"),
                    "reason": result.get("reason"),
                    "approval_level": result.get("approval_level"),
                    "operation_mode": operation_mode,
                    "kill_switch_active": kill_switch_active,
                    "action_type": action_type,
                    "target": target,
                    "confidence": confidence,
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "check_policy_failed",
                action_type=action_type,
                target=target,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Policy check failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="check_policy",
            description=(
                "Check if a proposed action is allowed by the policy engine. "
                "Returns the decision (allowed, denied, or requires_approval), "
                "the current operation mode, and kill switch status. "
                "Use this before taking any significant action to ensure compliance."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "description": (
                            "Type of action to check (e.g., 'isolate_host', "
                            "'create_ticket', 'block_ip', 'disable_user')"
                        ),
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of the action (hostname, IP, user, etc.)",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence score from AI analysis (0.0-1.0)",
                        "default": 0.9,
                    },
                },
                "required": ["action_type", "target"],
            },
            handler=check_policy,
        )
    )

    async def submit_approval(action_type: str, target: str, level: str = "analyst") -> ToolResult:
        """Submit an approval request for an action that requires human approval.

        Call this when check_policy returns "requires_approval" to create
        a formal approval request that can be tracked and decided by humans.

        Args:
            action_type: Type of action requiring approval
            target: Target of the action
            level: Required approval level (analyst, senior, manager, executive)

        Returns:
            ToolResult with:
                - request_id: Unique identifier for tracking the approval
                - status: Current status (always "pending" for new requests)
        """
        start_time = time.perf_counter()
        bridge = get_policy_bridge()

        try:
            if bridge is not None:
                request_id = bridge.submit_approval_request(action_type, target, level)
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Approval submission unavailable: policy connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                request_id = _mock_submit_approval_request(action_type, target, level)
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "request_id": request_id,
                    "status": "pending",
                    "action_type": action_type,
                    "target": target,
                    "approval_level": level,
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "submit_approval_failed",
                action_type=action_type,
                target=target,
                level=level,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Approval submission failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="submit_approval",
            description=(
                "Submit an approval request for an action that requires human approval. "
                "Use this when check_policy returns 'requires_approval'. "
                "Returns a request_id that can be used to track the approval status."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "action_type": {
                        "type": "string",
                        "description": "Type of action requiring approval",
                    },
                    "target": {
                        "type": "string",
                        "description": "Target of the action",
                    },
                    "level": {
                        "type": "string",
                        "description": "Required approval level",
                        "enum": ["analyst", "senior", "manager", "executive"],
                        "default": "analyst",
                    },
                },
                "required": ["action_type", "target"],
            },
            handler=submit_approval,
        )
    )

    async def get_approval_status(request_id: str) -> ToolResult:
        """Check the status of an approval request.

        Use this to poll for the status of a previously submitted
        approval request.

        Args:
            request_id: The unique request ID from submit_approval

        Returns:
            ToolResult with:
                - status: "pending", "approved", "denied", or "expired"
                - decided_by: Who made the decision (if decided)
        """
        start_time = time.perf_counter()
        bridge = get_policy_bridge()

        try:
            if bridge is not None:
                result = bridge.check_approval_status(request_id)
                is_mock = False
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Approval status unavailable: policy connector required when "
                            "mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result = _mock_check_approval_status(request_id)
                is_mock = True

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "request_id": request_id,
                    "status": result.get("status", "expired"),
                    "decided_by": result.get("decided_by"),
                    "is_mock": is_mock,
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "get_approval_status_failed",
                request_id=request_id,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Approval status check failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="get_approval_status",
            description=(
                "Check the status of an approval request. "
                "Returns the current status (pending, approved, denied, or expired) "
                "and who made the decision if it has been decided."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "request_id": {
                        "type": "string",
                        "description": "The unique request ID from submit_approval",
                    },
                },
                "required": ["request_id"],
            },
            handler=get_approval_status,
        )
    )

    # ========================================================================
    # Email Triage Tools
    # ========================================================================

    async def analyze_email(email_data: dict[str, Any]) -> ToolResult:
        """Parse and analyze an email alert for security-relevant information.

        Uses parse_email_alert() from the email analysis module to extract
        headers, URLs, attachments, authentication results, and other
        security-relevant data from email alert JSON.

        Args:
            email_data: Dictionary containing email alert data with fields like:
                - message_id: Unique message identifier
                - subject: Email subject
                - from/sender: Sender address
                - to/recipients: Recipient addresses
                - headers: Raw email headers
                - body_text: Plain text body
                - body_html: HTML body
                - attachments: List of attachment info

        Returns:
            ToolResult with EmailAnalysis as dict including:
                - message_id, subject, sender, sender_display_name
                - recipients, cc, reply_to
                - headers, body_text, body_html
                - urls: List of extracted URLs with domain info
                - attachments: List of attachment info with hashes
                - authentication: SPF, DKIM, DMARC results
        """
        start_time = time.perf_counter()

        try:
            analysis: EmailAnalysis = parse_email_alert(email_data)

            # Convert dataclass to dict for serialization
            result_data = {
                "message_id": analysis.message_id,
                "subject": analysis.subject,
                "sender": analysis.sender,
                "sender_display_name": analysis.sender_display_name,
                "reply_to": analysis.reply_to,
                "recipients": analysis.recipients,
                "cc": analysis.cc,
                "headers": analysis.headers,
                "body_text": analysis.body_text,
                "body_html": analysis.body_html,
                "urls": [
                    {
                        "url": url.url,
                        "domain": url.domain,
                        "display_text": url.display_text,
                        "is_shortened": url.is_shortened,
                        "is_ip_based": url.is_ip_based,
                    }
                    for url in analysis.urls
                ],
                "attachments": [
                    {
                        "filename": att.filename,
                        "content_type": att.content_type,
                        "size_bytes": att.size_bytes,
                        "md5": att.md5,
                        "sha256": att.sha256,
                    }
                    for att in analysis.attachments
                ],
                "received_timestamps": [ts.isoformat() for ts in analysis.received_timestamps],
                "authentication": {
                    "spf": analysis.authentication.spf,
                    "dkim": analysis.authentication.dkim,
                    "dmarc": analysis.authentication.dmarc,
                },
            }

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data=result_data,
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("analyze_email_failed", error=str(e))
            return ToolResult.fail(
                error=f"Email analysis failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="analyze_email",
            description=(
                "Parse and analyze an email alert for security-relevant information. "
                "Extracts sender info, recipients, headers, URLs, attachments, and "
                "email authentication results (SPF, DKIM, DMARC). Use this to "
                "understand the structure and content of a suspicious email."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "email_data": {
                        "type": "object",
                        "description": (
                            "Email alert data containing message_id, subject, "
                            "from/sender, to/recipients, headers, body_text, "
                            "body_html, and attachments"
                        ),
                    }
                },
                "required": ["email_data"],
            },
            handler=analyze_email,
        )
    )

    async def check_phishing_indicators(email_data: dict[str, Any]) -> ToolResult:
        """Analyze email for phishing indicators and calculate risk score.

        Uses analyze_phishing_indicators() from the phishing analysis module
        to detect typosquatting, urgency language, credential requests,
        URL/text mismatches, and other phishing signals.

        Args:
            email_data: Dictionary containing email information. Can be:
                - Raw email data with subject, body, sender_email, etc.
                - Or output from analyze_email with extracted fields

        Returns:
            ToolResult with PhishingIndicators as dict including:
                - typosquat_domains: Detected typosquatting domains
                - urgency_phrases: Urgency language found
                - credential_request_detected: Whether credentials are requested
                - suspicious_urls: List of suspicious URLs
                - url_text_mismatch: Whether display text differs from URL
                - sender_domain_mismatch: Whether sender impersonates another org
                - attachment_risk_level: none/low/medium/high/critical
                - overall_risk_score: 0-100 risk score
                - risk_factors: Human-readable list of risk factors
        """
        start_time = time.perf_counter()

        try:
            # Normalize email_data to the format expected by analyze_phishing_indicators
            normalized_data = _normalize_email_data_for_phishing(email_data)

            indicators: PhishingIndicators = analyze_phishing_indicators(normalized_data)

            # Convert dataclass to dict for serialization
            result_data = {
                "typosquat_domains": [
                    {
                        "suspicious_domain": m.suspicious_domain,
                        "similar_to": m.similar_to,
                        "similarity_score": m.similarity_score,
                        "technique": m.technique,
                    }
                    for m in indicators.typosquat_domains
                ],
                "urgency_phrases": indicators.urgency_phrases,
                "credential_request_detected": indicators.credential_request_detected,
                "suspicious_urls": indicators.suspicious_urls,
                "url_text_mismatch": indicators.url_text_mismatch,
                "sender_domain_mismatch": indicators.sender_domain_mismatch,
                "attachment_risk_level": indicators.attachment_risk_level,
                "overall_risk_score": indicators.overall_risk_score,
                "risk_factors": indicators.risk_factors,
            }

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data=result_data,
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("check_phishing_indicators_failed", error=str(e))
            return ToolResult.fail(
                error=f"Phishing indicator check failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="check_phishing_indicators",
            description=(
                "Analyze an email for phishing indicators and calculate a risk score. "
                "Detects typosquatting domains, urgency language, credential requests, "
                "URL/text mismatches, sender domain impersonation, and risky attachments. "
                "Returns a risk score (0-100) and list of risk factors. Use this to "
                "assess whether an email is likely a phishing attempt."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "email_data": {
                        "type": "object",
                        "description": (
                            "Email data containing subject, body, sender_email, "
                            "sender_display_name, reply_to, urls, attachments. "
                            "Can be raw email data or output from analyze_email."
                        ),
                    }
                },
                "required": ["email_data"],
            },
            handler=check_phishing_indicators,
        )
    )

    async def extract_email_urls(text: str, include_html: bool = True) -> ToolResult:
        """Extract URLs from email content.

        Uses extract_urls() and extract_urls_from_html() from the email
        analysis module to find and normalize URLs in text content.
        Handles defanged URLs (hxxp, [.], etc.) automatically.

        Args:
            text: Text content to extract URLs from.
            include_html: If True and text appears to contain HTML,
                also extract URLs from anchor tags with display text.

        Returns:
            ToolResult with list of ExtractedURL as dicts including:
                - url: The normalized URL
                - domain: Domain portion of the URL
                - display_text: For HTML links, the visible anchor text
                - is_shortened: Whether URL uses a shortening service
                - is_ip_based: Whether URL uses an IP instead of domain
        """
        start_time = time.perf_counter()

        try:
            urls: list[ExtractedURL] = []
            seen_urls: set[str] = set()

            # Check if text contains HTML
            has_html = include_html and ("<a " in text.lower() or "<a>" in text.lower())

            if has_html:
                # Extract from HTML (also extracts plain text URLs)
                html_urls = extract_urls_from_html(text)
                for url in html_urls:
                    if url.url not in seen_urls:
                        seen_urls.add(url.url)
                        urls.append(url)
            else:
                # Extract from plain text only
                text_urls = extract_urls(text)
                for url in text_urls:
                    if url.url not in seen_urls:
                        seen_urls.add(url.url)
                        urls.append(url)

            # Convert to dicts for serialization
            result_data = {
                "urls": [
                    {
                        "url": url.url,
                        "domain": url.domain,
                        "display_text": url.display_text,
                        "is_shortened": url.is_shortened,
                        "is_ip_based": url.is_ip_based,
                    }
                    for url in urls
                ],
                "total_count": len(urls),
                "shortened_count": sum(1 for url in urls if url.is_shortened),
                "ip_based_count": sum(1 for url in urls if url.is_ip_based),
            }

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data=result_data,
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("extract_email_urls_failed", error=str(e))
            return ToolResult.fail(
                error=f"URL extraction failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="extract_email_urls",
            description=(
                "Extract URLs from email content (plain text or HTML). "
                "Handles defanged URLs (hxxp://, [.], [://]) automatically. "
                "Returns normalized URLs with domain info, identifies shortened "
                "URLs (bit.ly, etc.) and IP-based URLs. For HTML, extracts "
                "anchor display text to detect URL/text mismatches."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text content to extract URLs from",
                    },
                    "include_html": {
                        "type": "boolean",
                        "description": "Extract from HTML anchor tags if present (default: true)",
                        "default": True,
                    },
                },
                "required": ["text"],
            },
            handler=extract_email_urls,
        )
    )

    async def check_sender_reputation(sender_email: str) -> ToolResult:
        """Check the reputation of an email sender.

        Performs reputation lookup for the sender email address,
        including domain age, known sender status, and reputation score.

        Args:
            sender_email: The sender's email address to check.

        Returns:
            ToolResult with reputation dict including:
                - sender_email: The email address checked
                - domain: The domain portion of the email
                - score: Reputation score (0-100, higher is better)
                - is_known_sender: Whether sender is in known/trusted list
                - domain_age_days: Age of the domain in days (if available)
                - category: Categorization (trusted, suspicious, unknown, etc.)
                - risk_level: low/medium/high based on reputation
        """
        start_time = time.perf_counter()

        try:
            bridge = get_threat_intel_bridge()
            if bridge is not None:
                domain = _extract_sender_domain(sender_email)
                lookup_result = bridge.lookup_domain(domain)
                result_data = _reputation_from_domain_lookup(sender_email, lookup_result)
            else:
                if not _mock_fallbacks_allowed():
                    execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                    return ToolResult.fail(
                        error=(
                            "Sender reputation unavailable: threat intel connector required "
                            "when mock fallback is disabled"
                        ),
                        execution_time_ms=execution_time_ms,
                    )
                result_data = _mock_check_sender_reputation(sender_email)

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data=result_data,
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error("check_sender_reputation_failed", error=str(e))
            return ToolResult.fail(
                error=f"Sender reputation check failed: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="check_sender_reputation",
            description=(
                "Check the reputation of an email sender. "
                "Returns a reputation score (0-100, higher is better), "
                "whether the sender is in a known/trusted list, domain age, "
                "and risk level. Use this to assess sender trustworthiness "
                "when investigating suspicious emails."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "sender_email": {
                        "type": "string",
                        "description": "The sender's email address to check",
                    },
                },
                "required": ["sender_email"],
            },
            handler=check_sender_reputation,
        )
    )

    # ========================================================================
    # Phishing Response Action Tools
    # ========================================================================

    async def quarantine_email(message_id: str, reason: str) -> ToolResult:
        """Quarantine a suspicious or malicious email.

        Moves the email to quarantine and prevents delivery/access.
        Requires policy approval before execution.

        Args:
            message_id: Unique identifier of the email message
            reason: Reason for quarantining the email

        Returns:
            ToolResult with:
                - success: Whether the action completed
                - action_id: Unique identifier for this action
                - message: Human-readable result message
        """
        start_time = time.perf_counter()

        try:
            # Check policy before taking action
            if not is_action_allowed("quarantine_email", message_id, 0.9):
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                logger.warning(
                    "quarantine_email_denied_by_policy",
                    message_id=message_id,
                    reason=reason,
                )
                return ToolResult.ok(
                    data={
                        "success": False,
                        "action_id": None,
                        "message": "Action denied by policy. Requires approval.",
                    },
                    execution_time_ms=execution_time_ms,
                )

            # Generate action ID
            import uuid

            action_id = f"qe-{uuid.uuid4().hex[:12]}"

            # Mock implementation - log the action
            logger.info(
                "quarantine_email_executed",
                action_id=action_id,
                message_id=message_id,
                reason=reason,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "success": True,
                    "action_id": action_id,
                    "message": f"Email {message_id} quarantined successfully. Reason: {reason}",
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "quarantine_email_failed",
                message_id=message_id,
                reason=reason,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Failed to quarantine email: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="quarantine_email",
            description=(
                "Quarantine a suspicious or malicious email. "
                "Moves the email to quarantine storage and prevents delivery or access. "
                "Requires policy approval. Use this for confirmed phishing emails."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "message_id": {
                        "type": "string",
                        "description": "Unique identifier of the email message to quarantine",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for quarantining (e.g., phishing, malware)",
                    },
                },
                "required": ["message_id", "reason"],
            },
            handler=quarantine_email,
            requires_confirmation=True,
        )
    )

    async def block_sender(sender: str, block_type: str, reason: str) -> ToolResult:
        """Block an email sender or domain.

        Adds the sender or domain to the block list to prevent future emails.
        Domain blocks require higher approval level than email blocks.

        Args:
            sender: Email address or domain to block
            block_type: Type of block - "email" for single address, "domain" for entire domain
            reason: Reason for blocking

        Returns:
            ToolResult with:
                - success: Whether the action completed
                - action_id: Unique identifier for this action
                - blocked: The email/domain that was blocked
        """
        start_time = time.perf_counter()

        try:
            # Validate block_type
            if block_type not in ("email", "domain"):
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.fail(
                    error=f"Invalid block_type: {block_type}. Must be 'email' or 'domain'.",
                    execution_time_ms=execution_time_ms,
                )

            # Domain blocks require higher approval (senior level)
            action_type = "block_sender_domain" if block_type == "domain" else "block_sender_email"

            if not is_action_allowed(action_type, sender, 0.9):
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                approval_note = (
                    "Domain blocks require senior approval." if block_type == "domain" else ""
                )
                logger.warning(
                    "block_sender_denied_by_policy",
                    sender=sender,
                    block_type=block_type,
                    reason=reason,
                )
                return ToolResult.ok(
                    data={
                        "success": False,
                        "action_id": None,
                        "blocked": None,
                        "message": f"Action denied by policy. Requires approval. {approval_note}",
                    },
                    execution_time_ms=execution_time_ms,
                )

            # Generate action ID
            import uuid

            action_id = f"bs-{uuid.uuid4().hex[:12]}"

            # Mock implementation - log the action
            logger.info(
                "block_sender_executed",
                action_id=action_id,
                sender=sender,
                block_type=block_type,
                reason=reason,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "success": True,
                    "action_id": action_id,
                    "blocked": sender,
                    "block_type": block_type,
                    "message": f"Successfully blocked {block_type}: {sender}. Reason: {reason}",
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "block_sender_failed",
                sender=sender,
                block_type=block_type,
                reason=reason,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Failed to block sender: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="block_sender",
            description=(
                "Block an email sender or entire domain. "
                "Use block_type='email' to block a single address, or "
                "block_type='domain' to block all emails from a domain. "
                "Domain blocks require higher approval level."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "sender": {
                        "type": "string",
                        "description": "Email address or domain to block",
                    },
                    "block_type": {
                        "type": "string",
                        "enum": ["email", "domain"],
                        "description": "Block type: email for address, domain for entire domain",
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for blocking the sender",
                    },
                },
                "required": ["sender", "block_type", "reason"],
            },
            handler=block_sender,
            requires_confirmation=True,
        )
    )

    async def notify_user(
        recipient: str,
        notification_type: str,
        subject: str,
        body: str,
    ) -> ToolResult:
        """Send a security notification to a user.

        Sends notifications about phishing attempts, security alerts,
        or actions taken on their behalf.

        Args:
            recipient: Email address of the notification recipient
            notification_type: Type of notification (phishing_warning, security_alert, action_taken)
            subject: Subject line of the notification
            body: Body content of the notification

        Returns:
            ToolResult with:
                - success: Whether the notification was sent
                - notification_id: Unique identifier for tracking
        """
        start_time = time.perf_counter()

        try:
            # Validate notification_type
            valid_types = ("phishing_warning", "security_alert", "action_taken")
            if notification_type not in valid_types:
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.fail(
                    error=f"Invalid notification_type: {notification_type}. "
                    f"Must be one of: {valid_types}",
                    execution_time_ms=execution_time_ms,
                )

            # Generate notification ID
            import uuid

            notification_id = f"notif-{uuid.uuid4().hex[:12]}"

            # Mock implementation - log the notification
            logger.info(
                "notify_user_executed",
                notification_id=notification_id,
                recipient=recipient,
                notification_type=notification_type,
                subject=subject,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "success": True,
                    "notification_id": notification_id,
                    "recipient": recipient,
                    "notification_type": notification_type,
                    "message": f"Notification sent to {recipient}",
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "notify_user_failed",
                recipient=recipient,
                notification_type=notification_type,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Failed to send notification: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="notify_user",
            description=(
                "Send a security notification to a user. "
                "Use for phishing warnings, security alerts, or notifying users "
                "of actions taken on suspicious emails they received."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "description": "Email address of the notification recipient",
                    },
                    "notification_type": {
                        "type": "string",
                        "enum": ["phishing_warning", "security_alert", "action_taken"],
                        "description": "Type of notification to send",
                    },
                    "subject": {
                        "type": "string",
                        "description": "Subject line of the notification",
                    },
                    "body": {
                        "type": "string",
                        "description": "Body content of the notification message",
                    },
                },
                "required": ["recipient", "notification_type", "subject", "body"],
            },
            handler=notify_user,
        )
    )

    async def create_security_ticket(
        title: str,
        description: str,
        severity: str,
        indicators: list[str],
    ) -> ToolResult:
        """Create a security incident ticket.

        Creates a ticket in the ticketing system for tracking and
        investigation of security incidents.

        Args:
            title: Title/summary of the security ticket
            description: Detailed description of the incident
            severity: Severity level (critical, high, medium, low)
            indicators: List of IOCs or indicators related to the incident

        Returns:
            ToolResult with:
                - success: Whether the ticket was created
                - ticket_id: Unique ticket identifier
                - ticket_url: URL to access the ticket
        """
        start_time = time.perf_counter()

        try:
            # Validate severity
            valid_severities = ("critical", "high", "medium", "low")
            if severity.lower() not in valid_severities:
                execution_time_ms = int((time.perf_counter() - start_time) * 1000)
                return ToolResult.fail(
                    error=f"Invalid severity: {severity}. Must be one of: {valid_severities}",
                    execution_time_ms=execution_time_ms,
                )

            # Generate ticket ID
            import uuid

            ticket_id = f"SEC-{uuid.uuid4().hex[:8].upper()}"
            ticket_url = f"https://tickets.example.com/security/{ticket_id}"

            # Mock implementation - log the ticket creation
            logger.info(
                "create_security_ticket_executed",
                ticket_id=ticket_id,
                title=title,
                severity=severity,
                indicators_count=len(indicators) if indicators else 0,
            )

            execution_time_ms = int((time.perf_counter() - start_time) * 1000)

            return ToolResult.ok(
                data={
                    "success": True,
                    "ticket_id": ticket_id,
                    "ticket_url": ticket_url,
                    "title": title,
                    "severity": severity.lower(),
                    "indicators_count": len(indicators) if indicators else 0,
                    "message": f"Security ticket {ticket_id} created successfully",
                },
                execution_time_ms=execution_time_ms,
            )
        except Exception as e:
            execution_time_ms = int((time.perf_counter() - start_time) * 1000)
            logger.error(
                "create_security_ticket_failed",
                title=title,
                severity=severity,
                error=str(e),
            )
            return ToolResult.fail(
                error=f"Failed to create security ticket: {str(e)}",
                execution_time_ms=execution_time_ms,
            )

    registry.register(
        Tool(
            name="create_security_ticket",
            description=(
                "Create a security incident ticket for tracking and investigation. "
                "Include relevant indicators of compromise (IOCs) such as malicious "
                "URLs, sender addresses, file hashes, and IP addresses."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Title/summary of the security ticket",
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the incident",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low"],
                        "description": "Severity level of the incident",
                    },
                    "indicators": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of indicators of compromise (IOCs)",
                    },
                },
                "required": ["title", "description", "severity", "indicators"],
            },
            handler=create_security_ticket,
        )
    )

    return registry
