"""Action tool definitions for agentic response."""

from __future__ import annotations

import re
from typing import Any

import structlog
from pydantic import BaseModel, Field

from tw_ai.agents.response_planner import RiskLevel

logger = structlog.get_logger()


class ParameterSpec(BaseModel):
    """Specification for a tool parameter."""

    name: str
    param_type: str  # string, integer, ip_address, hostname, email, boolean
    description: str = ""
    required: bool = True
    default: Any = None
    validation_pattern: str | None = None


class ActionTool(BaseModel):
    """An action tool available for automated response."""

    name: str
    description: str
    category: str  # containment, eradication, recovery, investigation, notification
    parameters: list[ParameterSpec] = Field(default_factory=list)
    requires_approval: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    estimated_duration_secs: int = 30
    reversible: bool = False
    rollback_tool: str | None = None

    def validate_params(self, params: dict[str, Any]) -> tuple[bool, list[str]]:
        """Validate parameters against specs."""
        errors: list[str] = []

        # Check required params
        for spec in self.parameters:
            if spec.required and spec.name not in params:
                if spec.default is None:
                    errors.append(f"Missing required parameter: '{spec.name}'")
                continue

            if spec.name not in params:
                continue

            value = params[spec.name]

            # Type validation
            if spec.param_type == "integer":
                if not isinstance(value, int):
                    try:
                        int(value)
                    except (ValueError, TypeError):
                        errors.append(
                            f"Parameter '{spec.name}' must be an integer,"
                            f" got {type(value).__name__}"
                        )
            elif spec.param_type == "boolean":
                if not isinstance(value, bool):
                    errors.append(
                        f"Parameter '{spec.name}' must be a boolean, got {type(value).__name__}"
                    )
            elif spec.param_type == "ip_address":
                if not isinstance(value, str) or not _is_valid_ip(value):
                    errors.append(f"Parameter '{spec.name}' must be a valid IP address")
            elif spec.param_type == "hostname":
                if not isinstance(value, str) or not _is_valid_hostname(value):
                    errors.append(f"Parameter '{spec.name}' must be a valid hostname")
            elif spec.param_type == "email":
                if not isinstance(value, str) or not _is_valid_email(value):
                    errors.append(f"Parameter '{spec.name}' must be a valid email address")
            elif spec.param_type == "string":
                if not isinstance(value, str):
                    errors.append(
                        f"Parameter '{spec.name}' must be a string, got {type(value).__name__}"
                    )

            # Pattern validation
            if spec.validation_pattern and isinstance(value, str):
                if not re.match(spec.validation_pattern, value):
                    errors.append(
                        f"Parameter '{spec.name}' does not match"
                        f" pattern '{spec.validation_pattern}'"
                    )

        # Check for unknown params
        known_names = {spec.name for spec in self.parameters}
        for key in params:
            if key not in known_names:
                errors.append(f"Unknown parameter: '{key}'")

        return len(errors) == 0, errors


def _is_valid_ip(value: str) -> bool:
    """Basic IPv4/IPv6 validation."""
    # IPv4
    parts = value.split(".")
    if len(parts) == 4:
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    # IPv6 basic check
    if ":" in value:
        try:
            import ipaddress

            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
    return False


def _is_valid_hostname(value: str) -> bool:
    """Basic hostname validation."""
    if not value or len(value) > 253:
        return False
    pattern = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )
    return bool(pattern.match(value))


def _is_valid_email(value: str) -> bool:
    """Basic email validation."""
    pattern = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")
    return bool(pattern.match(value))


class ActionToolRegistry:
    """Registry of available action tools."""

    def __init__(self) -> None:
        self._tools: dict[str, ActionTool] = {}
        self._register_defaults()

    def register(self, tool: ActionTool) -> None:
        """Register a new action tool."""
        self._tools[tool.name] = tool

    def get(self, name: str) -> ActionTool | None:
        """Get a tool by name."""
        return self._tools.get(name)

    def list_tools(self, category: str | None = None) -> list[ActionTool]:
        """List available tools, optionally filtered by category."""
        tools = list(self._tools.values())
        if category is not None:
            tools = [t for t in tools if t.category == category]
        return sorted(tools, key=lambda t: t.name)

    def list_categories(self) -> list[str]:
        """List all unique categories."""
        return sorted({t.category for t in self._tools.values()})

    def _register_defaults(self) -> None:
        """Register built-in action tools."""
        defaults = [
            # === Containment ===
            ActionTool(
                name="isolate_host",
                description="Isolate a host from the network to prevent lateral movement",
                category="containment",
                parameters=[
                    ParameterSpec(
                        name="hostname",
                        param_type="hostname",
                        description="Hostname of the target machine",
                    ),
                    ParameterSpec(
                        name="reason",
                        param_type="string",
                        description="Reason for isolation",
                        required=False,
                        default="Automated response",
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=60,
                reversible=True,
                rollback_tool="unisolate_host",
            ),
            ActionTool(
                name="unisolate_host",
                description="Remove network isolation from a host",
                category="recovery",
                parameters=[
                    ParameterSpec(
                        name="hostname",
                        param_type="hostname",
                        description="Hostname of the target machine",
                    ),
                    ParameterSpec(
                        name="reason",
                        param_type="string",
                        description="Reason for unisolation",
                        required=False,
                        default="Automated recovery",
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=60,
                reversible=True,
                rollback_tool="isolate_host",
            ),
            ActionTool(
                name="block_ip",
                description="Block an IP address at the firewall level",
                category="containment",
                parameters=[
                    ParameterSpec(
                        name="ip_address",
                        param_type="ip_address",
                        description="IP address to block",
                    ),
                    ParameterSpec(
                        name="direction",
                        param_type="string",
                        description="Block direction: inbound, outbound, both",
                        required=False,
                        default="both",
                    ),
                    ParameterSpec(
                        name="duration_hours",
                        param_type="integer",
                        description="Duration of block in hours (0=permanent)",
                        required=False,
                        default=24,
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.MEDIUM,
                estimated_duration_secs=30,
                reversible=True,
                rollback_tool=None,  # Unblock is a separate manual action
            ),
            ActionTool(
                name="block_domain",
                description="Block a domain via DNS sinkhole or proxy",
                category="containment",
                parameters=[
                    ParameterSpec(
                        name="domain",
                        param_type="hostname",
                        description="Domain to block",
                    ),
                    ParameterSpec(
                        name="include_subdomains",
                        param_type="boolean",
                        description="Also block subdomains",
                        required=False,
                        default=True,
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.MEDIUM,
                estimated_duration_secs=30,
                reversible=True,
            ),
            ActionTool(
                name="block_hash",
                description="Block a file hash across all endpoints via EDR",
                category="containment",
                parameters=[
                    ParameterSpec(
                        name="hash_value",
                        param_type="string",
                        description="SHA256 hash of the file to block",
                        validation_pattern=r"^[a-fA-F0-9]{64}$",
                    ),
                    ParameterSpec(
                        name="hash_type",
                        param_type="string",
                        description="Hash type (sha256, sha1, md5)",
                        required=False,
                        default="sha256",
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.MEDIUM,
                estimated_duration_secs=30,
                reversible=True,
            ),
            ActionTool(
                name="quarantine_email",
                description="Quarantine an email from all recipients' mailboxes",
                category="containment",
                parameters=[
                    ParameterSpec(
                        name="message_id",
                        param_type="string",
                        description="Email message ID to quarantine",
                    ),
                    ParameterSpec(
                        name="sender",
                        param_type="email",
                        description="Sender email address",
                        required=False,
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.MEDIUM,
                estimated_duration_secs=45,
                reversible=True,
            ),
            # === Eradication ===
            ActionTool(
                name="disable_user",
                description="Disable a user account to prevent unauthorized access",
                category="eradication",
                parameters=[
                    ParameterSpec(
                        name="username",
                        param_type="string",
                        description="Username to disable",
                    ),
                    ParameterSpec(
                        name="reason",
                        param_type="string",
                        description="Reason for disabling",
                        required=False,
                        default="Automated response",
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=30,
                reversible=True,
                rollback_tool="enable_user",
            ),
            ActionTool(
                name="enable_user",
                description="Re-enable a previously disabled user account",
                category="recovery",
                parameters=[
                    ParameterSpec(
                        name="username",
                        param_type="string",
                        description="Username to enable",
                    ),
                    ParameterSpec(
                        name="reason",
                        param_type="string",
                        description="Reason for re-enabling",
                        required=False,
                        default="Automated recovery",
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=30,
                reversible=True,
                rollback_tool="disable_user",
            ),
            ActionTool(
                name="reset_password",
                description="Force-reset a user's password",
                category="eradication",
                parameters=[
                    ParameterSpec(
                        name="username",
                        param_type="string",
                        description="Username whose password to reset",
                    ),
                    ParameterSpec(
                        name="notify_user",
                        param_type="boolean",
                        description="Notify user of password reset",
                        required=False,
                        default=True,
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=30,
                reversible=False,
            ),
            ActionTool(
                name="revoke_sessions",
                description="Revoke all active sessions for a user",
                category="eradication",
                parameters=[
                    ParameterSpec(
                        name="username",
                        param_type="string",
                        description="Username whose sessions to revoke",
                    ),
                ],
                requires_approval=True,
                risk_level=RiskLevel.HIGH,
                estimated_duration_secs=15,
                reversible=False,
            ),
            # === Investigation ===
            ActionTool(
                name="search_logs",
                description="Search SIEM logs for specific indicators or patterns",
                category="investigation",
                parameters=[
                    ParameterSpec(
                        name="query",
                        param_type="string",
                        description="Search query or indicator to look for",
                    ),
                    ParameterSpec(
                        name="time_range_hours",
                        param_type="integer",
                        description="How many hours back to search",
                        required=False,
                        default=24,
                    ),
                    ParameterSpec(
                        name="max_results",
                        param_type="integer",
                        description="Maximum results to return",
                        required=False,
                        default=100,
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.LOW,
                estimated_duration_secs=120,
                reversible=False,
            ),
            ActionTool(
                name="scan_host",
                description="Run an on-demand malware scan on a host",
                category="investigation",
                parameters=[
                    ParameterSpec(
                        name="hostname",
                        param_type="hostname",
                        description="Hostname to scan",
                    ),
                    ParameterSpec(
                        name="scan_type",
                        param_type="string",
                        description="Scan type: quick, full, custom",
                        required=False,
                        default="quick",
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.LOW,
                estimated_duration_secs=300,
                reversible=False,
            ),
            # === Notification ===
            ActionTool(
                name="create_ticket",
                description="Create an incident tracking ticket in the ITSM system",
                category="notification",
                parameters=[
                    ParameterSpec(
                        name="title",
                        param_type="string",
                        description="Ticket title",
                        required=False,
                        default="Security Incident",
                    ),
                    ParameterSpec(
                        name="description",
                        param_type="string",
                        description="Ticket description",
                        required=False,
                        default="",
                    ),
                    ParameterSpec(
                        name="priority",
                        param_type="string",
                        description="Ticket priority: low, medium, high, critical",
                        required=False,
                        default="medium",
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.LOW,
                estimated_duration_secs=15,
                reversible=False,
            ),
            ActionTool(
                name="notify_user",
                description="Send a notification to a user about a security event",
                category="notification",
                parameters=[
                    ParameterSpec(
                        name="recipient",
                        param_type="string",
                        description="User or group to notify (email/username/channel)",
                    ),
                    ParameterSpec(
                        name="message",
                        param_type="string",
                        description="Notification message",
                    ),
                    ParameterSpec(
                        name="channel",
                        param_type="string",
                        description="Notification channel: email, slack, teams",
                        required=False,
                        default="email",
                    ),
                ],
                requires_approval=False,
                risk_level=RiskLevel.LOW,
                estimated_duration_secs=10,
                reversible=False,
            ),
        ]

        for tool in defaults:
            self.register(tool)
