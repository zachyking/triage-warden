"""Tool definitions and registry for the ReAct agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable, Optional
import time

import structlog

from tw_ai.llm.base import ToolDefinition

logger = structlog.get_logger()

# =============================================================================
# Bridge Imports with Graceful Fallback
# =============================================================================

# Try to import bridges from the Rust PyO3 bridge
_THREAT_INTEL_BRIDGE_AVAILABLE = False
_EDR_BRIDGE_AVAILABLE = False
_SIEM_BRIDGE_AVAILABLE = False
ThreatIntelBridge = None
EDRBridge = None
SIEMBridge = None

try:
    from tw_bridge import ThreatIntelBridge
    _THREAT_INTEL_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.ThreatIntelBridge available")
except ImportError:
    logger.warning("tw_bridge.ThreatIntelBridge not available, using mock fallback")

try:
    from tw_bridge import EDRBridge
    _EDR_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.EDRBridge available")
except ImportError:
    logger.warning("tw_bridge.EDRBridge not available, using mock fallback")

try:
    from tw_bridge import SIEMBridge
    _SIEM_BRIDGE_AVAILABLE = True
    logger.info("tw_bridge.SIEMBridge available")
except ImportError:
    logger.warning("tw_bridge.SIEMBridge not available, using mock fallback")


# =============================================================================
# ToolResult Dataclass
# =============================================================================


@dataclass
class ToolResult:
    """Result of a tool execution."""

    success: bool
    data: "dict[str, Any]" = field(default_factory=dict)
    error: "Optional[str]" = None
    execution_time_ms: int = 0

    @classmethod
    def ok(cls, data: "dict[str, Any]", execution_time_ms: int = 0) -> "ToolResult":
        """Create a successful result."""
        return cls(success=True, data=data, execution_time_ms=execution_time_ms)

    @classmethod
    def fail(cls, error: str, execution_time_ms: int = 0) -> "ToolResult":
        """Create a failed result."""
        return cls(success=False, error=error, execution_time_ms=execution_time_ms)


# =============================================================================
# Singleton Bridge Instances
# =============================================================================

_threat_intel_bridge: Any = None
_edr_bridge: Any = None
_siem_bridge: Any = None


def get_threat_intel_bridge() -> Any:
    """Get or create the ThreatIntel bridge instance."""
    global _threat_intel_bridge
    if _threat_intel_bridge is None and _THREAT_INTEL_BRIDGE_AVAILABLE:
        try:
            _threat_intel_bridge = ThreatIntelBridge("mock")
            logger.info("ThreatIntelBridge initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize ThreatIntelBridge", error=str(e))
    return _threat_intel_bridge


def get_edr_bridge() -> Any:
    """Get or create the EDR bridge instance."""
    global _edr_bridge
    if _edr_bridge is None and _EDR_BRIDGE_AVAILABLE:
        try:
            _edr_bridge = EDRBridge("mock", with_sample_data=True)
            logger.info("EDRBridge initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize EDRBridge", error=str(e))
    return _edr_bridge


def get_siem_bridge() -> Any:
    """Get or create the SIEM bridge instance."""
    global _siem_bridge
    if _siem_bridge is None and _SIEM_BRIDGE_AVAILABLE:
        try:
            _siem_bridge = SIEMBridge("mock", with_sample_data=True)
            logger.info("SIEMBridge initialized successfully")
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
        """Execute a tool by name with the given arguments."""
        tool = self._tools.get(name)
        if not tool:
            raise ValueError(f"Tool not found: {name}")

        logger.debug("tool_execute", name=name, arguments=arguments)
        return await tool.handler(**arguments)


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

    async def search_siem(query: str, hours: int = 24, limit: int = 100) -> dict[str, Any]:
        """Search SIEM logs using the bridge or mock fallback.

        Args:
            query: Search query string (supports keywords like 'login_failure', 'malware', etc.)
            hours: Number of hours to search back (default: 24)
            limit: Maximum number of events to return (default: 100)

        Returns:
            dict containing:
                - events: List of matching events (formatted for LLM readability)
                - events_raw: List of raw event data
                - total_count: Total number of matching events
                - search_stats: Search execution statistics
                - source: Data source identifier
        """
        bridge = get_siem_bridge()

        if bridge is not None:
            try:
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

                return {
                    "events": formatted_events,
                    "events_raw": raw_events,
                    "total_count": total_count,
                    "search_stats": search_stats,
                    "source": "siem_bridge",
                }
            except Exception as e:
                logger.error("search_siem_bridge_error", error=str(e), query=query)
                # Fall through to mock

        # Mock fallback
        logger.debug("search_siem_mock", query=query, hours=hours, limit=limit)
        return {
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
            "source": "mock",
        }

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

    async def get_recent_alerts(limit: int = 10) -> dict[str, Any]:
        """Get recent alerts from the SIEM using the bridge or mock fallback.

        Args:
            limit: Maximum number of alerts to return (default: 10)

        Returns:
            dict containing:
                - alerts: List of alert summaries (formatted for LLM readability)
                - alerts_raw: List of raw alert data
                - total_count: Total number of alerts returned
                - source: Data source identifier
        """
        bridge = get_siem_bridge()

        if bridge is not None:
            try:
                logger.debug("get_recent_alerts_bridge", limit=limit)
                raw_alerts = bridge.get_recent_alerts(limit)

                # Format alerts for LLM readability
                formatted_alerts = [_format_alert_for_llm(a) for a in raw_alerts]

                return {
                    "alerts": formatted_alerts,
                    "alerts_raw": raw_alerts,
                    "total_count": len(raw_alerts),
                    "source": "siem_bridge",
                }
            except Exception as e:
                logger.error("get_recent_alerts_bridge_error", error=str(e))
                # Fall through to mock

        # Mock fallback
        logger.debug("get_recent_alerts_mock", limit=limit)
        return {
            "alerts": [],
            "alerts_raw": [],
            "total_count": 0,
            "source": "mock",
        }

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

    async def get_host_info(hostname: str) -> dict[str, Any]:
        """Get host information from EDR.

        Returns host details including OS, status, and isolation state.
        Uses the PyO3 bridge when available, otherwise returns mock data.
        """
        bridge = get_edr_bridge()
        if bridge is not None:
            try:
                result = bridge.get_host_info(hostname)
                # Format for LLM readability
                return _format_host_info_for_llm(result)
            except Exception as e:
                logger.warning(
                    "EDR bridge get_host_info failed, using mock",
                    hostname=hostname,
                    error=str(e),
                )

        # Mock fallback
        return {
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
            "source": "mock",
        }

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

    async def get_detections(hostname: str, hours: int = 24) -> dict[str, Any]:
        """Get recent detections/alerts for a host.

        Returns detections with severity, MITRE techniques, and process info.
        """
        bridge = get_edr_bridge()
        if bridge is not None:
            try:
                result = bridge.get_detections(hostname)
                return _format_detections_for_llm(result, hostname)
            except Exception as e:
                logger.warning(
                    "EDR bridge get_detections failed, using mock",
                    hostname=hostname,
                    error=str(e),
                )

        # Mock fallback with realistic detection data
        return {
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
            "source": "mock",
        }

    def _format_detections_for_llm(data: list[dict], hostname: str) -> dict[str, Any]:
        """Format detections for LLM readability."""
        formatted = []
        for det in data:
            formatted.append({
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
            })
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

    async def get_processes(hostname: str, hours: int = 24) -> dict[str, Any]:
        """Get process list for a host.

        Returns running processes with name, command line, user, and parent info.
        """
        bridge = get_edr_bridge()
        if bridge is not None:
            try:
                result = bridge.get_processes(hostname, hours)
                return _format_processes_for_llm(result, hostname, hours)
            except Exception as e:
                logger.warning(
                    "EDR bridge get_processes failed, using mock",
                    hostname=hostname,
                    error=str(e),
                )

        # Mock fallback with realistic process data
        return {
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
            "source": "mock",
        }

    def _format_processes_for_llm(
        data: list[dict], hostname: str, hours: int
    ) -> dict[str, Any]:
        """Format process list for LLM readability."""
        formatted = []
        for proc in data:
            formatted.append({
                "pid": proc.get("pid", 0),
                "name": proc.get("name", "unknown"),
                "command_line": proc.get("command_line", ""),
                "user": proc.get("user", ""),
                "parent_pid": proc.get("parent_pid", 0),
                "parent_name": proc.get("parent_name", ""),
                "start_time": proc.get("start_time", ""),
                "hash": proc.get("hash", ""),
            })
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

    async def get_network_connections(hostname: str, hours: int = 24) -> dict[str, Any]:
        """Get network connections for a host.

        Returns connections with destination IP, port, and associated process.
        """
        bridge = get_edr_bridge()
        if bridge is not None:
            try:
                result = bridge.get_network_connections(hostname, hours)
                return _format_network_connections_for_llm(result, hostname, hours)
            except Exception as e:
                logger.warning(
                    "EDR bridge get_network_connections failed, using mock",
                    hostname=hostname,
                    error=str(e),
                )

        # Mock fallback with realistic network data
        return {
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
            "source": "mock",
        }

    def _format_network_connections_for_llm(
        data: list[dict], hostname: str, hours: int
    ) -> dict[str, Any]:
        """Format network connections for LLM readability."""
        formatted = []
        for conn in data:
            formatted.append({
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
            })
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

    async def map_to_mitre(description: str) -> dict[str, Any]:
        """Map attack behavior to MITRE ATT&CK techniques."""
        return {
            "techniques": [],
            "tactics": [],
            "description": description,
            "source": "mock",
        }

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

    return registry
