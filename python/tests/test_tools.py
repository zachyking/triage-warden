"""Unit tests for SIEM and EDR tools in the ReAct agent."""

from __future__ import annotations

import sys
import importlib.util
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

# ============================================================================
# Mock modules for Python 3.9 compatibility
# ============================================================================

# Create mock ToolDefinition to avoid importing tw_ai.llm.base with 3.10+ syntax
@dataclass
class MockToolDefinition:
    """Mock ToolDefinition for testing."""
    name: str
    description: str
    parameters: dict


class _MockLLMBase:
    """Mock tw_ai.llm.base module."""
    ToolDefinition = MockToolDefinition


# Pre-register mock modules before loading tools.py
sys.modules["tw_ai.llm.base"] = _MockLLMBase()
sys.modules["tw_ai.llm"] = MagicMock()
sys.modules["tw_ai"] = MagicMock()


# Direct module loading to avoid import issues
_base_path = Path(__file__).parent.parent / "tw_ai" / "agents"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load tools module with mocked dependencies
_tools = _load_module("tw_ai.agents.tools", _base_path / "tools.py")
Tool = _tools.Tool
ToolResult = _tools.ToolResult
ToolRegistry = _tools.ToolRegistry
create_triage_tools = _tools.create_triage_tools
_format_event_for_llm = _tools._format_event_for_llm
_format_alert_for_llm = _tools._format_alert_for_llm
get_threat_intel_bridge = _tools.get_threat_intel_bridge
is_threat_intel_bridge_available = _tools.is_threat_intel_bridge_available
get_siem_bridge = _tools.get_siem_bridge
is_siem_bridge_available = _tools.is_siem_bridge_available
get_edr_bridge = _tools.get_edr_bridge
is_edr_bridge_available = _tools.is_edr_bridge_available
_mock_hash_lookup = _tools._mock_hash_lookup
_mock_ip_lookup = _tools._mock_ip_lookup
_mock_domain_lookup = _tools._mock_domain_lookup


# ============================================================================
# Test Data
# ============================================================================

SAMPLE_SIEM_EVENT = {
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "login_failure",
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.5",
    "user": "jdoe",
    "hostname": "workstation-001",
    "message": "Failed login attempt - invalid password",
    "severity": "high",
    "process_name": "sshd",
}

SAMPLE_SIEM_EVENT_MINIMAL = {
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "network_connection",
}

SAMPLE_ALERT = {
    "id": "ALERT-001",
    "name": "Brute Force Attack Detected",
    "severity": "high",
    "timestamp": "2024-01-15T10:35:00Z",
    "description": "Multiple failed login attempts detected from single source",
    "details": {
        "source_ip": "192.168.1.100",
        "target_user": "admin",
        "attempt_count": 50,
    },
}

SAMPLE_ALERT_MINIMAL = {
    "id": "ALERT-002",
    "name": "Suspicious Activity",
    "severity": "medium",
    "timestamp": "2024-01-15T11:00:00Z",
}

MOCK_SEARCH_RESULT = {
    "search_id": "search-123",
    "total_count": 5,
    "events": [SAMPLE_SIEM_EVENT, SAMPLE_SIEM_EVENT_MINIMAL],
    "stats": {
        "execution_time_ms": 150,
        "events_scanned": 1000,
    },
}


# ============================================================================
# Event Formatting Tests
# ============================================================================


class TestFormatEventForLLM:
    """Tests for _format_event_for_llm function."""

    def test_format_full_event(self):
        """Test formatting a complete event."""
        result = _format_event_for_llm(SAMPLE_SIEM_EVENT)

        assert "2024-01-15T10:30:00Z" in result
        assert "HIGH" in result
        assert "login_failure" in result
        assert "192.168.1.100" in result
        assert "10.0.0.5" in result
        assert "jdoe" in result
        assert "workstation-001" in result
        assert "Failed login attempt" in result
        assert "sshd" in result

    def test_format_minimal_event(self):
        """Test formatting an event with minimal fields."""
        result = _format_event_for_llm(SAMPLE_SIEM_EVENT_MINIMAL)

        assert "2024-01-15T10:30:00Z" in result
        assert "network_connection" in result
        assert "N/A" in result  # Missing fields show N/A

    def test_format_event_with_alt_field_names(self):
        """Test formatting with alternative field names."""
        event = {
            "timestamp": "2024-01-15T10:30:00Z",
            "type": "process_start",  # 'type' instead of 'event_type'
            "src_ip": "10.0.0.1",  # 'src_ip' instead of 'source_ip'
            "dst_ip": "10.0.0.2",  # 'dst_ip' instead of 'destination_ip'
            "username": "alice",  # 'username' instead of 'user'
            "host": "server-001",  # 'host' instead of 'hostname'
            "raw_log": "Process started",  # 'raw_log' instead of 'message'
        }
        result = _format_event_for_llm(event)

        assert "process_start" in result
        assert "10.0.0.1" in result
        assert "10.0.0.2" in result
        assert "alice" in result
        assert "server-001" in result
        assert "Process started" in result

    def test_format_event_includes_additional_fields(self):
        """Test that additional fields are included when present."""
        event = {
            "timestamp": "2024-01-15T10:30:00Z",
            "event_type": "process_execution",
            "command_line": "powershell -enc ABC123",
            "file_path": "/tmp/malware.exe",
            "action": "blocked",
        }
        result = _format_event_for_llm(event)

        assert "powershell -enc ABC123" in result
        assert "/tmp/malware.exe" in result
        assert "blocked" in result


class TestFormatAlertForLLM:
    """Tests for _format_alert_for_llm function."""

    def test_format_full_alert(self):
        """Test formatting a complete alert."""
        result = _format_alert_for_llm(SAMPLE_ALERT)

        assert "ALERT-001" in result
        assert "Brute Force Attack Detected" in result
        assert "HIGH" in result
        assert "2024-01-15T10:35:00Z" in result
        assert "Multiple failed login attempts" in result
        assert "source_ip" in result
        assert "192.168.1.100" in result
        assert "attempt_count" in result
        assert "50" in result

    def test_format_minimal_alert(self):
        """Test formatting an alert with minimal fields."""
        result = _format_alert_for_llm(SAMPLE_ALERT_MINIMAL)

        assert "ALERT-002" in result
        assert "Suspicious Activity" in result
        assert "MEDIUM" in result
        assert "2024-01-15T11:00:00Z" in result

    def test_format_alert_with_alt_field_names(self):
        """Test formatting with alternative field names."""
        alert = {
            "alert_id": "ALT-001",  # 'alert_id' instead of 'id'
            "title": "Test Alert",  # 'title' instead of 'name'
            "severity": "low",
            "created_at": "2024-01-15T12:00:00Z",  # 'created_at' instead of 'timestamp'
        }
        result = _format_alert_for_llm(alert)

        assert "ALT-001" in result
        assert "Test Alert" in result
        assert "LOW" in result
        assert "2024-01-15T12:00:00Z" in result


# ============================================================================
# Tool Registry Tests
# ============================================================================


class TestToolRegistry:
    """Tests for ToolRegistry class."""

    def test_registry_contains_siem_tools(self):
        """Test that registry includes SIEM tools."""
        registry = create_triage_tools()
        tools = registry.list_tools()

        assert "search_siem" in tools
        assert "get_recent_alerts" in tools

    def test_search_siem_tool_definition(self):
        """Test search_siem tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("search_siem")

        assert tool is not None
        assert tool.name == "search_siem"
        assert "query" in tool.parameters["properties"]
        assert "hours" in tool.parameters["properties"]
        assert "limit" in tool.parameters["properties"]
        assert tool.parameters["properties"]["hours"]["default"] == 24
        assert tool.parameters["properties"]["limit"]["default"] == 100
        assert tool.parameters["required"] == ["query"]

    def test_get_recent_alerts_tool_definition(self):
        """Test get_recent_alerts tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("get_recent_alerts")

        assert tool is not None
        assert tool.name == "get_recent_alerts"
        assert "limit" in tool.parameters["properties"]
        assert tool.parameters["properties"]["limit"]["default"] == 10
        assert tool.parameters["required"] == []


# ============================================================================
# SIEM Search Tool Tests
# ============================================================================


class TestSearchSIEMTool:
    """Tests for search_siem tool functionality."""

    @pytest.mark.asyncio
    async def test_search_siem_mock_fallback(self):
        """Test search_siem returns mock data when bridge unavailable."""
        # Ensure bridge is not available for this test
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute("search_siem", {"query": "login_failure"})

                assert result["source"] == "mock"
                assert result["total_count"] == 0
                assert result["events"] == []
                assert result["events_raw"] == []
                assert "search_stats" in result
                assert result["search_stats"]["query"] == "login_failure"
                assert result["search_stats"]["timerange_hours"] == 24
                assert result["search_stats"]["limit_applied"] == 100

    @pytest.mark.asyncio
    async def test_search_siem_with_custom_hours(self):
        """Test search_siem with custom hours parameter."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "search_siem", {"query": "malware", "hours": 48}
                )

                assert result["search_stats"]["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_search_siem_with_custom_limit(self):
        """Test search_siem with custom limit parameter."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "search_siem", {"query": "test", "limit": 50}
                )

                assert result["search_stats"]["limit_applied"] == 50

    @pytest.mark.asyncio
    async def test_search_siem_with_bridge(self):
        """Test search_siem uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.search.return_value = MOCK_SEARCH_RESULT

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "search_siem", {"query": "login_failure", "hours": 24}
                    )

                    mock_bridge.search.assert_called_once_with("login_failure", 24)
                    assert result["source"] == "siem_bridge"
                    assert result["total_count"] == 5
                    assert len(result["events"]) == 2
                    assert len(result["events_raw"]) == 2
                    assert result["search_stats"]["search_id"] == "search-123"
                    assert result["search_stats"]["execution_time_ms"] == 150

    @pytest.mark.asyncio
    async def test_search_siem_applies_limit_to_events(self):
        """Test that limit is applied to returned events."""
        mock_result = {
            "search_id": "test",
            "total_count": 100,
            "events": [{"event": i} for i in range(100)],
            "stats": {},
        }
        mock_bridge = MagicMock()
        mock_bridge.search.return_value = mock_result

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "search_siem", {"query": "test", "limit": 10}
                    )

                    assert len(result["events_raw"]) == 10
                    assert result["total_count"] == 100  # Original count preserved

    @pytest.mark.asyncio
    async def test_search_siem_bridge_error_fallback(self):
        """Test search_siem falls back to mock on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.search.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "search_siem", {"query": "test"}
                    )

                    assert result["source"] == "mock"
                    assert result["total_count"] == 0

    @pytest.mark.asyncio
    async def test_search_siem_formats_events(self):
        """Test that events are formatted for LLM readability."""
        mock_bridge = MagicMock()
        mock_bridge.search.return_value = MOCK_SEARCH_RESULT

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "search_siem", {"query": "test"}
                    )

                    # Check formatted events are strings
                    assert all(isinstance(e, str) for e in result["events"])
                    # Check raw events are dicts
                    assert all(isinstance(e, dict) for e in result["events_raw"])
                    # Check formatted event contains expected data
                    assert "login_failure" in result["events"][0]


# ============================================================================
# Get Recent Alerts Tool Tests
# ============================================================================


class TestGetRecentAlertsTool:
    """Tests for get_recent_alerts tool functionality."""

    @pytest.mark.asyncio
    async def test_get_recent_alerts_mock_fallback(self):
        """Test get_recent_alerts returns mock data when bridge unavailable."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute("get_recent_alerts", {})

                assert result["source"] == "mock"
                assert result["total_count"] == 0
                assert result["alerts"] == []
                assert result["alerts_raw"] == []

    @pytest.mark.asyncio
    async def test_get_recent_alerts_with_default_limit(self):
        """Test get_recent_alerts uses default limit."""
        mock_alerts = [SAMPLE_ALERT, SAMPLE_ALERT_MINIMAL]
        mock_bridge = MagicMock()
        mock_bridge.get_recent_alerts.return_value = mock_alerts

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute("get_recent_alerts", {})

                    mock_bridge.get_recent_alerts.assert_called_once_with(10)
                    assert result["source"] == "siem_bridge"
                    assert result["total_count"] == 2

    @pytest.mark.asyncio
    async def test_get_recent_alerts_with_custom_limit(self):
        """Test get_recent_alerts with custom limit."""
        mock_alerts = [SAMPLE_ALERT]
        mock_bridge = MagicMock()
        mock_bridge.get_recent_alerts.return_value = mock_alerts

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute("get_recent_alerts", {"limit": 5})

                    mock_bridge.get_recent_alerts.assert_called_once_with(5)

    @pytest.mark.asyncio
    async def test_get_recent_alerts_bridge_error_fallback(self):
        """Test get_recent_alerts falls back to mock on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.get_recent_alerts.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute("get_recent_alerts", {})

                    assert result["source"] == "mock"
                    assert result["total_count"] == 0

    @pytest.mark.asyncio
    async def test_get_recent_alerts_formats_alerts(self):
        """Test that alerts are formatted for LLM readability."""
        mock_alerts = [SAMPLE_ALERT, SAMPLE_ALERT_MINIMAL]
        mock_bridge = MagicMock()
        mock_bridge.get_recent_alerts.return_value = mock_alerts

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute("get_recent_alerts", {})

                    # Check formatted alerts are strings
                    assert all(isinstance(a, str) for a in result["alerts"])
                    # Check raw alerts are dicts
                    assert all(isinstance(a, dict) for a in result["alerts_raw"])
                    # Check formatted alert contains expected data
                    assert "Brute Force Attack" in result["alerts"][0]
                    assert "ALERT-001" in result["alerts"][0]


# ============================================================================
# Integration Tests
# ============================================================================


class TestSIEMToolsIntegration:
    """Integration tests for SIEM tools."""

    @pytest.mark.asyncio
    async def test_tool_not_found_raises_error(self):
        """Test that executing non-existent tool raises ValueError."""
        registry = create_triage_tools()

        with pytest.raises(ValueError, match="Tool not found"):
            await registry.execute("nonexistent_tool", {})

    def test_tool_definitions_are_valid(self):
        """Test that all tool definitions are valid for LLM."""
        registry = create_triage_tools()
        definitions = registry.get_tool_definitions()

        for defn in definitions:
            assert defn.name is not None
            assert defn.description is not None
            assert defn.parameters is not None
            assert "type" in defn.parameters
            assert defn.parameters["type"] == "object"

    @pytest.mark.asyncio
    async def test_search_siem_result_structure(self):
        """Test that search_siem result has expected structure."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute("search_siem", {"query": "test"})

                # Verify all required keys present
                assert "events" in result
                assert "events_raw" in result
                assert "total_count" in result
                assert "search_stats" in result
                assert "source" in result

                # Verify search_stats structure
                stats = result["search_stats"]
                assert "search_id" in stats
                assert "query" in stats
                assert "timerange_hours" in stats
                assert "limit_applied" in stats
                assert "events_returned" in stats

    @pytest.mark.asyncio
    async def test_get_recent_alerts_result_structure(self):
        """Test that get_recent_alerts result has expected structure."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute("get_recent_alerts", {})

                # Verify all required keys present
                assert "alerts" in result
                assert "alerts_raw" in result
                assert "total_count" in result
                assert "source" in result


# ============================================================================
# ToolResult Tests
# ============================================================================


class TestToolResult:
    """Tests for the ToolResult dataclass."""

    def test_tool_result_ok(self):
        """Test creating a successful ToolResult."""
        result = ToolResult.ok(
            data={"verdict": "malicious", "score": 95},
            execution_time_ms=150,
        )

        assert result.success is True
        assert result.data["verdict"] == "malicious"
        assert result.data["score"] == 95
        assert result.error is None
        assert result.execution_time_ms == 150

    def test_tool_result_fail(self):
        """Test creating a failed ToolResult."""
        result = ToolResult.fail(
            error="Bridge connection failed",
            execution_time_ms=50,
        )

        assert result.success is False
        assert result.error == "Bridge connection failed"
        assert result.data == {}
        assert result.execution_time_ms == 50

    def test_tool_result_ok_default_execution_time(self):
        """Test ToolResult.ok with default execution time."""
        result = ToolResult.ok(data={"key": "value"})

        assert result.success is True
        assert result.execution_time_ms == 0

    def test_tool_result_fail_default_execution_time(self):
        """Test ToolResult.fail with default execution time."""
        result = ToolResult.fail(error="Error occurred")

        assert result.success is False
        assert result.execution_time_ms == 0


# ============================================================================
# Threat Intelligence Mock Tests
# ============================================================================


class TestThreatIntelMockFunctions:
    """Tests for threat intelligence mock fallback functions."""

    def test_mock_hash_lookup_known_malicious(self):
        """Test mock hash lookup for known malicious hash (EICAR)."""
        result = _mock_hash_lookup("44d88612fea8a8f36de82e1278abb02f")

        assert result["verdict"] == "malicious"
        assert result["malicious_score"] == 95
        assert "EICAR-Test-File" in result["malware_families"]
        assert result["indicator_type"] == "md5"
        assert result["source"] == "mock"

    def test_mock_hash_lookup_unknown(self):
        """Test mock hash lookup for unknown hash."""
        result = _mock_hash_lookup("deadbeefcafe12345")

        assert result["verdict"] == "unknown"
        assert result["malicious_score"] == 0
        assert result["malware_families"] == []
        assert result["source"] == "mock"

    def test_mock_ip_lookup_malicious(self):
        """Test mock IP lookup for known malicious IP."""
        result = _mock_ip_lookup("203.0.113.100")

        assert result["verdict"] == "malicious"
        assert result["malicious_score"] == 85
        assert "c2" in result["categories"]
        assert result["country"] == "XX"
        assert result["source"] == "mock"

    def test_mock_ip_lookup_private_ranges(self):
        """Test mock IP lookup for private IP ranges."""
        for ip in ["10.0.0.1", "192.168.1.1", "172.16.0.1"]:
            result = _mock_ip_lookup(ip)

            assert result["verdict"] == "clean"
            assert result["malicious_score"] == 0
            assert "private" in result["categories"]
            assert result["country"] == "PRIVATE"

    def test_mock_ip_lookup_unknown(self):
        """Test mock IP lookup for unknown public IP."""
        result = _mock_ip_lookup("8.8.8.8")

        assert result["verdict"] == "unknown"
        assert result["malicious_score"] == 0
        assert result["source"] == "mock"

    def test_mock_domain_lookup_malicious(self):
        """Test mock domain lookup for known malicious domains."""
        for domain in ["evil.example.com", "malware.test", "phishing.bad"]:
            result = _mock_domain_lookup(domain)

            assert result["verdict"] == "malicious"
            assert result["malicious_score"] == 90
            assert "phishing" in result["categories"] or "malware" in result["categories"]

    def test_mock_domain_lookup_clean(self):
        """Test mock domain lookup for known clean domains."""
        for domain in ["google.com", "microsoft.com", "github.com"]:
            result = _mock_domain_lookup(domain)

            assert result["verdict"] == "clean"
            assert result["malicious_score"] == 0
            assert "technology" in result["categories"]

    def test_mock_domain_lookup_unknown(self):
        """Test mock domain lookup for unknown domain."""
        result = _mock_domain_lookup("random-domain.xyz")

        assert result["verdict"] == "unknown"
        assert result["malicious_score"] == 0
        assert result["categories"] == []


# ============================================================================
# Threat Intelligence Tool Tests
# ============================================================================


class TestLookupHashTool:
    """Tests for lookup_hash tool functionality."""

    @pytest.mark.asyncio
    async def test_lookup_hash_mock_fallback(self):
        """Test lookup_hash uses mock when bridge unavailable."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_hash", {"hash": "44d88612fea8a8f36de82e1278abb02f"}
                )

                assert isinstance(result, ToolResult)
                assert result.success is True
                assert result.data["verdict"] == "malicious"
                assert result.data["score"] == 95
                assert "EICAR-Test-File" in result.data["malware_families"]
                assert result.data["is_mock"] is True
                assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_lookup_hash_unknown_hash(self):
        """Test lookup_hash for unknown hash."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_hash", {"hash": "unknown_hash_value"}
                )

                assert result.success is True
                assert result.data["verdict"] == "unknown"
                assert result.data["score"] == 0

    @pytest.mark.asyncio
    async def test_lookup_hash_with_bridge(self):
        """Test lookup_hash uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.lookup_hash.return_value = {
            "indicator": "abc123",
            "indicator_type": "sha256",
            "verdict": "suspicious",
            "malicious_score": 50,
            "malware_families": ["Trojan.Generic"],
            "categories": ["malware"],
            "malicious_count": 10,
            "total_engines": 70,
            "source": "virustotal",
        }

        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
                with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "lookup_hash", {"hash": "abc123"}
                    )

                    mock_bridge.lookup_hash.assert_called_once_with("abc123")
                    assert result.success is True
                    assert result.data["verdict"] == "suspicious"
                    assert result.data["score"] == 50
                    assert result.data["is_mock"] is False

    @pytest.mark.asyncio
    async def test_lookup_hash_bridge_error(self):
        """Test lookup_hash handles bridge errors gracefully."""
        mock_bridge = MagicMock()
        mock_bridge.lookup_hash.side_effect = RuntimeError("Connection failed")

        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
                with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "lookup_hash", {"hash": "abc123"}
                    )

                    assert result.success is False
                    assert "Connection failed" in result.error
                    assert result.execution_time_ms >= 0


class TestLookupIPTool:
    """Tests for lookup_ip tool functionality."""

    @pytest.mark.asyncio
    async def test_lookup_ip_mock_malicious(self):
        """Test lookup_ip for known malicious IP with mock."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_ip", {"ip": "203.0.113.100"}
                )

                assert isinstance(result, ToolResult)
                assert result.success is True
                assert result.data["verdict"] == "malicious"
                assert result.data["score"] == 85
                assert "c2" in result.data["categories"]
                assert result.data["country"] == "XX"
                assert result.data["is_mock"] is True

    @pytest.mark.asyncio
    async def test_lookup_ip_private_range(self):
        """Test lookup_ip for private IP ranges."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_ip", {"ip": "192.168.1.100"}
                )

                assert result.success is True
                assert result.data["verdict"] == "clean"
                assert result.data["country"] == "PRIVATE"

    @pytest.mark.asyncio
    async def test_lookup_ip_with_bridge(self):
        """Test lookup_ip uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.lookup_ip.return_value = {
            "indicator": "8.8.8.8",
            "indicator_type": "ip",
            "verdict": "clean",
            "malicious_score": 0,
            "categories": ["dns"],
            "country": "US",
            "asn": "AS15169",
            "malicious_count": 0,
            "total_engines": 50,
            "source": "virustotal",
        }

        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
                with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "lookup_ip", {"ip": "8.8.8.8"}
                    )

                    mock_bridge.lookup_ip.assert_called_once_with("8.8.8.8")
                    assert result.success is True
                    assert result.data["country"] == "US"
                    assert result.data["asn"] == "AS15169"
                    assert result.data["is_mock"] is False


class TestLookupDomainTool:
    """Tests for lookup_domain tool functionality."""

    @pytest.mark.asyncio
    async def test_lookup_domain_mock_malicious(self):
        """Test lookup_domain for known malicious domain with mock."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_domain", {"domain": "evil.example.com"}
                )

                assert isinstance(result, ToolResult)
                assert result.success is True
                assert result.data["verdict"] == "malicious"
                assert result.data["score"] == 90
                assert "phishing" in result.data["categories"]
                assert result.data["is_mock"] is True

    @pytest.mark.asyncio
    async def test_lookup_domain_clean(self):
        """Test lookup_domain for known clean domain."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_domain", {"domain": "google.com"}
                )

                assert result.success is True
                assert result.data["verdict"] == "clean"
                assert "technology" in result.data["categories"]

    @pytest.mark.asyncio
    async def test_lookup_domain_with_bridge(self):
        """Test lookup_domain uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.lookup_domain.return_value = {
            "indicator": "suspicious-site.net",
            "indicator_type": "domain",
            "verdict": "suspicious",
            "malicious_score": 45,
            "categories": ["newly_registered"],
            "malicious_count": 5,
            "total_engines": 60,
            "source": "virustotal",
        }

        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
                with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "lookup_domain", {"domain": "suspicious-site.net"}
                    )

                    mock_bridge.lookup_domain.assert_called_once_with("suspicious-site.net")
                    assert result.success is True
                    assert result.data["verdict"] == "suspicious"
                    assert result.data["is_mock"] is False


# ============================================================================
# Threat Intel Tool Definition Tests
# ============================================================================


class TestThreatIntelToolDefinitions:
    """Tests for threat intelligence tool definitions."""

    def test_registry_contains_threat_intel_tools(self):
        """Test that registry includes all threat intel tools."""
        registry = create_triage_tools()
        tools = registry.list_tools()

        assert "lookup_hash" in tools
        assert "lookup_ip" in tools
        assert "lookup_domain" in tools

    def test_lookup_hash_tool_definition(self):
        """Test lookup_hash tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("lookup_hash")

        assert tool is not None
        assert tool.name == "lookup_hash"
        assert "hash" in tool.parameters["properties"]
        assert tool.parameters["required"] == ["hash"]
        assert "MD5" in tool.description or "SHA256" in tool.description

    def test_lookup_ip_tool_definition(self):
        """Test lookup_ip tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("lookup_ip")

        assert tool is not None
        assert tool.name == "lookup_ip"
        assert "ip" in tool.parameters["properties"]
        assert tool.parameters["required"] == ["ip"]
        assert "IPv4" in tool.description or "IP" in tool.description

    def test_lookup_domain_tool_definition(self):
        """Test lookup_domain tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("lookup_domain")

        assert tool is not None
        assert tool.name == "lookup_domain"
        assert "domain" in tool.parameters["properties"]
        assert tool.parameters["required"] == ["domain"]


# ============================================================================
# Tool Execution Time Tests
# ============================================================================


class TestToolExecutionTime:
    """Tests for tool execution time tracking."""

    @pytest.mark.asyncio
    async def test_lookup_hash_includes_execution_time(self):
        """Test that lookup_hash includes execution_time_ms."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_hash", {"hash": "test_hash"}
                )

                assert hasattr(result, "execution_time_ms")
                assert isinstance(result.execution_time_ms, int)
                assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_lookup_ip_includes_execution_time(self):
        """Test that lookup_ip includes execution_time_ms."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_ip", {"ip": "1.2.3.4"}
                )

                assert hasattr(result, "execution_time_ms")
                assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_lookup_domain_includes_execution_time(self):
        """Test that lookup_domain includes execution_time_ms."""
        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_threat_intel_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "lookup_domain", {"domain": "example.com"}
                )

                assert hasattr(result, "execution_time_ms")
                assert result.execution_time_ms >= 0


# ============================================================================
# EDR Test Data
# ============================================================================

SAMPLE_HOST_INFO = {
    "hostname": "workstation-001",
    "host_id": "host-abc-123",
    "ip_addresses": ["192.168.1.100", "10.0.0.50"],
    "os": "Windows 10 Enterprise",
    "os_version": "10.0.19044",
    "status": "online",
    "isolated": False,
    "last_seen": "2025-01-29T10:30:00Z",
    "agent_version": "7.0.0",
    "tags": ["workstation", "finance"],
}

SAMPLE_DETECTION = {
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
}

SAMPLE_PROCESS = {
    "pid": 1234,
    "name": "powershell.exe",
    "command_line": "powershell.exe -enc SQBFAFgA...",
    "user": "DOMAIN\\user1",
    "parent_pid": 5678,
    "parent_name": "cmd.exe",
    "start_time": "2025-01-29T09:14:30Z",
    "hash": "abc123",
}

SAMPLE_NETWORK_CONNECTION = {
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
}


# ============================================================================
# EDR Tool Registry Tests
# ============================================================================


class TestEDRToolRegistry:
    """Tests for EDR tool registration."""

    def test_registry_contains_edr_tools(self):
        """Test that registry includes EDR tools."""
        registry = create_triage_tools()
        tools = registry.list_tools()

        assert "get_host_info" in tools
        assert "get_detections" in tools
        assert "get_processes" in tools
        assert "get_network_connections" in tools

    def test_get_host_info_tool_definition(self):
        """Test get_host_info tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("get_host_info")

        assert tool is not None
        assert tool.name == "get_host_info"
        assert "hostname" in tool.parameters["properties"]
        assert "hostname" in tool.parameters["required"]

    def test_get_detections_tool_definition(self):
        """Test get_detections tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("get_detections")

        assert tool is not None
        assert tool.name == "get_detections"
        assert "hostname" in tool.parameters["properties"]
        assert "hours" in tool.parameters["properties"]
        assert tool.parameters["properties"]["hours"]["default"] == 24
        assert "hostname" in tool.parameters["required"]

    def test_get_processes_tool_definition(self):
        """Test get_processes tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("get_processes")

        assert tool is not None
        assert tool.name == "get_processes"
        assert "hostname" in tool.parameters["properties"]
        assert "hours" in tool.parameters["properties"]
        assert tool.parameters["properties"]["hours"]["default"] == 24

    def test_get_network_connections_tool_definition(self):
        """Test get_network_connections tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("get_network_connections")

        assert tool is not None
        assert tool.name == "get_network_connections"
        assert "hostname" in tool.parameters["properties"]
        assert "hours" in tool.parameters["properties"]
        assert tool.parameters["properties"]["hours"]["default"] == 24


# ============================================================================
# get_host_info Tool Tests
# ============================================================================


class TestGetHostInfoTool:
    """Tests for get_host_info tool functionality."""

    @pytest.mark.asyncio
    async def test_get_host_info_mock_fallback(self):
        """Test get_host_info returns mock data when bridge unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_host_info", {"hostname": "workstation-001"}
                )

                assert result["source"] == "mock"
                assert result["hostname"] == "workstation-001"
                assert "status" in result
                assert "os" in result
                assert "isolated" in result
                assert isinstance(result["ip_addresses"], list)
                assert isinstance(result["tags"], list)

    @pytest.mark.asyncio
    async def test_get_host_info_with_bridge(self):
        """Test get_host_info uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.get_host_info.return_value = SAMPLE_HOST_INFO

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_host_info", {"hostname": "workstation-001"}
                    )

                    mock_bridge.get_host_info.assert_called_once_with("workstation-001")
                    assert result["source"] == "edr_bridge"
                    assert result["hostname"] == "workstation-001"
                    assert result["status"] == "online"

    @pytest.mark.asyncio
    async def test_get_host_info_bridge_error_fallback(self):
        """Test get_host_info falls back to mock on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.get_host_info.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_host_info", {"hostname": "workstation-001"}
                    )

                    assert result["source"] == "mock"
                    assert "hostname" in result

    @pytest.mark.asyncio
    async def test_get_host_info_result_structure(self):
        """Test get_host_info result has expected structure."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_host_info", {"hostname": "test-host"}
                )

                # Verify all required keys present
                assert "hostname" in result
                assert "host_id" in result
                assert "ip_addresses" in result
                assert "os" in result
                assert "os_version" in result
                assert "status" in result
                assert "isolated" in result
                assert "last_seen" in result
                assert "agent_version" in result
                assert "tags" in result
                assert "source" in result


# ============================================================================
# get_detections Tool Tests
# ============================================================================


class TestGetDetectionsTool:
    """Tests for get_detections tool functionality."""

    @pytest.mark.asyncio
    async def test_get_detections_mock_fallback(self):
        """Test get_detections returns mock data when bridge unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "workstation-001"}
                )

                assert result["source"] == "mock"
                assert result["hostname"] == "workstation-001"
                assert "total_count" in result
                assert "detections" in result
                assert isinstance(result["detections"], list)
                assert len(result["detections"]) > 0

    @pytest.mark.asyncio
    async def test_get_detections_with_bridge(self):
        """Test get_detections uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.get_detections.return_value = [SAMPLE_DETECTION]

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_detections", {"hostname": "workstation-001"}
                    )

                    mock_bridge.get_detections.assert_called_once_with("workstation-001")
                    assert result["source"] == "edr_bridge"
                    assert result["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_detections_with_hours_parameter(self):
        """Test get_detections with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "workstation-001", "hours": 48}
                )

                assert result["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_get_detections_includes_mitre_info(self):
        """Test get_detections includes MITRE ATT&CK information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "workstation-001"}
                )

                detection = result["detections"][0]
                assert "technique" in detection
                assert "tactic" in detection
                assert detection["technique"].startswith("T")

    @pytest.mark.asyncio
    async def test_get_detections_result_structure(self):
        """Test get_detections result has expected structure."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "test-host"}
                )

                # Verify top-level structure
                assert "hostname" in result
                assert "total_count" in result
                assert "detections" in result
                assert "source" in result

                # Verify detection structure
                if result["detections"]:
                    det = result["detections"][0]
                    assert "id" in det
                    assert "name" in det
                    assert "severity" in det
                    assert "timestamp" in det
                    assert "technique" in det
                    assert "tactic" in det


# ============================================================================
# get_processes Tool Tests
# ============================================================================


class TestGetProcessesTool:
    """Tests for get_processes tool functionality."""

    @pytest.mark.asyncio
    async def test_get_processes_mock_fallback(self):
        """Test get_processes returns mock data when bridge unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "workstation-001"}
                )

                assert result["source"] == "mock"
                assert result["hostname"] == "workstation-001"
                assert "total_count" in result
                assert "processes" in result
                assert isinstance(result["processes"], list)
                assert len(result["processes"]) > 0

    @pytest.mark.asyncio
    async def test_get_processes_with_bridge(self):
        """Test get_processes uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.get_processes.return_value = [SAMPLE_PROCESS]

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_processes", {"hostname": "workstation-001", "hours": 24}
                    )

                    mock_bridge.get_processes.assert_called_once_with("workstation-001", 24)
                    assert result["source"] == "edr_bridge"
                    assert result["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_processes_with_hours_parameter(self):
        """Test get_processes with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "workstation-001", "hours": 72}
                )

                assert result["timerange_hours"] == 72

    @pytest.mark.asyncio
    async def test_get_processes_includes_parent_info(self):
        """Test get_processes includes parent process information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "workstation-001"}
                )

                process = result["processes"][0]
                assert "parent_pid" in process or "parent_name" in process

    @pytest.mark.asyncio
    async def test_get_processes_result_structure(self):
        """Test get_processes result has expected structure."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "test-host"}
                )

                # Verify top-level structure
                assert "hostname" in result
                assert "timerange_hours" in result
                assert "total_count" in result
                assert "processes" in result
                assert "source" in result

                # Verify process structure
                if result["processes"]:
                    proc = result["processes"][0]
                    assert "pid" in proc
                    assert "name" in proc
                    assert "command_line" in proc
                    assert "user" in proc


# ============================================================================
# get_network_connections Tool Tests
# ============================================================================


class TestGetNetworkConnectionsTool:
    """Tests for get_network_connections tool functionality."""

    @pytest.mark.asyncio
    async def test_get_network_connections_mock_fallback(self):
        """Test get_network_connections returns mock data when bridge unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "workstation-001"}
                )

                assert result["source"] == "mock"
                assert result["hostname"] == "workstation-001"
                assert "total_count" in result
                assert "connections" in result
                assert isinstance(result["connections"], list)
                assert len(result["connections"]) > 0

    @pytest.mark.asyncio
    async def test_get_network_connections_with_bridge(self):
        """Test get_network_connections uses bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.get_network_connections.return_value = [SAMPLE_NETWORK_CONNECTION]

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_network_connections", {"hostname": "workstation-001", "hours": 24}
                    )

                    mock_bridge.get_network_connections.assert_called_once_with("workstation-001", 24)
                    assert result["source"] == "edr_bridge"
                    assert result["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_network_connections_with_hours_parameter(self):
        """Test get_network_connections with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "workstation-001", "hours": 48}
                )

                assert result["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_get_network_connections_includes_process_info(self):
        """Test get_network_connections includes process information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "workstation-001"}
                )

                conn = result["connections"][0]
                assert "process_name" in conn
                assert "process_pid" in conn

    @pytest.mark.asyncio
    async def test_get_network_connections_result_structure(self):
        """Test get_network_connections result has expected structure."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "test-host"}
                )

                # Verify top-level structure
                assert "hostname" in result
                assert "timerange_hours" in result
                assert "total_count" in result
                assert "connections" in result
                assert "source" in result

                # Verify connection structure
                if result["connections"]:
                    conn = result["connections"][0]
                    assert "remote_ip" in conn
                    assert "remote_port" in conn
                    assert "direction" in conn
                    assert "protocol" in conn
                    assert "process_name" in conn


# ============================================================================
# EDR Bridge Availability Tests
# ============================================================================


class TestEDRBridgeAvailability:
    """Tests for EDR bridge availability checks."""

    def test_is_edr_bridge_available_returns_bool(self):
        """Test that is_edr_bridge_available returns a boolean."""
        result = is_edr_bridge_available()
        assert isinstance(result, bool)

    def test_get_edr_bridge_without_bridge_returns_none(self):
        """Test that get_edr_bridge returns None when bridge unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                bridge = get_edr_bridge()
                assert bridge is None


# ============================================================================
# EDR Tools Integration Tests
# ============================================================================


class TestEDRToolsIntegration:
    """Integration tests for EDR tools."""

    @pytest.mark.asyncio
    async def test_all_edr_tools_work_with_mock_fallback(self):
        """Test that all EDR tools work when bridge is unavailable."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()

                # Test all EDR tools
                host_info = await registry.execute(
                    "get_host_info", {"hostname": "test-host"}
                )
                assert host_info["source"] == "mock"

                detections = await registry.execute(
                    "get_detections", {"hostname": "test-host"}
                )
                assert detections["source"] == "mock"

                processes = await registry.execute(
                    "get_processes", {"hostname": "test-host"}
                )
                assert processes["source"] == "mock"

                connections = await registry.execute(
                    "get_network_connections", {"hostname": "test-host"}
                )
                assert connections["source"] == "mock"

    def test_edr_tool_definitions_are_valid(self):
        """Test that all EDR tool definitions are valid for LLM."""
        registry = create_triage_tools()
        edr_tool_names = ["get_host_info", "get_detections", "get_processes", "get_network_connections"]

        for name in edr_tool_names:
            tool = registry.get(name)
            assert tool is not None
            assert tool.description is not None
            assert len(tool.description) > 20  # Should have meaningful description
            assert "type" in tool.parameters
            assert tool.parameters["type"] == "object"
            assert "properties" in tool.parameters
