"""Tests for the tw_bridge Python module.

These tests verify the Rust-Python bridge functionality by importing
the compiled module and testing the exposed classes and functions.
"""

import pytest


def test_import_module():
    """Verify the module can be imported."""
    import tw_bridge
    assert tw_bridge is not None


def test_triage_request_creation():
    """Test creating a PyTriageRequest."""
    from tw_bridge import PyTriageRequest

    request = PyTriageRequest("test-123", "{}", "[]")
    assert request.incident_id == "test-123"
    assert request.alert_data == "{}"
    assert request.enrichments == "[]"


def test_triage_result_failure():
    """Test creating a failure PyTriageResult."""
    from tw_bridge import PyTriageResult

    result = PyTriageResult.failure("Test error")
    assert result.success is False
    assert result.verdict == "error"
    assert result.confidence == 0.0
    assert result.error == "Test error"


def test_triage_result_success():
    """Test creating a successful PyTriageResult."""
    from tw_bridge import PyTriageResult

    result = PyTriageResult(
        success=True,
        verdict="malicious",
        confidence=0.95,
        summary="Malware detected",
        reasoning="Multiple indicators found",
        recommended_actions='["isolate_host"]',
        mitre_techniques='["T1059.001"]',
        error=None,
    )
    assert result.success is True
    assert result.verdict == "malicious"
    assert result.confidence == 0.95
    assert result.error is None


def test_threat_intel_result_unknown():
    """Test creating an unknown threat intel result."""
    from tw_bridge import PyThreatIntelResult

    result = PyThreatIntelResult.unknown("hash", "abc123")
    assert result.indicator_type == "hash"
    assert result.indicator == "abc123"
    assert result.verdict == "unknown"
    assert result.malicious_score == 0


def test_bridge_config():
    """Test creating a BridgeConfig."""
    from tw_bridge import BridgeConfig

    config = BridgeConfig("/etc/tw/config.yaml")
    assert config.config_path == "/etc/tw/config.yaml"


class TestThreatIntelBridge:
    """Tests for ThreatIntelBridge."""

    def test_create_mock_bridge(self):
        """Test creating a mock threat intel bridge."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        assert bridge is not None

    def test_lookup_known_hash(self):
        """Test looking up a known malicious hash."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        result = bridge.lookup_hash("44d88612fea8a8f36de82e1278abb02f")

        assert result is not None
        assert result["verdict"] == "malicious"
        assert result["malicious_score"] == 95

    def test_lookup_unknown_hash(self):
        """Test looking up an unknown hash."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        result = bridge.lookup_hash("unknown_hash_value")

        assert result is not None
        assert result["verdict"] == "unknown"

    def test_lookup_malicious_ip(self):
        """Test looking up a malicious IP."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        result = bridge.lookup_ip("203.0.113.100")

        assert result is not None
        assert result["verdict"] == "malicious"

    def test_lookup_malicious_domain(self):
        """Test looking up a malicious domain."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        result = bridge.lookup_domain("evil.example.com")

        assert result is not None
        assert result["verdict"] == "malicious"

    def test_lookup_clean_domain(self):
        """Test looking up a clean domain."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")
        result = bridge.lookup_domain("google.com")

        assert result is not None
        assert result["verdict"] == "clean"


class TestSIEMBridge:
    """Tests for SIEMBridge."""

    def test_create_mock_bridge(self):
        """Test creating a mock SIEM bridge."""
        from tw_bridge import SIEMBridge

        bridge = SIEMBridge("mock")
        assert bridge is not None

    def test_search(self):
        """Test SIEM search."""
        from tw_bridge import SIEMBridge

        bridge = SIEMBridge("mock")
        result = bridge.search("login_failure", 24)

        assert result is not None
        assert "total_count" in result
        assert "events" in result
        assert result["total_count"] >= 0

    def test_get_recent_alerts(self):
        """Test getting recent alerts."""
        from tw_bridge import SIEMBridge

        bridge = SIEMBridge("mock")
        alerts = bridge.get_recent_alerts(10)

        assert alerts is not None
        assert isinstance(alerts, list)


class TestEDRBridge:
    """Tests for EDRBridge."""

    def test_create_mock_bridge(self):
        """Test creating a mock EDR bridge."""
        from tw_bridge import EDRBridge

        bridge = EDRBridge("mock")
        assert bridge is not None

    def test_get_host_info(self):
        """Test getting host info."""
        from tw_bridge import EDRBridge

        bridge = EDRBridge("mock")
        # Mock connector should have workstation-001 pre-configured
        result = bridge.get_host_info("workstation-001")

        # Result depends on mock implementation
        assert result is not None


class TestTicketingBridge:
    """Tests for TicketingBridge."""

    def test_create_mock_bridge(self):
        """Test creating a mock ticketing bridge."""
        from tw_bridge import TicketingBridge

        bridge = TicketingBridge("mock")
        assert bridge is not None

    def test_create_ticket(self):
        """Test creating a ticket."""
        from tw_bridge import TicketingBridge

        bridge = TicketingBridge("mock")
        result = bridge.create_ticket(
            summary="Test Incident",
            description="Test description",
            priority="high",
            labels=["security", "test"],
        )

        assert result is not None
        assert "id" in result
        assert "key" in result


class TestEmailGatewayBridge:
    """Tests for EmailGatewayBridge."""

    def test_create_mock_bridge(self):
        """Test creating a mock email gateway bridge."""
        from tw_bridge import EmailGatewayBridge

        bridge = EmailGatewayBridge("mock")
        assert bridge is not None


class TestPolicyBridge:
    """Tests for PolicyBridge."""

    def test_create_bridge(self):
        """Test creating a policy bridge."""
        from tw_bridge import PolicyBridge

        bridge = PolicyBridge()
        assert bridge is not None

    def test_kill_switch_status(self):
        """Test getting kill switch status."""
        from tw_bridge import PolicyBridge

        bridge = PolicyBridge()
        status = bridge.is_kill_switch_active()

        # Default should be inactive
        assert status is False
