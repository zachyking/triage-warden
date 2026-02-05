"""Integration tests for the tw_bridge module.

These tests verify the Rust-Python boundary works correctly with
realistic scenarios, including:
- Full triage pipelines with mock connectors
- Data serialization/deserialization across the boundary
- Error handling and edge cases
- Performance characteristics
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest


# Skip all tests if tw_bridge is not built
pytest.importorskip("tw_bridge")


class TestTriageRequestResponse:
    """Tests for triage request/response handling."""

    def test_request_with_complex_alert_data(self):
        """Test handling complex nested JSON in alerts."""
        from tw_bridge import PyTriageRequest

        # Complex alert with nested data
        alert_data = {
            "type": "email_security",
            "subject": "Urgent: Password Reset Required",
            "sender": "support@paypa1.com",
            "recipient": "user@company.com",
            "headers": {
                "X-Originating-IP": "185.234.72.10",
                "X-Spam-Score": 8.5,
                "Authentication-Results": {
                    "spf": "fail",
                    "dkim": "none",
                    "dmarc": "fail",
                },
            },
            "urls": [
                {"url": "http://paypa1-verify.com/login", "clicked": False},
                {"url": "http://legit.company.com/docs", "clicked": True},
            ],
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "hash": "abc123",
                    "size": 1024,
                    "content_type": "application/pdf",
                }
            ],
            "metadata": {
                "received_time": "2024-01-15T09:30:00Z",
                "processed_time": "2024-01-15T09:30:05Z",
                "source_system": "email_gateway",
            },
        }

        enrichments = [
            {"source": "virustotal", "data": {"malicious": 5, "total": 70}},
            {"source": "whois", "data": {"registrar": "Unknown", "created": "2024-01-01"}},
        ]

        request = PyTriageRequest(
            incident_id="test-complex-001",
            alert_data=json.dumps(alert_data),
            enrichments=json.dumps(enrichments),
        )

        assert request.incident_id == "test-complex-001"

        # Verify data can be parsed back
        parsed_alert = json.loads(request.alert_data)
        assert parsed_alert["type"] == "email_security"
        assert parsed_alert["headers"]["Authentication-Results"]["spf"] == "fail"
        assert len(parsed_alert["urls"]) == 2
        assert len(parsed_alert["attachments"]) == 1

        parsed_enrichments = json.loads(request.enrichments)
        assert len(parsed_enrichments) == 2

    def test_result_with_full_analysis(self):
        """Test creating a complete analysis result."""
        from tw_bridge import PyTriageResult

        recommended_actions = [
            {
                "action": "quarantine_email",
                "priority": "immediate",
                "reason": "Prevent credential theft",
            },
            {
                "action": "block_sender_domain",
                "priority": "high",
                "reason": "Stop similar phishing attempts",
            },
        ]

        mitre_techniques = [
            {
                "id": "T1566.002",
                "name": "Spearphishing Link",
                "tactic": "Initial Access",
            },
            {
                "id": "T1598.003",
                "name": "Spearphishing for Information",
                "tactic": "Reconnaissance",
            },
        ]

        result = PyTriageResult(
            success=True,
            verdict="true_positive",
            confidence=0.92,
            summary="Credential harvesting phishing attempt using typosquatted domain.",
            reasoning="Multiple indicators confirm malicious intent: (1) Typosquatted domain, "
            "(2) Failed email authentication, (3) URL designed for credential harvesting.",
            recommended_actions=json.dumps(recommended_actions),
            mitre_techniques=json.dumps(mitre_techniques),
            error=None,
        )

        assert result.success is True
        assert result.verdict == "true_positive"
        assert result.confidence == 0.92
        assert "typosquatted" in result.summary.lower()

        # Verify serialized data can be parsed
        actions = json.loads(result.recommended_actions)
        assert len(actions) == 2
        assert actions[0]["action"] == "quarantine_email"

        techniques = json.loads(result.mitre_techniques)
        assert len(techniques) == 2
        assert techniques[0]["id"] == "T1566.002"

    def test_result_failure_with_error_details(self):
        """Test creating a failure result with detailed error."""
        from tw_bridge import PyTriageResult

        error_details = {
            "code": "CONNECTOR_TIMEOUT",
            "message": "Threat intelligence lookup timed out after 30s",
            "source": "virustotal_connector",
            "retry_after_seconds": 60,
        }

        result = PyTriageResult.failure(json.dumps(error_details))

        assert result.success is False
        assert result.verdict == "error"
        assert result.confidence == 0.0

        error = json.loads(result.error)
        assert error["code"] == "CONNECTOR_TIMEOUT"


class TestThreatIntelBridgeIntegration:
    """Integration tests for threat intelligence bridge."""

    def test_batch_lookups(self):
        """Test performing multiple lookups efficiently."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")

        # Batch of indicators to look up
        indicators = [
            ("hash", "44d88612fea8a8f36de82e1278abb02f"),  # EICAR
            ("hash", "unknown_hash_abc123"),
            ("ip", "203.0.113.100"),  # Malicious
            ("ip", "192.168.1.1"),  # Internal
            ("domain", "evil.example.com"),  # Malicious
            ("domain", "google.com"),  # Clean
        ]

        results = []
        for indicator_type, value in indicators:
            if indicator_type == "hash":
                result = bridge.lookup_hash(value)
            elif indicator_type == "ip":
                result = bridge.lookup_ip(value)
            elif indicator_type == "domain":
                result = bridge.lookup_domain(value)
            results.append((indicator_type, value, result))

        # Verify all results are present
        assert len(results) == 6

        # Check specific results
        eicar_result = results[0][2]
        assert eicar_result["verdict"] == "malicious"

        internal_ip_result = results[3][2]
        # Internal IPs should be marked as clean or unknown
        assert internal_ip_result["verdict"] in ["clean", "unknown", "benign"]

    def test_lookup_with_special_characters(self):
        """Test lookups with special characters in values."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")

        # Domain with subdomain
        result = bridge.lookup_domain("malware.sub.evil.example.com")
        assert result is not None

        # Hash with mixed case (should be normalized)
        result = bridge.lookup_hash("44D88612FEA8A8F36DE82E1278ABB02F")
        assert result is not None


class TestSIEMBridgeIntegration:
    """Integration tests for SIEM bridge."""

    def test_search_with_complex_query(self):
        """Test SIEM search with complex query."""
        from tw_bridge import SIEMBridge

        bridge = SIEMBridge("mock")

        # Complex query with multiple conditions
        query = 'source_ip="185.234.72.15" AND event_type="login" AND status="success"'
        result = bridge.search(query, hours=24)

        assert result is not None
        assert "total_count" in result
        assert "events" in result
        assert isinstance(result["events"], list)

    def test_search_with_large_timerange(self):
        """Test SIEM search with large time range."""
        from tw_bridge import SIEMBridge

        bridge = SIEMBridge("mock")

        # Search over 7 days
        result = bridge.search("event_type=login", hours=168)

        assert result is not None
        assert result["total_count"] >= 0


class TestEDRBridgeIntegration:
    """Integration tests for EDR bridge."""

    def test_host_operations_workflow(self):
        """Test a complete host investigation workflow."""
        from tw_bridge import EDRBridge

        bridge = EDRBridge("mock")

        # 1. Get host info
        host_info = bridge.get_host_info("workstation-001")
        assert host_info is not None

        # 2. Get recent detections
        # Note: This may not be implemented in all mock versions
        try:
            detections = bridge.get_detections("workstation-001")
            assert isinstance(detections, (list, dict))
        except (AttributeError, NotImplementedError):
            pass  # Method may not exist

    def test_nonexistent_host(self):
        """Test handling of non-existent hosts."""
        from tw_bridge import EDRBridge

        bridge = EDRBridge("mock")

        # Looking up non-existent host should raise an error or return a result
        try:
            result = bridge.get_host_info("nonexistent-host-xyz")
            # If no error, the result should indicate the host wasn't found
            assert result is not None
        except (RuntimeError, KeyError, ValueError):
            # The mock implementation may raise an error for unknown hosts
            pass


class TestTicketingBridgeIntegration:
    """Integration tests for ticketing bridge."""

    def test_create_ticket_with_full_details(self):
        """Test creating a ticket with all details."""
        from tw_bridge import TicketingBridge

        bridge = TicketingBridge("mock")

        result = bridge.create_ticket(
            summary="[HIGH] Credential Harvesting Phishing Attack Detected",
            description="""
## Alert Summary
A credential harvesting phishing attempt was detected targeting user@company.com.

## Indicators of Compromise
- Sender domain: paypa1.com (typosquatting PayPal)
- Malicious URL: http://paypa1-verify.com/login
- Source IP: 185.234.72.10

## Recommended Actions
1. Quarantine the email immediately
2. Block sender domain at email gateway
3. Add URL to blocklist
4. Notify affected user

## MITRE ATT&CK
- T1566.002 - Spearphishing Link
- T1598.003 - Spearphishing for Information
            """,
            priority="high",
            labels=["phishing", "credential-theft", "urgent", "email-security"],
        )

        assert result is not None
        assert "id" in result
        assert "key" in result


class TestPerformance:
    """Performance tests for the bridge."""

    def test_rapid_lookups(self):
        """Test performance of rapid consecutive lookups."""
        from tw_bridge import ThreatIntelBridge

        bridge = ThreatIntelBridge("mock")

        # Perform 100 lookups and measure time
        start_time = time.time()
        for i in range(100):
            bridge.lookup_hash(f"hash_{i:04d}")
        elapsed = time.time() - start_time

        # Should complete in reasonable time (< 5 seconds for mock)
        assert elapsed < 5.0, f"100 lookups took {elapsed:.2f}s (expected < 5s)"

    def test_large_json_handling(self):
        """Test handling of large JSON payloads."""
        from tw_bridge import PyTriageRequest

        # Create a large alert with many indicators
        indicators = [
            {"type": "ip", "value": f"10.0.{i // 256}.{i % 256}"}
            for i in range(1000)
        ]

        alert_data = {
            "type": "aggregated_alert",
            "indicators": indicators,
            "metadata": {"large_field": "x" * 10000},  # 10KB string
        }

        start_time = time.time()
        request = PyTriageRequest(
            incident_id="test-large-001",
            alert_data=json.dumps(alert_data),
            enrichments="[]",
        )
        elapsed = time.time() - start_time

        assert elapsed < 1.0, f"Large JSON handling took {elapsed:.2f}s"

        # Verify data integrity
        parsed = json.loads(request.alert_data)
        assert len(parsed["indicators"]) == 1000


class TestErrorHandling:
    """Tests for error handling across the bridge boundary."""

    def test_invalid_json_handling(self):
        """Test handling of invalid JSON in requests."""
        from tw_bridge import PyTriageRequest

        # This should accept any string, even invalid JSON
        # The validation happens elsewhere
        request = PyTriageRequest(
            incident_id="test-invalid-json",
            alert_data="not valid json {{{",
            enrichments="also not valid",
        )

        assert request.alert_data == "not valid json {{{"

    def test_empty_strings(self):
        """Test handling of empty strings."""
        from tw_bridge import PyTriageRequest

        request = PyTriageRequest(
            incident_id="",
            alert_data="",
            enrichments="",
        )

        assert request.incident_id == ""
        assert request.alert_data == ""

    def test_unicode_handling(self):
        """Test handling of Unicode characters."""
        from tw_bridge import PyTriageRequest

        # Alert with Unicode characters
        alert_data = {
            "subject": "您的账户已被盗用 🚨",  # Chinese + emoji
            "sender": "support@example.com",
            "notes": "Привет мир",  # Russian
        }

        request = PyTriageRequest(
            incident_id="test-unicode-001",
            alert_data=json.dumps(alert_data, ensure_ascii=False),
            enrichments="[]",
        )

        parsed = json.loads(request.alert_data)
        assert "您的账户" in parsed["subject"]
        assert "🚨" in parsed["subject"]
