"""Shared sample data for integration tests.

This module provides standardized test data that can be used across
both Python and Rust tests for consistency. The data is also exported
to JSON files in tests/fixtures/data/ for use by the Rust test suite.

Usage:
    from tests.fixtures import SampleAlerts, create_sample_incident

    # Use predefined alerts
    phishing = SampleAlerts.PHISHING_TYPOSQUAT
    malware = SampleAlerts.MALWARE_EICAR

    # Create sample incidents
    incident = create_sample_incident("phishing")
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AlertData:
    """Base class for alert data."""

    alert_type: str
    data: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {"type": self.alert_type, **self.data}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class SampleAlerts:
    """Collection of sample security alerts for testing.

    These alerts are designed to trigger specific analysis patterns
    and can be used for deterministic testing.
    """

    # Phishing alerts
    PHISHING_TYPOSQUAT = AlertData(
        alert_type="email_security",
        data={
            "subject": "Urgent: Your account has been compromised",
            "sender": "support@paypa1.com",
            "urls": ["http://paypa1-verify.com/login"],
            "recipient": "user@company.com",
            "received_time": "2024-01-15T09:30:00Z",
            "spf_result": "fail",
            "dkim_result": "none",
            "dmarc_result": "fail",
            "headers": {
                "X-Originating-IP": "185.234.72.10",
                "X-Spam-Status": "Yes, score=8.5",
            },
        },
    )

    PHISHING_LEGITIMATE = AlertData(
        alert_type="email_security",
        data={
            "subject": "Monthly Report - December 2024",
            "sender": "reports@company.com",
            "urls": ["https://sharepoint.company.com/reports/december"],
            "recipient": "user@company.com",
            "received_time": "2024-01-15T10:00:00Z",
            "spf_result": "pass",
            "dkim_result": "pass",
            "dmarc_result": "pass",
        },
    )

    # Malware alerts
    MALWARE_EICAR = AlertData(
        alert_type="edr_detection",
        data={
            "hostname": "workstation-001",
            "process": "powershell.exe",
            "command_line": "-enc SGVsbG8gV29ybGQ=",
            "file_hash": "44d88612fea8a8f36de82e1278abb02f",  # EICAR test hash
            "parent_process": "cmd.exe",
            "user": "DOMAIN\\jsmith",
            "detection_time": "2024-01-15T14:30:00Z",
            "file_path": "C:\\Users\\jsmith\\Downloads\\invoice.pdf.exe",
        },
    )

    MALWARE_LSASS_ACCESS = AlertData(
        alert_type="edr_detection",
        data={
            "hostname": "workstation-002",
            "process": "notepad.exe",
            "command_line": "notepad.exe",
            "file_hash": "unknown_hash_12345",
            "parent_process": "powershell.exe",
            "target_process": "lsass.exe",
            "access_mask": "0x1fffff",
            "user": "DOMAIN\\svc_account",
            "detection_time": "2024-01-15T15:00:00Z",
        },
    )

    # Authentication alerts
    AUTH_IMPOSSIBLE_TRAVEL = AlertData(
        alert_type="authentication",
        data={
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
        },
    )

    AUTH_BRUTE_FORCE = AlertData(
        alert_type="authentication",
        data={
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
        },
    )

    AUTH_NORMAL_LOGIN = AlertData(
        alert_type="authentication",
        data={
            "user": "jdoe@company.com",
            "event_type": "successful_login",
            "timestamp": "2024-01-15T09:00:00Z",
            "source_ip": "192.168.1.100",
            "geo_location": {"country": "US", "city": "New York"},
            "auth_method": "password_mfa",
            "mfa_status": "passed",
        },
    )

    @classmethod
    def all(cls) -> list[AlertData]:
        """Return all sample alerts."""
        return [
            cls.PHISHING_TYPOSQUAT,
            cls.PHISHING_LEGITIMATE,
            cls.MALWARE_EICAR,
            cls.MALWARE_LSASS_ACCESS,
            cls.AUTH_IMPOSSIBLE_TRAVEL,
            cls.AUTH_BRUTE_FORCE,
            cls.AUTH_NORMAL_LOGIN,
        ]

    @classmethod
    def by_type(cls, alert_type: str) -> list[AlertData]:
        """Return alerts of a specific type."""
        return [a for a in cls.all() if a.alert_type == alert_type]


@dataclass
class IncidentData:
    """Sample incident data for testing."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    alert_type: str = ""
    alert_data: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "alert_type": self.alert_type,
            "alert_data": self.alert_data,
            "status": self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class SampleIncidents:
    """Pre-built sample incidents for common scenarios."""

    @staticmethod
    def phishing_incident(tenant_id: str | None = None) -> IncidentData:
        """Create a phishing incident."""
        return IncidentData(
            tenant_id=tenant_id or str(uuid.uuid4()),
            alert_type="email_security",
            alert_data=SampleAlerts.PHISHING_TYPOSQUAT.to_dict(),
        )

    @staticmethod
    def malware_incident(tenant_id: str | None = None) -> IncidentData:
        """Create a malware incident."""
        return IncidentData(
            tenant_id=tenant_id or str(uuid.uuid4()),
            alert_type="edr_detection",
            alert_data=SampleAlerts.MALWARE_EICAR.to_dict(),
        )

    @staticmethod
    def auth_incident(tenant_id: str | None = None) -> IncidentData:
        """Create an authentication incident."""
        return IncidentData(
            tenant_id=tenant_id or str(uuid.uuid4()),
            alert_type="authentication",
            alert_data=SampleAlerts.AUTH_IMPOSSIBLE_TRAVEL.to_dict(),
        )


def create_sample_incident(
    scenario: str = "phishing",
    tenant_id: str | None = None,
    **overrides: Any,
) -> IncidentData:
    """Create a sample incident for a given scenario.

    Args:
        scenario: One of "phishing", "malware", "auth", "brute_force"
        tenant_id: Optional tenant ID (generated if not provided)
        **overrides: Additional fields to override

    Returns:
        IncidentData with the specified scenario
    """
    scenarios = {
        "phishing": SampleAlerts.PHISHING_TYPOSQUAT,
        "phishing_benign": SampleAlerts.PHISHING_LEGITIMATE,
        "malware": SampleAlerts.MALWARE_EICAR,
        "lsass": SampleAlerts.MALWARE_LSASS_ACCESS,
        "auth": SampleAlerts.AUTH_IMPOSSIBLE_TRAVEL,
        "brute_force": SampleAlerts.AUTH_BRUTE_FORCE,
        "normal_login": SampleAlerts.AUTH_NORMAL_LOGIN,
    }

    alert = scenarios.get(scenario, SampleAlerts.PHISHING_TYPOSQUAT)

    incident = IncidentData(
        tenant_id=tenant_id or str(uuid.uuid4()),
        alert_type=alert.alert_type,
        alert_data=alert.to_dict(),
    )

    # Apply overrides
    for key, value in overrides.items():
        if hasattr(incident, key):
            setattr(incident, key, value)

    return incident


@dataclass
class PlaybookData:
    """Sample playbook data for testing."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    alert_types: list[str] = field(default_factory=list)
    playbook_yaml: str = ""
    enabled: bool = True
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "description": self.description,
            "alert_types": self.alert_types,
            "playbook_yaml": self.playbook_yaml,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


def create_sample_playbook(
    playbook_type: str = "phishing",
    tenant_id: str | None = None,
    **overrides: Any,
) -> PlaybookData:
    """Create a sample playbook for testing.

    Args:
        playbook_type: One of "phishing", "malware", "auth"
        tenant_id: Optional tenant ID
        **overrides: Additional fields to override

    Returns:
        PlaybookData for the specified type
    """
    playbooks = {
        "phishing": PlaybookData(
            name="Phishing Analysis Playbook",
            description="Automated analysis for email-based threats",
            alert_types=["email_security"],
            playbook_yaml="""
name: Phishing Analysis Playbook
description: Automated analysis for email-based threats
alert_types:
  - email_security
steps:
  - name: Check sender domain
    tool: lookup_domain
    input:
      domain: "{{ alert.sender_domain }}"
  - name: Check URLs in email
    tool: lookup_url
    input:
      url: "{{ alert.urls[0] }}"
  - name: Verify email authentication
    tool: check_email_auth
    input:
      spf: "{{ alert.spf_result }}"
      dkim: "{{ alert.dkim_result }}"
      dmarc: "{{ alert.dmarc_result }}"
""",
        ),
        "malware": PlaybookData(
            name="Malware Analysis Playbook",
            description="Automated analysis for endpoint threats",
            alert_types=["edr_detection"],
            playbook_yaml="""
name: Malware Analysis Playbook
description: Automated analysis for endpoint threats
alert_types:
  - edr_detection
steps:
  - name: Check file hash
    tool: lookup_hash
    input:
      hash: "{{ alert.file_hash }}"
  - name: Get host info
    tool: get_host_info
    input:
      hostname: "{{ alert.hostname }}"
  - name: Check related detections
    tool: get_detections
    input:
      hostname: "{{ alert.hostname }}"
      hours: 24
""",
        ),
        "auth": PlaybookData(
            name="Authentication Analysis Playbook",
            description="Automated analysis for suspicious logins",
            alert_types=["authentication"],
            playbook_yaml="""
name: Authentication Analysis Playbook
description: Automated analysis for suspicious logins
alert_types:
  - authentication
steps:
  - name: Check source IP
    tool: lookup_ip
    input:
      ip: "{{ alert.source_ip }}"
  - name: Check user activity
    tool: search_siem
    input:
      query: "user={{ alert.user }}"
      hours: 24
  - name: Get user's recent logins
    tool: get_user_logins
    input:
      user: "{{ alert.user }}"
      hours: 72
""",
        ),
    }

    playbook = playbooks.get(playbook_type, playbooks["phishing"])
    playbook.tenant_id = tenant_id or str(uuid.uuid4())

    # Apply overrides
    for key, value in overrides.items():
        if hasattr(playbook, key):
            setattr(playbook, key, value)

    return playbook


def export_fixtures_to_json(output_dir: Path | str | None = None) -> None:
    """Export all fixtures to JSON files for use by Rust tests.

    This function exports sample data to JSON files that can be loaded
    by both Python and Rust test suites for consistency.

    Args:
        output_dir: Directory to write JSON files (default: tests/fixtures/data/)
    """
    if output_dir is None:
        output_dir = Path(__file__).parent / "data"
    else:
        output_dir = Path(output_dir)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Export alerts
    alerts_data = {
        "phishing_typosquat": SampleAlerts.PHISHING_TYPOSQUAT.to_dict(),
        "phishing_legitimate": SampleAlerts.PHISHING_LEGITIMATE.to_dict(),
        "malware_eicar": SampleAlerts.MALWARE_EICAR.to_dict(),
        "malware_lsass_access": SampleAlerts.MALWARE_LSASS_ACCESS.to_dict(),
        "auth_impossible_travel": SampleAlerts.AUTH_IMPOSSIBLE_TRAVEL.to_dict(),
        "auth_brute_force": SampleAlerts.AUTH_BRUTE_FORCE.to_dict(),
        "auth_normal_login": SampleAlerts.AUTH_NORMAL_LOGIN.to_dict(),
    }

    with open(output_dir / "sample_alerts.json", "w") as f:
        json.dump(alerts_data, f, indent=2)

    # Export playbooks
    playbooks_data = {
        "phishing": create_sample_playbook("phishing").to_dict(),
        "malware": create_sample_playbook("malware").to_dict(),
        "auth": create_sample_playbook("auth").to_dict(),
    }

    with open(output_dir / "sample_playbooks.json", "w") as f:
        json.dump(playbooks_data, f, indent=2)

    print(f"Exported fixtures to {output_dir}")


if __name__ == "__main__":
    # Run this script to generate JSON fixtures
    export_fixtures_to_json()
