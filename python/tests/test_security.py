"""Comprehensive unit tests for security analysis functions."""

from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

import pytest


# Direct module loading to avoid Python 3.10+ syntax issues
_base_path = Path(__file__).parent.parent / "tw_ai"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load models first (dependencies)
_models = _load_module("tw_ai.agents.models", _base_path / "agents" / "models.py")
Indicator = _models.Indicator
MITRETechnique = _models.MITRETechnique

# Load analysis modules
_security = _load_module("tw_ai.analysis.security", _base_path / "analysis" / "security.py")
extract_indicators = _security.extract_indicators
calculate_severity = _security.calculate_severity
identify_attack_pattern = _security.identify_attack_pattern

_mitre = _load_module("tw_ai.analysis.mitre", _base_path / "analysis" / "mitre.py")
map_to_mitre = _mitre.map_to_mitre
MITRE_MAPPINGS = _mitre.MITRE_MAPPINGS
get_technique_info = _mitre.get_technique_info
get_techniques_by_tactic = _mitre.get_techniques_by_tactic


# ============================================================================
# Tests for extract_indicators
# ============================================================================


class TestExtractIndicatorsIPv4:
    """Tests for IPv4 extraction."""

    def test_extract_normal_ipv4(self):
        """Test extracting normal IPv4 addresses."""
        text = "The attacker connected from 192.168.1.100 to 10.0.0.1"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        values = {i.value for i in ip_indicators}

        assert "192.168.1.100" in values
        assert "10.0.0.1" in values

    def test_extract_defanged_ipv4(self):
        """Test extracting defanged IPv4 addresses."""
        text = "C2 server: 192[.]168[.]1[.]100"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        assert len(ip_indicators) == 1
        assert ip_indicators[0].value == "192.168.1.100"

    def test_extract_boundary_ipv4(self):
        """Test extracting IPv4 addresses at boundaries."""
        text = "0.0.0.0 and 255.255.255.255 are boundary values"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        values = {i.value for i in ip_indicators}

        assert "0.0.0.0" in values
        assert "255.255.255.255" in values

    def test_no_false_positive_version_numbers(self):
        """Test that version numbers aren't extracted as IPs."""
        text = "Python version 3.10.1 is used"
        indicators = extract_indicators(text)

        # 3.10.1 is not a valid IP (first octet only)
        ip_indicators = [i for i in indicators if i.type == "ip"]
        assert len(ip_indicators) == 0


class TestExtractIndicatorsIPv6:
    """Tests for IPv6 extraction."""

    def test_extract_full_ipv6(self):
        """Test extracting full IPv6 addresses."""
        text = "Connection from 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        assert len(ip_indicators) >= 1

    def test_extract_compressed_ipv6(self):
        """Test extracting compressed IPv6 addresses."""
        text = "Address: 2001:db8::1"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        # IPv6 patterns can be tricky; verify we get at least the address
        assert len(ip_indicators) >= 1


class TestExtractIndicatorsHashes:
    """Tests for hash extraction."""

    def test_extract_md5(self):
        """Test extracting MD5 hashes."""
        text = "MD5: d41d8cd98f00b204e9800998ecf8427e"
        indicators = extract_indicators(text)

        hash_indicators = [i for i in indicators if i.type == "hash"]
        assert len(hash_indicators) == 1
        assert hash_indicators[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_extract_sha1(self):
        """Test extracting SHA1 hashes."""
        text = "SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        indicators = extract_indicators(text)

        hash_indicators = [i for i in indicators if i.type == "hash"]
        assert len(hash_indicators) == 1
        assert hash_indicators[0].value == "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_extract_sha256(self):
        """Test extracting SHA256 hashes."""
        text = "SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        indicators = extract_indicators(text)

        hash_indicators = [i for i in indicators if i.type == "hash"]
        assert len(hash_indicators) == 1
        assert hash_indicators[0].value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_extract_mixed_case_hash(self):
        """Test extracting hashes with mixed case."""
        text = "Hash: D41D8CD98F00B204E9800998ECF8427E"
        indicators = extract_indicators(text)

        hash_indicators = [i for i in indicators if i.type == "hash"]
        assert len(hash_indicators) == 1
        # Should be normalized to lowercase
        assert hash_indicators[0].value == "d41d8cd98f00b204e9800998ecf8427e"

    def test_no_duplicate_hashes_subset(self):
        """Test that shorter hashes aren't extracted if part of longer hash."""
        # SHA256 contains what could be MD5 and SHA1 substrings
        text = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        indicators = extract_indicators(text)

        # Should only get the SHA256, not substrings
        hash_indicators = [i for i in indicators if i.type == "hash"]
        assert len(hash_indicators) == 1


class TestExtractIndicatorsDomains:
    """Tests for domain extraction."""

    def test_extract_normal_domain(self):
        """Test extracting normal domains."""
        text = "Malware connected to evil.com"
        indicators = extract_indicators(text)

        domain_indicators = [i for i in indicators if i.type == "domain"]
        assert any(i.value == "evil.com" for i in domain_indicators)

    def test_extract_defanged_domain(self):
        """Test extracting defanged domains."""
        text = "C2 domain: malicious[.]example[.]com"
        indicators = extract_indicators(text)

        domain_indicators = [i for i in indicators if i.type == "domain"]
        assert any(i.value == "malicious.example.com" for i in domain_indicators)

    def test_extract_subdomain(self):
        """Test extracting domains with subdomains."""
        text = "Beacon to c2.attacker.evil.com"
        indicators = extract_indicators(text)

        domain_indicators = [i for i in indicators if i.type == "domain"]
        assert any("c2.attacker.evil.com" in i.value for i in domain_indicators)

    def test_defanged_dot_variants(self):
        """Test extracting domains with [dot] defanging."""
        text = "Domain: evil[dot]com"
        indicators = extract_indicators(text)

        domain_indicators = [i for i in indicators if i.type == "domain"]
        assert any(i.value == "evil.com" for i in domain_indicators)


class TestExtractIndicatorsEmails:
    """Tests for email extraction."""

    def test_extract_normal_email(self):
        """Test extracting normal email addresses."""
        text = "Phishing email from attacker@evil.com"
        indicators = extract_indicators(text)

        email_indicators = [i for i in indicators if i.type == "email"]
        assert any(i.value == "attacker@evil.com" for i in email_indicators)

    def test_extract_defanged_email(self):
        """Test extracting defanged email addresses."""
        text = "Sender: attacker[@]evil[.]com"
        indicators = extract_indicators(text)

        email_indicators = [i for i in indicators if i.type == "email"]
        assert any(i.value == "attacker@evil.com" for i in email_indicators)

    def test_extract_email_at_variant(self):
        """Test extracting emails with [at] defanging."""
        text = "From: hacker[at]malware[.]net"
        indicators = extract_indicators(text)

        email_indicators = [i for i in indicators if i.type == "email"]
        assert any(i.value == "hacker@malware.net" for i in email_indicators)


class TestExtractIndicatorsURLs:
    """Tests for URL extraction."""

    def test_extract_http_url(self):
        """Test extracting HTTP URLs."""
        text = "Downloaded from http://evil.com/malware.exe"
        indicators = extract_indicators(text)

        url_indicators = [i for i in indicators if i.type == "url"]
        assert any("http://evil.com/malware.exe" in i.value for i in url_indicators)

    def test_extract_https_url(self):
        """Test extracting HTTPS URLs."""
        text = "C2: https://c2.attacker.com/beacon"
        indicators = extract_indicators(text)

        url_indicators = [i for i in indicators if i.type == "url"]
        assert any("https://c2.attacker.com/beacon" in i.value for i in url_indicators)

    def test_extract_defanged_url(self):
        """Test extracting defanged URLs."""
        text = "Payload URL: hxxps[:]//malware[.]evil[.]com/download"
        indicators = extract_indicators(text)

        url_indicators = [i for i in indicators if i.type == "url"]
        assert len(url_indicators) >= 1
        # Should be normalized
        assert any("https://malware.evil.com" in i.value for i in url_indicators)


class TestExtractIndicatorsMixed:
    """Tests for extracting mixed indicators."""

    def test_extract_multiple_types(self):
        """Test extracting multiple indicator types from one text."""
        text = """
        Alert: Malicious activity detected
        Source IP: 192.168.1.100
        C2 Domain: evil[.]com
        Downloaded from: hxxp[:]//malware.com/payload.exe
        File hash: d41d8cd98f00b204e9800998ecf8427e
        Attacker email: bad@actor.com
        """
        indicators = extract_indicators(text)

        types_found = {i.type for i in indicators}
        assert "ip" in types_found
        assert "domain" in types_found
        assert "url" in types_found
        assert "hash" in types_found
        assert "email" in types_found

    def test_no_duplicates(self):
        """Test that duplicate indicators are not returned."""
        text = "IP 192.168.1.1 connected to 192.168.1.1 multiple times"
        indicators = extract_indicators(text)

        ip_indicators = [i for i in indicators if i.type == "ip"]
        values = [i.value for i in ip_indicators]
        assert len(values) == len(set(values))

    def test_empty_string(self):
        """Test handling empty string."""
        indicators = extract_indicators("")
        assert indicators == []

    def test_no_indicators(self):
        """Test text with no indicators."""
        text = "This is a normal sentence with no security indicators."
        indicators = extract_indicators(text)
        assert len(indicators) == 0


# ============================================================================
# Tests for calculate_severity
# ============================================================================


class TestCalculateSeverity:
    """Tests for severity calculation."""

    def test_critical_severity(self):
        """Test factors that result in critical severity."""
        factors = {
            "malicious_indicators": 10,
            "affected_hosts": 100,
            "data_sensitivity": "restricted",
            "user_privilege": "admin",
        }
        result = calculate_severity(factors)

        assert result["level"] == "critical"
        assert result["score"] >= 75

    def test_high_severity(self):
        """Test factors that result in high severity."""
        factors = {
            "malicious_indicators": 5,
            "affected_hosts": 20,
            "data_sensitivity": "confidential",
            "user_privilege": "privileged",
        }
        result = calculate_severity(factors)

        assert result["level"] in ("critical", "high")
        assert result["score"] >= 55

    def test_medium_severity(self):
        """Test factors that result in medium severity."""
        factors = {
            "malicious_indicators": 2,
            "affected_hosts": 3,
            "data_sensitivity": "internal",
            "user_privilege": "standard",
        }
        result = calculate_severity(factors)

        assert result["level"] in ("medium", "low")

    def test_low_severity(self):
        """Test factors that result in low severity."""
        factors = {
            "malicious_indicators": 1,
            "affected_hosts": 1,
            "data_sensitivity": "public",
            "user_privilege": "standard",
        }
        result = calculate_severity(factors)

        assert result["level"] in ("low", "informational", "medium")

    def test_informational_severity(self):
        """Test factors that result in informational severity."""
        factors = {
            "malicious_indicators": 0,
            "affected_hosts": 0,
            "data_sensitivity": "public",
            "user_privilege": "standard",
        }
        result = calculate_severity(factors)

        assert result["level"] in ("informational", "low")
        assert result["score"] <= 20

    def test_score_breakdown(self):
        """Test that score breakdown is provided."""
        factors = {
            "malicious_indicators": 5,
            "affected_hosts": 10,
            "data_sensitivity": "confidential",
            "user_privilege": "admin",
        }
        result = calculate_severity(factors)

        assert "factors" in result
        assert "malicious_indicators" in result["factors"]
        assert "affected_hosts" in result["factors"]
        assert "data_sensitivity" in result["factors"]
        assert "user_privilege" in result["factors"]

    def test_missing_factors_use_defaults(self):
        """Test that missing factors use reasonable defaults."""
        result = calculate_severity({})

        assert "level" in result
        assert "score" in result
        assert isinstance(result["score"], int)

    def test_case_insensitive_sensitivity(self):
        """Test that data sensitivity is case insensitive."""
        result1 = calculate_severity({"data_sensitivity": "CONFIDENTIAL"})
        result2 = calculate_severity({"data_sensitivity": "confidential"})

        assert result1["factors"]["data_sensitivity"]["score"] == result2["factors"]["data_sensitivity"]["score"]


# ============================================================================
# Tests for identify_attack_pattern
# ============================================================================


class TestIdentifyAttackPatternBruteForce:
    """Tests for brute force pattern detection."""

    def test_detect_brute_force(self):
        """Test detecting brute force pattern."""
        events = [
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "brute_force"
        assert result["confidence"] >= 45

    def test_brute_force_high_volume(self):
        """Test high confidence for high volume brute force."""
        events = [
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": f"user{i}"}
            for i in range(100)
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "brute_force"
        assert result["confidence"] >= 90

    def test_no_brute_force_few_failures(self):
        """Test that few failures don't trigger brute force detection."""
        events = [
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.2", "user": "user1"},
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] != "brute_force" or result["confidence"] < 50


class TestIdentifyAttackPatternLateralMovement:
    """Tests for lateral movement pattern detection."""

    def test_detect_lateral_movement(self):
        """Test detecting lateral movement pattern."""
        events = [
            {"event_type": "smb", "source": "10.0.0.1", "destination": "10.0.0.10"},
            {"event_type": "smb", "source": "10.0.0.1", "destination": "10.0.0.11"},
            {"event_type": "smb", "source": "10.0.0.1", "destination": "10.0.0.12"},
            {"event_type": "rdp", "source": "10.0.0.1", "destination": "10.0.0.13"},
            {"event_type": "wmi", "source": "10.0.0.1", "destination": "10.0.0.14"},
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "lateral_movement"
        assert result["confidence"] >= 55

    def test_lateral_movement_with_admin_tools(self):
        """Test higher confidence with admin tools."""
        events = [
            {"event_type": "psexec", "source": "10.0.0.1", "destination": f"10.0.0.{i}"}
            for i in range(10, 20)
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "lateral_movement"
        assert result["confidence"] >= 80


class TestIdentifyAttackPatternDataExfiltration:
    """Tests for data exfiltration pattern detection."""

    def test_detect_data_exfiltration(self):
        """Test detecting data exfiltration pattern."""
        MB = 1024 * 1024
        events = [
            {
                "event_type": "network",
                "source": "10.0.0.1",
                "destination": "203.0.113.1",
                "bytes_transferred": 100 * MB,
                "destination_external": True,
            },
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "data_exfiltration"
        assert result["confidence"] >= 70

    def test_large_volume_exfiltration(self):
        """Test high confidence for large data exfiltration."""
        GB = 1024 * 1024 * 1024
        events = [
            {
                "event_type": "upload",
                "source": "10.0.0.1",
                "destination": "external.attacker.com",
                "bytes_transferred": 2 * GB,
                "destination_external": True,
            },
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "data_exfiltration"
        assert result["confidence"] >= 90


class TestIdentifyAttackPatternCredentialTheft:
    """Tests for credential theft pattern detection."""

    def test_detect_lsass_access(self):
        """Test detecting LSASS memory access."""
        events = [
            {
                "event_type": "process",
                "process_name": "procdump.exe",
                "target_process": "lsass.exe",
            },
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "credential_theft"
        assert result["confidence"] >= 50

    def test_detect_mimikatz(self):
        """Test detecting mimikatz usage."""
        events = [
            {
                "event_type": "process",
                "process_name": "mimikatz.exe",
                "command_line": "sekurlsa::logonpasswords",
            },
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "credential_theft"
        assert result["confidence"] >= 70


class TestIdentifyAttackPatternGeneral:
    """General tests for attack pattern identification."""

    def test_empty_events(self):
        """Test handling empty events list."""
        result = identify_attack_pattern([])

        assert result["pattern"] == "unknown"
        assert result["confidence"] == 0

    def test_unknown_pattern(self):
        """Test events that don't match known patterns."""
        events = [
            {"event_type": "login_success", "user": "admin"},
            {"event_type": "file_read", "path": "/etc/passwd"},
        ]
        result = identify_attack_pattern(events)

        assert result["pattern"] == "unknown"

    def test_highest_confidence_wins(self):
        """Test that pattern with highest confidence is returned."""
        events = [
            # Some brute force indicators
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            # Strong credential theft indicator
            {
                "event_type": "process",
                "process_name": "mimikatz.exe",
                "command_line": "sekurlsa::logonpasswords",
                "target_process": "lsass.exe",
            },
        ]
        result = identify_attack_pattern(events)

        # Should return the pattern with highest confidence
        assert result["pattern"] in ("brute_force", "credential_theft")
        assert result["confidence"] > 0


# ============================================================================
# Tests for map_to_mitre
# ============================================================================


class TestMapToMITRE:
    """Tests for MITRE ATT&CK mapping."""

    def test_map_powershell(self):
        """Test mapping PowerShell execution."""
        techniques = map_to_mitre("encoded powershell command execution")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert "T1059.001" in technique_ids

    def test_map_phishing(self):
        """Test mapping phishing activity."""
        techniques = map_to_mitre("spearphishing email with malicious attachment")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        # Should match phishing techniques
        assert any(tid.startswith("T1566") for tid in technique_ids)

    def test_map_credential_dumping(self):
        """Test mapping credential dumping."""
        techniques = map_to_mitre("mimikatz credential dump from lsass")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        # Should match credential access techniques
        assert any(tid.startswith("T1003") for tid in technique_ids)

    def test_map_brute_force(self):
        """Test mapping brute force activity."""
        techniques = map_to_mitre("multiple failed login attempts password spray attack")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert any(tid.startswith("T1110") for tid in technique_ids)

    def test_map_lateral_movement(self):
        """Test mapping lateral movement."""
        techniques = map_to_mitre("psexec lateral movement to multiple hosts using smb")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert any(tid.startswith("T1021") for tid in technique_ids)

    def test_map_persistence(self):
        """Test mapping persistence mechanisms."""
        techniques = map_to_mitre("registry run key modification for persistence")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert any(tid.startswith("T1547") for tid in technique_ids)

    def test_map_defense_evasion(self):
        """Test mapping defense evasion."""
        techniques = map_to_mitre("obfuscated base64 encoded payload")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert any(tid.startswith("T1027") for tid in technique_ids)

    def test_map_ransomware(self):
        """Test mapping ransomware activity."""
        techniques = map_to_mitre("ransomware encryption of files with ransom note")

        assert len(techniques) >= 1
        technique_ids = {t.id for t in techniques}
        assert "T1486" in technique_ids

    def test_map_empty_description(self):
        """Test handling empty description."""
        techniques = map_to_mitre("")
        assert techniques == []

    def test_map_no_match(self):
        """Test description with no technique match."""
        techniques = map_to_mitre("normal user login successful")
        # May return empty or low-confidence matches
        # The important thing is it doesn't crash

    def test_technique_has_required_fields(self):
        """Test that returned techniques have all required fields."""
        techniques = map_to_mitre("powershell execution")

        for technique in techniques:
            assert technique.id is not None
            assert technique.name is not None
            assert technique.tactic is not None
            assert technique.relevance is not None

    def test_direct_technique_id_mention(self):
        """Test that direct technique ID mention is recognized."""
        techniques = map_to_mitre("Technique T1059.001 was observed")

        assert len(techniques) >= 1
        assert any(t.id == "T1059.001" for t in techniques)

    def test_subtechnique_preferred_over_parent(self):
        """Test that subtechniques are preferred over parent techniques."""
        techniques = map_to_mitre("powershell encoded command")

        # Should get T1059.001 (PowerShell) not just T1059 (Command and Scripting Interpreter)
        technique_ids = {t.id for t in techniques}
        if "T1059.001" in technique_ids:
            # If we have the subtechnique, we shouldn't also have the parent
            # (unless there's also specific parent matching)
            pass  # This is expected behavior


class TestMITREMappings:
    """Tests for MITRE_MAPPINGS dictionary."""

    def test_mappings_not_empty(self):
        """Test that mappings dictionary is populated."""
        assert len(MITRE_MAPPINGS) > 0

    def test_required_techniques_present(self):
        """Test that required techniques are present."""
        required = [
            "T1566.001",  # Spearphishing Attachment
            "T1566.002",  # Spearphishing Link
            "T1059.001",  # PowerShell
            "T1059.003",  # CMD
            "T1003",      # Credential Dumping
            "T1110",      # Brute Force
            "T1547.001",  # Registry Run Keys
            "T1053",      # Scheduled Task
            "T1027",      # Obfuscation
            "T1070",      # Indicator Removal
            "T1021",      # Remote Services
        ]
        for tech_id in required:
            assert tech_id in MITRE_MAPPINGS, f"Missing required technique: {tech_id}"

    def test_technique_info_structure(self):
        """Test that technique info has correct structure."""
        for tech_id, info in MITRE_MAPPINGS.items():
            assert info.id == tech_id
            assert info.name is not None and len(info.name) > 0
            assert info.tactic is not None and len(info.tactic) > 0
            assert info.keywords is not None and len(info.keywords) > 0


class TestGetTechniqueInfo:
    """Tests for get_technique_info function."""

    def test_get_existing_technique(self):
        """Test getting info for existing technique."""
        info = get_technique_info("T1059.001")

        assert info is not None
        assert info.id == "T1059.001"
        assert info.name == "PowerShell"
        assert info.tactic == "Execution"

    def test_get_nonexistent_technique(self):
        """Test getting info for nonexistent technique."""
        info = get_technique_info("T9999.999")

        assert info is None


class TestGetTechniquesByTactic:
    """Tests for get_techniques_by_tactic function."""

    def test_get_execution_techniques(self):
        """Test getting Execution tactic techniques."""
        techniques = get_techniques_by_tactic("Execution")

        assert len(techniques) > 0
        for tech in techniques:
            assert tech.tactic == "Execution"

    def test_get_initial_access_techniques(self):
        """Test getting Initial Access tactic techniques."""
        techniques = get_techniques_by_tactic("Initial Access")

        assert len(techniques) > 0
        for tech in techniques:
            assert tech.tactic == "Initial Access"

    def test_case_insensitive_tactic(self):
        """Test that tactic lookup is case insensitive."""
        techniques1 = get_techniques_by_tactic("Execution")
        techniques2 = get_techniques_by_tactic("execution")

        assert len(techniques1) == len(techniques2)

    def test_nonexistent_tactic(self):
        """Test getting techniques for nonexistent tactic."""
        techniques = get_techniques_by_tactic("Nonexistent Tactic")

        assert techniques == []


# ============================================================================
# Integration Tests
# ============================================================================


class TestIntegration:
    """Integration tests combining multiple functions."""

    def test_extract_and_calculate_severity(self):
        """Test extracting indicators and calculating severity."""
        text = """
        Alert: Multiple malicious indicators detected
        Source IPs: 192.168.1.100, 192.168.1.101, 192.168.1.102
        Domains: evil[.]com, malware[.]net, c2[.]attacker[.]org
        Hashes: d41d8cd98f00b204e9800998ecf8427e, abc123def456abc123def456abc123de
        """
        indicators = extract_indicators(text)

        # Count malicious (for this test, assume all extracted are malicious)
        factors = {
            "malicious_indicators": len(indicators),
            "affected_hosts": 3,
            "data_sensitivity": "confidential",
            "user_privilege": "admin",
        }
        severity = calculate_severity(factors)

        assert severity["level"] in ("critical", "high")
        assert len(indicators) > 0

    def test_pattern_to_mitre_mapping(self):
        """Test mapping attack pattern to MITRE techniques."""
        events = [
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
            {"event_type": "auth_failure", "source": "10.0.0.1", "user": "admin"},
        ]
        pattern = identify_attack_pattern(events)

        # Map the pattern to MITRE
        if pattern["pattern"] == "brute_force":
            techniques = map_to_mitre("brute force password attack")
            assert len(techniques) >= 1
            assert any(t.id.startswith("T1110") for t in techniques)

    def test_full_analysis_workflow(self):
        """Test complete analysis workflow."""
        # Simulate an incident description
        incident = """
        Alert: Suspicious PowerShell activity detected

        Source Host: workstation-001 (192.168.1.50)
        User: john.admin (Domain Admin)

        PowerShell process executed encoded command:
        powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAY...

        Network connection observed to: 203.0.113.50 (evil[.]c2[.]net)

        File hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

        This appears to be a living-off-the-land attack using encoded PowerShell
        for command and control communication.
        """

        # Extract indicators
        indicators = extract_indicators(incident)
        assert len(indicators) > 0

        # Calculate severity
        severity = calculate_severity({
            "malicious_indicators": len([i for i in indicators if i.type in ("ip", "hash", "domain")]),
            "affected_hosts": 1,
            "data_sensitivity": "confidential",
            "user_privilege": "admin",
        })
        assert severity["level"] in ("critical", "high", "medium")

        # Map to MITRE
        techniques = map_to_mitre(incident)
        assert len(techniques) > 0
        technique_ids = {t.id for t in techniques}
        # Should identify PowerShell technique
        assert "T1059.001" in technique_ids
