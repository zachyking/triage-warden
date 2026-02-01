"""Security-specific analysis functions for indicator extraction and severity calculation."""

from __future__ import annotations

import re
from typing import Any, Literal

from tw_ai.agents.models import Indicator

# ============================================================================
# Regex Patterns for Indicator Extraction
# ============================================================================

# IPv4 - handles both normal and defanged formats (192.168.1.1 or 192[.]168[.]1[.]1)
IPV4_PATTERN = re.compile(
    r"\b(?:"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"(?:\[\.\]|\.)"
    r"){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r"\b"
)

# IPv6 - simplified pattern for common formats
IPV6_PATTERN = re.compile(
    r"\b(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"  # Full form
    r"(?:[0-9a-fA-F]{1,4}:){1,7}:|"  # With trailing ::
    r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"  # :: in middle
    r"(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|"
    r"(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|"
    r"[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|"
    r":(?::[0-9a-fA-F]{1,4}){1,7}|"  # Leading ::
    r"::(?:[fF]{4}:)?"  # IPv4-mapped prefix
    r"(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    r")\b",
    re.IGNORECASE,
)

# Hash patterns
MD5_PATTERN = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_PATTERN = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_PATTERN = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Domain pattern - handles defanged formats (evil[.]com, evil[dot]com)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?" r"(?:\[\.\]|\[dot\]|\.))+[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

# Email pattern - handles defanged formats
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+(?:@|\[@\]|\[at\])[a-zA-Z0-9.-]+(?:\[\.\]|\[dot\]|\.)[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

# URL pattern - handles defanged formats (hxxp, hxxps, [://])
URL_PATTERN = re.compile(
    r"(?:hxxps?|https?|ftp)(?:\[:\]|:)(?://|\[//\])" r"[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+",
    re.IGNORECASE,
)


def _defang_to_normal(value: str) -> str:
    """Convert defanged indicators back to normal format.

    Examples:
        192[.]168[.]1[.]1 -> 192.168.1.1
        evil[.]com -> evil.com
        hxxp[:]// -> http://
        user[@]evil[.]com -> user@evil.com
    """
    result = value
    # Handle IP/domain defanging
    result = result.replace("[.]", ".")
    result = result.replace("[dot]", ".")
    # Handle URL defanging
    result = result.replace("hxxp", "http")
    result = result.replace("[:]", ":")
    result = result.replace("[//]", "//")
    # Handle email defanging
    result = result.replace("[@]", "@")
    result = result.replace("[at]", "@")
    return result


def extract_indicators(text: str) -> list[Indicator]:
    """Extract security indicators from text.

    Extracts various indicators of compromise (IOCs) including:
    - IPv4 addresses (including defanged: 192[.]168[.]1[.]1)
    - IPv6 addresses
    - MD5, SHA1, SHA256 hashes
    - Domains (including defanged: evil[.]com)
    - Email addresses (including defanged: user[@]evil[.]com)
    - URLs (including defanged: hxxp://)

    Args:
        text: The text to scan for indicators.

    Returns:
        List of Indicator objects with extracted values.
        Each indicator has type, value (normalized), and verdict.
    """
    indicators: list[Indicator] = []
    seen_values: set[str] = set()

    def add_indicator(
        indicator_type: Literal[
            "ip", "domain", "url", "hash", "email", "file", "registry", "process", "other"
        ],
        raw_value: str,
    ) -> None:
        """Add an indicator if not already seen."""
        normalized = _defang_to_normal(raw_value)
        if normalized not in seen_values:
            seen_values.add(normalized)
            indicators.append(
                Indicator(
                    type=indicator_type,
                    value=normalized,
                    verdict="unknown",
                    context="Extracted from text",
                )
            )

    # Extract URLs first (most specific)
    for match in URL_PATTERN.finditer(text):
        add_indicator("url", match.group())

    # Extract email addresses
    for match in EMAIL_PATTERN.finditer(text):
        add_indicator("email", match.group())

    # Extract SHA256 hashes (longest first to avoid partial matches)
    for match in SHA256_PATTERN.finditer(text):
        add_indicator("hash", match.group().lower())

    # Extract SHA1 hashes (check not part of SHA256)
    for match in SHA1_PATTERN.finditer(text):
        value = match.group().lower()
        if value not in seen_values:
            add_indicator("hash", value)

    # Extract MD5 hashes (check not part of longer hash)
    for match in MD5_PATTERN.finditer(text):
        value = match.group().lower()
        if value not in seen_values:
            add_indicator("hash", value)

    # Extract IPv4 addresses
    for match in IPV4_PATTERN.finditer(text):
        add_indicator("ip", match.group())

    # Extract IPv6 addresses
    for match in IPV6_PATTERN.finditer(text):
        add_indicator("ip", match.group())

    # Extract domains (filter out those that are part of URLs or emails)
    for match in DOMAIN_PATTERN.finditer(text):
        raw_domain = match.group()
        normalized = _defang_to_normal(raw_domain)

        # Skip if this domain is already part of a URL or email
        is_part_of_other = any(
            normalized in seen_val for seen_val in seen_values if normalized != seen_val
        )
        if not is_part_of_other:
            add_indicator("domain", raw_domain)

    return indicators


def calculate_severity(factors: dict[str, Any]) -> dict[str, Any]:
    """Calculate incident severity based on multiple factors.

    Takes into account:
    - Number of malicious indicators found
    - Number of affected hosts
    - Data sensitivity level
    - User privilege level

    Args:
        factors: Dictionary containing:
            - malicious_indicators (int): Number of malicious IOCs
            - affected_hosts (int): Number of affected systems
            - data_sensitivity (str): "public", "internal", "confidential", "restricted"
            - user_privilege (str): "standard", "privileged", "admin", "service"

    Returns:
        Dictionary with:
            - level: "critical", "high", "medium", "low", "informational"
            - score: Integer 0-100
            - factors: Breakdown of scoring factors
    """
    score = 0
    factor_breakdown = {}

    # Malicious indicators scoring (0-25 points)
    malicious_count = factors.get("malicious_indicators", 0)
    if malicious_count >= 10:
        indicator_score = 25
    elif malicious_count >= 5:
        indicator_score = 20
    elif malicious_count >= 3:
        indicator_score = 15
    elif malicious_count >= 1:
        indicator_score = 10
    else:
        indicator_score = 0
    score += indicator_score
    factor_breakdown["malicious_indicators"] = {
        "count": malicious_count,
        "score": indicator_score,
    }

    # Affected hosts scoring (0-25 points)
    affected_hosts = factors.get("affected_hosts", 0)
    if affected_hosts >= 100:
        hosts_score = 25
    elif affected_hosts >= 50:
        hosts_score = 20
    elif affected_hosts >= 10:
        hosts_score = 15
    elif affected_hosts >= 5:
        hosts_score = 10
    elif affected_hosts >= 1:
        hosts_score = 5
    else:
        hosts_score = 0
    score += hosts_score
    factor_breakdown["affected_hosts"] = {
        "count": affected_hosts,
        "score": hosts_score,
    }

    # Data sensitivity scoring (0-25 points)
    sensitivity_scores = {
        "public": 0,
        "internal": 10,
        "confidential": 20,
        "restricted": 25,
    }
    data_sensitivity = factors.get("data_sensitivity", "public").lower()
    sensitivity_score = sensitivity_scores.get(data_sensitivity, 0)
    score += sensitivity_score
    factor_breakdown["data_sensitivity"] = {
        "level": data_sensitivity,
        "score": sensitivity_score,
    }

    # User privilege scoring (0-25 points)
    privilege_scores = {
        "standard": 5,
        "privileged": 15,
        "admin": 20,
        "service": 25,  # Service accounts often have broad access
    }
    user_privilege = factors.get("user_privilege", "standard").lower()
    privilege_score = privilege_scores.get(user_privilege, 5)
    score += privilege_score
    factor_breakdown["user_privilege"] = {
        "level": user_privilege,
        "score": privilege_score,
    }

    # Determine severity level based on total score
    if score >= 75:
        level = "critical"
    elif score >= 55:
        level = "high"
    elif score >= 35:
        level = "medium"
    elif score >= 15:
        level = "low"
    else:
        level = "informational"

    return {
        "level": level,
        "score": score,
        "factors": factor_breakdown,
    }


def identify_attack_pattern(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Identify attack patterns from a sequence of security events.

    Analyzes events to detect common attack patterns:
    - brute_force: Multiple failed authentication attempts
    - lateral_movement: Access to multiple hosts from single source
    - data_exfiltration: Large data transfers to external destinations
    - credential_theft: Access to credential stores or LSASS

    Args:
        events: List of event dictionaries, each containing:
            - event_type (str): Type of event (e.g., "auth_failure", "network", "process")
            - source (str): Source IP/host
            - destination (str, optional): Target IP/host
            - user (str, optional): Associated user
            - bytes_transferred (int, optional): Data volume
            - process_name (str, optional): Process name
            - Additional event-specific fields

    Returns:
        Dictionary with:
            - pattern: Detected attack pattern name or "unknown"
            - confidence: Integer 0-100
            - indicators: List of evidence supporting the detection
    """
    if not events:
        return {
            "pattern": "unknown",
            "confidence": 0,
            "indicators": [],
        }

    # Analyze patterns
    patterns_detected = []

    # Check for brute force
    brute_force_result = _detect_brute_force(events)
    if brute_force_result["detected"]:
        patterns_detected.append(("brute_force", brute_force_result))

    # Check for lateral movement
    lateral_result = _detect_lateral_movement(events)
    if lateral_result["detected"]:
        patterns_detected.append(("lateral_movement", lateral_result))

    # Check for data exfiltration
    exfil_result = _detect_data_exfiltration(events)
    if exfil_result["detected"]:
        patterns_detected.append(("data_exfiltration", exfil_result))

    # Check for credential theft
    cred_result = _detect_credential_theft(events)
    if cred_result["detected"]:
        patterns_detected.append(("credential_theft", cred_result))

    if not patterns_detected:
        return {
            "pattern": "unknown",
            "confidence": 0,
            "indicators": ["No known attack patterns detected"],
        }

    # Return the pattern with highest confidence
    patterns_detected.sort(key=lambda x: x[1]["confidence"], reverse=True)
    best_pattern, best_result = patterns_detected[0]

    return {
        "pattern": best_pattern,
        "confidence": best_result["confidence"],
        "indicators": best_result["indicators"],
    }


def _detect_brute_force(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect brute force attack pattern."""
    auth_failures = [
        e
        for e in events
        if e.get("event_type") in ("auth_failure", "login_failure", "authentication_failed")
    ]

    if len(auth_failures) < 3:
        return {"detected": False, "confidence": 0, "indicators": []}

    # Group by source
    sources: dict[str, int] = {}
    users_targeted: set[str] = set()

    for event in auth_failures:
        source = event.get("source", "unknown")
        sources[source] = sources.get(source, 0) + 1
        if event.get("user"):
            users_targeted.add(event["user"])

    # Find sources with multiple failures
    suspicious_sources = [s for s, count in sources.items() if count >= 3]

    if not suspicious_sources:
        return {"detected": False, "confidence": 0, "indicators": []}

    max_failures = max(sources.values())

    # Calculate confidence based on volume and pattern
    if max_failures >= 100:
        confidence = 95
    elif max_failures >= 50:
        confidence = 90
    elif max_failures >= 20:
        confidence = 85
    elif max_failures >= 10:
        confidence = 75
    elif max_failures >= 5:
        confidence = 60
    else:
        confidence = 45

    indicators = [
        f"{len(auth_failures)} authentication failures detected",
        f"Suspicious sources: {', '.join(suspicious_sources[:5])}",
        f"Max failures from single source: {max_failures}",
    ]

    if len(users_targeted) > 1:
        indicators.append(f"Multiple users targeted: {len(users_targeted)}")

    return {
        "detected": True,
        "confidence": confidence,
        "indicators": indicators,
    }


def _detect_lateral_movement(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect lateral movement pattern."""
    network_events = [
        e
        for e in events
        if e.get("event_type") in ("network", "connection", "smb", "rdp", "ssh", "wmi", "psexec")
    ]

    if len(network_events) < 2:
        return {"detected": False, "confidence": 0, "indicators": []}

    # Group by source to find single sources accessing multiple destinations
    source_to_destinations: dict[str, set[str]] = {}

    for event in network_events:
        source = event.get("source")
        dest = event.get("destination")
        if source and dest:
            if source not in source_to_destinations:
                source_to_destinations[source] = set()
            source_to_destinations[source].add(dest)

    # Find sources connecting to multiple destinations
    lateral_sources = {
        source: dests for source, dests in source_to_destinations.items() if len(dests) >= 3
    }

    if not lateral_sources:
        return {"detected": False, "confidence": 0, "indicators": []}

    max_destinations = max(len(dests) for dests in lateral_sources.values())

    # Calculate confidence
    if max_destinations >= 20:
        confidence = 95
    elif max_destinations >= 10:
        confidence = 85
    elif max_destinations >= 5:
        confidence = 70
    else:
        confidence = 55

    indicators = [
        f"{len(lateral_sources)} source(s) connecting to multiple hosts",
        f"Max hosts from single source: {max_destinations}",
    ]

    # Check for use of admin tools
    admin_tools = {"psexec", "wmi", "rdp", "ssh", "smb"}
    tools_used: set[str] = {
        e.get("event_type")  # type: ignore[misc]
        for e in network_events
        if e.get("event_type") in admin_tools
    }
    if tools_used:
        indicators.append(f"Admin tools detected: {', '.join(tools_used)}")
        confidence = min(confidence + 10, 98)

    return {
        "detected": True,
        "confidence": confidence,
        "indicators": indicators,
    }


def _detect_data_exfiltration(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect data exfiltration pattern."""
    data_events = [
        e
        for e in events
        if e.get("event_type") in ("network", "upload", "transfer", "dns")
        and e.get("bytes_transferred", 0) > 0
    ]

    if not data_events:
        return {"detected": False, "confidence": 0, "indicators": []}

    # Calculate total data transferred
    total_bytes = sum(e.get("bytes_transferred", 0) for e in data_events)

    # Check for external destinations
    external_transfers = [
        e
        for e in data_events
        if e.get("destination_external", False) or _is_external_ip(e.get("destination", ""))
    ]

    external_bytes = sum(e.get("bytes_transferred", 0) for e in external_transfers)

    # Thresholds for suspicious data volumes
    mb = 1024 * 1024
    gb = 1024 * mb

    if external_bytes < 10 * mb:  # Less than 10MB to external
        return {"detected": False, "confidence": 0, "indicators": []}

    # Calculate confidence based on volume
    if external_bytes >= gb:
        confidence = 95
    elif external_bytes >= 500 * mb:
        confidence = 90
    elif external_bytes >= 100 * mb:
        confidence = 80
    elif external_bytes >= 50 * mb:
        confidence = 70
    else:
        confidence = 55

    # Check for suspicious destinations
    destinations: list[str] = [
        e.get("destination")  # type: ignore[misc]
        for e in external_transfers
        if e.get("destination")
    ]
    # Remove duplicates while preserving order
    destinations = list(dict.fromkeys(destinations))

    indicators = [
        f"External data transfer: {external_bytes / mb:.2f} MB",
        f"Total data transfer: {total_bytes / mb:.2f} MB",
        f"External destinations: {len(destinations)}",
    ]

    if destinations:
        indicators.append(f"Top destinations: {', '.join(destinations[:5])}")

    # Check for unusual timing
    off_hours_events = [e for e in external_transfers if e.get("off_hours", False)]
    if len(off_hours_events) > len(external_transfers) // 2:
        indicators.append("Majority of transfers occurred outside business hours")
        confidence = min(confidence + 5, 98)

    return {
        "detected": True,
        "confidence": confidence,
        "indicators": indicators,
    }


def _detect_credential_theft(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Detect credential theft pattern."""
    credential_events = [
        e
        for e in events
        if (
            e.get("event_type") in ("process", "file_access", "registry")
            and _is_credential_related(e)
        )
    ]

    if not credential_events:
        return {"detected": False, "confidence": 0, "indicators": []}

    indicators = []
    confidence = 50

    # Check for LSASS access
    lsass_events = [
        e
        for e in credential_events
        if "lsass" in str(e.get("target_process", "")).lower()
        or "lsass" in str(e.get("process_name", "")).lower()
    ]
    if lsass_events:
        indicators.append(f"LSASS process access detected ({len(lsass_events)} events)")
        confidence += 20

    # Check for SAM/SECURITY hive access
    hive_events = [
        e
        for e in credential_events
        if any(
            hive in str(e.get("file_path", "")).upper() for hive in ("SAM", "SECURITY", "SYSTEM")
        )
    ]
    if hive_events:
        indicators.append(f"Registry hive access detected ({len(hive_events)} events)")
        confidence += 15

    # Check for credential dumping tools
    dump_tools = {"mimikatz", "procdump", "comsvcs", "secretsdump", "lazagne"}
    tool_events = [
        e
        for e in credential_events
        if any(
            tool in str(e.get("process_name", "")).lower()
            or tool in str(e.get("command_line", "")).lower()
            for tool in dump_tools
        )
    ]
    if tool_events:
        tools_found = set()
        for e in tool_events:
            for tool in dump_tools:
                if (
                    tool in str(e.get("process_name", "")).lower()
                    or tool in str(e.get("command_line", "")).lower()
                ):
                    tools_found.add(tool)
        indicators.append(f"Credential dumping tools detected: {', '.join(tools_found)}")
        confidence += 25

    if not indicators:
        indicators.append(
            f"Suspicious credential-related activity ({len(credential_events)} events)"
        )

    return {
        "detected": True,
        "confidence": min(confidence, 98),
        "indicators": indicators,
    }


def _is_credential_related(event: dict[str, Any]) -> bool:
    """Check if an event is related to credential access."""
    credential_indicators = [
        "lsass",
        "sam",
        "security",
        "ntds",
        "credential",
        "password",
        "vault",
        "mimikatz",
        "procdump",
        "secretsdump",
        "hashdump",
        "kerberos",
        "krbtgt",
    ]

    event_str = str(event).lower()
    return any(indicator in event_str for indicator in credential_indicators)


def _is_external_ip(ip: str) -> bool:
    """Check if an IP address is external (non-RFC1918)."""
    if not ip:
        return False

    # Simple check for private IP ranges
    private_prefixes = [
        "10.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31.",
        "192.168.",
        "127.",
        "169.254.",
    ]

    return not any(ip.startswith(prefix) for prefix in private_prefixes)
