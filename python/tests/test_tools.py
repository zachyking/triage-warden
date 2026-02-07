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

# Load actual email analysis modules
_tw_ai_base = Path(__file__).parent.parent / "tw_ai"
sys.path.insert(0, str(_tw_ai_base.parent))

# Import and register real email/phishing modules
def _setup_analysis_modules():
    """Setup the analysis modules before tools.py loads."""
    from dataclasses import dataclass, field
    from typing import Optional, Literal
    import re

    # Create email module
    email_module = MagicMock()

    @dataclass
    class ExtractedURL:
        url: str
        domain: str
        display_text: Optional[str] = None
        is_shortened: bool = False
        is_ip_based: bool = False

    @dataclass
    class AttachmentInfo:
        filename: str
        content_type: str
        size_bytes: int
        md5: Optional[str] = None
        sha256: Optional[str] = None

    @dataclass
    class EmailAuthResult:
        spf: str = "none"
        dkim: str = "none"
        dmarc: str = "none"

    @dataclass
    class EmailAnalysis:
        message_id: str
        subject: str
        sender: str
        sender_display_name: Optional[str] = None
        reply_to: Optional[str] = None
        recipients: list = field(default_factory=list)
        cc: list = field(default_factory=list)
        headers: dict = field(default_factory=dict)
        body_text: Optional[str] = None
        body_html: Optional[str] = None
        urls: list = field(default_factory=list)
        attachments: list = field(default_factory=list)
        received_timestamps: list = field(default_factory=list)
        authentication: EmailAuthResult = field(default_factory=EmailAuthResult)

    # URL shorteners
    URL_SHORTENERS = frozenset([
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    ])

    # URL pattern
    URL_PATTERN = re.compile(
        r"(?P<scheme>hxxps?|https?|ftp)"
        r"(?:\[:\]|:)"
        r"(?://|\[//\])"
        r"(?P<url_body>[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)",
        re.IGNORECASE,
    )

    IP_ADDRESS_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\[\.\]|\.)){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )

    def _defang_to_normal(value):
        result = value
        result = re.sub(r"hxxp", "http", result, flags=re.IGNORECASE)
        result = result.replace("[:]", ":")
        result = result.replace("[//]", "//")
        result = result.replace("[.]", ".")
        result = result.replace("[dot]", ".")
        result = result.replace("[@]", "@")
        result = result.replace("[at]", "@")
        return result

    def _extract_domain_from_url(url):
        url_no_scheme = re.sub(r"^[a-zA-Z]+://", "", url)
        host = url_no_scheme.split("/")[0]
        if "@" in host:
            host = host.split("@")[-1]
        host = host.split(":")[0]
        return host.lower()

    def _is_url_shortened(domain):
        return domain.lower() in URL_SHORTENERS

    def _is_ip_based_url(domain):
        normalized = _defang_to_normal(domain)
        return bool(IP_ADDRESS_PATTERN.match(normalized))

    def extract_urls(text):
        if not text:
            return []
        urls = []
        seen = set()
        for match in URL_PATTERN.finditer(text):
            full_match = match.group(0)
            normalized = _defang_to_normal(full_match)
            if normalized in seen:
                continue
            seen.add(normalized)
            domain = _extract_domain_from_url(normalized)
            urls.append(ExtractedURL(
                url=normalized,
                domain=domain,
                display_text=None,
                is_shortened=_is_url_shortened(domain),
                is_ip_based=_is_ip_based_url(domain),
            ))
        return urls

    def extract_urls_from_html(html):
        if not html:
            return []
        urls = []
        seen = set()

        # Simple HTML link extraction
        from html.parser import HTMLParser

        class LinkExtractor(HTMLParser):
            def __init__(self):
                super().__init__()
                self.links = []
                self._current_link = None
                self._current_text = []

            def handle_starttag(self, tag, attrs):
                if tag.lower() == "a":
                    for name, value in attrs:
                        if name.lower() == "href" and value:
                            self._current_link = value
                            self._current_text = []
                            break

            def handle_endtag(self, tag):
                if tag.lower() == "a" and self._current_link:
                    text = "".join(self._current_text).strip()
                    self.links.append((self._current_link, text))
                    self._current_link = None
                    self._current_text = []

            def handle_data(self, data):
                if self._current_link is not None:
                    self._current_text.append(data)

        parser = LinkExtractor()
        try:
            parser.feed(html)
        except Exception:
            pass

        for href, display_text in parser.links:
            normalized = _defang_to_normal(href)
            if not normalized.lower().startswith(("http://", "https://", "ftp://")):
                continue
            if normalized in seen:
                continue
            seen.add(normalized)
            domain = _extract_domain_from_url(normalized)
            urls.append(ExtractedURL(
                url=normalized,
                domain=domain,
                display_text=display_text if display_text else None,
                is_shortened=_is_url_shortened(domain),
                is_ip_based=_is_ip_based_url(domain),
            ))

        # Also extract text URLs
        text_urls = extract_urls(html)
        for url in text_urls:
            if url.url not in seen:
                seen.add(url.url)
                urls.append(url)

        return urls

    def _parse_spf_result(auth_header):
        header_lower = auth_header.lower()
        spf_match = re.search(r"spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", header_lower)
        if spf_match:
            result = spf_match.group(1)
            if result == "pass":
                return "pass"
            elif result in ("fail", "permerror"):
                return "fail"
            elif result in ("softfail", "neutral", "temperror"):
                return "softfail"
        return "none"

    def _parse_dkim_result(auth_header):
        header_lower = auth_header.lower()
        dkim_match = re.search(r"dkim\s*=\s*(pass|fail|neutral|none|temperror|permerror)", header_lower)
        if dkim_match:
            result = dkim_match.group(1)
            if result == "pass":
                return "pass"
            elif result in ("fail", "permerror"):
                return "fail"
        return "none"

    def _parse_dmarc_result(auth_header):
        header_lower = auth_header.lower()
        dmarc_match = re.search(r"dmarc\s*=\s*(pass|fail|none|bestguesspass)", header_lower)
        if dmarc_match:
            result = dmarc_match.group(1)
            if result in ("pass", "bestguesspass"):
                return "pass"
            elif result == "fail":
                return "fail"
        return "none"

    def parse_email_alert(alert_data):
        headers = alert_data.get("headers", {})
        if isinstance(headers, str):
            headers = {}

        message_id = alert_data.get("message_id") or headers.get("Message-ID", "") or ""
        subject = alert_data.get("subject") or headers.get("Subject", "") or ""

        sender_raw = alert_data.get("from") or alert_data.get("sender") or headers.get("From", "") or ""
        sender = sender_raw.lower().strip() if sender_raw else ""
        if "<" in sender and ">" in sender:
            import re as re2
            match = re2.search(r"<([^>]+)>", sender)
            if match:
                sender = match.group(1)

        reply_to_raw = alert_data.get("reply_to") or headers.get("Reply-To", "")
        reply_to = None
        if reply_to_raw:
            reply_to = reply_to_raw.lower().strip()
            if reply_to == sender:
                reply_to = None

        recipients_raw = alert_data.get("to") or alert_data.get("recipients") or headers.get("To", "") or ""
        if isinstance(recipients_raw, list):
            recipients = [r.lower().strip() for r in recipients_raw if r]
        elif recipients_raw:
            recipients = [r.strip().lower() for r in recipients_raw.split(",") if r.strip()]
        else:
            recipients = []

        cc_raw = alert_data.get("cc") or headers.get("Cc", "") or ""
        if isinstance(cc_raw, list):
            cc = [c.lower().strip() for c in cc_raw if c]
        elif cc_raw:
            cc = [c.strip().lower() for c in cc_raw.split(",") if c.strip()]
        else:
            cc = []

        body_text = alert_data.get("body_text") or alert_data.get("body") or None
        body_html = alert_data.get("body_html") or None

        urls = []
        seen_urls = set()
        if body_html:
            for url in extract_urls_from_html(body_html):
                if url.url not in seen_urls:
                    seen_urls.add(url.url)
                    urls.append(url)
        if body_text:
            for url in extract_urls(body_text):
                if url.url not in seen_urls:
                    seen_urls.add(url.url)
                    urls.append(url)

        attachments = []
        for att in alert_data.get("attachments", []):
            if isinstance(att, dict):
                attachments.append(AttachmentInfo(
                    filename=att.get("filename", att.get("name", "unknown")),
                    content_type=att.get("content_type", "application/octet-stream"),
                    size_bytes=att.get("size_bytes", att.get("size", 0)),
                    md5=att.get("md5"),
                    sha256=att.get("sha256"),
                ))

        auth_results = headers.get("Authentication-Results", "")
        spf = _parse_spf_result(auth_results)
        dkim = _parse_dkim_result(auth_results)
        dmarc = _parse_dmarc_result(auth_results)

        return EmailAnalysis(
            message_id=message_id,
            subject=subject,
            sender=sender,
            sender_display_name=None,
            reply_to=reply_to,
            recipients=recipients,
            cc=cc,
            headers=headers,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            attachments=attachments,
            received_timestamps=[],
            authentication=EmailAuthResult(spf=spf, dkim=dkim, dmarc=dmarc),
        )

    email_module.parse_email_alert = parse_email_alert
    email_module.extract_urls = extract_urls
    email_module.extract_urls_from_html = extract_urls_from_html
    email_module.EmailAnalysis = EmailAnalysis
    email_module.ExtractedURL = ExtractedURL
    email_module.AttachmentInfo = AttachmentInfo
    email_module.EmailAuthResult = EmailAuthResult

    # Create phishing module
    phishing_module = MagicMock()

    @dataclass
    class TyposquatMatch:
        suspicious_domain: str
        similar_to: str
        similarity_score: float
        technique: str

    @dataclass
    class PhishingIndicators:
        typosquat_domains: list = field(default_factory=list)
        urgency_phrases: list = field(default_factory=list)
        credential_request_detected: bool = False
        suspicious_urls: list = field(default_factory=list)
        url_text_mismatch: bool = False
        sender_domain_mismatch: bool = False
        attachment_risk_level: str = "none"
        overall_risk_score: int = 0
        risk_factors: list = field(default_factory=list)

    LEGITIMATE_DOMAINS = ["paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com"]
    URGENCY_KEYWORDS = ["urgent", "immediately", "suspended", "verify", "expire", "within 24 hours", "account locked", "action required"]
    CREDENTIAL_PATTERNS = [r"enter your password", r"verify your account", r"click here to login", r"verify your password"]
    HIGH_RISK_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js"}
    MEDIUM_RISK_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".zip", ".rar"}
    LOW_RISK_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".txt"}
    HOMOGLYPHS = {"o": ["0", "O"], "0": ["o", "O"], "l": ["1", "I", "i"], "1": ["l", "I", "i"], "a": ["@", "4"]}

    def _get_domain_name(domain):
        parts = domain.split(".")
        if len(parts) >= 2:
            return parts[-2]
        return domain

    def _get_base_domain_name(domain_name):
        """Extract base name from compound domains like 'amaz0n-security' -> 'amaz0n'."""
        if "-" in domain_name:
            parts = domain_name.split("-")
            return parts[0]
        return domain_name

    def _levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            s1, s2 = s2, s1
        if len(s2) == 0:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def _check_homoglyph(domain, legitimate):
        if domain == legitimate:
            return 0.0
        if len(domain) != len(legitimate):
            return 0.0
        homoglyph_matches = 0
        total_diff = 0
        for d_char, l_char in zip(domain, legitimate):
            if d_char == l_char:
                continue
            total_diff += 1
            if l_char in HOMOGLYPHS and d_char in HOMOGLYPHS[l_char]:
                homoglyph_matches += 1
            elif d_char in HOMOGLYPHS and l_char in HOMOGLYPHS[d_char]:
                homoglyph_matches += 1
        if total_diff > 0 and homoglyph_matches == total_diff:
            return 0.9
        elif homoglyph_matches > 0:
            return 0.85
        return 0.0

    def check_typosquat(domain, legitimate_domains):
        matches = []
        domain_lower = domain.lower().strip()
        if domain_lower in [d.lower() for d in legitimate_domains]:
            return matches
        for legit_domain in legitimate_domains:
            legit_lower = legit_domain.lower()
            domain_name = _get_domain_name(domain_lower)
            legit_name = _get_domain_name(legit_lower)
            base_domain_name = _get_base_domain_name(domain_name)

            # Check homoglyph on full domain name
            score = _check_homoglyph(domain_name, legit_name)
            if score > 0.8:
                matches.append(TyposquatMatch(
                    suspicious_domain=domain,
                    similar_to=legit_domain,
                    similarity_score=score,
                    technique="homoglyph",
                ))
                continue

            # Check homoglyph on base domain name (for compound domains like amaz0n-security)
            if base_domain_name != domain_name:
                base_score = _check_homoglyph(base_domain_name, legit_name)
                if base_score > 0.8:
                    matches.append(TyposquatMatch(
                        suspicious_domain=domain,
                        similar_to=legit_domain,
                        similarity_score=base_score * 0.9,
                        technique="homoglyph",
                    ))
                    continue

            # Check Levenshtein on full domain name
            distance = _levenshtein_distance(domain_name, legit_name)
            if distance > 0 and distance < 3:
                similarity = 1.0 - (distance / max(len(domain_name), len(legit_name)))
                matches.append(TyposquatMatch(
                    suspicious_domain=domain,
                    similar_to=legit_domain,
                    similarity_score=similarity,
                    technique="typo",
                ))
                continue

            # Check Levenshtein on base domain name
            if base_domain_name != domain_name:
                base_distance = _levenshtein_distance(base_domain_name, legit_name)
                if base_distance > 0 and base_distance < 3:
                    similarity = 1.0 - (base_distance / max(len(base_domain_name), len(legit_name)))
                    matches.append(TyposquatMatch(
                        suspicious_domain=domain,
                        similar_to=legit_domain,
                        similarity_score=similarity * 0.9,
                        technique="typo",
                    ))
        return matches

    def detect_urgency_language(text):
        found = []
        text_lower = text.lower()
        for keyword in URGENCY_KEYWORDS:
            if keyword.lower() in text_lower:
                found.append(keyword)
        return found

    def detect_credential_request(text):
        text_lower = text.lower()
        for pattern in CREDENTIAL_PATTERNS:
            if re.search(pattern, text_lower):
                return True
        return False

    def _extract_domain_from_email(email):
        if "@" in email:
            return email.split("@")[-1].lower().strip()
        return None

    def _assess_attachment_risk(attachments):
        if not attachments:
            return "none"
        highest = "none"
        risk_order = ["none", "low", "medium", "high", "critical"]
        for att in attachments:
            ext = ""
            if "." in att:
                ext = "." + att.rsplit(".", 1)[-1].lower()
            # Check for double extension
            parts = att.lower().split(".")
            if len(parts) >= 3:
                final = "." + parts[-1]
                penultimate = "." + parts[-2]
                if final in HIGH_RISK_EXTENSIONS and penultimate in LOW_RISK_EXTENSIONS:
                    return "critical"
            if ext in HIGH_RISK_EXTENSIONS:
                if risk_order.index("high") > risk_order.index(highest):
                    highest = "high"
            elif ext in MEDIUM_RISK_EXTENSIONS:
                if risk_order.index("medium") > risk_order.index(highest):
                    highest = "medium"
            elif ext in LOW_RISK_EXTENSIONS:
                if risk_order.index("low") > risk_order.index(highest):
                    highest = "low"
        return highest

    def calculate_risk_score(indicators):
        score = 0
        if indicators.typosquat_domains:
            highest = max(m.similarity_score for m in indicators.typosquat_domains)
            score += int(25 * highest)
        if len(indicators.urgency_phrases) >= 5:
            score += 15
        elif len(indicators.urgency_phrases) >= 3:
            score += 12
        elif len(indicators.urgency_phrases) >= 1:
            score += 8
        if indicators.credential_request_detected:
            score += 20
        if len(indicators.suspicious_urls) >= 3:
            score += 15
        elif len(indicators.suspicious_urls) >= 1:
            score += 10
        if indicators.url_text_mismatch:
            score += 10
        if indicators.sender_domain_mismatch:
            score += 10
        attachment_scores = {"critical": 15, "high": 15, "medium": 10, "low": 3, "none": 0}
        score += attachment_scores.get(indicators.attachment_risk_level, 0)
        return min(score, 100)

    def analyze_phishing_indicators(email_data):
        indicators = PhishingIndicators()
        subject = email_data.get("subject", "")
        body = email_data.get("body", "")
        combined_text = f"{subject} {body}".lower()

        # Check URLs for typosquatting
        urls = email_data.get("urls", [])
        for url in urls:
            domain = None
            if "://" in url:
                domain = url.split("://")[1].split("/")[0]
            elif "/" in url:
                domain = url.split("/")[0]
            if domain:
                typosquats = check_typosquat(domain, LEGITIMATE_DOMAINS)
                indicators.typosquat_domains.extend(typosquats)
                if typosquats:
                    indicators.suspicious_urls.append(url)

        # Check sender domain
        sender_email = email_data.get("sender_email", "")
        sender_domain = _extract_domain_from_email(sender_email)
        if sender_domain:
            sender_typosquats = check_typosquat(sender_domain, LEGITIMATE_DOMAINS)
            indicators.typosquat_domains.extend(sender_typosquats)
            if sender_typosquats:
                indicators.risk_factors.append(f"Sender domain '{sender_domain}' appears to be typosquatting")

        indicators.urgency_phrases = detect_urgency_language(combined_text)
        indicators.credential_request_detected = detect_credential_request(combined_text)

        # Attachment risk
        attachments = email_data.get("attachments", [])
        indicators.attachment_risk_level = _assess_attachment_risk(attachments)

        # Build risk factors
        if indicators.typosquat_domains:
            domains = [m.suspicious_domain for m in indicators.typosquat_domains[:3]]
            indicators.risk_factors.append(f"Typosquatting domains detected: {', '.join(domains)}")
        if indicators.urgency_phrases:
            phrases = indicators.urgency_phrases[:3]
            indicators.risk_factors.append(f"Urgency language used: {', '.join(phrases)}")
        if indicators.credential_request_detected:
            indicators.risk_factors.append("Email requests credentials or sensitive information")
        if indicators.suspicious_urls:
            indicators.risk_factors.append(f"Found {len(indicators.suspicious_urls)} suspicious URL(s)")
        if indicators.attachment_risk_level in ("high", "critical"):
            indicators.risk_factors.append(f"High-risk attachment type detected ({indicators.attachment_risk_level})")

        indicators.overall_risk_score = calculate_risk_score(indicators)
        return indicators

    phishing_module.analyze_phishing_indicators = analyze_phishing_indicators
    phishing_module.PhishingIndicators = PhishingIndicators
    phishing_module.TyposquatMatch = TyposquatMatch

    return email_module, phishing_module

email_module, phishing_module = _setup_analysis_modules()
sys.modules["tw_ai.analysis"] = MagicMock()
sys.modules["tw_ai.analysis.email"] = email_module
sys.modules["tw_ai.analysis.phishing"] = phishing_module
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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["total_count"] == 0
                assert result.data["events"] == []
                assert result.data["events_raw"] == []
                assert "search_stats" in result.data
                assert result.data["search_stats"]["query"] == "login_failure"
                assert result.data["search_stats"]["timerange_hours"] == 24
                assert result.data["search_stats"]["limit_applied"] == 100

    @pytest.mark.asyncio
    async def test_search_siem_with_custom_hours(self):
        """Test search_siem with custom hours parameter."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "search_siem", {"query": "malware", "hours": 48}
                )

                assert result.data["search_stats"]["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_search_siem_with_custom_limit(self):
        """Test search_siem with custom limit parameter."""
        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_siem_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "search_siem", {"query": "test", "limit": 50}
                )

                assert result.data["search_stats"]["limit_applied"] == 50

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["total_count"] == 5
                    assert len(result.data["events"]) == 2
                    assert len(result.data["events_raw"]) == 2
                    assert result.data["search_stats"]["search_id"] == "search-123"
                    assert result.data["search_stats"]["execution_time_ms"] == 150

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

                    assert len(result.data["events_raw"]) == 10
                    assert result.data["total_count"] == 100  # Original count preserved

    @pytest.mark.asyncio
    async def test_search_siem_bridge_error_returns_failure(self):
        """Test search_siem returns failure on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.search.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "search_siem", {"query": "test"}
                    )

                    assert result.success is False
                    assert "SIEM search failed" in result.error

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
                    assert all(isinstance(e, str) for e in result.data["events"])
                    # Check raw events are dicts
                    assert all(isinstance(e, dict) for e in result.data["events_raw"])
                    # Check formatted event contains expected data
                    assert "login_failure" in result.data["events"][0]


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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["total_count"] == 0
                assert result.data["alerts"] == []
                assert result.data["alerts_raw"] == []

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["total_count"] == 2

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
    async def test_get_recent_alerts_bridge_error_returns_failure(self):
        """Test get_recent_alerts returns failure on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.get_recent_alerts.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_SIEM_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_siem_bridge", mock_bridge):
                with patch.object(_tools, "get_siem_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute("get_recent_alerts", {})

                    assert result.success is False
                    assert "Get recent alerts failed" in result.error

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
                    assert all(isinstance(a, str) for a in result.data["alerts"])
                    # Check raw alerts are dicts
                    assert all(isinstance(a, dict) for a in result.data["alerts_raw"])
                    # Check formatted alert contains expected data
                    assert "Brute Force Attack" in result.data["alerts"][0]
                    assert "ALERT-001" in result.data["alerts"][0]


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
                assert result.success is True
                assert "events" in result.data
                assert "events_raw" in result.data
                assert "total_count" in result.data
                assert "search_stats" in result.data
                assert "is_mock" in result.data

                # Verify search_stats structure
                stats = result.data["search_stats"]
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
                assert result.success is True
                assert "alerts" in result.data
                assert "alerts_raw" in result.data
                assert "total_count" in result.data
                assert "is_mock" in result.data


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
                # Use a valid MD5 hash format that isn't in the known malicious list
                result = await registry.execute(
                    "lookup_hash", {"hash": "00000000000000000000000000000000"}
                )

                assert result.success is True
                assert result.data["verdict"] == "unknown"
                assert result.data["score"] == 0

    @pytest.mark.asyncio
    async def test_lookup_hash_with_bridge(self):
        """Test lookup_hash uses bridge when available."""
        # Use a valid SHA256 hash format
        test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        mock_bridge = MagicMock()
        mock_bridge.lookup_hash.return_value = {
            "indicator": test_hash,
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
                        "lookup_hash", {"hash": test_hash}
                    )

                    mock_bridge.lookup_hash.assert_called_once_with(test_hash)
                    assert result.success is True
                    assert result.data["verdict"] == "suspicious"
                    assert result.data["score"] == 50
                    assert result.data["is_mock"] is False

    @pytest.mark.asyncio
    async def test_lookup_hash_bridge_error(self):
        """Test lookup_hash handles bridge errors gracefully."""
        # Use a valid MD5 hash format
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        mock_bridge = MagicMock()
        mock_bridge.lookup_hash.side_effect = RuntimeError("Connection failed")

        with patch.object(_tools, "_THREAT_INTEL_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_threat_intel_bridge", mock_bridge):
                with patch.object(_tools, "get_threat_intel_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "lookup_hash", {"hash": test_hash}
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
                # Use a valid MD5 hash format
                result = await registry.execute(
                    "lookup_hash", {"hash": "d41d8cd98f00b204e9800998ecf8427e"}
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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["hostname"] == "workstation-001"
                assert "status" in result.data
                assert "os" in result.data
                assert "isolated" in result.data
                assert isinstance(result.data["ip_addresses"], list)
                assert isinstance(result.data["tags"], list)

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["hostname"] == "workstation-001"
                    assert result.data["status"] == "online"

    @pytest.mark.asyncio
    async def test_get_host_info_bridge_error_returns_failure(self):
        """Test get_host_info returns failure on bridge error."""
        mock_bridge = MagicMock()
        mock_bridge.get_host_info.side_effect = RuntimeError("Bridge error")

        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", True):
            with patch.object(_tools, "_edr_bridge", mock_bridge):
                with patch.object(_tools, "get_edr_bridge", return_value=mock_bridge):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "get_host_info", {"hostname": "workstation-001"}
                    )

                    assert result.success is False
                    assert "Get host info failed" in result.error

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
                assert result.success is True
                assert "hostname" in result.data
                assert "host_id" in result.data
                assert "ip_addresses" in result.data
                assert "os" in result.data
                assert "os_version" in result.data
                assert "status" in result.data
                assert "isolated" in result.data
                assert "last_seen" in result.data
                assert "agent_version" in result.data
                assert "tags" in result.data
                assert "is_mock" in result.data


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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["hostname"] == "workstation-001"
                assert "total_count" in result.data
                assert "detections" in result.data
                assert isinstance(result.data["detections"], list)
                assert len(result.data["detections"]) > 0

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_detections_with_hours_parameter(self):
        """Test get_detections with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "workstation-001", "hours": 48}
                )

                assert result.data["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_get_detections_includes_mitre_info(self):
        """Test get_detections includes MITRE ATT&CK information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_detections", {"hostname": "workstation-001"}
                )

                detection = result.data["detections"][0]
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
                assert result.success is True
                assert "hostname" in result.data
                assert "total_count" in result.data
                assert "detections" in result.data
                assert "is_mock" in result.data

                # Verify detection structure
                if result.data["detections"]:
                    det = result.data["detections"][0]
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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["hostname"] == "workstation-001"
                assert "total_count" in result.data
                assert "processes" in result.data
                assert isinstance(result.data["processes"], list)
                assert len(result.data["processes"]) > 0

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_processes_with_hours_parameter(self):
        """Test get_processes with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "workstation-001", "hours": 72}
                )

                assert result.data["timerange_hours"] == 72

    @pytest.mark.asyncio
    async def test_get_processes_includes_parent_info(self):
        """Test get_processes includes parent process information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_processes", {"hostname": "workstation-001"}
                )

                process = result.data["processes"][0]
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
                assert result.success is True
                assert "hostname" in result.data
                assert "timerange_hours" in result.data
                assert "total_count" in result.data
                assert "processes" in result.data
                assert "is_mock" in result.data

                # Verify process structure
                if result.data["processes"]:
                    proc = result.data["processes"][0]
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

                assert result.success is True
                assert result.data["is_mock"] is True
                assert result.data["hostname"] == "workstation-001"
                assert "total_count" in result.data
                assert "connections" in result.data
                assert isinstance(result.data["connections"], list)
                assert len(result.data["connections"]) > 0

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
                    assert result.success is True
                    assert result.data["is_mock"] is False
                    assert result.data["total_count"] == 1

    @pytest.mark.asyncio
    async def test_get_network_connections_with_hours_parameter(self):
        """Test get_network_connections with custom hours parameter."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "workstation-001", "hours": 48}
                )

                assert result.data["timerange_hours"] == 48

    @pytest.mark.asyncio
    async def test_get_network_connections_includes_process_info(self):
        """Test get_network_connections includes process information."""
        with patch.object(_tools, "_EDR_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_edr_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "get_network_connections", {"hostname": "workstation-001"}
                )

                conn = result.data["connections"][0]
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
                assert result.success is True
                assert "hostname" in result.data
                assert "timerange_hours" in result.data
                assert "total_count" in result.data
                assert "connections" in result.data
                assert "is_mock" in result.data

                # Verify connection structure
                if result.data["connections"]:
                    conn = result.data["connections"][0]
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
                assert host_info.success is True
                assert host_info.data["is_mock"] is True

                detections = await registry.execute(
                    "get_detections", {"hostname": "test-host"}
                )
                assert detections.success is True
                assert detections.data["is_mock"] is True

                processes = await registry.execute(
                    "get_processes", {"hostname": "test-host"}
                )
                assert processes.success is True
                assert processes.data["is_mock"] is True

                connections = await registry.execute(
                    "get_network_connections", {"hostname": "test-host"}
                )
                assert connections.success is True
                assert connections.data["is_mock"] is True

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


# ============================================================================
# Email Triage Tool Test Data
# ============================================================================

SAMPLE_EMAIL_DATA = {
    "message_id": "<test-123@example.com>",
    "subject": "Urgent: Verify Your Account",
    "from": "security@paypa1.com",
    "to": ["victim@company.com"],
    "headers": {
        "Authentication-Results": "spf=fail; dkim=none; dmarc=fail",
        "Received-SPF": "fail (domain paypa1.com does not designate sender)",
    },
    "body_text": "Click here to verify: hxxp://paypa1[.]com/verify",
    "body_html": '<p>Click <a href="http://evil.com/steal">http://paypal.com/secure</a> to verify.</p>',
    "attachments": [
        {
            "filename": "invoice.pdf.exe",
            "content_type": "application/x-msdownload",
            "size_bytes": 45000,
        }
    ],
}

SAMPLE_PHISHING_EMAIL = {
    "subject": "URGENT: Your account will be suspended within 24 hours",
    "body": "Dear customer, your account has been locked. Click here to verify your password immediately.",
    "sender_email": "support@amaz0n-security.com",
    "sender_display_name": "Amazon Security Team",
    "reply_to": "phisher@evil.net",
    "urls": ["http://amaz0n-verify.com/login"],
    "attachments": ["document.pdf.exe"],
}

SAMPLE_LEGITIMATE_EMAIL = {
    "subject": "Weekly Newsletter",
    "body": "Here is your weekly newsletter with updates.",
    "sender_email": "newsletter@google.com",
    "sender_display_name": "Google Newsletter",
    "urls": ["https://www.google.com/updates"],
    "attachments": [],
}


# ============================================================================
# Email Tool Registry Tests
# ============================================================================


class TestEmailToolRegistry:
    """Tests for email triage tool registration."""

    def test_registry_contains_email_tools(self):
        """Test that registry includes email triage tools."""
        registry = create_triage_tools()
        tools = registry.list_tools()

        assert "analyze_email" in tools
        assert "check_phishing_indicators" in tools
        assert "extract_email_urls" in tools
        assert "check_sender_reputation" in tools

    def test_analyze_email_tool_definition(self):
        """Test analyze_email tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("analyze_email")

        assert tool is not None
        assert tool.name == "analyze_email"
        assert "email_data" in tool.parameters["properties"]
        assert "email_data" in tool.parameters["required"]
        assert "SPF" in tool.description or "headers" in tool.description

    def test_check_phishing_indicators_tool_definition(self):
        """Test check_phishing_indicators tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("check_phishing_indicators")

        assert tool is not None
        assert tool.name == "check_phishing_indicators"
        assert "email_data" in tool.parameters["properties"]
        assert "email_data" in tool.parameters["required"]
        assert "phishing" in tool.description.lower()
        assert "risk" in tool.description.lower()

    def test_extract_email_urls_tool_definition(self):
        """Test extract_email_urls tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("extract_email_urls")

        assert tool is not None
        assert tool.name == "extract_email_urls"
        assert "text" in tool.parameters["properties"]
        assert "include_html" in tool.parameters["properties"]
        assert tool.parameters["properties"]["include_html"]["default"] is True
        assert "text" in tool.parameters["required"]
        assert "defang" in tool.description.lower() or "URL" in tool.description

    def test_check_sender_reputation_tool_definition(self):
        """Test check_sender_reputation tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("check_sender_reputation")

        assert tool is not None
        assert tool.name == "check_sender_reputation"
        assert "sender_email" in tool.parameters["properties"]
        assert "sender_email" in tool.parameters["required"]
        assert "reputation" in tool.description.lower()


# ============================================================================
# analyze_email Tool Tests
# ============================================================================


class TestAnalyzeEmailTool:
    """Tests for analyze_email tool functionality."""

    @pytest.mark.asyncio
    async def test_analyze_email_basic(self):
        """Test analyze_email with basic email data."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.execution_time_ms >= 0

        data = result.data
        assert data["message_id"] == "<test-123@example.com>"
        assert data["subject"] == "Urgent: Verify Your Account"
        assert data["sender"] == "security@paypa1.com"
        assert "victim@company.com" in data["recipients"]

    @pytest.mark.asyncio
    async def test_analyze_email_extracts_urls(self):
        """Test analyze_email extracts URLs from body."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert result.success is True
        data = result.data
        assert "urls" in data
        assert len(data["urls"]) > 0

        # Check URL structure
        url_entry = data["urls"][0]
        assert "url" in url_entry
        assert "domain" in url_entry
        assert "is_shortened" in url_entry
        assert "is_ip_based" in url_entry

    @pytest.mark.asyncio
    async def test_analyze_email_extracts_attachments(self):
        """Test analyze_email extracts attachment info."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert result.success is True
        data = result.data
        assert "attachments" in data
        assert len(data["attachments"]) == 1

        att = data["attachments"][0]
        assert att["filename"] == "invoice.pdf.exe"
        assert att["content_type"] == "application/x-msdownload"
        assert att["size_bytes"] == 45000

    @pytest.mark.asyncio
    async def test_analyze_email_parses_authentication(self):
        """Test analyze_email parses authentication headers."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert result.success is True
        data = result.data
        assert "authentication" in data

        auth = data["authentication"]
        assert "spf" in auth
        assert "dkim" in auth
        assert "dmarc" in auth
        assert auth["spf"] == "fail"

    @pytest.mark.asyncio
    async def test_analyze_email_handles_empty_data(self):
        """Test analyze_email handles empty email data gracefully."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": {}})

        assert result.success is True
        data = result.data
        assert data["subject"] == ""
        assert data["sender"] == ""
        assert data["urls"] == []
        assert data["attachments"] == []

    @pytest.mark.asyncio
    async def test_analyze_email_result_structure(self):
        """Test analyze_email result has expected structure."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert result.success is True
        data = result.data

        # Verify all required keys present
        expected_keys = [
            "message_id", "subject", "sender", "sender_display_name",
            "reply_to", "recipients", "cc", "headers", "body_text",
            "body_html", "urls", "attachments", "received_timestamps",
            "authentication"
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"


# ============================================================================
# check_phishing_indicators Tool Tests
# ============================================================================


class TestCheckPhishingIndicatorsTool:
    """Tests for check_phishing_indicators tool functionality."""

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_detects_phishing(self):
        """Test check_phishing_indicators detects phishing signals."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.execution_time_ms >= 0

        data = result.data
        assert data["overall_risk_score"] > 50  # Should be high risk
        assert len(data["urgency_phrases"]) > 0  # Should detect urgency
        assert data["credential_request_detected"] is True  # Asks for password

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_detects_typosquat(self):
        """Test check_phishing_indicators detects typosquatting domains."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert result.success is True
        data = result.data

        # Should detect amaz0n typosquatting
        assert len(data["typosquat_domains"]) > 0

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_detects_attachment_risk(self):
        """Test check_phishing_indicators detects risky attachments."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert result.success is True
        data = result.data

        # Should detect .exe in double extension as critical
        assert data["attachment_risk_level"] in ("high", "critical")

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_legitimate_email(self):
        """Test check_phishing_indicators gives low score for legitimate email."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_LEGITIMATE_EMAIL}
        )

        assert result.success is True
        data = result.data
        assert data["overall_risk_score"] < 30  # Should be low risk
        assert len(data["urgency_phrases"]) == 0
        assert data["credential_request_detected"] is False

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_returns_risk_factors(self):
        """Test check_phishing_indicators returns human-readable risk factors."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert result.success is True
        data = result.data
        assert "risk_factors" in data
        assert isinstance(data["risk_factors"], list)
        assert len(data["risk_factors"]) > 0

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_from_analyze_email_output(self):
        """Test check_phishing_indicators works with analyze_email output format."""
        registry = create_triage_tools()

        # First analyze the email
        analysis_result = await registry.execute(
            "analyze_email", {"email_data": SAMPLE_EMAIL_DATA}
        )
        assert analysis_result.success is True

        # Now check phishing indicators using analysis output
        phishing_result = await registry.execute(
            "check_phishing_indicators", {"email_data": analysis_result.data}
        )

        assert phishing_result.success is True
        data = phishing_result.data
        assert "overall_risk_score" in data
        assert "typosquat_domains" in data

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_result_structure(self):
        """Test check_phishing_indicators result has expected structure."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert result.success is True
        data = result.data

        expected_keys = [
            "typosquat_domains", "urgency_phrases", "credential_request_detected",
            "suspicious_urls", "url_text_mismatch", "sender_domain_mismatch",
            "attachment_risk_level", "overall_risk_score", "risk_factors"
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"


# ============================================================================
# extract_email_urls Tool Tests
# ============================================================================


class TestExtractEmailUrlsTool:
    """Tests for extract_email_urls tool functionality."""

    @pytest.mark.asyncio
    async def test_extract_email_urls_plain_text(self):
        """Test extract_email_urls extracts from plain text."""
        registry = create_triage_tools()
        text = "Check this link: https://example.com/page and also http://test.org"
        result = await registry.execute("extract_email_urls", {"text": text})

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.execution_time_ms >= 0

        data = result.data
        assert data["total_count"] == 2
        assert len(data["urls"]) == 2

    @pytest.mark.asyncio
    async def test_extract_email_urls_defanged(self):
        """Test extract_email_urls handles defanged URLs."""
        registry = create_triage_tools()
        text = "Malicious URL: hxxp://evil[.]com/malware and hxxps://bad[.]site/phish"
        result = await registry.execute("extract_email_urls", {"text": text})

        assert result.success is True
        data = result.data
        assert data["total_count"] == 2

        # Check URLs are normalized
        urls = [u["url"] for u in data["urls"]]
        assert "http://evil.com/malware" in urls
        assert "https://bad.site/phish" in urls

    @pytest.mark.asyncio
    async def test_extract_email_urls_html(self):
        """Test extract_email_urls extracts from HTML with display text."""
        registry = create_triage_tools()
        html = '<p>Click <a href="http://evil.com">Safe Link</a></p>'
        result = await registry.execute("extract_email_urls", {"text": html})

        assert result.success is True
        data = result.data
        assert data["total_count"] >= 1

        # Check display text is captured
        url_entry = next((u for u in data["urls"] if u["url"] == "http://evil.com"), None)
        assert url_entry is not None
        assert url_entry["display_text"] == "Safe Link"

    @pytest.mark.asyncio
    async def test_extract_email_urls_identifies_shortened(self):
        """Test extract_email_urls identifies shortened URLs."""
        registry = create_triage_tools()
        text = "Click: https://bit.ly/abc123 or https://tinyurl.com/xyz"
        result = await registry.execute("extract_email_urls", {"text": text})

        assert result.success is True
        data = result.data
        assert data["shortened_count"] == 2

        for url_entry in data["urls"]:
            assert url_entry["is_shortened"] is True

    @pytest.mark.asyncio
    async def test_extract_email_urls_identifies_ip_based(self):
        """Test extract_email_urls identifies IP-based URLs."""
        registry = create_triage_tools()
        text = "Suspicious: http://192.168.1.100/login"
        result = await registry.execute("extract_email_urls", {"text": text})

        assert result.success is True
        data = result.data
        assert data["ip_based_count"] == 1
        assert data["urls"][0]["is_ip_based"] is True

    @pytest.mark.asyncio
    async def test_extract_email_urls_include_html_false(self):
        """Test extract_email_urls with include_html=False."""
        registry = create_triage_tools()
        html = '<a href="http://link.com">text</a>'
        result = await registry.execute(
            "extract_email_urls", {"text": html, "include_html": False}
        )

        assert result.success is True
        # Should not extract anchor hrefs when include_html is False
        # (unless there's a plain text URL)

    @pytest.mark.asyncio
    async def test_extract_email_urls_empty_text(self):
        """Test extract_email_urls rejects empty text (validation enforced)."""
        registry = create_triage_tools()
        # Empty text is now rejected by schema validation (Security Task 5.4)
        with pytest.raises(_tools.ToolArgumentValidationError):
            await registry.execute("extract_email_urls", {"text": ""})

    @pytest.mark.asyncio
    async def test_extract_email_urls_result_structure(self):
        """Test extract_email_urls result has expected structure."""
        registry = create_triage_tools()
        result = await registry.execute(
            "extract_email_urls", {"text": "https://example.com"}
        )

        assert result.success is True
        data = result.data

        assert "urls" in data
        assert "total_count" in data
        assert "shortened_count" in data
        assert "ip_based_count" in data

        if data["urls"]:
            url_entry = data["urls"][0]
            assert "url" in url_entry
            assert "domain" in url_entry
            assert "display_text" in url_entry
            assert "is_shortened" in url_entry
            assert "is_ip_based" in url_entry


# ============================================================================
# check_sender_reputation Tool Tests
# ============================================================================


class TestCheckSenderReputationTool:
    """Tests for check_sender_reputation tool functionality."""

    @pytest.mark.asyncio
    async def test_check_sender_reputation_trusted_domain(self):
        """Test check_sender_reputation for trusted domain."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "user@google.com"}
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.execution_time_ms >= 0

        data = result.data
        assert data["sender_email"] == "user@google.com"
        assert data["domain"] == "google.com"
        assert data["score"] >= 90  # High reputation
        assert data["is_known_sender"] is True
        assert data["risk_level"] == "low"

    @pytest.mark.asyncio
    async def test_check_sender_reputation_suspicious_domain(self):
        """Test check_sender_reputation for suspicious domain."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "admin@paypa1-security.com"}
        )

        assert result.success is True
        data = result.data
        assert data["score"] <= 20  # Low reputation
        assert data["risk_level"] == "high"

    @pytest.mark.asyncio
    async def test_check_sender_reputation_malicious_domain(self):
        """Test check_sender_reputation for known malicious domain."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "attacker@phishing.bad"}
        )

        assert result.success is True
        data = result.data
        assert data["score"] <= 10
        assert data["risk_level"] == "high"
        assert data["category"] == "phishing"

    @pytest.mark.asyncio
    async def test_check_sender_reputation_unknown_domain(self):
        """Test check_sender_reputation for unknown domain."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "user@random-unknown-domain.xyz"}
        )

        assert result.success is True
        data = result.data
        assert data["score"] == 50  # Neutral
        assert data["is_known_sender"] is False
        assert data["risk_level"] == "medium"
        assert data["category"] == "unknown"

    @pytest.mark.asyncio
    async def test_check_sender_reputation_includes_domain_age(self):
        """Test check_sender_reputation includes domain age for known domains."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "contact@microsoft.com"}
        )

        assert result.success is True
        data = result.data
        assert "domain_age_days" in data
        assert data["domain_age_days"] is not None
        assert data["domain_age_days"] > 1000  # Microsoft is old

    @pytest.mark.asyncio
    async def test_check_sender_reputation_is_mock(self):
        """Test check_sender_reputation returns is_mock flag."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "test@example.com"}
        )

        assert result.success is True
        data = result.data
        assert "is_mock" in data
        assert data["is_mock"] is True

    @pytest.mark.asyncio
    async def test_check_sender_reputation_result_structure(self):
        """Test check_sender_reputation result has expected structure."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "test@example.com"}
        )

        assert result.success is True
        data = result.data

        expected_keys = [
            "sender_email", "domain", "score", "is_known_sender",
            "domain_age_days", "category", "risk_level", "is_mock"
        ]
        for key in expected_keys:
            assert key in data, f"Missing key: {key}"


# ============================================================================
# Email Tool Execution Time Tests
# ============================================================================


class TestEmailToolExecutionTime:
    """Tests for email tool execution time tracking."""

    @pytest.mark.asyncio
    async def test_analyze_email_includes_execution_time(self):
        """Test that analyze_email includes execution_time_ms."""
        registry = create_triage_tools()
        result = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})

        assert hasattr(result, "execution_time_ms")
        assert isinstance(result.execution_time_ms, int)
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_check_phishing_indicators_includes_execution_time(self):
        """Test that check_phishing_indicators includes execution_time_ms."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_PHISHING_EMAIL}
        )

        assert hasattr(result, "execution_time_ms")
        assert isinstance(result.execution_time_ms, int)
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_extract_email_urls_includes_execution_time(self):
        """Test that extract_email_urls includes execution_time_ms."""
        registry = create_triage_tools()
        result = await registry.execute(
            "extract_email_urls", {"text": "https://example.com"}
        )

        assert hasattr(result, "execution_time_ms")
        assert isinstance(result.execution_time_ms, int)
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_check_sender_reputation_includes_execution_time(self):
        """Test that check_sender_reputation includes execution_time_ms."""
        registry = create_triage_tools()
        result = await registry.execute(
            "check_sender_reputation", {"sender_email": "test@example.com"}
        )

        assert hasattr(result, "execution_time_ms")
        assert isinstance(result.execution_time_ms, int)
        assert result.execution_time_ms >= 0


# ============================================================================
# Email Tools Integration Tests
# ============================================================================


class TestEmailToolsIntegration:
    """Integration tests for email triage tools."""

    @pytest.mark.asyncio
    async def test_full_email_triage_workflow(self):
        """Test complete email triage workflow using all tools."""
        registry = create_triage_tools()

        # Step 1: Analyze the email
        analysis = await registry.execute("analyze_email", {"email_data": SAMPLE_EMAIL_DATA})
        assert analysis.success is True
        assert analysis.data["sender"] == "security@paypa1.com"

        # Step 2: Check phishing indicators
        phishing = await registry.execute(
            "check_phishing_indicators", {"email_data": SAMPLE_EMAIL_DATA}
        )
        assert phishing.success is True
        assert phishing.data["overall_risk_score"] > 0

        # Step 3: Extract URLs for further analysis
        urls = await registry.execute(
            "extract_email_urls", {"text": SAMPLE_EMAIL_DATA["body_text"]}
        )
        assert urls.success is True

        # Step 4: Check sender reputation
        reputation = await registry.execute(
            "check_sender_reputation", {"sender_email": analysis.data["sender"]}
        )
        assert reputation.success is True
        assert reputation.data["risk_level"] == "high"  # paypa1.com is suspicious

    def test_email_tool_definitions_are_valid(self):
        """Test that all email tool definitions are valid for LLM."""
        registry = create_triage_tools()
        email_tool_names = [
            "analyze_email", "check_phishing_indicators",
            "extract_email_urls", "check_sender_reputation"
        ]

        for name in email_tool_names:
            tool = registry.get(name)
            assert tool is not None, f"Tool not found: {name}"
            assert tool.description is not None
            assert len(tool.description) > 20  # Should have meaningful description
            assert "type" in tool.parameters
            assert tool.parameters["type"] == "object"
            assert "properties" in tool.parameters
            assert "required" in tool.parameters


# ============================================================================
# Phishing Response Action Tool Registry Tests
# ============================================================================


class TestPhishingResponseActionToolRegistry:
    """Tests for phishing response action tool registration."""

    def test_registry_contains_phishing_response_tools(self):
        """Test that registry includes phishing response action tools."""
        registry = create_triage_tools()
        tools = registry.list_tools()

        assert "quarantine_email" in tools
        assert "block_sender" in tools
        assert "notify_user" in tools
        assert "create_security_ticket" in tools

    def test_quarantine_email_tool_definition(self):
        """Test quarantine_email tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("quarantine_email")

        assert tool is not None
        assert tool.name == "quarantine_email"
        assert "message_id" in tool.parameters["properties"]
        assert "reason" in tool.parameters["properties"]
        assert "message_id" in tool.parameters["required"]
        assert "reason" in tool.parameters["required"]
        assert tool.requires_confirmation is True

    def test_block_sender_tool_definition(self):
        """Test block_sender tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("block_sender")

        assert tool is not None
        assert tool.name == "block_sender"
        assert "sender" in tool.parameters["properties"]
        assert "block_type" in tool.parameters["properties"]
        assert "reason" in tool.parameters["properties"]
        assert tool.parameters["properties"]["block_type"]["enum"] == ["email", "domain"]
        assert set(tool.parameters["required"]) == {"sender", "block_type", "reason"}
        assert tool.requires_confirmation is True

    def test_notify_user_tool_definition(self):
        """Test notify_user tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("notify_user")

        assert tool is not None
        assert tool.name == "notify_user"
        assert "recipient" in tool.parameters["properties"]
        assert "notification_type" in tool.parameters["properties"]
        assert "subject" in tool.parameters["properties"]
        assert "body" in tool.parameters["properties"]
        assert tool.parameters["properties"]["notification_type"]["enum"] == [
            "phishing_warning", "security_alert", "action_taken"
        ]
        assert set(tool.parameters["required"]) == {"recipient", "notification_type", "subject", "body"}

    def test_create_security_ticket_tool_definition(self):
        """Test create_security_ticket tool has correct definition."""
        registry = create_triage_tools()
        tool = registry.get("create_security_ticket")

        assert tool is not None
        assert tool.name == "create_security_ticket"
        assert "title" in tool.parameters["properties"]
        assert "description" in tool.parameters["properties"]
        assert "severity" in tool.parameters["properties"]
        assert "indicators" in tool.parameters["properties"]
        assert tool.parameters["properties"]["severity"]["enum"] == ["critical", "high", "medium", "low"]
        assert tool.parameters["properties"]["indicators"]["type"] == "array"
        assert set(tool.parameters["required"]) == {"title", "description", "severity", "indicators"}


# ============================================================================
# quarantine_email Tool Tests
# ============================================================================


class TestQuarantineEmailTool:
    """Tests for quarantine_email tool functionality."""

    @pytest.mark.asyncio
    async def test_quarantine_email_success(self):
        """Test quarantine_email succeeds when policy allows."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "quarantine_email",
                    {"message_id": "MSG-12345", "reason": "phishing detected"}
                )

                assert isinstance(result, ToolResult)
                assert result.success is True
                assert result.data["success"] is True
                assert result.data["action_id"] is not None
                assert result.data["action_id"].startswith("qe-")
                assert "MSG-12345" in result.data["message"]
                assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_quarantine_email_includes_reason_in_message(self):
        """Test quarantine_email includes reason in result message."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "quarantine_email",
                    {"message_id": "MSG-99999", "reason": "malware attachment"}
                )

                assert result.data["success"] is True
                assert "malware attachment" in result.data["message"]

    @pytest.mark.asyncio
    async def test_quarantine_email_policy_check(self):
        """Test quarantine_email checks policy before execution."""
        # When policy denies, action should not be allowed
        def mock_check_denied(action_type, target, confidence):
            return {"decision": "requires_approval", "reason": "Test denial", "approval_level": "analyst"}

        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_mock_check_action", mock_check_denied):
                registry = create_triage_tools()
                result = await registry.execute(
                    "quarantine_email",
                    {"message_id": "MSG-DENIED", "reason": "test"}
                )

                assert result.success is True  # ToolResult is success, but action wasn't executed
                assert result.data["success"] is False
                assert "denied" in result.data["message"].lower() or "approval" in result.data["message"].lower()

    @pytest.mark.asyncio
    async def test_quarantine_email_uses_email_gateway_bridge_when_available(self):
        """Test quarantine_email uses email gateway bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.quarantine_email.return_value = True

        with patch.object(_tools, "get_email_gateway_bridge", return_value=mock_bridge):
            with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
                with patch.object(_tools, "_policy_bridge", None):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "quarantine_email",
                        {"message_id": "MSG-BRIDGE", "reason": "phishing"}
                    )

        assert result.success is True
        assert result.data["success"] is True
        assert result.data["is_mock"] is False
        mock_bridge.quarantine_email.assert_called_once_with("MSG-BRIDGE")


# ============================================================================
# block_sender Tool Tests
# ============================================================================


class TestBlockSenderTool:
    """Tests for block_sender tool functionality."""

    @pytest.mark.asyncio
    async def test_block_sender_email_success(self):
        """Test block_sender with email type succeeds."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "block_sender",
                    {
                        "sender": "attacker@evil.com",
                        "block_type": "email",
                        "reason": "phishing sender"
                    }
                )

                assert isinstance(result, ToolResult)
                assert result.success is True
                assert result.data["success"] is True
                assert result.data["action_id"] is not None
                assert result.data["action_id"].startswith("bs-")
                assert result.data["blocked"] == "attacker@evil.com"
                assert result.data["block_type"] == "email"

    @pytest.mark.asyncio
    async def test_block_sender_domain_requires_approval(self):
        """Test block_sender with domain type requires higher approval."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "block_sender",
                    {
                        "sender": "evil.com",
                        "block_type": "domain",
                        "reason": "malicious domain"
                    }
                )

                # Domain blocks require senior approval by default
                assert result.success is True
                assert result.data["success"] is False
                assert "approval" in result.data["message"].lower()

    @pytest.mark.asyncio
    async def test_block_sender_invalid_block_type(self):
        """Test block_sender fails with invalid block_type (validation enforced)."""
        registry = create_triage_tools()
        # Invalid block_type is now rejected by schema validation (Security Task 5.4)
        with pytest.raises(_tools.ToolArgumentValidationError) as exc_info:
            await registry.execute(
                "block_sender",
                {
                    "sender": "test@test.com",
                    "block_type": "invalid_type",
                    "reason": "test"
                }
            )
        assert "block_type" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_block_sender_includes_reason(self):
        """Test block_sender includes reason in result message."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()
                result = await registry.execute(
                    "block_sender",
                    {
                        "sender": "spam@spam.net",
                        "block_type": "email",
                        "reason": "repeated spam"
                    }
                )

                assert result.data["success"] is True
                assert "repeated spam" in result.data["message"]

    @pytest.mark.asyncio
    async def test_block_sender_uses_email_gateway_bridge_when_available(self):
        """Test block_sender uses email gateway bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.block_sender.return_value = True

        with patch.object(_tools, "get_email_gateway_bridge", return_value=mock_bridge):
            with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
                with patch.object(_tools, "_policy_bridge", None):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "block_sender",
                        {
                            "sender": "attacker@evil.com",
                            "block_type": "email",
                            "reason": "phishing sender"
                        }
                    )

        assert result.success is True
        assert result.data["success"] is True
        assert result.data["is_mock"] is False
        mock_bridge.block_sender.assert_called_once_with("attacker@evil.com")


# ============================================================================
# notify_user Tool Tests
# ============================================================================


class TestNotifyUserTool:
    """Tests for notify_user tool functionality."""

    @pytest.mark.asyncio
    async def test_notify_user_phishing_warning(self):
        """Test notify_user with phishing_warning type."""
        registry = create_triage_tools()
        result = await registry.execute(
            "notify_user",
            {
                "recipient": "user@company.com",
                "notification_type": "phishing_warning",
                "subject": "Phishing Email Detected",
                "body": "A phishing email was detected and removed from your inbox."
            }
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["success"] is True
        assert result.data["notification_id"] is not None
        assert result.data["notification_id"].startswith("notif-")
        assert result.data["recipient"] == "user@company.com"
        assert result.data["notification_type"] == "phishing_warning"

    @pytest.mark.asyncio
    async def test_notify_user_security_alert(self):
        """Test notify_user with security_alert type."""
        registry = create_triage_tools()
        result = await registry.execute(
            "notify_user",
            {
                "recipient": "admin@company.com",
                "notification_type": "security_alert",
                "subject": "Security Alert",
                "body": "Suspicious activity detected on your account."
            }
        )

        assert result.success is True
        assert result.data["notification_type"] == "security_alert"

    @pytest.mark.asyncio
    async def test_notify_user_action_taken(self):
        """Test notify_user with action_taken type."""
        registry = create_triage_tools()
        result = await registry.execute(
            "notify_user",
            {
                "recipient": "user@company.com",
                "notification_type": "action_taken",
                "subject": "Security Action Completed",
                "body": "The malicious email has been quarantined."
            }
        )

        assert result.success is True
        assert result.data["notification_type"] == "action_taken"

    @pytest.mark.asyncio
    async def test_notify_user_invalid_notification_type(self):
        """Test notify_user fails with invalid notification_type (validation enforced)."""
        registry = create_triage_tools()
        # Invalid notification_type is now rejected by schema validation (Security Task 5.4)
        with pytest.raises(_tools.ToolArgumentValidationError) as exc_info:
            await registry.execute(
                "notify_user",
                {
                    "recipient": "user@company.com",
                    "notification_type": "invalid_type",
                    "subject": "Test",
                    "body": "Test body"
                }
            )
        assert "notification_type" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_notify_user_includes_execution_time(self):
        """Test notify_user includes execution time."""
        registry = create_triage_tools()
        result = await registry.execute(
            "notify_user",
            {
                "recipient": "test@test.com",
                "notification_type": "phishing_warning",
                "subject": "Test",
                "body": "Test body"
            }
        )

        assert result.execution_time_ms >= 0


# ============================================================================
# create_security_ticket Tool Tests
# ============================================================================


class TestCreateSecurityTicketTool:
    """Tests for create_security_ticket tool functionality."""

    @pytest.mark.asyncio
    async def test_create_security_ticket_success(self):
        """Test create_security_ticket creates ticket successfully."""
        registry = create_triage_tools()
        result = await registry.execute(
            "create_security_ticket",
            {
                "title": "Phishing Campaign Detected",
                "description": "Multiple users received phishing emails from attacker@evil.com",
                "severity": "high",
                "indicators": ["attacker@evil.com", "http://evil.com/phish", "192.168.1.100"]
            }
        )

        assert isinstance(result, ToolResult)
        assert result.success is True
        assert result.data["success"] is True
        assert result.data["ticket_id"] is not None
        assert "ticket_url" in result.data
        assert result.data["ticket_url"] is not None
        assert str(result.data["ticket_url"]).startswith("http")
        assert result.data["severity"] == "high"
        assert result.data["indicators_count"] == 3
        assert "is_mock" in result.data

    @pytest.mark.asyncio
    async def test_create_security_ticket_with_all_severities(self):
        """Test create_security_ticket accepts all valid severity levels."""
        registry = create_triage_tools()

        for severity in ["critical", "high", "medium", "low"]:
            result = await registry.execute(
                "create_security_ticket",
                {
                    "title": f"Test {severity} incident",
                    "description": "Test description",
                    "severity": severity,
                    "indicators": []
                }
            )

            assert result.success is True
            assert result.data["severity"] == severity

    @pytest.mark.asyncio
    async def test_create_security_ticket_invalid_severity(self):
        """Test create_security_ticket fails with invalid severity (validation enforced)."""
        registry = create_triage_tools()
        # Invalid severity is now rejected by schema validation (Security Task 5.4)
        with pytest.raises(_tools.ToolArgumentValidationError) as exc_info:
            await registry.execute(
                "create_security_ticket",
                {
                    "title": "Test",
                    "description": "Test",
                    "severity": "ultra-critical",
                    "indicators": []
                }
            )
        assert "severity" in str(exc_info.value).lower()

    @pytest.mark.asyncio
    async def test_create_security_ticket_empty_indicators(self):
        """Test create_security_ticket works with empty indicators list."""
        registry = create_triage_tools()
        result = await registry.execute(
            "create_security_ticket",
            {
                "title": "Minor Security Event",
                "description": "An event with no IOCs",
                "severity": "low",
                "indicators": []
            }
        )

        assert result.success is True
        assert result.data["indicators_count"] == 0

    @pytest.mark.asyncio
    async def test_create_security_ticket_includes_execution_time(self):
        """Test create_security_ticket includes execution time."""
        registry = create_triage_tools()
        result = await registry.execute(
            "create_security_ticket",
            {
                "title": "Test",
                "description": "Test",
                "severity": "medium",
                "indicators": ["ioc1"]
            }
        )

        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_create_security_ticket_unique_ids(self):
        """Test create_security_ticket generates unique ticket IDs."""
        registry = create_triage_tools()
        ticket_ids = set()

        for i in range(5):
            result = await registry.execute(
                "create_security_ticket",
                {
                    "title": f"Test ticket {i}",
                    "description": "Test",
                    "severity": "low",
                    "indicators": []
                }
            )
            ticket_ids.add(result.data["ticket_id"])

        # All ticket IDs should be unique
        assert len(ticket_ids) == 5

    @pytest.mark.asyncio
    async def test_create_security_ticket_uses_ticketing_bridge_when_available(self):
        """Test create_security_ticket uses ticketing bridge when available."""
        mock_bridge = MagicMock()
        mock_bridge.create_ticket.return_value = {
            "id": "1001",
            "key": "SEC-1001",
            "url": "https://jira.example.com/browse/SEC-1001",
        }

        with patch.object(_tools, "get_ticketing_bridge", return_value=mock_bridge):
            with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
                with patch.object(_tools, "_policy_bridge", None):
                    registry = create_triage_tools()
                    result = await registry.execute(
                        "create_security_ticket",
                        {
                            "title": "Bridge-backed ticket",
                            "description": "Created through ticketing connector",
                            "severity": "critical",
                            "indicators": ["ioc-1"]
                        }
                    )

        assert result.success is True
        assert result.data["ticket_id"] == "SEC-1001"
        assert result.data["is_mock"] is False
        mock_bridge.create_ticket.assert_called_once_with(
            "Bridge-backed ticket",
            "Created through ticketing connector",
            "highest",
            ["security", "severity-critical", "ioc-present"],
        )


# ============================================================================
# Phishing Response Action Integration Tests
# ============================================================================


class TestPhishingResponseActionIntegration:
    """Integration tests for phishing response action tools."""

    @pytest.mark.asyncio
    async def test_all_action_tools_return_tool_result(self):
        """Test all phishing response action tools return ToolResult."""
        with patch.object(_tools, "_POLICY_BRIDGE_AVAILABLE", False):
            with patch.object(_tools, "_policy_bridge", None):
                registry = create_triage_tools()

                # quarantine_email
                result = await registry.execute(
                    "quarantine_email",
                    {"message_id": "MSG-TEST", "reason": "test"}
                )
                assert isinstance(result, ToolResult)

                # block_sender
                result = await registry.execute(
                    "block_sender",
                    {"sender": "test@test.com", "block_type": "email", "reason": "test"}
                )
                assert isinstance(result, ToolResult)

                # notify_user
                result = await registry.execute(
                    "notify_user",
                    {
                        "recipient": "test@test.com",
                        "notification_type": "phishing_warning",
                        "subject": "Test",
                        "body": "Test"
                    }
                )
                assert isinstance(result, ToolResult)

                # create_security_ticket
                result = await registry.execute(
                    "create_security_ticket",
                    {
                        "title": "Test",
                        "description": "Test",
                        "severity": "low",
                        "indicators": []
                    }
                )
                assert isinstance(result, ToolResult)

    def test_action_tool_definitions_are_valid(self):
        """Test that all action tool definitions are valid for LLM."""
        registry = create_triage_tools()
        action_tool_names = [
            "quarantine_email",
            "block_sender",
            "notify_user",
            "create_security_ticket"
        ]

        for name in action_tool_names:
            tool = registry.get(name)
            assert tool is not None
            assert tool.description is not None
            assert len(tool.description) > 20  # Should have meaningful description
            assert "type" in tool.parameters
            assert tool.parameters["type"] == "object"
            assert "properties" in tool.parameters
            assert "required" in tool.parameters

    @pytest.mark.asyncio
    async def test_action_tools_include_execution_timing(self):
        """Test all action tools include execution timing."""
        registry = create_triage_tools()

        result = await registry.execute(
            "notify_user",
            {
                "recipient": "test@test.com",
                "notification_type": "security_alert",
                "subject": "Test",
                "body": "Test"
            }
        )
        assert hasattr(result, "execution_time_ms")
        assert isinstance(result.execution_time_ms, int)
        assert result.execution_time_ms >= 0

        result = await registry.execute(
            "create_security_ticket",
            {
                "title": "Test",
                "description": "Test",
                "severity": "low",
                "indicators": []
            }
        )
        assert result.execution_time_ms >= 0
