"""Phishing-specific indicator detection and scoring for Triage Warden.

This module provides comprehensive phishing analysis capabilities including:
- Typosquatting detection (homoglyphs, typos, TLD swaps, subdomain tricks)
- Urgency language detection
- Credential request pattern detection
- URL/text mismatch detection
- Attachment risk assessment
- Overall risk scoring
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlparse


# ============================================================================
# Dataclasses
# ============================================================================


@dataclass
class TyposquatMatch:
    """Represents a detected typosquatting domain match."""

    suspicious_domain: str
    similar_to: str
    similarity_score: float
    technique: Literal["homoglyph", "typo", "tld_swap", "subdomain"]


@dataclass
class PhishingIndicators:
    """Comprehensive phishing indicator analysis results."""

    typosquat_domains: list[TyposquatMatch] = field(default_factory=list)
    urgency_phrases: list[str] = field(default_factory=list)
    credential_request_detected: bool = False
    suspicious_urls: list[str] = field(default_factory=list)
    url_text_mismatch: bool = False
    sender_domain_mismatch: bool = False
    attachment_risk_level: Literal["none", "low", "medium", "high", "critical"] = "none"
    overall_risk_score: int = 0
    risk_factors: list[str] = field(default_factory=list)


# ============================================================================
# Constants
# ============================================================================

# Legitimate domains to check against for typosquatting
LEGITIMATE_DOMAINS = [
    "paypal.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "netflix.com",
    "linkedin.com",
    "dropbox.com",
    "adobe.com",
]

# Homoglyph substitution mappings (character -> list of look-alikes)
HOMOGLYPHS = {
    "o": ["0", "O"],
    "0": ["o", "O"],
    "l": ["1", "I", "i"],
    "1": ["l", "I", "i"],
    "i": ["1", "l", "I"],
    "I": ["1", "l", "i"],
    "a": ["@", "4"],
    "e": ["3"],
    "s": ["5", "$"],
    "g": ["9", "q"],
    "q": ["g", "9"],
    "n": ["m"],  # rn -> m trick handled separately
}

# Common character sequences that look similar
SEQUENCE_HOMOGLYPHS = [
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
]

# Urgency keywords and phrases
URGENCY_KEYWORDS = [
    "urgent",
    "immediate",
    "immediately",
    "suspended",
    "verify",
    "expire",
    "expires",
    "expired",
    "within 24 hours",
    "within 48 hours",
    "account locked",
    "account suspended",
    "security alert",
    "security warning",
    "unauthorized",
    "unauthorized access",
    "confirm your",
    "action required",
    "act now",
    "limited time",
    "final notice",
    "final warning",
    "will be closed",
    "will be suspended",
    "will be terminated",
    "failure to",
    "must verify",
    "must confirm",
]

# Credential request patterns
CREDENTIAL_PATTERNS = [
    r"enter your password",
    r"confirm your credentials",
    r"verify your account",
    r"click here to login",
    r"click here to log in",
    r"click here to sign in",
    r"update your payment",
    r"update your billing",
    r"enter your (credit card|card number|cvv|social security|ssn)",
    r"verify your identity",
    r"confirm your identity",
    r"reset your password",
    r"password reset",
    r"enter your login",
    r"enter your username",
    r"verify your information",
    r"confirm your payment",
    r"update your information",
    r"provide your (password|credentials|login)",
    r"sign in to (verify|confirm|update)",
]

# Attachment extensions and risk levels
HIGH_RISK_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msi", ".com", ".pif"}
MEDIUM_RISK_EXTENSIONS = {".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".zip", ".rar", ".7z", ".iso", ".img"}
LOW_RISK_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".pptx", ".txt", ".csv", ".png", ".jpg", ".jpeg", ".gif"}


# ============================================================================
# Core Functions
# ============================================================================


def analyze_phishing_indicators(email_data: dict) -> PhishingIndicators:
    """Analyze email data for phishing indicators.

    Args:
        email_data: Dictionary containing email information:
            - subject (str): Email subject
            - body (str): Email body text
            - sender_email (str): Sender's email address
            - sender_display_name (str, optional): Display name
            - reply_to (str, optional): Reply-to address
            - urls (list[str], optional): List of URLs in the email
            - url_display_texts (list[dict], optional): List of {url, display_text} mappings
            - attachments (list[str], optional): List of attachment filenames

    Returns:
        PhishingIndicators with all detected indicators and risk score.
    """
    indicators = PhishingIndicators()

    # Extract text content
    subject = email_data.get("subject", "")
    body = email_data.get("body", "")
    combined_text = f"{subject} {body}".lower()

    # 1. Check URLs for typosquatting
    urls = email_data.get("urls", [])
    for url in urls:
        domain = _extract_domain_from_url(url)
        if domain:
            typosquats = check_typosquat(domain, LEGITIMATE_DOMAINS)
            indicators.typosquat_domains.extend(typosquats)
            if typosquats:
                indicators.suspicious_urls.append(url)

    # 2. Check sender domain for typosquatting
    sender_email = email_data.get("sender_email", "")
    sender_domain = _extract_domain_from_email(sender_email)
    if sender_domain:
        sender_typosquats = check_typosquat(sender_domain, LEGITIMATE_DOMAINS)
        indicators.typosquat_domains.extend(sender_typosquats)
        if sender_typosquats:
            indicators.risk_factors.append(f"Sender domain '{sender_domain}' appears to be typosquatting")

    # 3. Check for sender domain mismatch (display name vs actual domain)
    sender_display = email_data.get("sender_display_name", "")
    indicators.sender_domain_mismatch = _check_sender_mismatch(sender_email, sender_display)

    # 4. Check for reply-to mismatch
    reply_to = email_data.get("reply_to", "")
    if reply_to:
        reply_domain = _extract_domain_from_email(reply_to)
        if reply_domain and sender_domain and reply_domain != sender_domain:
            indicators.risk_factors.append(
                f"Reply-to domain '{reply_domain}' differs from sender domain '{sender_domain}'"
            )

    # 5. Detect urgency language
    indicators.urgency_phrases = detect_urgency_language(combined_text)

    # 6. Detect credential requests
    indicators.credential_request_detected = detect_credential_request(combined_text)

    # 7. Check URL/text mismatch
    url_text_mappings = email_data.get("url_display_texts", [])
    indicators.url_text_mismatch = _check_url_text_mismatch(url_text_mappings)

    # 8. Assess attachment risk
    attachments = email_data.get("attachments", [])
    indicators.attachment_risk_level = _assess_attachment_risk(attachments)

    # 9. Build risk factors list
    indicators.risk_factors.extend(_build_risk_factors(indicators))

    # 10. Calculate overall risk score
    indicators.overall_risk_score = calculate_risk_score(indicators)

    return indicators


def check_typosquat(domain: str, legitimate_domains: list[str]) -> list[TyposquatMatch]:
    """Check if a domain is typosquatting a legitimate domain.

    Checks for:
    - TLD swaps (paypal.com vs paypal.co)
    - Subdomain tricks (paypal.evil.com)
    - Homoglyph substitutions (0->o, 1->l, rn->m, etc.)
    - Levenshtein distance (threshold < 3)

    Args:
        domain: The suspicious domain to check.
        legitimate_domains: List of legitimate domains to compare against.

    Returns:
        List of TyposquatMatch objects for any detected matches.
    """
    matches: list[TyposquatMatch] = []
    domain_lower = domain.lower().strip()

    # Skip if the domain is exactly a legitimate domain
    if domain_lower in [d.lower() for d in legitimate_domains]:
        return matches

    for legit_domain in legitimate_domains:
        legit_lower = legit_domain.lower()

        # Extract domain name without TLD for comparison
        domain_name = _get_domain_name(domain_lower)
        legit_name = _get_domain_name(legit_lower)
        domain_tld = _get_tld(domain_lower)
        legit_tld = _get_tld(legit_lower)

        # Also get base name for compound domains (e.g., netf1ix-billing -> netf1ix)
        base_domain_name = _get_base_domain_name(domain_name)

        # 1. Check for TLD swap first (exact domain name match but different TLD)
        # e.g., paypal.co vs paypal.com, amazon.net vs amazon.com
        if domain_name == legit_name and domain_tld != legit_tld:
            matches.append(
                TyposquatMatch(
                    suspicious_domain=domain,
                    similar_to=legit_domain,
                    similarity_score=0.95,
                    technique="tld_swap",
                )
            )
            continue

        # 2. Check for subdomain trick (legitimate domain appears as subdomain or prefix)
        # e.g., paypal.evil.com, login-paypal.com, secure-paypal.attacker.com
        # Must check this AFTER TLD swap to avoid false positives on paypal.co
        if legit_name in domain_lower and domain_name != legit_name:
            # Check for patterns where legit domain is embedded as subdomain or prefix
            parts = domain_lower.split(".")
            if (len(parts) > 2 and legit_name in parts[:-1]) or (  # paypal.evil.com
                f"-{legit_name}" in domain_name or  # login-paypal.com
                f"{legit_name}-" in domain_name):   # paypal-login.com
                matches.append(
                    TyposquatMatch(
                        suspicious_domain=domain,
                        similar_to=legit_domain,
                        similarity_score=0.7,
                        technique="subdomain",
                    )
                )
                continue

        # 3. Check for homoglyph substitution (on full domain name)
        homoglyph_score = _check_homoglyph(domain_name, legit_name)
        if homoglyph_score > 0.8:
            matches.append(
                TyposquatMatch(
                    suspicious_domain=domain,
                    similar_to=legit_domain,
                    similarity_score=homoglyph_score,
                    technique="homoglyph",
                )
            )
            continue

        # 4. Check for homoglyph on base domain name (for compound domains)
        # e.g., netf1ix-billing.com -> check netf1ix against netflix
        if base_domain_name != domain_name:
            base_homoglyph_score = _check_homoglyph(base_domain_name, legit_name)
            if base_homoglyph_score > 0.8:
                matches.append(
                    TyposquatMatch(
                        suspicious_domain=domain,
                        similar_to=legit_domain,
                        similarity_score=base_homoglyph_score * 0.9,  # Slightly lower due to suffix
                        technique="homoglyph",
                    )
                )
                continue

        # 5. Check Levenshtein distance for typos (on full domain name)
        distance = _levenshtein_distance(domain_name, legit_name)
        if distance > 0 and distance < 3:
            similarity = 1.0 - (distance / max(len(domain_name), len(legit_name)))
            matches.append(
                TyposquatMatch(
                    suspicious_domain=domain,
                    similar_to=legit_domain,
                    similarity_score=similarity,
                    technique="typo",
                )
            )
            continue

        # 6. Check Levenshtein distance on base domain name (for compound domains)
        # e.g., amason-support.com -> check amason against amazon
        if base_domain_name != domain_name:
            base_distance = _levenshtein_distance(base_domain_name, legit_name)
            if base_distance > 0 and base_distance < 3:
                similarity = 1.0 - (base_distance / max(len(base_domain_name), len(legit_name)))
                matches.append(
                    TyposquatMatch(
                        suspicious_domain=domain,
                        similar_to=legit_domain,
                        similarity_score=similarity * 0.9,  # Slightly lower due to suffix
                        technique="typo",
                    )
                )

    return matches


def detect_urgency_language(text: str) -> list[str]:
    """Detect urgency language commonly used in phishing emails.

    Args:
        text: The text to analyze (should be lowercase).

    Returns:
        List of urgency phrases found in the text.
    """
    found_phrases: list[str] = []
    text_lower = text.lower()

    for keyword in URGENCY_KEYWORDS:
        if keyword.lower() in text_lower:
            found_phrases.append(keyword)

    return found_phrases


def detect_credential_request(text: str) -> bool:
    """Detect if text contains credential request patterns.

    Args:
        text: The text to analyze.

    Returns:
        True if credential request patterns are detected.
    """
    text_lower = text.lower()

    for pattern in CREDENTIAL_PATTERNS:
        if re.search(pattern, text_lower):
            return True

    return False


def calculate_risk_score(indicators: PhishingIndicators) -> int:
    """Calculate overall phishing risk score based on indicators.

    Args:
        indicators: PhishingIndicators dataclass with detection results.

    Returns:
        Risk score from 0-100.
    """
    score = 0

    # Typosquatting detection (0-25 points)
    if indicators.typosquat_domains:
        highest_similarity = max(m.similarity_score for m in indicators.typosquat_domains)
        typosquat_score = int(25 * highest_similarity)
        score += typosquat_score

    # Urgency language (0-15 points)
    urgency_count = len(indicators.urgency_phrases)
    if urgency_count >= 5:
        score += 15
    elif urgency_count >= 3:
        score += 12
    elif urgency_count >= 1:
        score += 8

    # Credential request (0-20 points)
    if indicators.credential_request_detected:
        score += 20

    # Suspicious URLs (0-15 points)
    url_count = len(indicators.suspicious_urls)
    if url_count >= 3:
        score += 15
    elif url_count >= 1:
        score += 10

    # URL/text mismatch (0-10 points)
    if indicators.url_text_mismatch:
        score += 10

    # Sender domain mismatch (0-10 points)
    if indicators.sender_domain_mismatch:
        score += 10

    # Attachment risk (0-15 points)
    attachment_scores = {
        "critical": 15,
        "high": 15,
        "medium": 10,
        "low": 3,
        "none": 0,
    }
    score += attachment_scores.get(indicators.attachment_risk_level, 0)

    # Cap at 100
    return min(score, 100)


# ============================================================================
# Helper Functions
# ============================================================================


def _extract_domain_from_url(url: str) -> str | None:
    """Extract domain from a URL."""
    try:
        parsed = urlparse(url)
        if parsed.netloc:
            return parsed.netloc.lower()
        # Handle URLs without scheme
        if "/" in url:
            return url.split("/")[0].lower()
        return url.lower() if "." in url else None
    except Exception:
        return None


def _extract_domain_from_email(email: str) -> str | None:
    """Extract domain from an email address."""
    if "@" in email:
        return email.split("@")[-1].lower().strip()
    return None


def _get_domain_name(domain: str) -> str:
    """Extract the main domain name without TLD (e.g., 'paypal' from 'paypal.com').

    For compound domains like 'netf1ix-billing.com', returns 'netf1ix-billing'.
    """
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain


def _get_tld(domain: str) -> str:
    """Extract the TLD from a domain (e.g., 'com' from 'paypal.com')."""
    parts = domain.split(".")
    if len(parts) >= 1:
        return parts[-1]
    return ""


def _get_base_domain_name(domain_name: str) -> str:
    """Extract the base name from a compound domain name.

    Examples:
        'netf1ix-billing' -> 'netf1ix'
        'app1e-id-support' -> 'app1e'
        'paypal' -> 'paypal'
        'login-paypal' -> 'paypal' (if paypal is at the end)
    """
    # Handle hyphenated domains - take the first part
    if "-" in domain_name:
        parts = domain_name.split("-")
        # Return the longest part that could be a brand name (usually first)
        return parts[0]
    return domain_name


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
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


def _check_homoglyph(domain: str, legitimate: str) -> float:
    """Check if domain uses homoglyph substitutions to mimic legitimate domain.

    Returns a similarity score (0.0-1.0) if homoglyph detected, 0.0 otherwise.
    """
    if domain == legitimate:
        return 0.0

    # First check sequence homoglyphs (rn -> m, etc.)
    normalized_domain = domain
    for seq, replacement in SEQUENCE_HOMOGLYPHS:
        if seq in normalized_domain:
            # Try replacing and see if it matches
            test_domain = normalized_domain.replace(seq, replacement)
            if test_domain == legitimate:
                return 0.95
        if replacement in normalized_domain:
            test_domain = normalized_domain.replace(replacement, seq)
            if test_domain == legitimate:
                return 0.95

    # Check character-level homoglyphs
    if len(domain) != len(legitimate):
        return 0.0

    homoglyph_matches = 0
    total_diff = 0

    for d_char, l_char in zip(domain, legitimate):
        if d_char == l_char:
            continue

        total_diff += 1

        # Check if d_char is a homoglyph of l_char
        if l_char in HOMOGLYPHS and d_char in HOMOGLYPHS[l_char]:
            homoglyph_matches += 1
        elif d_char in HOMOGLYPHS and l_char in HOMOGLYPHS[d_char]:
            homoglyph_matches += 1

    if total_diff > 0 and homoglyph_matches == total_diff:
        # All differences are homoglyphs
        return 0.9
    elif homoglyph_matches > 0:
        return 0.85

    return 0.0


def _check_sender_mismatch(sender_email: str, display_name: str) -> bool:
    """Check if sender display name suggests different domain than actual sender."""
    if not display_name or not sender_email:
        return False

    display_lower = display_name.lower()
    sender_domain = _extract_domain_from_email(sender_email)

    # Check if display name contains a different well-known domain
    for legit_domain in LEGITIMATE_DOMAINS:
        legit_name = _get_domain_name(legit_domain)
        if legit_name in display_lower:
            # Display name mentions a legitimate brand
            if sender_domain and legit_name not in sender_domain:
                # But sender domain doesn't match
                return True

    return False


def _check_url_text_mismatch(url_text_mappings: list[dict]) -> bool:
    """Check if any URL's display text suggests a different destination.

    Args:
        url_text_mappings: List of {url, display_text} dictionaries.

    Returns:
        True if mismatch detected.
    """
    for mapping in url_text_mappings:
        url = mapping.get("url", "")
        display_text = mapping.get("display_text", "")

        if not url or not display_text:
            continue

        # Check if display text looks like a URL
        if display_text.startswith(("http://", "https://", "www.")):
            url_domain = _extract_domain_from_url(url)
            display_domain = _extract_domain_from_url(display_text)

            if url_domain and display_domain and url_domain != display_domain:
                return True

        # Check if display text mentions a legitimate domain but URL goes elsewhere
        url_domain = _extract_domain_from_url(url)
        if url_domain:
            display_lower = display_text.lower()
            for legit_domain in LEGITIMATE_DOMAINS:
                legit_name = _get_domain_name(legit_domain)
                if legit_name in display_lower and legit_name not in url_domain:
                    return True

    return False


def _assess_attachment_risk(attachments: list[str]) -> Literal["none", "low", "medium", "high", "critical"]:
    """Assess the risk level of email attachments.

    Args:
        attachments: List of attachment filenames.

    Returns:
        Risk level based on file extensions.
    """
    if not attachments:
        return "none"

    highest_risk = "none"
    risk_order = ["none", "low", "medium", "high", "critical"]

    for attachment in attachments:
        ext = _get_file_extension(attachment)

        if ext in HIGH_RISK_EXTENSIONS:
            # Check for double extension tricks
            if _has_double_extension(attachment):
                return "critical"
            if risk_order.index("high") > risk_order.index(highest_risk):
                highest_risk = "high"
        elif ext in MEDIUM_RISK_EXTENSIONS:
            if risk_order.index("medium") > risk_order.index(highest_risk):
                highest_risk = "medium"
        elif ext in LOW_RISK_EXTENSIONS:
            if risk_order.index("low") > risk_order.index(highest_risk):
                highest_risk = "low"

    return highest_risk


def _get_file_extension(filename: str) -> str:
    """Get lowercase file extension including the dot."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""


def _has_double_extension(filename: str) -> bool:
    """Check for double extension tricks (e.g., document.pdf.exe)."""
    parts = filename.lower().split(".")
    if len(parts) >= 3:
        # Check if the final extension is executable
        final_ext = "." + parts[-1]
        penultimate_ext = "." + parts[-2]
        if final_ext in HIGH_RISK_EXTENSIONS and penultimate_ext in LOW_RISK_EXTENSIONS:
            return True
    return False


def _build_risk_factors(indicators: PhishingIndicators) -> list[str]:
    """Build a list of human-readable risk factors."""
    factors: list[str] = []

    if indicators.typosquat_domains:
        domains = [m.suspicious_domain for m in indicators.typosquat_domains[:3]]
        factors.append(f"Typosquatting domains detected: {', '.join(domains)}")

    if indicators.urgency_phrases:
        phrases = indicators.urgency_phrases[:3]
        factors.append(f"Urgency language used: {', '.join(phrases)}")

    if indicators.credential_request_detected:
        factors.append("Email requests credentials or sensitive information")

    if indicators.suspicious_urls:
        factors.append(f"Found {len(indicators.suspicious_urls)} suspicious URL(s)")

    if indicators.url_text_mismatch:
        factors.append("URL display text does not match actual destination")

    if indicators.sender_domain_mismatch:
        factors.append("Sender display name suggests different organization than actual domain")

    if indicators.attachment_risk_level in ("high", "critical"):
        factors.append(f"High-risk attachment type detected ({indicators.attachment_risk_level})")
    elif indicators.attachment_risk_level == "medium":
        factors.append("Medium-risk attachment type detected (macro-enabled documents or archives)")

    return factors
