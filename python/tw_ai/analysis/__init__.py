"""Security analysis utilities for Triage Warden."""

from tw_ai.analysis.email import (
    AttachmentInfo,
    EmailAnalysis,
    EmailAuthResult,
    ExtractedURL,
    extract_urls,
    extract_urls_from_html,
    parse_authentication_headers,
    parse_email_alert,
)
from tw_ai.analysis.mitre import (
    MITRE_MAPPINGS,
    map_to_mitre,
)
from tw_ai.analysis.phishing import (
    PhishingIndicators,
    TyposquatMatch,
    analyze_phishing_indicators,
    calculate_risk_score,
    check_typosquat,
    detect_credential_request,
    detect_urgency_language,
)
from tw_ai.analysis.security import (
    calculate_severity,
    extract_indicators,
    identify_attack_pattern,
)

__all__ = [
    "extract_indicators",
    "calculate_severity",
    "identify_attack_pattern",
    "map_to_mitre",
    "MITRE_MAPPINGS",
    # Email analysis
    "EmailAnalysis",
    "ExtractedURL",
    "AttachmentInfo",
    "EmailAuthResult",
    "parse_email_alert",
    "extract_urls",
    "extract_urls_from_html",
    "parse_authentication_headers",
    # Phishing analysis
    "analyze_phishing_indicators",
    "check_typosquat",
    "detect_urgency_language",
    "detect_credential_request",
    "calculate_risk_score",
    "PhishingIndicators",
    "TyposquatMatch",
]
