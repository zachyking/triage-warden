"""Security analysis utilities for Triage Warden."""

from tw_ai.analysis.security import (
    extract_indicators,
    calculate_severity,
    identify_attack_pattern,
)
from tw_ai.analysis.mitre import (
    map_to_mitre,
    MITRE_MAPPINGS,
)
from tw_ai.analysis.email import (
    EmailAnalysis,
    ExtractedURL,
    AttachmentInfo,
    EmailAuthResult,
    parse_email_alert,
    extract_urls,
    extract_urls_from_html,
    parse_authentication_headers,
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
]
