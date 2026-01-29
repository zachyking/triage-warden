"""E2E test fixtures for Triage Warden."""

from .sample_emails import (
    OBVIOUS_PHISHING,
    SOPHISTICATED_PHISHING,
    LEGITIMATE_EMAIL,
    FALSE_POSITIVE,
)

__all__ = [
    "OBVIOUS_PHISHING",
    "SOPHISTICATED_PHISHING",
    "LEGITIMATE_EMAIL",
    "FALSE_POSITIVE",
]
