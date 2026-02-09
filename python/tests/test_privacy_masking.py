"""Tests for privacy masking utilities."""

from __future__ import annotations

from tw_ai.privacy.masking import DataSensitivity, PrivacyMaskingService


def test_mask_text_returns_outcome() -> None:
    service = PrivacyMaskingService()
    outcome = service.mask_text("email test@example.com and ssn 123-45-6789")

    assert outcome.redaction_count >= 1
    assert "[REDACTED" in outcome.masked_text
    assert "ssn" in outcome.pii_types or "email" in outcome.pii_types


def test_provider_routing_for_sensitive_data() -> None:
    selected = PrivacyMaskingService.select_provider(
        DataSensitivity.RESTRICTED,
        configured_provider="openai",
    )
    assert selected == "local"


def test_provider_routing_for_public_data() -> None:
    selected = PrivacyMaskingService.select_provider(
        DataSensitivity.PUBLIC,
        configured_provider="openai",
    )
    assert selected == "openai"
