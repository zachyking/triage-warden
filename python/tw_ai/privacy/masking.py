"""Privacy masking helpers for AI interactions.

This module provides:
- Sensitive data masking wrapper around PIIRedactor
- Data sensitivity classification for local-vs-cloud LLM routing
- Audit-friendly masking metadata
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from tw_ai.sanitization import PIIRedactor, PIIType, RedactionRecord


class DataSensitivity(str, Enum):
    """Data sensitivity level used for LLM routing."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class MaskingOutcome:
    """Result of masking text for external AI usage."""

    masked_text: str
    redaction_count: int
    pii_types: list[str]
    audit_records: list[dict[str, Any]]


class PrivacyMaskingService:
    """Privacy-aware masking and provider routing decisions."""

    def __init__(self, redactor: PIIRedactor | None = None) -> None:
        self._redactor = redactor or PIIRedactor()

    def mask_text(self, text: str) -> MaskingOutcome:
        """Mask sensitive text and return audit metadata."""
        result = self._redactor.redact(text)
        pii_types = sorted({pii_type.value for pii_type in result.pii_types_found})
        return MaskingOutcome(
            masked_text=result.redacted_text,
            redaction_count=result.redaction_count,
            pii_types=pii_types,
            audit_records=[record.to_dict() for record in result.records],
        )

    def mask_payload(self, payload: dict[str, Any]) -> tuple[dict[str, Any], list[RedactionRecord]]:
        """Mask nested payload values and return records."""
        return self._redactor.redact_dict(payload)

    def infer_sensitivity(self, text: str) -> DataSensitivity:
        """Infer data sensitivity from detected PII categories."""
        result = self._redactor.redact(text)
        pii_types = result.pii_types_found
        if not pii_types:
            return DataSensitivity.PUBLIC

        high_risk = {PIIType.SSN, PIIType.CREDIT_CARD}
        credential_risk = {PIIType.API_KEY}
        if pii_types & high_risk:
            return DataSensitivity.RESTRICTED
        if pii_types & credential_risk:
            return DataSensitivity.CONFIDENTIAL
        return DataSensitivity.INTERNAL

    @staticmethod
    def select_provider(
        sensitivity: DataSensitivity,
        configured_provider: str,
        local_provider_name: str = "local",
    ) -> str:
        """Route sensitive workloads to local LLM by policy."""
        if sensitivity in {DataSensitivity.CONFIDENTIAL, DataSensitivity.RESTRICTED}:
            return local_provider_name
        return configured_provider
