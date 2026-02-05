"""
Evidence parsing utilities for extracting structured evidence from LLM output.

This module provides functions to parse evidence items and investigation steps
from various formats that LLMs might produce, including:
- Structured JSON with evidence arrays
- Inline [EVIDENCE] tags (legacy format)
- Free-form text with evidence markers

Stage 2.1.2: AI Prompts for Evidence Collection
"""

from __future__ import annotations

import logging
import re
from typing import Any

from pydantic import ValidationError

from tw_ai.agents.models import EvidenceItem, InvestigationStep

logger = logging.getLogger(__name__)


# =============================================================================
# Evidence Parsing from JSON
# =============================================================================


def parse_evidence_from_dict(data: dict[str, Any]) -> list[EvidenceItem]:
    """
    Parse evidence items from a dictionary (typically from JSON response).

    Args:
        data: Dictionary containing evidence data, either as:
              - {"evidence": [...]} format
              - Direct list of evidence items

    Returns:
        List of validated EvidenceItem objects.

    Raises:
        ValueError: If the data format is invalid.
    """
    evidence_list: list[dict[str, Any]] = []

    if "evidence" in data and isinstance(data["evidence"], list):
        evidence_list = data["evidence"]
    elif isinstance(data, list):
        evidence_list = data
    else:
        return []

    parsed_evidence: list[EvidenceItem] = []

    for i, item in enumerate(evidence_list):
        if not isinstance(item, dict):
            logger.warning(f"Evidence item {i} is not a dict, skipping")
            continue

        try:
            # Normalize field names (handle variations from LLM output)
            normalized = _normalize_evidence_fields(item)
            evidence = EvidenceItem.model_validate(normalized)
            parsed_evidence.append(evidence)
        except ValidationError as e:
            logger.warning(
                f"Failed to validate evidence item {i}: {e.errors()}",
                extra={"item": item, "errors": e.errors()},
            )
            continue

    return parsed_evidence


def _normalize_evidence_fields(item: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize evidence field names to match the expected schema.

    LLMs may produce variations like:
    - "type" instead of "source_type"
    - "source" instead of "source_name"
    - "description" instead of "finding"

    Args:
        item: Raw evidence item dictionary.

    Returns:
        Normalized dictionary with expected field names.
    """
    normalized = dict(item)

    # Field name mappings (from possible LLM output to expected field)
    field_mappings = {
        # source_type variations
        "type": "source_type",
        "sourceType": "source_type",
        "evidence_source": "source_type",
        "category": "source_type",
        # source_name variations
        "source": "source_name",
        "sourceName": "source_name",
        "provider": "source_name",
        "platform": "source_name",
        # data_type variations
        "dataType": "data_type",
        "evidence_type": "data_type",
        "kind": "data_type",
        # value variations
        "data": "value",
        "content": "value",
        "evidence_data": "value",
        # finding variations
        "description": "finding",
        "observation": "finding",
        "what": "finding",
        # relevance variations
        "explanation": "relevance",
        "why": "relevance",
        "significance": "relevance",
        # confidence variations
        "score": "confidence",
        "certainty": "confidence",
        "confidence_score": "confidence",
        # link variations
        "url": "link",
        "deep_link": "link",
        "reference": "link",
    }

    for old_key, new_key in field_mappings.items():
        if old_key in normalized and new_key not in normalized:
            normalized[new_key] = normalized.pop(old_key)

    # Ensure value is a dict
    if "value" in normalized and not isinstance(normalized["value"], dict):
        # Wrap scalar values in a dict
        normalized["value"] = {"data": normalized["value"]}

    # Handle confidence as string (e.g., "85%")
    if "confidence" in normalized:
        conf = normalized["confidence"]
        if isinstance(conf, str):
            # Remove % sign and convert to int
            conf = conf.replace("%", "").strip()
            try:
                normalized["confidence"] = int(float(conf))
            except ValueError:
                normalized["confidence"] = 50  # Default confidence

    return normalized


# =============================================================================
# Investigation Step Parsing
# =============================================================================


def parse_investigation_steps_from_dict(
    data: dict[str, Any],
) -> list[InvestigationStep]:
    """
    Parse investigation steps from a dictionary.

    Args:
        data: Dictionary containing investigation steps, either as:
              - {"investigation_steps": [...]} format
              - Direct list of steps

    Returns:
        List of validated InvestigationStep objects.
    """
    steps_list: list[dict[str, Any]] = []

    if "investigation_steps" in data and isinstance(data["investigation_steps"], list):
        steps_list = data["investigation_steps"]
    elif isinstance(data, list):
        steps_list = data
    else:
        return []

    parsed_steps: list[InvestigationStep] = []

    for i, item in enumerate(steps_list):
        if not isinstance(item, dict):
            logger.warning(f"Investigation step {i} is not a dict, skipping")
            continue

        try:
            # Normalize field names
            normalized = _normalize_step_fields(item, order=i + 1)
            step = InvestigationStep.model_validate(normalized)
            parsed_steps.append(step)
        except ValidationError as e:
            logger.warning(
                f"Failed to validate investigation step {i}: {e.errors()}",
                extra={"item": item, "errors": e.errors()},
            )
            continue

    return parsed_steps


def _normalize_step_fields(item: dict[str, Any], order: int) -> dict[str, Any]:
    """
    Normalize investigation step field names.

    Args:
        item: Raw step item dictionary.
        order: Default order if not present.

    Returns:
        Normalized dictionary with expected field names.
    """
    normalized = dict(item)

    # Field name mappings
    field_mappings = {
        # order variations
        "step": "order",
        "step_number": "order",
        "sequence": "order",
        # action variations
        "description": "action",
        "what": "action",
        "task": "action",
        # result variations
        "output": "result",
        "finding": "result",
        "outcome": "result",
        # tool variations
        "tool_used": "tool",
        "method": "tool",
        "using": "tool",
        # status variations
        "state": "status",
        "completion": "status",
    }

    for old_key, new_key in field_mappings.items():
        if old_key in normalized and new_key not in normalized:
            normalized[new_key] = normalized.pop(old_key)

    # Set default order if not present
    if "order" not in normalized:
        normalized["order"] = order

    # Ensure order is an int
    if "order" in normalized and not isinstance(normalized["order"], int):
        try:
            normalized["order"] = int(normalized["order"])
        except (ValueError, TypeError):
            normalized["order"] = order

    # Default status to completed if not present
    if "status" not in normalized:
        normalized["status"] = "completed"

    # Normalize status values
    if "status" in normalized:
        status = str(normalized["status"]).lower()
        if status in ("success", "done", "complete", "ok"):
            normalized["status"] = "completed"
        elif status in ("error", "fail", "failure"):
            normalized["status"] = "failed"
        elif status in ("skip", "skipped", "n/a"):
            normalized["status"] = "skipped"

    return normalized


# =============================================================================
# Legacy [EVIDENCE] Tag Parsing
# =============================================================================

# Pattern for legacy evidence tags in text
# [EVIDENCE] Source: {source} | Type: {type} | Finding: {finding} | Confidence: {0-100}
EVIDENCE_TAG_PATTERN = re.compile(
    r"\[EVIDENCE\]\s*"
    r"Source:\s*(?P<source>[^|]+)\s*\|\s*"
    r"Type:\s*(?P<type>[^|]+)\s*\|\s*"
    r"Finding:\s*(?P<finding>[^|]+)\s*\|\s*"
    r"Confidence:\s*(?P<confidence>\d+)",
    re.IGNORECASE,
)


def parse_evidence_from_text(text: str) -> list[EvidenceItem]:
    """
    Parse evidence from free-form text containing [EVIDENCE] tags.

    This supports the legacy format specified in the Stage 2 plan:
    [EVIDENCE] Source: {source} | Type: {type} | Finding: {finding} | Confidence: {0-100}

    Args:
        text: Text containing evidence tags.

    Returns:
        List of parsed EvidenceItem objects.
    """
    parsed_evidence: list[EvidenceItem] = []

    for match in EVIDENCE_TAG_PATTERN.finditer(text):
        try:
            source = match.group("source").strip()
            evidence_type = match.group("type").strip()
            finding = match.group("finding").strip()
            confidence = int(match.group("confidence"))

            # Map simple type to data_type enum value
            data_type = _map_simple_type_to_data_type(evidence_type)
            source_type = _infer_source_type(source)

            evidence = EvidenceItem(
                source_type=source_type,  # type: ignore[arg-type]
                source_name=source,
                data_type=data_type,  # type: ignore[arg-type]
                value={"raw_finding": finding},
                finding=finding,
                relevance=f"Evidence from {source} supporting analysis",
                confidence=min(100, max(0, confidence)),
            )
            parsed_evidence.append(evidence)

        except (ValidationError, ValueError) as e:
            logger.warning(f"Failed to parse evidence tag: {e}")
            continue

    return parsed_evidence


def _map_simple_type_to_data_type(
    simple_type: str,
) -> str:
    """Map simple type strings to data_type enum values."""
    type_lower = simple_type.lower()

    mapping = {
        "ip": "network_activity",
        "ip address": "network_activity",
        "network": "network_activity",
        "connection": "network_activity",
        "hash": "file_artifact",
        "file": "file_artifact",
        "binary": "file_artifact",
        "process": "process_execution",
        "execution": "process_execution",
        "command": "process_execution",
        "user": "user_behavior",
        "behavior": "user_behavior",
        "login": "authentication_event",
        "email": "email_content",
        "phishing": "email_content",
        "threat intel": "threat_intel_match",
        "ti": "threat_intel_match",
        "reputation": "threat_intel_match",
        "mitre": "mitre_observation",
        "technique": "mitre_observation",
        "registry": "system_change",
        "system": "system_change",
        "dns": "dns_activity",
        "domain": "dns_activity",
        "url": "web_activity",
        "web": "web_activity",
        "cloud": "cloud_activity",
        "aws": "cloud_activity",
        "azure": "cloud_activity",
        "auth": "authentication_event",
        "data": "data_access",
        "exfil": "data_access",
        "malware": "malware_indicator",
    }

    for key, value in mapping.items():
        if key in type_lower:
            return value

    return "threat_intel_match"  # Default


def _infer_source_type(source_name: str) -> str:
    """Infer source_type from source name."""
    source_lower = source_name.lower()

    threat_intel = ["virustotal", "shodan", "otx", "threatcrowd", "hybrid-analysis"]
    if any(ti in source_lower for ti in threat_intel):
        return "threat_intel"
    siem_sources = ["splunk", "elastic", "sentinel", "qradar", "arcsight"]
    if any(siem in source_lower for siem in siem_sources):
        return "siem"
    edr_sources = ["crowdstrike", "defender", "carbon black", "sentinelone", "cylance"]
    if any(edr in source_lower for edr in edr_sources):
        return "edr"
    email_sources = ["proofpoint", "mimecast", "email", "o365", "exchange"]
    if any(email in source_lower for email in email_sources):
        return "email"
    elif any(idp in source_lower for idp in ["okta", "azure ad", "ping", "duo"]):
        return "identity_provider"
    elif any(cloud in source_lower for cloud in ["aws", "azure", "gcp", "cloudtrail"]):
        return "cloud"
    elif "alert" in source_lower or "original" in source_lower:
        return "alert_data"
    elif "enrichment" in source_lower:
        return "enrichment"
    else:
        return "manual"


# =============================================================================
# Combined Parsing
# =============================================================================


def extract_evidence_from_response(
    response_data: dict[str, Any],
    response_text: str | None = None,
) -> tuple[list[EvidenceItem], list[InvestigationStep]]:
    """
    Extract evidence and investigation steps from an LLM response.

    This function tries multiple parsing strategies:
    1. Structured JSON with evidence/investigation_steps arrays
    2. Legacy [EVIDENCE] tags in the reasoning text
    3. Free-form text analysis as fallback

    Args:
        response_data: Parsed JSON response from LLM.
        response_text: Optional raw text response for tag parsing.

    Returns:
        Tuple of (evidence_items, investigation_steps).
    """
    evidence: list[EvidenceItem] = []
    steps: list[InvestigationStep] = []

    # Strategy 1: Parse from structured JSON
    if "evidence" in response_data:
        evidence = parse_evidence_from_dict(response_data)

    if "investigation_steps" in response_data:
        steps = parse_investigation_steps_from_dict(response_data)

    # Strategy 2: Parse legacy [EVIDENCE] tags from text
    if response_text and not evidence:
        evidence = parse_evidence_from_text(response_text)

    # Also check reasoning field for evidence tags
    reasoning = response_data.get("reasoning", "")
    if reasoning and not evidence:
        evidence = parse_evidence_from_text(reasoning)

    # Log parsing results
    logger.info(
        "Evidence extraction complete",
        extra={
            "evidence_count": len(evidence),
            "steps_count": len(steps),
            "from_json": "evidence" in response_data,
            "from_tags": bool(response_text and "evidence" not in response_data),
        },
    )

    return evidence, steps


def validate_evidence_quality(
    evidence: list[EvidenceItem],
    min_items: int = 3,
    min_avg_confidence: float = 50.0,
) -> dict[str, Any]:
    """
    Validate the quality of collected evidence.

    Args:
        evidence: List of evidence items to validate.
        min_items: Minimum number of evidence items required.
        min_avg_confidence: Minimum average confidence required.

    Returns:
        Dictionary with validation results.
    """
    if not evidence:
        return {
            "valid": False,
            "reason": "No evidence collected",
            "evidence_count": 0,
            "avg_confidence": 0.0,
            "recommendations": ["Collect at least 3 pieces of supporting evidence"],
        }

    avg_confidence = sum(e.confidence for e in evidence) / len(evidence)
    has_min_items = len(evidence) >= min_items
    has_min_confidence = avg_confidence >= min_avg_confidence

    # Check for diverse sources
    sources = {e.source_type for e in evidence}
    has_diverse_sources = len(sources) >= 2

    # Check for high-confidence evidence
    high_conf_count = sum(1 for e in evidence if e.confidence >= 80)
    has_high_conf = high_conf_count >= 1

    recommendations = []
    if not has_min_items:
        recommendations.append(f"Collect at least {min_items} pieces of evidence")
    if not has_min_confidence:
        recommendations.append(f"Improve evidence quality (current avg: {avg_confidence:.1f}%)")
    if not has_diverse_sources:
        recommendations.append("Include evidence from multiple source types")
    if not has_high_conf:
        recommendations.append("Include at least one high-confidence (80%+) evidence item")

    return {
        "valid": has_min_items and has_min_confidence,
        "evidence_count": len(evidence),
        "avg_confidence": round(avg_confidence, 1),
        "source_diversity": len(sources),
        "high_confidence_count": high_conf_count,
        "recommendations": recommendations,
    }
