"""Threat intelligence ingester.

Ingests threat intelligence indicators for similarity search.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import structlog

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import ThreatIntelDocument

if TYPE_CHECKING:
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()

INDICATOR_TYPE_MAP: dict[str, str] = {
    "ip": "ip",
    "ipv4": "ip",
    "ipv6": "ip",
    "ip_address": "ip",
    "domain": "domain",
    "domain_name": "domain",
    "url": "url",
    "uri": "url",
    "hash": "hash",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "email": "email",
    "other": "other",
}

VERDICT_MAP: dict[str, str] = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "benign": "benign",
    "unknown": "unknown",
    "clean": "benign",
}

STIX_VALUE_PATTERN = re.compile(r"^\[(?P<kind>[a-zA-Z0-9_-]+):value\s*=\s*'(?P<value>[^']+)'\]$")
STIX_HASH_PATTERN = re.compile(
    r"^\[file:hashes\.'(?P<algo>MD5|SHA-1|SHA-256)'\s*=\s*'(?P<value>[^']+)'\]$"
)


class ThreatIntelIngester(BaseIngester):
    """Ingester for threat intelligence indicators.

    Ingests IOCs and threat context for semantic search.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize threat intel ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the threat intel collection name."""
        return self._vector_store._config.threat_intel_collection

    async def ingest(self, source: list[dict[str, Any]] | str | Path | None = None) -> int:
        """Ingest threat intelligence from batches, files, or feed URLs.

        Returns:
            Number of indicators ingested.
        """
        if source is None:
            logger.info(
                "threat_intel_batch_ingestion_skipped",
                reason="no_indicators_provided",
            )
            return 0

        if isinstance(source, list):
            return await self.ingest_batch(source)

        source_text = str(source)
        if source_text.startswith(("http://", "https://")):
            return await self.ingest_from_url(source_text)

        source_path = Path(source_text)
        if not source_path.exists():
            logger.warning("threat_intel_source_not_found", source=source_text)
            return 0

        return await self.ingest_from_file(source_path)

    async def ingest_indicator(
        self,
        indicator: str,
        indicator_type: Literal["ip", "domain", "url", "hash", "email", "other"],
        verdict: Literal["malicious", "suspicious", "benign", "unknown"],
        context: str,
        threat_actor: str | None = None,
        confidence: int = 50,
    ) -> str:
        """Ingest a single threat intelligence indicator.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.
            verdict: Threat verdict.
            context: Contextual information about the indicator.
            threat_actor: Associated threat actor if known.
            confidence: Confidence in the verdict (0-100).

        Returns:
            Document ID of ingested indicator.
        """
        # Generate unique document ID
        doc_id = self._generate_doc_id(indicator, indicator_type)

        # Build content for embedding
        content = self._build_content(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            context=context,
            threat_actor=threat_actor,
        )

        doc = ThreatIntelDocument(
            id=doc_id,
            content=content,
            indicator=indicator,
            indicator_type=indicator_type,
            verdict=verdict,
            threat_actor=threat_actor,
            confidence=confidence,
            created_at=datetime.utcnow(),
        )

        self._add_document(doc)

        logger.info(
            "threat_intel_ingested",
            doc_id=doc_id,
            indicator_type=indicator_type,
            verdict=verdict,
        )

        return doc_id

    async def ingest_batch(
        self,
        indicators: list[dict[str, Any]],
    ) -> int:
        """Ingest multiple threat intelligence indicators.

        Args:
            indicators: List of indicator dictionaries with keys:
                - indicator: str
                - indicator_type: str
                - verdict: str
                - context: str
                - threat_actor: str (optional)
                - confidence: int (optional)

        Returns:
            Number of indicators ingested.
        """
        documents: list[ThreatIntelDocument] = []

        for idx, ind in enumerate(indicators):
            normalized = self._normalize_indicator(ind)
            if normalized is None:
                logger.warning("threat_intel_indicator_skipped", index=idx)
                continue

            indicator = normalized["indicator"]
            indicator_type = normalized["indicator_type"]
            verdict = normalized["verdict"]
            context = normalized["context"]
            threat_actor = normalized.get("threat_actor")
            confidence = int(normalized.get("confidence", 50))

            doc_id = self._generate_doc_id(indicator, indicator_type)
            content = self._build_content(
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                context=context,
                threat_actor=threat_actor,
            )

            doc = ThreatIntelDocument(
                id=doc_id,
                content=content,
                indicator=indicator,
                indicator_type=indicator_type,
                verdict=verdict,
                threat_actor=threat_actor,
                confidence=confidence,
                created_at=datetime.utcnow(),
            )
            documents.append(doc)

        if documents:
            self._add_documents(documents)

        logger.info("threat_intel_batch_ingested", count=len(documents))
        return len(documents)

    async def ingest_from_file(self, file_path: Path) -> int:
        """Ingest indicators from a local JSON/JSONL/CSV feed file."""
        suffix = file_path.suffix.lower()
        if suffix == ".json":
            with file_path.open() as f:
                payload = json.load(f)
            return await self.ingest_batch(self._records_from_json(payload))

        if suffix == ".jsonl":
            records: list[dict[str, Any]] = []
            with file_path.open() as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        parsed = json.loads(stripped)
                    except json.JSONDecodeError:
                        logger.warning(
                            "threat_intel_jsonl_line_invalid",
                            source=str(file_path),
                            line_preview=stripped[:120],
                        )
                        continue
                    if isinstance(parsed, dict):
                        records.append(parsed)
            return await self.ingest_batch(records)

        if suffix == ".csv":
            with file_path.open(newline="") as f:
                reader = csv.DictReader(f)
                records = [dict(row) for row in reader]
            return await self.ingest_batch(records)

        logger.warning("threat_intel_file_unsupported", source=str(file_path), suffix=suffix)
        return 0

    async def ingest_from_url(self, url: str, timeout_seconds: float = 30.0) -> int:
        """Ingest indicators from an external HTTP(S) threat feed."""
        import httpx

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds, follow_redirects=True) as client:
                response = await client.get(url)
                response.raise_for_status()
        except Exception as exc:
            logger.error("threat_intel_feed_fetch_failed", source=url, error=str(exc))
            return 0

        content_type = response.headers.get("content-type", "").lower()
        url_lc = url.lower()

        if "text/csv" in content_type or url_lc.endswith(".csv"):
            csv_rows = list(csv.DictReader(io.StringIO(response.text)))
            return await self.ingest_batch([dict(row) for row in csv_rows])

        if url_lc.endswith(".jsonl"):
            jsonl_records: list[dict[str, Any]] = []
            for line in response.text.splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    parsed = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    jsonl_records.append(parsed)
            return await self.ingest_batch(jsonl_records)

        try:
            payload = response.json()
        except json.JSONDecodeError:
            logger.error("threat_intel_feed_parse_failed", source=url, reason="invalid_json")
            return 0

        return await self.ingest_batch(self._records_from_json(payload))

    def _records_from_json(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [entry for entry in payload if isinstance(entry, dict)]

        if not isinstance(payload, dict):
            return []

        if isinstance(payload.get("indicators"), list):
            return [entry for entry in payload["indicators"] if isinstance(entry, dict)]

        # STIX 2.x bundle support
        if payload.get("type") == "bundle" and isinstance(payload.get("objects"), list):
            converted: list[dict[str, Any]] = []
            for obj in payload["objects"]:
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                parsed = self._parse_stix_indicator(obj)
                if parsed is not None:
                    converted.append(parsed)
            return converted

        return [payload]

    def _parse_stix_indicator(self, obj: dict[str, Any]) -> dict[str, Any] | None:
        pattern = obj.get("pattern")
        if not isinstance(pattern, str):
            return None

        parsed = self._extract_from_stix_pattern(pattern)
        if parsed is None:
            return None
        indicator, indicator_type = parsed

        labels = obj.get("labels")
        verdict = "unknown"
        if isinstance(labels, list):
            labels_lc = [str(label).lower() for label in labels]
            if any("malicious" in label for label in labels_lc):
                verdict = "malicious"
            elif any("suspicious" in label for label in labels_lc):
                verdict = "suspicious"

        description = obj.get("description")
        name = obj.get("name")
        context = "Imported from STIX feed"
        if isinstance(description, str) and description.strip():
            context = description.strip()
        elif isinstance(name, str) and name.strip():
            context = name.strip()

        confidence_raw = obj.get("confidence", 50)
        confidence = self._to_confidence(confidence_raw)

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "context": context,
            "confidence": confidence,
        }

    def _extract_from_stix_pattern(self, pattern: str) -> tuple[str, str] | None:
        hash_match = STIX_HASH_PATTERN.match(pattern.strip())
        if hash_match:
            value = hash_match.group("value").strip()
            if value:
                return value, "hash"
            return None

        value_match = STIX_VALUE_PATTERN.match(pattern.strip())
        if not value_match:
            return None

        kind = value_match.group("kind").strip().lower()
        value = value_match.group("value").strip()
        if not value:
            return None

        type_map = {
            "ipv4-addr": "ip",
            "ipv6-addr": "ip",
            "domain-name": "domain",
            "url": "url",
            "email-addr": "email",
        }
        return value, type_map.get(kind, "other")

    def _normalize_indicator(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        indicator = str(raw.get("indicator") or raw.get("value") or "").strip()
        if not indicator:
            return None

        indicator_type_raw = str(raw.get("indicator_type") or raw.get("type") or "other").lower()
        indicator_type = cast(
            Literal["ip", "domain", "url", "hash", "email", "other"],
            INDICATOR_TYPE_MAP.get(indicator_type_raw, "other"),
        )

        verdict_raw = str(raw.get("verdict") or raw.get("classification") or "unknown").lower()
        verdict = cast(
            Literal["malicious", "suspicious", "benign", "unknown"],
            VERDICT_MAP.get(verdict_raw, "unknown"),
        )

        context = str(
            raw.get("context")
            or raw.get("description")
            or raw.get("note")
            or "Imported from external threat feed"
        ).strip()

        threat_actor_raw = raw.get("threat_actor") or raw.get("actor")
        threat_actor = (
            str(threat_actor_raw).strip()
            if isinstance(threat_actor_raw, str) and threat_actor_raw.strip()
            else None
        )

        confidence = self._to_confidence(raw.get("confidence", 50))

        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "verdict": verdict,
            "context": context,
            "threat_actor": threat_actor,
            "confidence": confidence,
        }

    def _to_confidence(self, value: Any) -> int:
        if isinstance(value, bool):
            return 100 if value else 0
        if not isinstance(value, (int, float, str)):
            return 50
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return 50
        return int(max(0, min(100, round(numeric))))

    def _generate_doc_id(self, indicator: str, indicator_type: str) -> str:
        """Generate a unique document ID.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.

        Returns:
            Unique document ID.
        """
        content = f"{indicator_type}:{indicator}"
        hash_value = hashlib.md5(content.encode()).hexdigest()[:12]
        return f"ti_{indicator_type}_{hash_value}"

    def _build_content(
        self,
        indicator: str,
        indicator_type: str,
        verdict: str,
        context: str,
        threat_actor: str | None = None,
    ) -> str:
        """Build text content for threat intel embedding.

        Args:
            indicator: The indicator value.
            indicator_type: Type of indicator.
            verdict: Threat verdict.
            context: Contextual information.
            threat_actor: Associated threat actor.

        Returns:
            Text content for embedding.
        """
        parts = [
            f"Threat Intelligence Indicator: {indicator}",
            f"Type: {indicator_type}",
            f"Verdict: {verdict}",
            f"Context: {context}",
        ]

        if threat_actor:
            parts.append(f"Threat Actor: {threat_actor}")

        return "\n".join(parts)
