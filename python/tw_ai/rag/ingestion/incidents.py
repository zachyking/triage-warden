"""Incident ingester for historical triage results.

Ingests completed TriageAnalysis results as historical incidents
for similarity search.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import structlog

from tw_ai.rag.ingestion.base import BaseIngester
from tw_ai.rag.models import IncidentDocument

if TYPE_CHECKING:
    from tw_ai.agents.models import Indicator, MITRETechnique, RecommendedAction, TriageAnalysis
    from tw_ai.rag.vector_store import VectorStore

logger = structlog.get_logger()

RUST_IOC_TYPE_MAP: dict[str, str] = {
    "ipv4": "ip",
    "ipv6": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "md5": "hash",
    "sha1": "hash",
    "sha256": "hash",
    "hash": "hash",
    "email": "email",
    "file_name": "file",
    "filename": "file",
    "file_path": "file",
    "registry_key": "registry",
    "process": "process",
}

RUST_VERDICT_MAP: dict[str, str] = {
    "true_positive": "true_positive",
    "likely_true_positive": "suspicious",
    "suspicious": "suspicious",
    "likely_false_positive": "false_positive",
    "false_positive": "false_positive",
    "inconclusive": "inconclusive",
}

SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}


class IncidentIngester(BaseIngester):
    """Ingester for historical triage incidents.

    Converts TriageAnalysis results into searchable documents
    containing the summary, reasoning, indicators, and techniques.
    """

    def __init__(self, vector_store: VectorStore) -> None:
        """Initialize incident ingester."""
        super().__init__(vector_store)

    @property
    def collection_name(self) -> str:
        """Get the incidents collection name."""
        return self._vector_store._config.incidents_collection

    async def ingest(
        self,
        source: list[dict[str, Any]] | str | Path | None = None,
        *,
        limit: int | None = None,
    ) -> int:
        """Ingest incidents from batch records, files, or SQLite databases.

        Supported sources:
        - `list[dict]`: Each item includes `analysis`, `alert_id`, `alert_type`.
        - `*.json` / `*.jsonl`: Records containing either:
            - `analysis` + `alert_id` (+ optional `alert_type`), or
            - incident-style rows (`id`, `analysis`, `alert_data`, `severity`).
        - `*.db` / `*.sqlite` / `*.sqlite3`: SQLite DB with an `incidents` table
          containing `id`, `analysis`, `alert_data`, and optional `severity`.

        Returns:
            Number of incidents successfully ingested.
        """
        if source is None:
            logger.info("incident_batch_ingestion_skipped", reason="no_analyses_provided")
            return 0

        if isinstance(source, list):
            return await self._ingest_records(source)

        source_path = Path(source)
        if not source_path.exists():
            logger.warning("incident_source_not_found", source=str(source_path))
            return 0

        suffix = source_path.suffix.lower()
        if suffix in {".db", ".sqlite", ".sqlite3"}:
            return await self.ingest_from_sqlite(source_path, limit=limit)

        if suffix in {".json", ".jsonl"}:
            return await self.ingest_from_file(source_path, limit=limit)

        logger.warning(
            "incident_source_unsupported",
            source=str(source_path),
            supported=[".db", ".sqlite", ".sqlite3", ".json", ".jsonl"],
        )
        return 0

    async def ingest_from_sqlite(self, db_path: Path, limit: int | None = None) -> int:
        """Ingest historical incidents from a SQLite database."""
        conn: sqlite3.Connection | None = None
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            base_query = """
                SELECT id, alert_data, analysis, severity
                FROM incidents
                WHERE analysis IS NOT NULL
                ORDER BY created_at DESC
            """
            if limit is not None and limit > 0:
                cursor.execute(f"{base_query} LIMIT ?", (limit,))
            else:
                cursor.execute(base_query)

            rows = cursor.fetchall()
            ingested = 0
            for row in rows:
                alert_id = str(row["id"])
                alert_data = row["alert_data"]
                analysis_payload = row["analysis"]
                severity_hint = row["severity"] if "severity" in row.keys() else None
                alert_type = self._extract_alert_type(alert_data) or "unknown"

                analysis = self._parse_analysis_payload(
                    analysis_payload,
                    severity_hint=str(severity_hint) if severity_hint else None,
                    alert_data=alert_data,
                )
                if analysis is None:
                    continue

                await self.ingest_analysis(
                    analysis=analysis,
                    alert_id=alert_id,
                    alert_type=alert_type,
                )
                ingested += 1

            logger.info(
                "incident_sqlite_ingestion_complete",
                source=str(db_path),
                ingested=ingested,
                total_rows=len(rows),
            )
            return ingested
        except sqlite3.Error as exc:
            logger.error(
                "incident_sqlite_ingestion_failed",
                source=str(db_path),
                error=str(exc),
            )
            return 0
        finally:
            if conn is not None:
                conn.close()

    async def ingest_from_file(self, file_path: Path, limit: int | None = None) -> int:
        """Ingest historical incidents from JSON/JSONL files."""
        records: list[dict[str, Any]] = []
        suffix = file_path.suffix.lower()

        if suffix == ".json":
            with file_path.open() as f:
                payload = json.load(f)
            if isinstance(payload, dict):
                if isinstance(payload.get("incidents"), list):
                    records = [r for r in payload["incidents"] if isinstance(r, dict)]
                else:
                    records = [payload]
            elif isinstance(payload, list):
                records = [r for r in payload if isinstance(r, dict)]
        elif suffix == ".jsonl":
            with file_path.open() as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        parsed = json.loads(stripped)
                    except json.JSONDecodeError:
                        logger.warning(
                            "incident_jsonl_line_invalid",
                            source=str(file_path),
                            line_preview=stripped[:120],
                        )
                        continue
                    if isinstance(parsed, dict):
                        records.append(parsed)
        else:
            logger.warning("incident_file_unsupported", source=str(file_path), suffix=suffix)
            return 0

        if limit is not None and limit > 0:
            records = records[:limit]

        ingested = await self._ingest_records(records)
        logger.info(
            "incident_file_ingestion_complete",
            source=str(file_path),
            ingested=ingested,
            total_records=len(records),
        )
        return ingested

    async def _ingest_records(self, records: list[dict[str, Any]]) -> int:
        ingested = 0
        for idx, item in enumerate(records):
            parsed = self._parse_record(item)
            if parsed is None:
                logger.warning(
                    "incident_batch_item_skipped",
                    index=idx,
                )
                continue

            analysis, alert_id, alert_type = parsed
            await self.ingest_analysis(
                analysis=analysis,
                alert_id=alert_id,
                alert_type=alert_type,
            )
            ingested += 1

        logger.info("incident_batch_ingested", count=ingested, total=len(records))
        return ingested

    def _parse_record(
        self,
        item: dict[str, Any],
    ) -> tuple[TriageAnalysis, str, str] | None:
        if "analysis" not in item:
            return None

        alert_data = item.get("alert_data")
        alert_id = str(item.get("alert_id") or item.get("id") or "")
        if not alert_id:
            return None

        alert_type = str(
            item.get("alert_type") or self._extract_alert_type(alert_data) or "unknown"
        )
        analysis = self._parse_analysis_payload(
            item["analysis"],
            severity_hint=item.get("severity"),
            alert_data=alert_data,
        )
        if analysis is None:
            return None

        return analysis, alert_id, alert_type

    def _parse_analysis_payload(
        self,
        payload: Any,
        *,
        severity_hint: Any = None,
        alert_data: Any = None,
    ) -> TriageAnalysis | None:
        from tw_ai.agents.models import TriageAnalysis

        if isinstance(payload, TriageAnalysis):
            return payload

        analysis_data = payload
        if isinstance(analysis_data, str):
            stripped = analysis_data.strip()
            if not stripped:
                return None
            try:
                analysis_data = json.loads(stripped)
            except json.JSONDecodeError:
                logger.warning("incident_analysis_json_invalid")
                return None

        if not isinstance(analysis_data, dict):
            return None

        # Path 1: payload is already in Python TriageAnalysis schema.
        try:
            if "indicators" in analysis_data and "recommended_actions" in analysis_data:
                return TriageAnalysis.model_validate(analysis_data)
        except Exception as exc:
            logger.warning("incident_python_analysis_validation_failed", error=str(exc))

        # Path 2: payload is Rust incident::TriageAnalysis schema.
        mapped = self._map_rust_analysis(
            analysis_data,
            severity_hint=str(severity_hint) if severity_hint is not None else None,
            alert_data=alert_data,
        )
        if mapped is None:
            return None

        try:
            return TriageAnalysis.model_validate(mapped)
        except Exception as exc:
            logger.warning("incident_rust_analysis_validation_failed", error=str(exc))
            return None

    def _map_rust_analysis(
        self,
        analysis_data: dict[str, Any],
        *,
        severity_hint: str | None = None,
        alert_data: Any = None,
    ) -> dict[str, Any] | None:
        verdict_raw = str(analysis_data.get("verdict", "inconclusive")).strip().lower()
        verdict = RUST_VERDICT_MAP.get(verdict_raw, "inconclusive")

        summary = str(analysis_data.get("summary", "")).strip() or self._extract_summary(alert_data)
        if not summary:
            summary = "Imported incident analysis"

        reasoning = str(analysis_data.get("reasoning", "")).strip()
        if not reasoning:
            reasoning = "Imported from external source"

        risk_score = analysis_data.get("risk_score")
        risk_int = 50
        if isinstance(risk_score, (int, float)):
            risk_int = int(max(0, min(100, round(float(risk_score)))))

        return {
            "verdict": verdict,
            "confidence": self._to_percentage(analysis_data.get("confidence")),
            "severity": self._map_severity(severity_hint),
            "summary": summary,
            "reasoning": reasoning,
            "indicators": self._map_rust_iocs(analysis_data.get("iocs")),
            "mitre_techniques": self._map_rust_mitre(analysis_data.get("mitre_techniques")),
            "recommended_actions": self._map_recommendations(
                analysis_data.get("recommendations"),
                risk_int,
            ),
        }

    def _map_rust_iocs(self, iocs: Any) -> list[Indicator]:
        from tw_ai.agents.models import Indicator

        if not isinstance(iocs, list):
            return []

        mapped: list[Indicator] = []
        for entry in iocs:
            if not isinstance(entry, dict):
                continue

            value = str(entry.get("value", "")).strip()
            if not value:
                continue

            ioc_type_raw = str(entry.get("ioc_type", "other")).strip().lower()
            indicator_type = cast(
                Literal[
                    "ip",
                    "domain",
                    "url",
                    "hash",
                    "email",
                    "file",
                    "registry",
                    "process",
                    "other",
                ],
                RUST_IOC_TYPE_MAP.get(ioc_type_raw, "other"),
            )
            score = entry.get("score")
            verdict = "suspicious"
            if isinstance(score, (int, float)):
                if float(score) >= 0.8:
                    verdict = "malicious"
                elif float(score) < 0.4:
                    verdict = "benign"

            context_val = entry.get("context")
            context = str(context_val) if context_val is not None else None

            try:
                mapped.append(
                    Indicator(
                        type=indicator_type,
                        value=value,
                        verdict=verdict,
                        context=context,
                    )
                )
            except Exception as exc:
                logger.warning("incident_ioc_mapping_failed", error=str(exc), value=value)
        return mapped

    def _map_rust_mitre(self, techniques: Any) -> list[MITRETechnique]:
        from tw_ai.agents.models import MITRETechnique

        if not isinstance(techniques, list):
            return []

        mapped: list[MITRETechnique] = []
        for entry in techniques:
            if not isinstance(entry, dict):
                continue

            tech_id = str(entry.get("id", "")).strip()
            if not tech_id:
                continue
            confidence = entry.get("confidence")
            relevance = (
                f"Imported mapping (confidence={confidence})"
                if isinstance(confidence, (int, float))
                else "Imported mapping"
            )

            try:
                mapped.append(
                    MITRETechnique(
                        id=tech_id,
                        name=str(entry.get("name", tech_id)),
                        tactic=str(entry.get("tactic", "Unknown")),
                        relevance=relevance,
                    )
                )
            except Exception as exc:
                logger.warning(
                    "incident_mitre_mapping_failed",
                    error=str(exc),
                    technique_id=tech_id,
                )
        return mapped

    def _map_recommendations(
        self,
        recommendations: Any,
        risk_score: int,
    ) -> list[RecommendedAction]:
        from tw_ai.agents.models import RecommendedAction

        if not isinstance(recommendations, list):
            return []

        if risk_score >= 75:
            priority: Literal["immediate", "high", "medium", "low"] = "high"
        elif risk_score >= 50:
            priority = "medium"
        else:
            priority = "low"

        mapped: list[RecommendedAction] = []
        for entry in recommendations:
            action_text = (
                str(entry).strip()
                if not isinstance(entry, dict)
                else str(entry.get("action", "")).strip()
            )
            if not action_text:
                continue
            reason = (
                str(entry.get("reason", "")).strip()
                if isinstance(entry, dict)
                else "Imported from historical incident"
            )
            if not reason:
                reason = "Imported from historical incident"

            try:
                mapped.append(
                    RecommendedAction(
                        action=action_text,
                        priority=priority,
                        reason=reason,
                        requires_approval=(priority in {"high", "immediate"}),
                    )
                )
            except Exception as exc:
                logger.warning(
                    "incident_recommendation_mapping_failed",
                    error=str(exc),
                    action=action_text,
                )
        return mapped

    def _extract_alert_type(self, alert_data: Any) -> str | None:
        parsed = alert_data
        if isinstance(parsed, str):
            stripped = parsed.strip()
            if not stripped:
                return None
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return None

        if isinstance(parsed, dict):
            alert_type = parsed.get("alert_type")
            if isinstance(alert_type, str) and alert_type.strip():
                return alert_type.strip()
        return None

    def _extract_summary(self, alert_data: Any) -> str:
        parsed = alert_data
        if isinstance(parsed, str):
            stripped = parsed.strip()
            if not stripped:
                return ""
            try:
                parsed = json.loads(stripped)
            except json.JSONDecodeError:
                return ""
        if not isinstance(parsed, dict):
            return ""

        for key in ("title", "summary", "description"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""

    def _to_percentage(self, value: Any) -> int:
        if not isinstance(value, (int, float)):
            return 50
        numeric = float(value)
        if numeric <= 1.0:
            numeric *= 100.0
        return int(max(0, min(100, round(numeric))))

    def _map_severity(self, severity_hint: str | None) -> str:
        if not severity_hint:
            return "medium"
        return SEVERITY_MAP.get(severity_hint.strip().lower(), "medium")

    async def ingest_analysis(
        self,
        analysis: TriageAnalysis,
        alert_id: str,
        alert_type: str,
    ) -> str:
        """Ingest a single triage analysis as a historical incident.

        Args:
            analysis: Completed triage analysis.
            alert_id: Original alert identifier.
            alert_type: Type of alert (phishing, malware, etc.)

        Returns:
            Document ID of ingested incident.
        """
        # Generate unique document ID
        doc_id = self._generate_doc_id(alert_id, analysis)

        # Build content from analysis
        content = self._build_content(analysis)

        # Extract technique IDs
        technique_ids = [t.id for t in analysis.mitre_techniques]

        doc = IncidentDocument(
            id=doc_id,
            content=content,
            verdict=analysis.verdict,
            severity=analysis.severity,
            confidence=analysis.confidence,
            alert_type=alert_type,
            alert_id=alert_id,
            technique_ids=technique_ids,
            indicator_count=len(analysis.indicators),
            created_at=datetime.utcnow(),
        )

        self._add_document(doc)

        logger.info(
            "incident_ingested",
            doc_id=doc_id,
            alert_id=alert_id,
            verdict=analysis.verdict,
        )

        return doc_id

    def _generate_doc_id(self, alert_id: str, analysis: TriageAnalysis) -> str:
        """Generate a unique document ID.

        Args:
            alert_id: Alert identifier.
            analysis: Triage analysis.

        Returns:
            Unique document ID.
        """
        # Create hash from alert_id and key analysis fields
        content = f"{alert_id}:{analysis.verdict}:{analysis.summary[:100]}"
        hash_suffix = hashlib.md5(content.encode()).hexdigest()[:8]
        return f"incident_{alert_id}_{hash_suffix}"

    def _build_content(self, analysis: TriageAnalysis) -> str:
        """Build text content from a triage analysis.

        Args:
            analysis: Triage analysis result.

        Returns:
            Text content for embedding.
        """
        parts = [
            f"Verdict: {analysis.verdict}",
            f"Severity: {analysis.severity}",
            f"Confidence: {analysis.confidence}%",
            f"Summary: {analysis.summary}",
        ]

        # Add reasoning if present
        if analysis.reasoning:
            parts.append(f"Reasoning: {analysis.reasoning}")

        # Add indicators
        if analysis.indicators:
            indicators_str = "; ".join(
                f"{i.type}: {i.value} ({i.verdict})" for i in analysis.indicators
            )
            parts.append(f"Indicators: {indicators_str}")

        # Add MITRE techniques
        if analysis.mitre_techniques:
            techniques_str = "; ".join(
                f"{t.id} - {t.name} ({t.tactic})" for t in analysis.mitre_techniques
            )
            parts.append(f"MITRE Techniques: {techniques_str}")

        # Add recommended actions
        if analysis.recommended_actions:
            actions_str = "; ".join(
                f"{a.action} ({a.priority})" for a in analysis.recommended_actions
            )
            parts.append(f"Recommended Actions: {actions_str}")

        return "\n".join(parts)
