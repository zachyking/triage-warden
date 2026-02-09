"""AI interaction audit logging for compliance and forensics."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass
class AiInteractionLog:
    """Single AI interaction audit entry."""

    id: str
    timestamp: float
    provider: str
    model: str
    prompt_hash: str
    prompt_size: int
    response_hash: str
    response_size: int
    latency_ms: int
    incident_id: str | None = None
    user_id: str | None = None
    cost_estimate: float | None = None
    masked_fields: list[str] = field(default_factory=list)
    error: str | None = None
    full_prompt: str | None = None
    full_response: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AiInteractionAuditLogger:
    """Audit logger with optional durable NDJSON output."""

    def __init__(self, path: str | Path | None = None) -> None:
        self._entries: list[AiInteractionLog] = []
        self._path = Path(path) if path else None
        if self._path:
            self._path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        *,
        provider: str,
        model: str,
        prompt: str,
        response: str,
        latency_ms: int,
        incident_id: str | None = None,
        user_id: str | None = None,
        cost_estimate: float | None = None,
        masked_fields: list[str] | None = None,
        error: str | None = None,
        store_full_content: bool = False,
    ) -> AiInteractionLog:
        """Create and store an audit entry."""
        entry = AiInteractionLog(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            provider=provider,
            model=model,
            prompt_hash=_hash_text(prompt),
            prompt_size=len(prompt),
            response_hash=_hash_text(response),
            response_size=len(response),
            latency_ms=latency_ms,
            incident_id=incident_id,
            user_id=user_id,
            cost_estimate=cost_estimate,
            masked_fields=masked_fields or [],
            error=error,
            full_prompt=prompt if store_full_content else None,
            full_response=response if store_full_content else None,
        )
        self._entries.append(entry)
        self._append_to_disk(entry)
        return entry

    def list_entries(self) -> list[AiInteractionLog]:
        """Return all in-memory entries."""
        return list(self._entries)

    def summarize(self) -> dict[str, Any]:
        """Basic usage metrics for dashboards."""
        total = len(self._entries)
        if total == 0:
            return {
                "total_requests": 0,
                "total_prompt_bytes": 0,
                "total_response_bytes": 0,
                "avg_latency_ms": 0.0,
                "error_count": 0,
            }

        total_prompt = sum(e.prompt_size for e in self._entries)
        total_response = sum(e.response_size for e in self._entries)
        avg_latency = sum(e.latency_ms for e in self._entries) / total
        errors = sum(1 for e in self._entries if e.error)
        return {
            "total_requests": total,
            "total_prompt_bytes": total_prompt,
            "total_response_bytes": total_response,
            "avg_latency_ms": avg_latency,
            "error_count": errors,
        }

    def _append_to_disk(self, entry: AiInteractionLog) -> None:
        if not self._path:
            return
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict(), sort_keys=True))
            fh.write("\n")
