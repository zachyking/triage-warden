"""Tests for AI interaction audit logger."""

from __future__ import annotations

from pathlib import Path

from tw_ai.logging.audit import AiInteractionAuditLogger


def test_ai_audit_logger_records_and_summarizes() -> None:
    logger = AiInteractionAuditLogger()
    logger.log(
        provider="openai",
        model="gpt-4o",
        prompt="hello",
        response="world",
        latency_ms=120,
    )

    entries = logger.list_entries()
    assert len(entries) == 1
    summary = logger.summarize()
    assert summary["total_requests"] == 1
    assert summary["avg_latency_ms"] == 120


def test_ai_audit_logger_writes_ndjson(tmp_path: Path) -> None:
    path = tmp_path / "ai-audit.ndjson"
    logger = AiInteractionAuditLogger(path)
    logger.log(
        provider="local",
        model="foundation-sec-8b",
        prompt="sensitive prompt",
        response="safe response",
        latency_ms=42,
    )

    content = path.read_text(encoding="utf-8")
    assert "foundation-sec-8b" in content
    assert "prompt_hash" in content
