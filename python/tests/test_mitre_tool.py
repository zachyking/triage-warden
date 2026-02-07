"""Tests for the map_to_mitre agent tool."""

from __future__ import annotations

import pytest

from tw_ai.agents.tools import ToolResult, create_triage_tools


@pytest.mark.asyncio
async def test_map_to_mitre_returns_real_matches() -> None:
    """map_to_mitre should return non-mock MITRE mappings for known behaviors."""
    registry = create_triage_tools()
    result = await registry.execute(
        "map_to_mitre",
        {"description": "encoded powershell command execution"},
    )

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.data["is_mock"] is False
    assert result.data["match_count"] > 0
    assert any(technique["id"] == "T1059.001" for technique in result.data["techniques"])
    assert "Execution" in result.data["tactics"]


@pytest.mark.asyncio
async def test_map_to_mitre_returns_empty_for_unrelated_text() -> None:
    """map_to_mitre should return empty results for unrelated text."""
    registry = create_triage_tools()
    result = await registry.execute(
        "map_to_mitre",
        {"description": "weekly cafeteria menu and office celebration notes"},
    )

    assert isinstance(result, ToolResult)
    assert result.success is True
    assert result.data["is_mock"] is False
    assert result.data["match_count"] == 0
    assert result.data["techniques"] == []
    assert result.data["tactics"] == []
