"""Tests for production-safe bridge mode resolution."""

from __future__ import annotations

import os
from unittest.mock import patch

import tw_ai.agents.tools as _tools


def test_resolve_bridge_mode_defaults_to_mock_in_non_production() -> None:
    with patch.dict(os.environ, {}, clear=True):
        assert _tools._resolve_bridge_mode("TW_THREAT_INTEL_MODE") == "mock"


def test_resolve_bridge_mode_defaults_to_production_in_production_env() -> None:
    with patch.dict(os.environ, {"TW_ENV": "production"}, clear=True):
        assert _tools._resolve_bridge_mode("TW_THREAT_INTEL_MODE") == "production"


def test_resolve_bridge_mode_blocks_explicit_mock_in_production() -> None:
    with patch.dict(
        os.environ,
        {"TW_ENV": "production", "TW_THREAT_INTEL_MODE": "mock"},
        clear=True,
    ):
        assert _tools._resolve_bridge_mode("TW_THREAT_INTEL_MODE") == "production"


def test_resolve_bridge_mode_allows_explicit_mock_with_override() -> None:
    with patch.dict(
        os.environ,
        {
            "TW_ENV": "production",
            _tools.MOCK_FALLBACK_OVERRIDE_ENV: "true",
            "TW_THREAT_INTEL_MODE": "mock",
        },
        clear=True,
    ):
        assert _tools._resolve_bridge_mode("TW_THREAT_INTEL_MODE") == "mock"
