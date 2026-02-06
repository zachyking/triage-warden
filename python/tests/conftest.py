"""Pytest configuration for tw_ai tests."""

import sys
import types

import pytest


def pytest_configure(config):
    """Configure custom markers for pytest."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (deselect with '-m \"not integration\"')",
    )
    config.addinivalue_line(
        "markers",
        "e2e: marks tests as end-to-end tests (deselect with '-m \"not e2e\"')",
    )
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow-running (deselect with '-m \"not slow\"')",
    )


_tw_ai_module_snapshots: dict[str, dict[str, object]] = {}


def pytest_collectstart(collector):
    """Save tw_ai sys.modules state before each Module is collected."""
    if not isinstance(collector, pytest.Module):
        return
    saved = {}
    for key in list(sys.modules.keys()):
        if key == "tw_ai" or key.startswith("tw_ai."):
            saved[key] = sys.modules[key]
    _tw_ai_module_snapshots[collector.nodeid] = saved


def pytest_collectreport(report):
    """Restore tw_ai sys.modules state after each Module is collected."""
    saved = _tw_ai_module_snapshots.pop(report.nodeid, None)
    if saved is None:
        return
    # Remove mock/stub entries that were added during collection.
    # Keep real imported modules (have __file__) to avoid class identity
    # mismatches when tests later re-import the same module.
    # Stubs created via types.ModuleType() lack __file__.
    for key in list(sys.modules.keys()):
        if key == "tw_ai" or key.startswith("tw_ai."):
            if key not in saved:
                mod = sys.modules[key]
                is_real = (
                    isinstance(mod, types.ModuleType)
                    and getattr(mod, "__file__", None) is not None
                )
                if not is_real:
                    del sys.modules[key]
    # Restore original entries
    for key, mod in saved.items():
        sys.modules[key] = mod
