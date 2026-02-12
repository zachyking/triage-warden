"""Pytest configuration for tw_ai tests.

Handles sys.modules isolation to prevent cross-test pollution when test files
manipulate tw_ai module entries (e.g. E2E tests install mock modules).

The E2E test fixtures install mock modules into sys.modules at conftest import
time (module-level code in _e2e_fixtures.py).  This happens during pytest's
conftest discovery phase, which runs BEFORE pytest_collectstart hooks fire for
the e2e Package.  To prevent these mocks from leaking into non-E2E test
collection, we:

1. Capture the pristine sys.modules state in pytest_configure (the only hook
   that runs before conftest discovery).
2. Before collecting each non-E2E Module, restore the pristine state so that
   test file imports see real tw_ai modules.
3. Per-Module save/restore hooks handle tests that manipulate sys.modules
   during their own collection (e.g. module-level sys.modules["tw_ai"] = ...).
4. After all collection is done (pytest_collection_modifyitems), do a final
   pristine restore so test execution starts with clean imports.
"""

import sys
import types

import pytest


# Snapshot of tw_ai sys.modules entries captured at pytest startup, before any
# conftest files are loaded.  This is the "pristine" state that all non-e2e
# tests expect to see.
_tw_ai_pristine_snapshot: dict[str, object] = {}


def pytest_configure(config):
    """Configure custom markers and capture pristine sys.modules state."""
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
    # Capture the clean tw_ai state before any conftest imports.
    for key in list(sys.modules.keys()):
        if key == "tw_ai" or key.startswith("tw_ai."):
            _tw_ai_pristine_snapshot[key] = sys.modules[key]


def _restore_pristine_tw_ai():
    """Reset tw_ai sys.modules entries to the pristine state from startup.

    Removes mock/stub entries installed by E2E fixtures and restores real
    module entries to their original state.
    """
    for key in list(sys.modules.keys()):
        if key == "tw_ai" or key.startswith("tw_ai."):
            if key not in _tw_ai_pristine_snapshot:
                mod = sys.modules[key]
                is_real = (
                    isinstance(mod, types.ModuleType)
                    and getattr(mod, "__file__", None) is not None
                )
                if not is_real:
                    del sys.modules[key]
    for key, mod in _tw_ai_pristine_snapshot.items():
        sys.modules[key] = mod


_tw_ai_module_snapshots: dict[str, dict[str, object]] = {}


def pytest_collectstart(collector):
    """Save tw_ai sys.modules state before each Module is collected.

    Before collecting a non-E2E Module, restore the pristine sys.modules state
    so that test file imports see real tw_ai modules instead of E2E mocks that
    may have leaked from conftest discovery.
    """
    if not isinstance(collector, pytest.Module):
        return

    # Restore pristine state before collecting non-E2E modules to undo any
    # mock pollution from E2E conftest loading.
    if "/e2e/" not in collector.nodeid and not collector.nodeid.startswith("tests/e2e/"):
        _restore_pristine_tw_ai()

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
    for key, mod in saved.items():
        sys.modules[key] = mod


def pytest_collection_modifyitems(session, config, items):
    """Restore pristine tw_ai sys.modules after all collection is complete.

    Final cleanup so test execution starts with clean imports regardless of
    which test directories were collected.
    """
    _restore_pristine_tw_ai()
