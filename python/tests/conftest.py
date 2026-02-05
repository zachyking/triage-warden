"""Pytest configuration for tw_ai tests."""

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
