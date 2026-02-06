"""E2E test configuration - import fixtures from _e2e_fixtures."""

from tests.e2e._e2e_fixtures import (  # noqa: F401
    false_positive,
    legitimate_email,
    mock_llm_provider,
    mock_tool_registry,
    obvious_phishing,
    phishing_workflow,
    sophisticated_phishing,
)
