"""Tests for phishing prompt rendering helpers."""

from tw_ai.agents.prompts.phishing import get_phishing_triage_prompt


def test_phishing_prompt_includes_examples_by_default() -> None:
    prompt = get_phishing_triage_prompt(alert_context="Sample alert context")

    assert "## Example Analyses" in prompt
    assert "### Example 1: Clear Phishing Attack" in prompt


def test_phishing_prompt_excludes_examples_when_disabled() -> None:
    prompt = get_phishing_triage_prompt(
        alert_context="Sample alert context",
        include_examples=False,
    )

    assert "## Example Analyses" not in prompt
    assert "### Example 1: Clear Phishing Attack" not in prompt


def test_phishing_prompt_includes_organization_context() -> None:
    prompt = get_phishing_triage_prompt(
        alert_context="Sample alert context",
        organization_context="We are a healthcare SOC.",
    )

    assert "## Organization Context" in prompt
    assert "We are a healthcare SOC." in prompt
