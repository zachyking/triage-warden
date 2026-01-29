"""Unit tests for output parsing and validation."""

from __future__ import annotations

import sys
import importlib.util
from pathlib import Path

import pytest

# Direct module loading to avoid Python 3.10+ syntax in tw_ai/__init__.py
# This allows running tests on Python 3.9 while the rest of the codebase requires 3.10+
_base_path = Path(__file__).parent.parent / "tw_ai" / "agents"


def _load_module(name: str, file_path: Path):
    """Load a module directly from file path."""
    spec = importlib.util.spec_from_file_location(name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Load models first (output_parser depends on it)
_models = _load_module("tw_ai.agents.models", _base_path / "models.py")
Indicator = _models.Indicator
MITRETechnique = _models.MITRETechnique
RecommendedAction = _models.RecommendedAction
TriageAnalysis = _models.TriageAnalysis

# Load output_parser
_parser = _load_module("tw_ai.agents.output_parser", _base_path / "output_parser.py")
ParseError = _parser.ParseError
parse_json_from_response = _parser.parse_json_from_response
parse_triage_analysis = _parser.parse_triage_analysis


# ============================================================================
# Test Data
# ============================================================================

VALID_TRIAGE_JSON = """{
    "verdict": "true_positive",
    "confidence": 85,
    "severity": "high",
    "summary": "Confirmed phishing attempt targeting finance department",
    "indicators": [
        {
            "type": "domain",
            "value": "evil-phish.com",
            "verdict": "malicious",
            "context": "Known phishing domain"
        },
        {
            "type": "ip",
            "value": "192.168.1.100",
            "verdict": "suspicious"
        }
    ],
    "mitre_techniques": [
        {
            "id": "T1566.001",
            "name": "Spearphishing Attachment",
            "tactic": "Initial Access",
            "relevance": "Email contained malicious attachment"
        }
    ],
    "recommended_actions": [
        {
            "action": "Block sender domain",
            "priority": "immediate",
            "reason": "Prevent further phishing attempts",
            "requires_approval": false
        },
        {
            "action": "Reset affected user credentials",
            "priority": "high",
            "reason": "User may have entered credentials on phishing page",
            "requires_approval": true
        }
    ],
    "reasoning": "Analysis indicates a sophisticated phishing campaign..."
}"""

MINIMAL_TRIAGE_JSON = """{
    "verdict": "false_positive",
    "confidence": 95,
    "severity": "low",
    "summary": "Benign alert triggered by legitimate automation"
}"""


# ============================================================================
# Model Validation Tests
# ============================================================================


class TestIndicatorModel:
    """Tests for the Indicator model."""

    def test_valid_indicator(self):
        """Test creating a valid indicator."""
        indicator = Indicator(
            type="ip",
            value="192.168.1.1",
            verdict="malicious",
            context="C2 server",
        )
        assert indicator.type == "ip"
        assert indicator.value == "192.168.1.1"
        assert indicator.context == "C2 server"

    def test_indicator_without_context(self):
        """Test creating an indicator without optional context."""
        indicator = Indicator(
            type="hash",
            value="abc123",
            verdict="suspicious",
        )
        assert indicator.context is None

    def test_indicator_strips_whitespace(self):
        """Test that indicator values are stripped."""
        indicator = Indicator(
            type="domain",
            value="  example.com  ",
            verdict="benign",
        )
        assert indicator.value == "example.com"

    def test_indicator_empty_value_fails(self):
        """Test that empty value raises validation error."""
        with pytest.raises(ValueError, match="cannot be empty"):
            Indicator(type="ip", value="", verdict="unknown")

    def test_indicator_invalid_type_fails(self):
        """Test that invalid indicator type raises error."""
        with pytest.raises(ValueError):
            Indicator(type="invalid_type", value="test", verdict="unknown")


class TestMITRETechniqueModel:
    """Tests for the MITRETechnique model."""

    def test_valid_technique_with_subtechnique(self):
        """Test a technique with subtechnique ID."""
        technique = MITRETechnique(
            id="T1566.001",
            name="Spearphishing Attachment",
            tactic="Initial Access",
            relevance="Email-based attack vector",
        )
        assert technique.id == "T1566.001"

    def test_valid_technique_without_subtechnique(self):
        """Test a technique without subtechnique."""
        technique = MITRETechnique(
            id="T1566",
            name="Phishing",
            tactic="Initial Access",
            relevance="General phishing",
        )
        assert technique.id == "T1566"

    def test_valid_technique_three_digit_subtechnique(self):
        """Test a technique with 3-digit subtechnique."""
        technique = MITRETechnique(
            id="T1059.001",
            name="PowerShell",
            tactic="Execution",
            relevance="Script execution",
        )
        assert technique.id == "T1059.001"

    def test_invalid_technique_id_format(self):
        """Test that invalid MITRE ID format raises error."""
        with pytest.raises(ValueError, match="Invalid MITRE technique ID"):
            MITRETechnique(
                id="ATTACK-001",
                name="Test",
                tactic="Test",
                relevance="Test",
            )

    def test_invalid_technique_id_too_few_digits(self):
        """Test that MITRE ID with too few digits fails."""
        with pytest.raises(ValueError, match="Invalid MITRE technique ID"):
            MITRETechnique(
                id="T123",
                name="Test",
                tactic="Test",
                relevance="Test",
            )

    def test_invalid_technique_id_no_t_prefix(self):
        """Test that MITRE ID without T prefix fails."""
        with pytest.raises(ValueError, match="Invalid MITRE technique ID"):
            MITRETechnique(
                id="1566.001",
                name="Test",
                tactic="Test",
                relevance="Test",
            )


class TestRecommendedActionModel:
    """Tests for the RecommendedAction model."""

    def test_valid_action_all_priorities(self):
        """Test creating actions with all priority levels."""
        for priority in ["immediate", "high", "medium", "low"]:
            action = RecommendedAction(
                action=f"Test action with {priority} priority",
                priority=priority,
                reason="Test reason",
            )
            assert action.priority == priority

    def test_action_requires_approval_default(self):
        """Test that requires_approval defaults to False."""
        action = RecommendedAction(
            action="Block IP",
            priority="immediate",
            reason="Known malicious",
        )
        assert action.requires_approval is False

    def test_invalid_priority_fails(self):
        """Test that invalid priority raises error."""
        with pytest.raises(ValueError):
            RecommendedAction(
                action="Test",
                priority="urgent",  # not a valid priority
                reason="Test",
            )


class TestTriageAnalysisModel:
    """Tests for the TriageAnalysis model."""

    def test_valid_complete_analysis(self):
        """Test a complete valid analysis."""
        analysis = TriageAnalysis(
            verdict="true_positive",
            confidence=85,
            severity="high",
            summary="Confirmed incident",
            indicators=[
                Indicator(type="ip", value="1.2.3.4", verdict="malicious")
            ],
            mitre_techniques=[
                MITRETechnique(
                    id="T1566",
                    name="Phishing",
                    tactic="Initial Access",
                    relevance="Test",
                )
            ],
            recommended_actions=[
                RecommendedAction(
                    action="Block",
                    priority="immediate",
                    reason="Malicious",
                )
            ],
            reasoning="Detailed reasoning here",
        )
        assert analysis.verdict == "true_positive"
        assert analysis.confidence == 85

    def test_valid_minimal_analysis(self):
        """Test a minimal valid analysis with defaults."""
        analysis = TriageAnalysis(
            verdict="false_positive",
            confidence=90,
            severity="low",
            summary="Benign activity",
        )
        assert analysis.indicators == []
        assert analysis.mitre_techniques == []
        assert analysis.recommended_actions == []
        assert analysis.reasoning == ""

    def test_confidence_boundary_values(self):
        """Test confidence at boundary values."""
        # Valid boundaries
        TriageAnalysis(
            verdict="inconclusive",
            confidence=0,
            severity="informational",
            summary="Test",
        )
        TriageAnalysis(
            verdict="inconclusive",
            confidence=100,
            severity="informational",
            summary="Test",
        )

    def test_confidence_out_of_range_fails(self):
        """Test that confidence outside 0-100 fails."""
        with pytest.raises(ValueError):
            TriageAnalysis(
                verdict="suspicious",
                confidence=101,
                severity="medium",
                summary="Test",
            )
        with pytest.raises(ValueError):
            TriageAnalysis(
                verdict="suspicious",
                confidence=-1,
                severity="medium",
                summary="Test",
            )

    def test_invalid_verdict_fails(self):
        """Test that invalid verdict raises error."""
        with pytest.raises(ValueError):
            TriageAnalysis(
                verdict="maybe_bad",
                confidence=50,
                severity="medium",
                summary="Test",
            )


# ============================================================================
# JSON Parsing Tests
# ============================================================================


class TestParseJsonFromResponse:
    """Tests for parse_json_from_response function."""

    def test_raw_json_object(self):
        """Test parsing raw JSON object."""
        result = parse_json_from_response('{"key": "value", "number": 42}')
        assert result == {"key": "value", "number": 42}

    def test_json_in_markdown_code_block(self):
        """Test extracting JSON from ```json code block."""
        text = """Here's my analysis:

```json
{
    "verdict": "true_positive",
    "confidence": 85
}
```

Let me know if you have questions."""

        result = parse_json_from_response(text)
        assert result == {"verdict": "true_positive", "confidence": 85}

    def test_json_in_generic_code_block(self):
        """Test extracting JSON from plain ``` code block."""
        text = """Analysis:

```
{"result": "success"}
```
"""
        result = parse_json_from_response(text)
        assert result == {"result": "success"}

    def test_json_with_surrounding_text(self):
        """Test extracting JSON from text without code blocks."""
        text = """Based on my analysis, here is the result:

{
    "verdict": "false_positive",
    "reason": "Legitimate traffic"
}

This concludes my assessment."""

        result = parse_json_from_response(text)
        assert result["verdict"] == "false_positive"

    def test_empty_response_fails(self):
        """Test that empty response raises ParseError."""
        with pytest.raises(ParseError, match="Empty response"):
            parse_json_from_response("")

        with pytest.raises(ParseError, match="Empty response"):
            parse_json_from_response("   ")


class TestMalformedJsonRecovery:
    """Tests for malformed JSON recovery."""

    def test_trailing_comma_in_object(self):
        """Test recovery from trailing comma in object."""
        text = '{"key": "value", "another": 123,}'
        result = parse_json_from_response(text)
        assert result == {"key": "value", "another": 123}

    def test_trailing_comma_in_array(self):
        """Test recovery from trailing comma in array."""
        text = '{"items": [1, 2, 3,]}'
        result = parse_json_from_response(text)
        assert result == {"items": [1, 2, 3]}

    def test_single_quotes_in_keys(self):
        """Test recovery from single-quoted keys."""
        text = "{'key': \"value\"}"
        result = parse_json_from_response(text)
        assert result == {"key": "value"}

    def test_single_quotes_in_values(self):
        """Test recovery from single-quoted values."""
        text = '{"key": \'value\'}'
        result = parse_json_from_response(text)
        assert result == {"key": "value"}

    def test_python_boolean_true(self):
        """Test recovery from Python True instead of true."""
        text = '{"active": True}'
        result = parse_json_from_response(text)
        assert result == {"active": True}

    def test_python_boolean_false(self):
        """Test recovery from Python False instead of false."""
        text = '{"active": False}'
        result = parse_json_from_response(text)
        assert result == {"active": False}

    def test_python_none(self):
        """Test recovery from Python None instead of null."""
        text = '{"value": None}'
        result = parse_json_from_response(text)
        assert result == {"value": None}

    def test_combined_issues(self):
        """Test recovery from multiple issues combined."""
        text = """```json
{
    'verdict': 'true_positive',
    "active": True,
    "items": [1, 2, 3,],
}
```"""
        result = parse_json_from_response(text)
        assert result["verdict"] == "true_positive"
        assert result["active"] is True
        assert result["items"] == [1, 2, 3]

    def test_unrecoverable_json_fails(self):
        """Test that completely invalid JSON raises ParseError."""
        with pytest.raises(ParseError, match="Failed to parse JSON"):
            parse_json_from_response("This is not JSON at all")

        with pytest.raises(ParseError, match="Failed to parse JSON"):
            parse_json_from_response("{invalid json structure")


# ============================================================================
# Triage Analysis Parsing Tests
# ============================================================================


class TestParseTriageAnalysis:
    """Tests for parse_triage_analysis function."""

    def test_valid_complete_analysis(self):
        """Test parsing a complete valid analysis."""
        result = parse_triage_analysis(VALID_TRIAGE_JSON)

        assert result.verdict == "true_positive"
        assert result.confidence == 85
        assert result.severity == "high"
        assert "phishing" in result.summary.lower()
        assert len(result.indicators) == 2
        assert len(result.mitre_techniques) == 1
        assert len(result.recommended_actions) == 2

        # Check nested objects
        assert result.indicators[0].type == "domain"
        assert result.indicators[0].value == "evil-phish.com"
        assert result.mitre_techniques[0].id == "T1566.001"
        assert result.recommended_actions[0].priority == "immediate"
        assert result.recommended_actions[1].requires_approval is True

    def test_minimal_analysis_with_defaults(self):
        """Test parsing minimal analysis uses defaults for optional fields."""
        result = parse_triage_analysis(MINIMAL_TRIAGE_JSON)

        assert result.verdict == "false_positive"
        assert result.confidence == 95
        assert result.indicators == []
        assert result.mitre_techniques == []
        assert result.recommended_actions == []
        assert result.reasoning == ""

    def test_analysis_in_markdown_block(self):
        """Test parsing analysis from markdown code block."""
        text = f"""Here is my triage analysis:

```json
{MINIMAL_TRIAGE_JSON}
```

Please review and let me know if you need more details."""

        result = parse_triage_analysis(text)
        assert result.verdict == "false_positive"

    def test_validation_error_invalid_verdict(self):
        """Test that invalid verdict produces helpful error."""
        invalid_json = """{
            "verdict": "probably_bad",
            "confidence": 50,
            "severity": "medium",
            "summary": "Test"
        }"""

        with pytest.raises(ParseError) as exc_info:
            parse_triage_analysis(invalid_json)

        assert "Validation failed" in str(exc_info.value)
        assert "verdict" in str(exc_info.value)

    def test_validation_error_missing_required_field(self):
        """Test that missing required field produces helpful error."""
        invalid_json = """{
            "verdict": "true_positive",
            "confidence": 85,
            "severity": "high"
        }"""  # Missing summary

        with pytest.raises(ParseError) as exc_info:
            parse_triage_analysis(invalid_json)

        assert "Validation failed" in str(exc_info.value)
        assert "summary" in str(exc_info.value).lower()

    def test_validation_error_invalid_indicator(self):
        """Test that invalid nested indicator produces helpful error."""
        invalid_json = """{
            "verdict": "suspicious",
            "confidence": 60,
            "severity": "medium",
            "summary": "Test analysis",
            "indicators": [
                {
                    "type": "ip",
                    "value": "",
                    "verdict": "unknown"
                }
            ]
        }"""

        with pytest.raises(ParseError) as exc_info:
            parse_triage_analysis(invalid_json)

        assert "Validation failed" in str(exc_info.value)
        assert "indicators" in str(exc_info.value)

    def test_validation_error_invalid_mitre_id(self):
        """Test that invalid MITRE ID produces helpful error."""
        invalid_json = """{
            "verdict": "true_positive",
            "confidence": 80,
            "severity": "high",
            "summary": "Test",
            "mitre_techniques": [
                {
                    "id": "INVALID",
                    "name": "Test",
                    "tactic": "Test",
                    "relevance": "Test"
                }
            ]
        }"""

        with pytest.raises(ParseError) as exc_info:
            parse_triage_analysis(invalid_json)

        assert "Validation failed" in str(exc_info.value)
        assert "mitre_techniques" in str(exc_info.value)

    def test_parse_error_preserves_raw_text(self):
        """Test that ParseError preserves the raw text for debugging."""
        raw_text = "completely invalid content"

        with pytest.raises(ParseError) as exc_info:
            parse_triage_analysis(raw_text)

        assert exc_info.value.raw_text == raw_text


# ============================================================================
# Edge Cases and Integration Tests
# ============================================================================


class TestEdgeCases:
    """Edge case and integration tests."""

    def test_unicode_in_values(self):
        """Test handling of unicode characters."""
        json_text = """{
            "verdict": "true_positive",
            "confidence": 75,
            "severity": "medium",
            "summary": "Detected suspicious activity from \u4e2d\u56fd"
        }"""

        result = parse_triage_analysis(json_text)
        assert "\u4e2d\u56fd" in result.summary

    def test_nested_json_in_strings(self):
        """Test that JSON inside string values doesn't break parsing."""
        json_text = """{
            "verdict": "suspicious",
            "confidence": 50,
            "severity": "low",
            "summary": "Found string: {\\"nested\\": true}"
        }"""

        result = parse_triage_analysis(json_text)
        assert "nested" in result.summary

    def test_large_number_of_indicators(self):
        """Test handling many indicators."""
        indicators = [
            {"type": "ip", "value": f"192.168.1.{i}", "verdict": "suspicious"}
            for i in range(100)
        ]
        json_text = f"""{{
            "verdict": "true_positive",
            "confidence": 60,
            "severity": "high",
            "summary": "Mass scanning detected",
            "indicators": {indicators!r}
        }}""".replace("'", '"')

        result = parse_triage_analysis(json_text)
        assert len(result.indicators) == 100

    def test_multiline_reasoning(self):
        """Test handling of multiline reasoning text."""
        json_text = """{
            "verdict": "true_positive",
            "confidence": 90,
            "severity": "critical",
            "summary": "Active breach detected",
            "reasoning": "Step 1: Analyzed logs\\nStep 2: Correlated events\\nStep 3: Confirmed breach"
        }"""

        result = parse_triage_analysis(json_text)
        assert "Step 1" in result.reasoning
        assert "Step 3" in result.reasoning

    def test_code_block_with_extra_whitespace(self):
        """Test code block extraction with irregular whitespace."""
        text = """
        ```json

        {
            "verdict": "false_positive",
            "confidence": 99,
            "severity": "informational",
            "summary": "Test"
        }

        ```
        """

        result = parse_triage_analysis(text)
        assert result.verdict == "false_positive"
