"""Tests for the hunting hypothesis generator."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from tw_ai.hunting.hypothesis import (
    Hypothesis,
    HuntingContext,
    HypothesisGenerator,
    _get_technique_info,
)


# =============================================================================
# Model Tests
# =============================================================================


class TestHypothesisModel:
    """Tests for the Hypothesis pydantic model."""

    def test_basic_creation(self):
        h = Hypothesis(
            statement="Attackers may use Kerberoasting",
            priority="high",
            rationale="Coverage gap detected",
        )
        assert h.statement == "Attackers may use Kerberoasting"
        assert h.priority == "high"
        assert h.rationale == "Coverage gap detected"
        assert h.expected_indicators == []
        assert h.suggested_queries == []
        assert h.mitre_techniques == []
        assert h.data_sources == []

    def test_full_creation(self):
        h = Hypothesis(
            statement="Detect lateral movement via PsExec",
            priority="medium",
            expected_indicators=["PSEXESVC service", "EventCode 7045"],
            suggested_queries=[{"splunk": "index=wineventlog EventCode=7045"}],
            mitre_techniques=["T1570", "T1021.002"],
            rationale="PsExec is commonly used for lateral movement",
            data_sources=["windows_system_events"],
        )
        assert len(h.expected_indicators) == 2
        assert len(h.suggested_queries) == 1
        assert len(h.mitre_techniques) == 2
        assert len(h.data_sources) == 1

    def test_priority_validation_high(self):
        h = Hypothesis(statement="test", priority="high", rationale="test")
        assert h.priority == "high"

    def test_priority_validation_medium(self):
        h = Hypothesis(statement="test", priority="medium", rationale="test")
        assert h.priority == "medium"

    def test_priority_validation_low(self):
        h = Hypothesis(statement="test", priority="low", rationale="test")
        assert h.priority == "low"

    def test_priority_validation_invalid(self):
        with pytest.raises(Exception):
            Hypothesis(statement="test", priority="invalid", rationale="test")

    def test_serialization_roundtrip(self):
        h = Hypothesis(
            statement="Test hypothesis",
            priority="high",
            expected_indicators=["indicator1"],
            mitre_techniques=["T1558.003"],
            rationale="Test rationale",
            data_sources=["siem"],
        )
        data = h.model_dump()
        h2 = Hypothesis.model_validate(data)
        assert h == h2

    def test_json_serialization(self):
        h = Hypothesis(
            statement="Test",
            priority="low",
            rationale="Reason",
        )
        json_str = h.model_dump_json()
        h2 = Hypothesis.model_validate_json(json_str)
        assert h2.statement == "Test"


class TestHuntingContextModel:
    """Tests for the HuntingContext pydantic model."""

    def test_empty_context(self):
        ctx = HuntingContext()
        assert ctx.recent_incidents == []
        assert ctx.threat_intel_summary == ""
        assert ctx.asset_profile == {}
        assert ctx.mitre_coverage_gaps == []
        assert ctx.recent_false_positives == []

    def test_full_context(self):
        ctx = HuntingContext(
            recent_incidents=[
                {"id": "inc-1", "source": "edr", "severity": "high"},
                {"id": "inc-2", "source": "siem", "severity": "medium"},
            ],
            threat_intel_summary="New ransomware campaign targeting financial sector",
            asset_profile={"os_distribution": {"windows": 80, "linux": 20}},
            mitre_coverage_gaps=["T1558.003", "T1003.001"],
            recent_false_positives=[
                {"rule": "Suspicious PowerShell", "count": 50},
            ],
        )
        assert len(ctx.recent_incidents) == 2
        assert "ransomware" in ctx.threat_intel_summary
        assert len(ctx.mitre_coverage_gaps) == 2
        assert len(ctx.recent_false_positives) == 1


# =============================================================================
# Generator Tests (Rule-Based)
# =============================================================================


class TestHypothesisGeneratorRuleBased:
    """Tests for rule-based hypothesis generation (no LLM)."""

    @pytest.fixture
    def generator(self):
        return HypothesisGenerator(llm_provider=None)

    @pytest.mark.asyncio
    async def test_generate_empty_context(self, generator):
        ctx = HuntingContext()
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) >= 1
        # Should produce at least a default hypothesis
        assert all(isinstance(h, Hypothesis) for h in hypotheses)

    @pytest.mark.asyncio
    async def test_generate_with_coverage_gaps(self, generator):
        ctx = HuntingContext(
            mitre_coverage_gaps=["T1558.003", "T1003.001", "T1570"],
        )
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) >= 3
        # Should reference the coverage gap techniques
        all_techniques = []
        for h in hypotheses:
            all_techniques.extend(h.mitre_techniques)
        assert "T1558.003" in all_techniques
        assert "T1003.001" in all_techniques

    @pytest.mark.asyncio
    async def test_generate_with_incidents(self, generator):
        ctx = HuntingContext(
            recent_incidents=[
                {"id": "1", "source": "edr", "severity": "high"},
                {"id": "2", "source": "edr", "severity": "high"},
                {"id": "3", "source": "edr", "severity": "medium"},
            ],
        )
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) >= 1
        # Should mention recurring source
        found_incident_hyp = any("edr" in h.statement.lower() for h in hypotheses)
        assert found_incident_hyp

    @pytest.mark.asyncio
    async def test_generate_with_false_positives(self, generator):
        ctx = HuntingContext(
            recent_false_positives=[
                {"rule": "Suspicious PowerShell", "count": 50},
                {"rule": "Brute Force Detection", "count": 20},
            ],
        )
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) >= 1
        found_fp_hyp = any("false positive" in h.statement.lower() for h in hypotheses)
        assert found_fp_hyp

    @pytest.mark.asyncio
    async def test_generate_with_threat_intel(self, generator):
        ctx = HuntingContext(
            threat_intel_summary="APT29 campaign using novel C2 infrastructure",
        )
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) >= 1
        found_ti_hyp = any("threat" in h.statement.lower() or "landscape" in h.statement.lower() for h in hypotheses)
        assert found_ti_hyp

    @pytest.mark.asyncio
    async def test_generate_max_five(self, generator):
        ctx = HuntingContext(
            mitre_coverage_gaps=["T1558.003", "T1003.001", "T1570", "T1053.005",
                                  "T1048", "T1071.001", "T1059.001", "T1046"],
            recent_incidents=[
                {"id": str(i), "source": "edr"} for i in range(10)
            ],
            threat_intel_summary="Active campaign",
            recent_false_positives=[{"rule": "test", "count": 100}],
        )
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) <= 5

    @pytest.mark.asyncio
    async def test_generate_priority_ordering(self, generator):
        ctx = HuntingContext(
            mitre_coverage_gaps=["T1558.003"],
            threat_intel_summary="Active threat campaign",
            recent_false_positives=[{"rule": "test", "count": 100}],
        )
        hypotheses = await generator.generate(ctx)
        # High priority should come first
        priorities = [h.priority for h in hypotheses]
        priority_order = {"high": 0, "medium": 1, "low": 2}
        for i in range(len(priorities) - 1):
            assert priority_order.get(priorities[i], 3) <= priority_order.get(priorities[i + 1], 3)

    @pytest.mark.asyncio
    async def test_generate_hypotheses_have_required_fields(self, generator):
        ctx = HuntingContext(
            mitre_coverage_gaps=["T1558.003"],
        )
        hypotheses = await generator.generate(ctx)
        for h in hypotheses:
            assert h.statement
            assert h.priority in ("high", "medium", "low")
            assert h.rationale

    @pytest.mark.asyncio
    async def test_generate_insufficient_incidents_no_pattern(self, generator):
        """With fewer than 3 incidents from same source, no incident pattern hypothesis."""
        ctx = HuntingContext(
            recent_incidents=[
                {"id": "1", "source": "edr"},
                {"id": "2", "source": "siem"},
            ],
        )
        hypotheses = await generator.generate(ctx)
        # Should still generate hypotheses (at least the default)
        assert len(hypotheses) >= 1


# =============================================================================
# Generator Tests (LLM-Based)
# =============================================================================


class TestHypothesisGeneratorLLM:
    """Tests for LLM-based hypothesis generation."""

    @pytest.fixture
    def mock_llm(self):
        llm = MagicMock()
        llm.generate = AsyncMock()
        return llm

    @pytest.fixture
    def generator(self, mock_llm):
        return HypothesisGenerator(llm_provider=mock_llm)

    @pytest.mark.asyncio
    async def test_llm_success(self, generator, mock_llm):
        mock_llm.generate.return_value = json.dumps([
            {
                "statement": "LLM-generated hypothesis",
                "priority": "high",
                "expected_indicators": ["indicator1"],
                "suggested_queries": [{"splunk": "index=main"}],
                "mitre_techniques": ["T1059.001"],
                "rationale": "Based on threat intel analysis",
                "data_sources": ["sysmon"],
            }
        ])

        ctx = HuntingContext()
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) == 1
        assert hypotheses[0].statement == "LLM-generated hypothesis"
        mock_llm.generate.assert_called_once()

    @pytest.mark.asyncio
    async def test_llm_markdown_response(self, generator, mock_llm):
        mock_llm.generate.return_value = '```json\n[{"statement": "test", "priority": "high", "rationale": "reason"}]\n```'

        ctx = HuntingContext()
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) == 1
        assert hypotheses[0].statement == "test"

    @pytest.mark.asyncio
    async def test_llm_fallback_on_error(self, generator, mock_llm):
        mock_llm.generate.side_effect = Exception("LLM unavailable")

        ctx = HuntingContext(mitre_coverage_gaps=["T1558.003"])
        hypotheses = await generator.generate(ctx)
        # Should fallback to rule-based
        assert len(hypotheses) >= 1

    @pytest.mark.asyncio
    async def test_llm_fallback_on_invalid_json(self, generator, mock_llm):
        mock_llm.generate.return_value = "This is not JSON at all"

        ctx = HuntingContext(mitre_coverage_gaps=["T1558.003"])
        hypotheses = await generator.generate(ctx)
        # Should fallback to rule-based
        assert len(hypotheses) >= 1

    @pytest.mark.asyncio
    async def test_llm_fallback_on_empty_response(self, generator, mock_llm):
        mock_llm.generate.return_value = "[]"

        ctx = HuntingContext(mitre_coverage_gaps=["T1558.003"])
        hypotheses = await generator.generate(ctx)
        # Empty LLM response triggers fallback
        assert len(hypotheses) >= 1

    @pytest.mark.asyncio
    async def test_llm_multiple_hypotheses(self, generator, mock_llm):
        mock_llm.generate.return_value = json.dumps([
            {"statement": "Hypothesis 1", "priority": "high", "rationale": "r1"},
            {"statement": "Hypothesis 2", "priority": "medium", "rationale": "r2"},
            {"statement": "Hypothesis 3", "priority": "low", "rationale": "r3"},
        ])

        ctx = HuntingContext()
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) == 3

    @pytest.mark.asyncio
    async def test_llm_partial_valid_response(self, generator, mock_llm):
        """Test that valid hypotheses are kept even when some are invalid."""
        mock_llm.generate.return_value = json.dumps([
            {"statement": "Valid one", "priority": "high", "rationale": "good"},
            {"statement": "Invalid", "priority": "bogus"},  # Invalid priority
            {"statement": "Valid two", "priority": "low", "rationale": "also good"},
        ])

        ctx = HuntingContext()
        hypotheses = await generator.generate(ctx)
        assert len(hypotheses) == 2
        assert hypotheses[0].statement == "Valid one"
        assert hypotheses[1].statement == "Valid two"


# =============================================================================
# Prompt Building Tests
# =============================================================================


class TestPromptBuilding:
    """Tests for the prompt construction logic."""

    @pytest.fixture
    def generator(self):
        return HypothesisGenerator(llm_provider=None)

    def test_prompt_empty_context(self, generator):
        ctx = HuntingContext()
        prompt = generator._build_prompt(ctx)
        assert "threat hunter" in prompt.lower()
        assert "JSON array" in prompt

    def test_prompt_includes_incidents(self, generator):
        ctx = HuntingContext(
            recent_incidents=[{"id": "inc-1", "source": "edr"}],
        )
        prompt = generator._build_prompt(ctx)
        assert "Recent Incidents" in prompt
        assert "inc-1" in prompt

    def test_prompt_includes_threat_intel(self, generator):
        ctx = HuntingContext(
            threat_intel_summary="APT29 campaign active",
        )
        prompt = generator._build_prompt(ctx)
        assert "Threat Intelligence" in prompt
        assert "APT29" in prompt

    def test_prompt_includes_asset_profile(self, generator):
        ctx = HuntingContext(
            asset_profile={"critical_servers": ["DC01", "DB01"]},
        )
        prompt = generator._build_prompt(ctx)
        assert "Asset Profile" in prompt
        assert "DC01" in prompt

    def test_prompt_includes_coverage_gaps(self, generator):
        ctx = HuntingContext(
            mitre_coverage_gaps=["T1558.003", "T1003.001"],
        )
        prompt = generator._build_prompt(ctx)
        assert "Coverage Gaps" in prompt
        assert "T1558.003" in prompt

    def test_prompt_includes_false_positives(self, generator):
        ctx = HuntingContext(
            recent_false_positives=[{"rule": "Brute Force", "count": 50}],
        )
        prompt = generator._build_prompt(ctx)
        assert "False Positives" in prompt
        assert "Brute Force" in prompt

    def test_prompt_limits_incidents(self, generator):
        """Should only include first 10 incidents."""
        ctx = HuntingContext(
            recent_incidents=[{"id": str(i)} for i in range(20)],
        )
        prompt = generator._build_prompt(ctx)
        assert '"id": "0"' in prompt
        assert '"id": "9"' in prompt
        # The 11th should not be present
        assert '"id": "10"' not in prompt

    def test_prompt_limits_coverage_gaps(self, generator):
        """Should only include first 20 coverage gaps."""
        ctx = HuntingContext(
            mitre_coverage_gaps=[f"T{1000 + i}" for i in range(30)],
        )
        prompt = generator._build_prompt(ctx)
        assert "T1000" in prompt
        assert "T1019" in prompt


# =============================================================================
# Response Parsing Tests
# =============================================================================


class TestResponseParsing:
    """Tests for the LLM response parsing logic."""

    @pytest.fixture
    def generator(self):
        return HypothesisGenerator(llm_provider=None)

    def test_parse_valid_json_array(self, generator):
        response = json.dumps([
            {"statement": "Test", "priority": "high", "rationale": "reason"},
        ])
        result = generator._parse_hypotheses(response)
        assert len(result) == 1
        assert result[0].statement == "Test"

    def test_parse_markdown_code_block(self, generator):
        response = '```json\n[{"statement": "In block", "priority": "low", "rationale": "r"}]\n```'
        result = generator._parse_hypotheses(response)
        assert len(result) == 1
        assert result[0].statement == "In block"

    def test_parse_generic_code_block(self, generator):
        response = '```\n[{"statement": "Generic", "priority": "medium", "rationale": "r"}]\n```'
        result = generator._parse_hypotheses(response)
        assert len(result) == 1

    def test_parse_invalid_json(self, generator):
        result = generator._parse_hypotheses("This is not JSON")
        assert result == []

    def test_parse_non_array(self, generator):
        result = generator._parse_hypotheses('{"statement": "Not an array"}')
        assert result == []

    def test_parse_empty_array(self, generator):
        result = generator._parse_hypotheses("[]")
        assert result == []

    def test_parse_partial_valid(self, generator):
        response = json.dumps([
            {"statement": "Good", "priority": "high", "rationale": "r"},
            {"bad_key": "invalid"},
            {"statement": "Also good", "priority": "low", "rationale": "r"},
        ])
        result = generator._parse_hypotheses(response)
        assert len(result) == 2


# =============================================================================
# Technique Info Tests
# =============================================================================


class TestTechniqueInfo:
    """Tests for the built-in technique information mapping."""

    def test_technique_info_not_empty(self):
        info = _get_technique_info()
        assert len(info) > 0

    def test_technique_info_has_required_fields(self):
        info = _get_technique_info()
        for tech_id, data in info.items():
            assert tech_id.startswith("T"), f"Invalid technique ID: {tech_id}"
            assert "name" in data, f"Missing 'name' for {tech_id}"
            assert "tactic" in data, f"Missing 'tactic' for {tech_id}"

    def test_kerberoasting_info(self):
        info = _get_technique_info()
        assert "T1558.003" in info
        kerb = info["T1558.003"]
        assert kerb["name"] == "Kerberoasting"
        assert kerb["tactic"] == "Credential Access"
        assert len(kerb.get("queries", [])) > 0

    def test_all_techniques_have_data_sources(self):
        info = _get_technique_info()
        for tech_id, data in info.items():
            assert "data_sources" in data, f"Missing data_sources for {tech_id}"
            assert len(data["data_sources"]) > 0, f"Empty data_sources for {tech_id}"
