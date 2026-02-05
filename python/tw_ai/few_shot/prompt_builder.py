"""Prompt builder with dynamic few-shot example integration (Stage 2.4.2).

Provides utilities for building prompts with dynamically selected
few-shot examples, integrating with the existing prompt infrastructure.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from tw_ai.few_shot.ab_testing import ABTestManager, ExperimentVariant
from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.models import FormattedExamples

if TYPE_CHECKING:

    from tw_ai.few_shot.selector import FewShotSelector

logger = structlog.get_logger()


class DynamicPromptBuilder:
    """Builds prompts with dynamically selected few-shot examples.

    Integrates the FewShotSelector with the prompt templates to replace
    static examples with similarity-selected ones.
    """

    def __init__(
        self,
        selector: FewShotSelector,
        ab_manager: ABTestManager | None = None,
        config: FewShotConfig | None = None,
    ) -> None:
        """Initialize the prompt builder.

        Args:
            selector: Few-shot selector for example retrieval.
            ab_manager: A/B test manager for experiments.
            config: Few-shot configuration.
        """
        self._selector = selector
        self._ab_manager = ab_manager
        self._config = config or FewShotConfig()

    async def build_phishing_prompt(
        self,
        alert_context: str,
        incident_id: str | None = None,
        organization_context: str | None = None,
        experiment_name: str | None = None,
    ) -> tuple[str, FormattedExamples | None, ExperimentVariant]:
        """Build a phishing triage prompt with dynamic examples.

        Args:
            alert_context: The alert data to analyze.
            incident_id: Optional incident ID for A/B test tracking.
            organization_context: Optional organization-specific context.
            experiment_name: Optional A/B experiment to use.

        Returns:
            Tuple of (complete prompt, formatted examples if used, variant used).
        """
        return await self._build_specialized_prompt(
            alert_type="phishing",
            alert_context=alert_context,
            incident_id=incident_id,
            organization_context=organization_context,
            experiment_name=experiment_name,
        )

    async def build_malware_prompt(
        self,
        alert_context: str,
        incident_id: str | None = None,
        organization_context: str | None = None,
        experiment_name: str | None = None,
    ) -> tuple[str, FormattedExamples | None, ExperimentVariant]:
        """Build a malware triage prompt with dynamic examples.

        Args:
            alert_context: The alert data to analyze.
            incident_id: Optional incident ID for A/B test tracking.
            organization_context: Optional organization-specific context.
            experiment_name: Optional A/B experiment to use.

        Returns:
            Tuple of (complete prompt, formatted examples if used, variant used).
        """
        return await self._build_specialized_prompt(
            alert_type="malware",
            alert_context=alert_context,
            incident_id=incident_id,
            organization_context=organization_context,
            experiment_name=experiment_name,
        )

    async def build_suspicious_login_prompt(
        self,
        alert_context: str,
        incident_id: str | None = None,
        organization_context: str | None = None,
        experiment_name: str | None = None,
    ) -> tuple[str, FormattedExamples | None, ExperimentVariant]:
        """Build a suspicious login triage prompt with dynamic examples.

        Args:
            alert_context: The alert data to analyze.
            incident_id: Optional incident ID for A/B test tracking.
            organization_context: Optional organization-specific context.
            experiment_name: Optional A/B experiment to use.

        Returns:
            Tuple of (complete prompt, formatted examples if used, variant used).
        """
        return await self._build_specialized_prompt(
            alert_type="suspicious_login",
            alert_context=alert_context,
            incident_id=incident_id,
            organization_context=organization_context,
            experiment_name=experiment_name,
        )

    async def _build_specialized_prompt(
        self,
        alert_type: str,
        alert_context: str,
        incident_id: str | None,
        organization_context: str | None,
        experiment_name: str | None,
    ) -> tuple[str, FormattedExamples | None, ExperimentVariant]:
        """Build a specialized prompt with appropriate examples.

        Args:
            alert_type: Type of alert (phishing, malware, suspicious_login).
            alert_context: The alert data to analyze.
            incident_id: Optional incident ID for A/B testing.
            organization_context: Optional organization context.
            experiment_name: Optional A/B experiment name.

        Returns:
            Tuple of (prompt, formatted_examples, variant).
        """
        # Determine which variant to use
        variant = self._determine_variant(
            alert_type=alert_type,
            alert_context=alert_context,
            incident_id=incident_id,
            experiment_name=experiment_name,
        )

        # Get the base prompt (without examples section)
        base_prompt = self._get_base_prompt(alert_type)

        formatted_examples: FormattedExamples | None = None

        if variant == ExperimentVariant.ZERO_SHOT:
            # No examples - just use base prompt
            examples_section = ""

        elif variant == ExperimentVariant.STATIC:
            # Use static examples from existing prompt files
            examples_section = self._get_static_examples(alert_type)

        elif variant in (ExperimentVariant.DYNAMIC, ExperimentVariant.HYBRID):
            # Use dynamically selected examples
            example_set = await self._selector.select_examples(
                incident_text=alert_context,
                alert_type=alert_type,
                k=self._config.default_k,
            )

            formatted_examples = self._selector.format_for_prompt(example_set)
            examples_section = formatted_examples.formatted_text

            logger.info(
                "dynamic_examples_selected",
                alert_type=alert_type,
                example_count=formatted_examples.example_count,
                example_ids=formatted_examples.example_ids,
                variant=variant.value,
            )

        else:
            examples_section = ""

        # Assemble the complete prompt
        prompt_parts = [base_prompt]

        if examples_section:
            prompt_parts.append(examples_section)

        if organization_context:
            prompt_parts.append(f"""## Organization Context

{organization_context}""")

        prompt_parts.append(f"""## Alert to Analyze

{alert_context}

Analyze this alert following the methodology above. Gather additional evidence using the available \
tools as needed, then provide your structured assessment.""")

        complete_prompt = "\n\n".join(prompt_parts)

        return complete_prompt, formatted_examples, variant

    def _determine_variant(
        self,
        alert_type: str,
        alert_context: str,
        incident_id: str | None,
        experiment_name: str | None,
    ) -> ExperimentVariant:
        """Determine which variant to use for this request.

        Args:
            alert_type: Type of alert.
            alert_context: Alert context for hashing.
            incident_id: Optional incident ID.
            experiment_name: Optional experiment name.

        Returns:
            The variant to use.
        """
        if not self._ab_manager:
            # No A/B testing - use dynamic by default
            return ExperimentVariant.DYNAMIC

        # Check for active experiment
        if experiment_name:
            experiment = self._ab_manager._experiments.get(experiment_name)
        else:
            experiment = self._ab_manager.get_active_experiment(alert_type)

        if not experiment:
            return ExperimentVariant.DYNAMIC

        # Assign variant
        return self._ab_manager.assign_variant(
            experiment_name=experiment.name,
            incident_id=incident_id or "unknown",
            incident_text=alert_context,
        )

    def _get_base_prompt(self, alert_type: str) -> str:
        """Get the base prompt for an alert type (without examples).

        Args:
            alert_type: Type of alert.

        Returns:
            Base prompt text.
        """
        # Import the prompt modules
        from tw_ai.agents.prompts.malware import (
            MALWARE_INDICATORS,
        )
        from tw_ai.agents.prompts.phishing import (
            PHISHING_INDICATORS,
        )
        from tw_ai.agents.prompts.suspicious_login import (
            LOGIN_RISK_FACTORS,
        )
        from tw_ai.agents.prompts.system import (
            AVAILABLE_TOOLS,
            CHAIN_OF_THOUGHT_GUIDANCE,
            CONFIDENCE_SCORING_CRITERIA,
            SOC_ANALYST_PERSONA,
            format_output_schema,
        )

        if alert_type == "phishing":
            specialization = """## Specialization: Phishing Triage

You are specialized in analyzing phishing-related security alerts.
Phishing attacks (MITRE ATT&CK T1566.*) remain one of the most common initial access vectors,
and your role is to quickly and accurately determine whether reported emails or URLs
represent genuine threats.

### Relevant MITRE ATT&CK Techniques
- **T1566.001 - Spearphishing Attachment**: Malicious files sent via email
- **T1566.002 - Spearphishing Link**: Links to credential harvesting or malware
- **T1566.003 - Spearphishing via Service**: Phishing through social media, messaging
- **T1598.003 - Spearphishing for Information**: Reconnaissance via targeted emails"""

            indicators = PHISHING_INDICATORS

            confidence_modifiers = """### Phishing-Specific Confidence Modifiers
- **+15**: Known phishing domain/IP in threat intel
- **+10**: Email authentication failures (SPF/DKIM/DMARC)
- **+10**: Typosquatting or lookalike domain
- **-15**: All email authentication passes + known sender
- **-10**: Recipient confirms expected communication
- **+20**: Malicious attachment confirmed by sandbox"""

        elif alert_type == "malware":
            specialization = """## Specialization: Malware/EDR Triage

You are specialized in analyzing endpoint detection and response (EDR) alerts, \
malware detections, and suspicious process activity. Your role is to quickly determine \
whether detected activity represents genuine malware, living-off-the-land attacks, \
or legitimate software being flagged incorrectly."""

            indicators = MALWARE_INDICATORS

            confidence_modifiers = """### Malware-Specific Confidence Modifiers
- **+20**: Known malware hash in threat intel
- **+15**: C2 communication detected
- **+10**: Defense evasion techniques observed
- **-15**: Signed by trusted vendor + expected behavior
- **-10**: Known false positive pattern
- **+15**: Persistence mechanism detected"""

        elif alert_type == "suspicious_login":
            specialization = """## Specialization: Suspicious Login Triage

You are specialized in analyzing authentication anomalies, including suspicious logins, \
impossible travel alerts, credential stuffing attempts, and account compromise indicators. \
Your role is to determine whether authentication events indicate genuine account compromise \
or legitimate user activity."""

            indicators = LOGIN_RISK_FACTORS

            confidence_modifiers = """### Login-Specific Confidence Modifiers
- **+20**: Confirmed credential compromise in breach database
- **+15**: Impossible travel (multiple locations simultaneously)
- **+10**: Login from known malicious IP/TOR exit
- **-15**: User confirms travel or device change
- **-10**: VPN usage pattern matches user history
- **+15**: Password spray pattern detected"""

        else:
            # Generic
            specialization = f"## Specialization: {alert_type.title()} Triage"
            indicators = ""
            confidence_modifiers = ""

        # Assemble base prompt
        base_prompt = f"""{SOC_ANALYST_PERSONA}

{specialization}

{indicators}

{AVAILABLE_TOOLS}

{CHAIN_OF_THOUGHT_GUIDANCE}

{CONFIDENCE_SCORING_CRITERIA}

{confidence_modifiers}

## Required Output Format

You MUST respond with a JSON object matching this schema:

```json
{format_output_schema()}
```

Important:
- Always include ALL fields in your response
- Confidence must be an integer between 0 and 100
- Include at least one recommended action
- Your reasoning should explain your thought process step by step"""

        return base_prompt

    def _get_static_examples(self, alert_type: str) -> str:
        """Get static examples for an alert type.

        Args:
            alert_type: Type of alert.

        Returns:
            Static examples section.
        """
        if alert_type == "phishing":
            from tw_ai.agents.prompts.phishing import PHISHING_EXAMPLES

            return PHISHING_EXAMPLES
        elif alert_type == "malware":
            from tw_ai.agents.prompts.malware import MALWARE_EXAMPLES

            return MALWARE_EXAMPLES
        elif alert_type == "suspicious_login":
            from tw_ai.agents.prompts.suspicious_login import LOGIN_EXAMPLES

            return LOGIN_EXAMPLES
        else:
            return ""


async def build_prompt_with_dynamic_examples(
    selector: FewShotSelector,
    alert_type: str,
    alert_context: str,
    organization_context: str | None = None,
    k: int = 3,
) -> tuple[str, FormattedExamples | None]:
    """Convenience function to build a prompt with dynamic examples.

    Args:
        selector: Few-shot selector.
        alert_type: Type of alert.
        alert_context: Alert data.
        organization_context: Optional organization context.
        k: Number of examples to select.

    Returns:
        Tuple of (complete prompt, formatted examples).
    """
    builder = DynamicPromptBuilder(selector)

    if alert_type == "phishing":
        prompt, examples, _ = await builder.build_phishing_prompt(
            alert_context=alert_context,
            organization_context=organization_context,
        )
    elif alert_type == "malware":
        prompt, examples, _ = await builder.build_malware_prompt(
            alert_context=alert_context,
            organization_context=organization_context,
        )
    elif alert_type == "suspicious_login":
        prompt, examples, _ = await builder.build_suspicious_login_prompt(
            alert_context=alert_context,
            organization_context=organization_context,
        )
    else:
        # Generic prompt building
        example_set = await selector.select_examples(
            incident_text=alert_context,
            alert_type=alert_type,
            k=k,
        )
        examples = selector.format_for_prompt(example_set)
        prompt = f"Alert Context:\n{alert_context}\n\n{examples.formatted_text}"

    return prompt, examples
