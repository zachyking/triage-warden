"""
Prompt templates for Triage Warden AI agents.

This module provides structured system prompts for security triage operations,
including:
- Base SOC analyst persona and capabilities
- Specialized prompts for different threat categories (phishing, malware, suspicious logins)
- Output schema definitions for consistent, structured responses

All prompts follow the ReAct pattern and produce standardized JSON output
for integration with the Triage Warden workflow engine.
"""

from tw_ai.agents.prompts.system import (
    SOC_ANALYST_PERSONA,
    AVAILABLE_TOOLS,
    OUTPUT_SCHEMA,
    CHAIN_OF_THOUGHT_GUIDANCE,
    CONFIDENCE_SCORING_CRITERIA,
    get_base_system_prompt,
    format_output_schema,
)
from tw_ai.agents.prompts.phishing import (
    PHISHING_PROMPT,
    PHISHING_INDICATORS,
    PHISHING_EXAMPLES,
    get_phishing_triage_prompt,
)
from tw_ai.agents.prompts.malware import (
    MALWARE_PROMPT,
    MALWARE_INDICATORS,
    MALWARE_EXAMPLES,
    get_malware_triage_prompt,
)
from tw_ai.agents.prompts.suspicious_login import (
    SUSPICIOUS_LOGIN_PROMPT,
    LOGIN_RISK_FACTORS,
    LOGIN_EXAMPLES,
    get_suspicious_login_triage_prompt,
)

__all__ = [
    # Base system prompt components
    "SOC_ANALYST_PERSONA",
    "AVAILABLE_TOOLS",
    "OUTPUT_SCHEMA",
    "CHAIN_OF_THOUGHT_GUIDANCE",
    "CONFIDENCE_SCORING_CRITERIA",
    "get_base_system_prompt",
    "format_output_schema",
    # Phishing
    "PHISHING_PROMPT",
    "PHISHING_INDICATORS",
    "PHISHING_EXAMPLES",
    "get_phishing_triage_prompt",
    # Malware
    "MALWARE_PROMPT",
    "MALWARE_INDICATORS",
    "MALWARE_EXAMPLES",
    "get_malware_triage_prompt",
    # Suspicious login
    "SUSPICIOUS_LOGIN_PROMPT",
    "LOGIN_RISK_FACTORS",
    "LOGIN_EXAMPLES",
    "get_suspicious_login_triage_prompt",
]
