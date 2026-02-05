"""
Prompt templates for Triage Warden AI agents.

This module provides structured system prompts for security triage operations,
including:
- Base SOC analyst persona and capabilities
- Specialized prompts for different threat categories (phishing, malware, suspicious logins)
- Output schema definitions for consistent, structured responses
- Evidence collection prompts for audit-ready investigation reports (Stage 2.1.2)

All prompts follow the ReAct pattern and produce standardized JSON output
for integration with the Triage Warden workflow engine.
"""

from tw_ai.agents.prompts.evidence import (
    EVIDENCE_COLLECTION_EXAMPLES,
    EVIDENCE_COLLECTION_PROMPT,
    EVIDENCE_OUTPUT_SCHEMA,
    build_evidence_context,
    format_evidence_output_schema,
    get_evidence_enhanced_prompt,
)
from tw_ai.agents.prompts.malware import (
    MALWARE_EXAMPLES,
    MALWARE_INDICATORS,
    MALWARE_PROMPT,
    get_malware_triage_prompt,
)
from tw_ai.agents.prompts.phishing import (
    PHISHING_EXAMPLES,
    PHISHING_INDICATORS,
    PHISHING_PROMPT,
    get_phishing_triage_prompt,
)
from tw_ai.agents.prompts.suspicious_login import (
    LOGIN_EXAMPLES,
    LOGIN_RISK_FACTORS,
    SUSPICIOUS_LOGIN_PROMPT,
    get_suspicious_login_triage_prompt,
)
from tw_ai.agents.prompts.system import (
    AVAILABLE_TOOLS,
    CHAIN_OF_THOUGHT_GUIDANCE,
    CONFIDENCE_SCORING_CRITERIA,
    EVIDENCE_SCHEMA,
    OUTPUT_SCHEMA,
    SOC_ANALYST_PERSONA,
    format_output_schema,
    get_base_system_prompt,
    get_evidence_enhanced_schema,
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
    # Evidence collection (Stage 2.1.2)
    "EVIDENCE_COLLECTION_PROMPT",
    "EVIDENCE_COLLECTION_EXAMPLES",
    "EVIDENCE_OUTPUT_SCHEMA",
    "EVIDENCE_SCHEMA",
    "get_evidence_enhanced_prompt",
    "get_evidence_enhanced_schema",
    "format_evidence_output_schema",
    "build_evidence_context",
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
