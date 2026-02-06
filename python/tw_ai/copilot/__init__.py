"""Investigation copilot module for analyst assistance (Stage 4.1.4).

Provides an AI-powered investigation assistant that helps analysts
investigate incidents by answering questions, suggesting actions,
and providing context from similar past incidents.
"""

from tw_ai.copilot.assistant import (
    COPILOT_SYSTEM_PROMPT,
    CopilotResponse,
    InvestigationCopilot,
)

__all__ = [
    "InvestigationCopilot",
    "CopilotResponse",
    "COPILOT_SYSTEM_PROMPT",
]
