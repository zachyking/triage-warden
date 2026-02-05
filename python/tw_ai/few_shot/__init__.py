"""Few-shot learning module for dynamic example selection (Stage 2.4.2).

This module provides vector-similarity-based selection of few-shot examples
for security triage prompts. Instead of using static hardcoded examples,
the FewShotSelector dynamically retrieves the most relevant examples
based on the current incident being analyzed.

Public API:
    - FewShotSelector: Main class for dynamic example selection
    - Example: Model for a single few-shot example
    - ExampleDocument: RAG document model for examples
    - ExampleQuality: Quality tier enum for examples
    - FewShotConfig: Configuration for few-shot selection
    - create_few_shot_selector(): Factory function
    - ExampleIngester: Ingest examples into vector store
    - ExampleCurator: Curate and manage example quality
    - ABTestManager: A/B testing for few-shot vs zero-shot
"""

from tw_ai.few_shot.ab_testing import (
    ABTestManager,
    AssignmentStrategy,
    ExperimentConfig,
    ExperimentMetrics,
    ExperimentVariant,
    TrialResult,
    create_default_experiment,
    create_zero_shot_experiment,
)
from tw_ai.few_shot.config import FewShotConfig
from tw_ai.few_shot.ingestion import ExampleCurator, ExampleIngester
from tw_ai.few_shot.models import (
    Example,
    ExampleDocument,
    ExampleMetadata,
    ExampleQuality,
    ExampleSet,
    FormattedExamples,
)
from tw_ai.few_shot.prompt_builder import (
    DynamicPromptBuilder,
    build_prompt_with_dynamic_examples,
)
from tw_ai.few_shot.selector import FewShotSelector, create_few_shot_selector

__all__ = [
    # Core selector
    "FewShotSelector",
    "create_few_shot_selector",
    # Prompt building
    "DynamicPromptBuilder",
    "build_prompt_with_dynamic_examples",
    # Models
    "Example",
    "ExampleDocument",
    "ExampleMetadata",
    "ExampleQuality",
    "ExampleSet",
    "FormattedExamples",
    # Configuration
    "FewShotConfig",
    # Ingestion
    "ExampleIngester",
    "ExampleCurator",
    # A/B Testing
    "ABTestManager",
    "AssignmentStrategy",
    "ExperimentConfig",
    "ExperimentMetrics",
    "ExperimentVariant",
    "TrialResult",
    "create_default_experiment",
    "create_zero_shot_experiment",
]
