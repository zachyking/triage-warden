"""Security Task Benchmark Suite for Triage Warden.

This module provides a comprehensive benchmark suite for evaluating
AI model performance on security-specific tasks including:

- Incident Summarization
- Severity Rating
- Verdict Classification
- MITRE ATT&CK Mapping
- IoC SQL Query Generation
- Action Recommendation

Example Usage:
    from tw_ai.benchmarks import SecurityBenchmark, BenchmarkRunner

    benchmark = SecurityBenchmark()
    runner = BenchmarkRunner(model="gpt-4")
    results = await runner.run(benchmark)
    print(results.summary())
"""

from tw_ai.benchmarks.datasets import (
    BenchmarkDataset,
    BenchmarkExample,
    SecurityBenchmark,
    TaskType,
)
from tw_ai.benchmarks.metrics import (
    BenchmarkMetrics,
    TaskMetrics,
    calculate_bleu_score,
    calculate_exact_match,
    calculate_f1_score,
    calculate_rouge_scores,
)
from tw_ai.benchmarks.runner import (
    BenchmarkConfig,
    BenchmarkResults,
    BenchmarkRunner,
    ModelResult,
)
from tw_ai.benchmarks.tasks import (
    ActionRecommendationTask,
    BaseSecurityTask,
    IncidentSummarizationTask,
    IoCQueryGenerationTask,
    MitreMappingTask,
    SeverityRatingTask,
    VerdictClassificationTask,
)

__all__ = [
    # Datasets
    "BenchmarkDataset",
    "BenchmarkExample",
    "SecurityBenchmark",
    "TaskType",
    # Tasks
    "BaseSecurityTask",
    "IncidentSummarizationTask",
    "SeverityRatingTask",
    "VerdictClassificationTask",
    "MitreMappingTask",
    "IoCQueryGenerationTask",
    "ActionRecommendationTask",
    # Metrics
    "BenchmarkMetrics",
    "TaskMetrics",
    "calculate_exact_match",
    "calculate_f1_score",
    "calculate_bleu_score",
    "calculate_rouge_scores",
    # Runner
    "BenchmarkConfig",
    "BenchmarkResults",
    "BenchmarkRunner",
    "ModelResult",
]
