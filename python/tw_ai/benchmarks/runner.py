"""Benchmark runner for executing security task evaluations.

This module provides the infrastructure for running benchmark evaluations
against different LLM models.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from tw_ai.benchmarks.datasets import (
    BenchmarkDataset,
    BenchmarkExample,
    SecurityBenchmark,
    TaskType,
)
from tw_ai.benchmarks.metrics import BenchmarkMetrics, TaskMetrics
from tw_ai.benchmarks.tasks import BaseSecurityTask, TaskResult, get_task

logger = structlog.get_logger()


@dataclass
class BenchmarkConfig:
    """Configuration for benchmark execution.

    Attributes:
        max_concurrent: Maximum concurrent LLM calls
        timeout_per_example: Timeout in seconds per example
        retry_failed: Whether to retry failed examples
        max_retries: Maximum retries for failed examples
        verbose: Whether to log detailed progress
        save_results: Whether to save results to file
        output_dir: Directory for saving results
    """

    max_concurrent: int = 5
    timeout_per_example: float = 60.0
    retry_failed: bool = True
    max_retries: int = 2
    verbose: bool = True
    save_results: bool = True
    output_dir: str = "./benchmark_results"

    def __post_init__(self) -> None:
        """Validate configuration."""
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be at least 1")
        if self.timeout_per_example <= 0:
            raise ValueError("timeout_per_example must be positive")


@dataclass
class ModelResult:
    """Result from evaluating a single example.

    Attributes:
        example_id: ID of the benchmark example
        task_type: Type of security task
        scores: Dictionary of metric scores
        predicted_output: Model's predicted output
        expected_output: Ground truth expected output
        raw_output: Raw model output before parsing
        execution_time: Time taken to run the example
        error: Error message if evaluation failed
    """

    example_id: str
    task_type: str
    scores: dict[str, float]
    predicted_output: dict[str, Any]
    expected_output: dict[str, Any]
    raw_output: str = ""
    execution_time: float = 0.0
    error: str | None = None

    @property
    def passed(self) -> bool:
        """Check if the example passed based on primary score."""
        if self.error:
            return False
        return self.scores.get("primary", 0.0) >= 0.5

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "example_id": self.example_id,
            "task_type": self.task_type,
            "scores": self.scores,
            "predicted_output": self.predicted_output,
            "expected_output": self.expected_output,
            "raw_output": self.raw_output,
            "execution_time": self.execution_time,
            "error": self.error,
            "passed": self.passed,
        }


@dataclass
class BenchmarkResults:
    """Complete results from a benchmark run.

    Attributes:
        model_name: Name of the model evaluated
        metrics: Aggregate metrics across all tasks
        results: Individual results per example
        config: Configuration used for the run
        timestamp: When the benchmark was run
    """

    model_name: str
    metrics: BenchmarkMetrics
    results: list[ModelResult] = field(default_factory=list)
    config: BenchmarkConfig | None = None
    timestamp: str = ""

    def __post_init__(self) -> None:
        """Set timestamp if not provided."""
        if not self.timestamp:
            from datetime import datetime, timezone

            self.timestamp = datetime.now(timezone.utc).isoformat()

    def get_results_by_task(self, task_type: TaskType | str) -> list[ModelResult]:
        """Get results filtered by task type."""
        task_str = task_type.value if isinstance(task_type, TaskType) else task_type
        return [r for r in self.results if r.task_type == task_str]

    def get_failed_examples(self) -> list[ModelResult]:
        """Get results for examples that failed."""
        return [r for r in self.results if not r.passed]

    def get_error_examples(self) -> list[ModelResult]:
        """Get results for examples that had errors."""
        return [r for r in self.results if r.error]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "model_name": self.model_name,
            "timestamp": self.timestamp,
            "metrics": self.metrics.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }

    def save(self, path: str | Path) -> None:
        """Save results to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)

        logger.info("benchmark_results_saved", path=str(path))

    @classmethod
    def load(cls, path: str | Path) -> BenchmarkResults:
        """Load results from a JSON file."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        # Reconstruct metrics
        metrics = BenchmarkMetrics(model_name=data["model_name"])
        for task_name, task_data in data["metrics"]["tasks"].items():
            task_metrics = TaskMetrics(
                task_name=task_name,
                total_examples=task_data["total_examples"],
                primary_score=task_data["primary_score"],
                all_scores=task_data["all_scores"],
            )
            metrics.add_task_metrics(task_name, task_metrics)

        metrics.overall_score = data["metrics"]["overall_score"]
        metrics.total_examples = data["metrics"]["total_examples"]
        metrics.total_time_seconds = data["metrics"]["total_time_seconds"]

        # Reconstruct results
        results = []
        for r in data["results"]:
            results.append(
                ModelResult(
                    example_id=r["example_id"],
                    task_type=r["task_type"],
                    scores=r["scores"],
                    predicted_output=r["predicted_output"],
                    expected_output=r["expected_output"],
                    raw_output=r.get("raw_output", ""),
                    execution_time=r.get("execution_time", 0.0),
                    error=r.get("error"),
                )
            )

        return cls(
            model_name=data["model_name"],
            metrics=metrics,
            results=results,
            timestamp=data["timestamp"],
        )

    def summary(self) -> str:
        """Generate a human-readable summary."""
        return self.metrics.summary()


class BenchmarkRunner:
    """Runner for executing benchmark evaluations.

    Coordinates running benchmark examples against an LLM provider,
    collecting results, and computing metrics.

    Example:
        from tw_ai.benchmarks import BenchmarkRunner, SecurityBenchmark
        from tw_ai.llm import OpenAIProvider

        llm = OpenAIProvider(model="gpt-4")
        runner = BenchmarkRunner(llm=llm)

        benchmark = SecurityBenchmark.with_builtin_datasets()
        results = await runner.run(benchmark)

        print(results.summary())
        results.save("results.json")
    """

    def __init__(
        self,
        llm: Any,  # LLMProvider protocol
        config: BenchmarkConfig | None = None,
        model_name: str | None = None,
    ):
        """Initialize the benchmark runner.

        Args:
            llm: LLM provider implementing the complete() method
            config: Benchmark configuration (uses defaults if not provided)
            model_name: Name for the model (extracted from llm if not provided)
        """
        self.llm = llm
        self.config = config or BenchmarkConfig()
        self.model_name = model_name or getattr(llm, "model", "unknown")

        logger.info(
            "benchmark_runner_initialized",
            model=self.model_name,
            max_concurrent=self.config.max_concurrent,
        )

    async def run(
        self,
        benchmark: SecurityBenchmark,
        task_types: list[TaskType] | None = None,
    ) -> BenchmarkResults:
        """Run the complete benchmark suite.

        Args:
            benchmark: The benchmark suite to run
            task_types: Optional filter for specific task types

        Returns:
            BenchmarkResults with all metrics and individual results
        """
        start_time = time.time()

        model_name: str = self.model_name or "unknown"
        metrics = BenchmarkMetrics(model_name=model_name)
        all_results: list[ModelResult] = []

        # Filter tasks if specified
        tasks_to_run = task_types or benchmark.tasks

        logger.info(
            "benchmark_started",
            model=self.model_name,
            tasks=len(tasks_to_run),
            total_examples=sum(len(benchmark.get_dataset(t) or []) for t in tasks_to_run),
        )

        for task_type in tasks_to_run:
            dataset = benchmark.get_dataset(task_type)
            if not dataset:
                logger.warning("dataset_not_found", task_type=task_type.value)
                continue

            task_metrics, task_results = await self._run_task(task_type, dataset)
            metrics.add_task_metrics(task_type.value, task_metrics)
            all_results.extend(task_results)

        total_time = time.time() - start_time
        metrics.total_time_seconds = total_time
        metrics.calculate_overall_score()

        results = BenchmarkResults(
            model_name=model_name,
            metrics=metrics,
            results=all_results,
            config=self.config,
        )

        logger.info(
            "benchmark_completed",
            model=model_name,
            overall_score=metrics.overall_score,
            total_examples=metrics.total_examples,
            total_time=total_time,
        )

        # Save results if configured
        if self.config.save_results:
            filename = f"{model_name}_{results.timestamp}.json"
            output_path = Path(self.config.output_dir) / filename
            results.save(output_path)

        return results

    async def run_single_task(
        self,
        task_type: TaskType,
        dataset: BenchmarkDataset,
    ) -> BenchmarkResults:
        """Run benchmark for a single task type.

        Args:
            task_type: The task type to run
            dataset: Dataset of examples for this task

        Returns:
            BenchmarkResults for this task
        """
        start_time = time.time()

        task_metrics, task_results = await self._run_task(task_type, dataset)

        model_name: str = self.model_name or "unknown"
        metrics = BenchmarkMetrics(model_name=model_name)
        metrics.add_task_metrics(task_type.value, task_metrics)
        metrics.total_time_seconds = time.time() - start_time
        metrics.calculate_overall_score()

        return BenchmarkResults(
            model_name=model_name,
            metrics=metrics,
            results=task_results,
            config=self.config,
        )

    async def _run_task(
        self,
        task_type: TaskType,
        dataset: BenchmarkDataset,
    ) -> tuple[TaskMetrics, list[ModelResult]]:
        """Run a single task across its dataset.

        Returns:
            Tuple of (TaskMetrics, list of ModelResults)
        """
        task = get_task(task_type)
        task_metrics = TaskMetrics(task_name=task_type.value)
        results: list[ModelResult] = []

        logger.info(
            "task_started",
            task=task_type.value,
            examples=len(dataset),
        )

        # Run examples with concurrency limit
        semaphore = asyncio.Semaphore(self.config.max_concurrent)

        async def run_with_semaphore(example: BenchmarkExample) -> ModelResult:
            async with semaphore:
                return await self._run_example(task, example)

        tasks = [run_with_semaphore(ex) for ex in dataset]
        task_results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        for example, result in zip(dataset.examples, task_results):
            if isinstance(result, BaseException):
                # Handle exception
                model_result = ModelResult(
                    example_id=example.id,
                    task_type=task_type.value,
                    scores={},
                    predicted_output={},
                    expected_output=example.expected_output,
                    error=str(result),
                )
            else:
                model_result = result

            results.append(model_result)
            if not model_result.error:
                task_metrics.add_example(model_result.scores)

        task_metrics.finalize()

        logger.info(
            "task_completed",
            task=task_type.value,
            primary_score=task_metrics.primary_score,
            examples=task_metrics.total_examples,
        )

        return task_metrics, results

    async def _run_example(
        self,
        task: BaseSecurityTask,
        example: Any,
        retry_count: int = 0,
    ) -> ModelResult:
        """Run a single benchmark example.

        Args:
            task: The task handler
            example: The benchmark example
            retry_count: Current retry attempt

        Returns:
            ModelResult with scores and metadata
        """
        start_time = time.time()

        try:
            # Run with timeout
            task_result: TaskResult = await asyncio.wait_for(
                task.run(example, self.llm),
                timeout=self.config.timeout_per_example,
            )

            execution_time = time.time() - start_time

            should_retry = (
                task_result.error
                and self.config.retry_failed
                and retry_count < self.config.max_retries
            )
            if should_retry:
                logger.info(
                    "retrying_example",
                    example_id=example.id,
                    retry=retry_count + 1,
                    error=task_result.error,
                )
                return await self._run_example(task, example, retry_count + 1)

            return ModelResult(
                example_id=task_result.example_id,
                task_type=task_result.task_type.value,
                scores=task_result.scores,
                predicted_output=task_result.predicted,
                expected_output=task_result.expected,
                raw_output=task_result.raw_output,
                execution_time=execution_time,
                error=task_result.error,
            )

        except asyncio.TimeoutError:
            logger.warning(
                "example_timeout",
                example_id=example.id,
                timeout=self.config.timeout_per_example,
            )
            return ModelResult(
                example_id=example.id,
                task_type=task.task_type.value,
                scores={},
                predicted_output={},
                expected_output=example.expected_output,
                execution_time=time.time() - start_time,
                error=f"Timeout after {self.config.timeout_per_example}s",
            )

        except Exception as e:
            logger.error(
                "example_error",
                example_id=example.id,
                error=str(e),
                exc_info=True,
            )

            # Retry if configured
            if self.config.retry_failed and retry_count < self.config.max_retries:
                logger.info(
                    "retrying_example",
                    example_id=example.id,
                    retry=retry_count + 1,
                )
                return await self._run_example(task, example, retry_count + 1)

            return ModelResult(
                example_id=example.id,
                task_type=task.task_type.value,
                scores={},
                predicted_output={},
                expected_output=example.expected_output,
                execution_time=time.time() - start_time,
                error=str(e),
            )


def compare_results(
    results: list[BenchmarkResults],
) -> dict[str, Any]:
    """Compare benchmark results across multiple models.

    Args:
        results: List of BenchmarkResults from different models

    Returns:
        Comparison dictionary with rankings and differences
    """
    if not results:
        return {}

    comparison: dict[str, Any] = {
        "models": [],
        "overall_ranking": [],
        "task_rankings": {},
        "score_differences": {},
    }

    # Sort by overall score
    sorted_results = sorted(results, key=lambda r: r.metrics.overall_score, reverse=True)

    for rank, result in enumerate(sorted_results, 1):
        comparison["overall_ranking"].append(
            {
                "rank": rank,
                "model": result.model_name,
                "overall_score": result.metrics.overall_score,
            }
        )
        comparison["models"].append(result.model_name)

    # Per-task rankings
    all_tasks: set[str] = set()
    for result in results:
        all_tasks.update(result.metrics.task_metrics.keys())

    for task in all_tasks:
        task_scores = []
        for result in results:
            task_metric = result.metrics.task_metrics.get(task)
            if task_metric:
                task_scores.append(
                    {
                        "model": result.model_name,
                        "score": task_metric.primary_score,
                    }
                )

        task_scores.sort(key=lambda x: float(str(x.get("score", 0))), reverse=True)
        comparison["task_rankings"][task] = task_scores

    # Score differences (compared to best model)
    if len(sorted_results) > 1:
        best = sorted_results[0]
        for result in sorted_results[1:]:
            diff = best.metrics.overall_score - result.metrics.overall_score
            pct = (diff / best.metrics.overall_score * 100) if best.metrics.overall_score > 0 else 0
            comparison["score_differences"][result.model_name] = {
                "overall_diff": diff,
                "percentage": pct,
            }

    return comparison
