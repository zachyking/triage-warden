#!/usr/bin/env python3
"""Command-line interface for running security benchmarks.

Usage:
    python -m tw_ai.benchmarks.cli run --model gpt-4 --tasks all
    python -m tw_ai.benchmarks.cli run --model claude-3-opus --tasks verdict_classification
    python -m tw_ai.benchmarks.cli compare results1.json results2.json
    python -m tw_ai.benchmarks.cli list-tasks
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Any

from tw_ai.benchmarks.datasets import SecurityBenchmark, TaskType
from tw_ai.benchmarks.runner import (
    BenchmarkConfig,
    BenchmarkResults,
    BenchmarkRunner,
    compare_results,
)


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        description="Security Task Benchmark Suite for Triage Warden",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Run benchmark command
    run_parser = subparsers.add_parser("run", help="Run benchmark evaluation")
    run_parser.add_argument(
        "--model",
        type=str,
        required=True,
        help="Model to evaluate (e.g., gpt-4, claude-3-opus, gpt-3.5-turbo)",
    )
    run_parser.add_argument(
        "--tasks",
        type=str,
        nargs="+",
        default=["all"],
        help="Tasks to run (all, or specific task names)",
    )
    run_parser.add_argument(
        "--datasets-dir",
        type=str,
        default=None,
        help="Directory containing dataset YAML files (uses built-in if not specified)",
    )
    run_parser.add_argument(
        "--output",
        type=str,
        default="./benchmark_results",
        help="Output directory for results",
    )
    run_parser.add_argument(
        "--max-concurrent",
        type=int,
        default=5,
        help="Maximum concurrent LLM calls",
    )
    run_parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Timeout per example in seconds",
    )
    run_parser.add_argument(
        "--no-save",
        action="store_true",
        help="Don't save results to file",
    )
    run_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output",
    )
    run_parser.add_argument(
        "--provider",
        type=str,
        choices=["openai", "anthropic", "local", "mock"],
        default="openai",
        help="LLM provider to use",
    )

    # Compare results command
    compare_parser = subparsers.add_parser("compare", help="Compare benchmark results")
    compare_parser.add_argument(
        "results",
        type=str,
        nargs="+",
        help="Result JSON files to compare",
    )
    compare_parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file for comparison (prints to stdout if not specified)",
    )

    # List tasks command
    subparsers.add_parser("list-tasks", help="List available benchmark tasks")

    # Show datasets command
    show_parser = subparsers.add_parser("show-datasets", help="Show dataset statistics")
    show_parser.add_argument(
        "--datasets-dir",
        type=str,
        default=None,
        help="Directory containing dataset YAML files",
    )

    return parser


async def run_benchmark(args: argparse.Namespace) -> int:
    """Run benchmark evaluation."""
    # Create LLM provider
    llm = await create_llm_provider(args.provider, args.model)

    # Create benchmark config
    config = BenchmarkConfig(
        max_concurrent=args.max_concurrent,
        timeout_per_example=args.timeout,
        save_results=not args.no_save,
        output_dir=args.output,
        verbose=args.verbose,
    )

    # Load benchmark
    if args.datasets_dir:
        benchmark = SecurityBenchmark()
        benchmark.load_datasets(args.datasets_dir)
    else:
        benchmark = SecurityBenchmark.with_builtin_datasets()

    # Determine tasks to run
    if "all" in args.tasks:
        task_types = None
    else:
        task_types = []
        for task_name in args.tasks:
            try:
                task_types.append(TaskType(task_name))
            except ValueError:
                print(f"Unknown task type: {task_name}", file=sys.stderr)
                print(f"Available tasks: {[t.value for t in TaskType]}", file=sys.stderr)
                return 1

    # Create runner and run
    runner = BenchmarkRunner(llm=llm, config=config, model_name=args.model)
    results = await runner.run(benchmark, task_types=task_types)

    # Print summary
    print(results.summary())

    if not args.no_save:
        print(f"\nResults saved to: {args.output}/")

    return 0


async def create_llm_provider(provider: str, model: str) -> Any:
    """Create an LLM provider instance.

    Args:
        provider: Provider name (openai, anthropic, local, mock)
        model: Model name

    Returns:
        LLM provider instance
    """
    if provider == "mock":
        return MockLLMProvider(model)

    if provider == "openai":
        try:
            from tw_ai.llm.openai_provider import OpenAIProvider

            return OpenAIProvider(model=model)
        except ImportError:
            msg = "OpenAI provider not available. Install with: pip install openai"
            print(msg, file=sys.stderr)
            sys.exit(1)

    if provider == "anthropic":
        try:
            from tw_ai.llm.anthropic_provider import AnthropicProvider

            return AnthropicProvider(model=model)
        except ImportError:
            msg = "Anthropic provider not available. Install with: pip install anthropic"
            print(msg, file=sys.stderr)
            sys.exit(1)

    if provider == "local":
        try:
            from tw_ai.llm.local_provider import LocalProvider

            return LocalProvider(model=model)
        except ImportError:
            print("Local provider not available.", file=sys.stderr)
            sys.exit(1)

    print(f"Unknown provider: {provider}", file=sys.stderr)
    sys.exit(1)


class MockLLMProvider:
    """Mock LLM provider for testing benchmarks without actual LLM calls."""

    def __init__(self, model: str):
        self.model = model

    async def complete(self, prompt: str) -> str:
        """Return a mock response based on prompt content."""
        import json
        import random

        # Detect task type from prompt and return appropriate mock response
        prompt_lower = prompt.lower()

        if "classify" in prompt_lower and "verdict" in prompt_lower:
            verdicts = ["true_positive", "false_positive", "suspicious"]
            return json.dumps(
                {
                    "verdict": random.choice(verdicts),
                    "confidence": random.randint(60, 95),
                    "reasoning": "Mock analysis result",
                }
            )

        if "severity" in prompt_lower:
            severities = ["critical", "high", "medium", "low", "informational"]
            return json.dumps(
                {
                    "severity": random.choice(severities),
                    "justification": "Mock severity assessment",
                }
            )

        if "mitre" in prompt_lower:
            techniques = [
                {"id": "T1566.001", "name": "Spearphishing Attachment", "tactic": "Initial Access"},
                {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
            ]
            return json.dumps(
                {
                    "techniques": random.sample(techniques, random.randint(1, 2)),
                }
            )

        if "summarize" in prompt_lower or "summary" in prompt_lower:
            return json.dumps(
                {
                    "summary": "Mock incident summary describing the security event.",
                    "key_findings": ["Finding 1", "Finding 2"],
                }
            )

        if "action" in prompt_lower or "recommend" in prompt_lower:
            return json.dumps(
                {
                    "actions": [
                        {"action": "Isolate affected system", "priority": "immediate"},
                        {"action": "Reset user credentials", "priority": "high"},
                    ],
                }
            )

        if "query" in prompt_lower or "ioc" in prompt_lower:
            return json.dumps(
                {
                    "query": 'index=* src_ip="1.2.3.4" earliest=-7d',
                    "description": "Search for network traffic",
                }
            )

        return json.dumps({"result": "mock response"})


def compare_command(args: argparse.Namespace) -> int:
    """Compare benchmark results."""
    results = []

    for path in args.results:
        try:
            result = BenchmarkResults.load(path)
            results.append(result)
        except FileNotFoundError:
            print(f"File not found: {path}", file=sys.stderr)
            return 1
        except json.JSONDecodeError as e:
            print(f"Invalid JSON in {path}: {e}", file=sys.stderr)
            return 1

    comparison = compare_results(results)

    # Format output
    output = format_comparison(comparison)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Comparison saved to: {args.output}")
    else:
        print(output)

    return 0


def format_comparison(comparison: dict[str, Any]) -> str:
    """Format comparison results as readable text."""
    lines = [
        "=" * 60,
        "BENCHMARK COMPARISON",
        "=" * 60,
        "",
        "Overall Ranking:",
        "-" * 40,
    ]

    for entry in comparison.get("overall_ranking", []):
        lines.append(f"  #{entry['rank']}: {entry['model']} - {entry['overall_score']:.2%}")

    lines.extend(["", "Per-Task Rankings:", "-" * 40])

    for task, rankings in sorted(comparison.get("task_rankings", {}).items()):
        lines.append(f"\n  {task}:")
        for i, entry in enumerate(rankings, 1):
            lines.append(f"    #{i}: {entry['model']} - {entry['score']:.2%}")

    if comparison.get("score_differences"):
        lines.extend(["", "Score Differences (vs best):", "-" * 40])
        for model, diff in comparison["score_differences"].items():
            lines.append(
                f"  {model}: -{diff['overall_diff']:.2%} ({diff['percentage']:.1f}% lower)"
            )

    lines.append("=" * 60)
    return "\n".join(lines)


def list_tasks_command(args: argparse.Namespace) -> int:
    """List available benchmark tasks."""
    print("Available Benchmark Tasks:")
    print("-" * 40)

    for task_type in TaskType:
        print(f"  - {task_type.value}")

    return 0


def show_datasets_command(args: argparse.Namespace) -> int:
    """Show dataset statistics."""
    if args.datasets_dir:
        benchmark = SecurityBenchmark()
        benchmark.load_datasets(args.datasets_dir)
    else:
        benchmark = SecurityBenchmark.with_builtin_datasets()

    summary = benchmark.get_summary()

    print("Dataset Statistics:")
    print("=" * 50)
    print(f"Total Tasks: {summary['total_tasks']}")
    print(f"Total Examples: {summary['total_examples']}")
    print()

    for task_name, stats in sorted(summary["tasks"].items()):
        print(f"{task_name}:")
        print(f"  Examples: {stats['total_examples']}")
        print(f"  By Difficulty: {stats['by_difficulty']}")
        if stats.get("by_category"):
            print(f"  By Category: {stats['by_category']}")
        print()

    return 0


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    if args.command == "run":
        return asyncio.run(run_benchmark(args))
    elif args.command == "compare":
        return compare_command(args)
    elif args.command == "list-tasks":
        return list_tasks_command(args)
    elif args.command == "show-datasets":
        return show_datasets_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
