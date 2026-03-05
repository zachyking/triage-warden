#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ENV_REF_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")
PLACEHOLDER_MARKERS = (
    "example.local",
    "changeme",
    "replace_me",
    "placeholder",
    "dummy",
    "localhost",
    "127.0.0.1",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and render real manual-E2E configuration.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate env-backed real E2E configuration.",
    )
    add_shared_args(validate_parser)
    validate_parser.add_argument(
        "--require-connectors",
        action="store_true",
        help="Require a connector config file and validate it.",
    )

    render_parser = subparsers.add_parser(
        "render-connectors",
        help="Render connector config with environment substitutions applied.",
    )
    add_shared_args(render_parser)

    return parser.parse_args()


def add_shared_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Optional env file to load before validation or rendering.",
    )
    parser.add_argument(
        "--connector-config",
        type=Path,
        help="JSON file containing env-backed connector definitions.",
    )


def load_env(env_file: Path | None) -> dict[str, str]:
    env: dict[str, str] = {}

    if env_file is not None:
        env.update(parse_env_file(env_file))

    env.update(os.environ)
    return env


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise ValueError(f"Env file not found: {path}")

    env: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("export "):
            line = line[len("export ") :].strip()

        key, separator, value = line.partition("=")
        if separator != "=":
            raise ValueError(f"Invalid env line {line_number} in {path}: {raw_line}")

        key = key.strip()
        value = value.strip()

        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]

        env[key] = value

    return env


def load_connector_config(path: Path | None) -> list[dict[str, Any]]:
    if path is None:
        raise ValueError("Connector config is required")
    if not path.is_file():
        raise ValueError(f"Connector config not found: {path}")

    document = json.loads(path.read_text(encoding="utf-8"))
    connectors = document.get("connectors")

    if not isinstance(connectors, list) or not connectors:
        raise ValueError(f"{path} must contain a non-empty 'connectors' array")

    normalized: list[dict[str, Any]] = []
    for index, item in enumerate(connectors, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Connector entry {index} must be an object")
        for field in ("name", "connector_type", "config"):
            if field not in item:
                raise ValueError(f"Connector entry {index} is missing '{field}'")
        if not isinstance(item["config"], dict):
            raise ValueError(f"Connector entry {index} field 'config' must be an object")
        normalized.append(item)

    return normalized


def resolve_value(value: Any, env: dict[str, str], missing: set[str]) -> Any:
    if isinstance(value, dict):
        return {key: resolve_value(inner, env, missing) for key, inner in value.items()}
    if isinstance(value, list):
        return [resolve_value(inner, env, missing) for inner in value]
    if isinstance(value, str):
        resolved = ENV_REF_PATTERN.sub(lambda match: replace_env_ref(match, env, missing), value)
        return coerce_scalar(resolved)
    return value


def replace_env_ref(match: re.Match[str], env: dict[str, str], missing: set[str]) -> str:
    key = match.group(1)
    value = env.get(key, "").strip()
    if not value:
        missing.add(key)
        return ""
    return value


def coerce_scalar(value: str) -> Any:
    lowered = value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if value.isdigit():
        return int(value)
    return value


def looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    return any(marker in lowered for marker in PLACEHOLDER_MARKERS)


def iter_string_values(value: Any) -> list[str]:
    strings: list[str] = []
    if isinstance(value, dict):
        for inner in value.values():
            strings.extend(iter_string_values(inner))
    elif isinstance(value, list):
        for inner in value:
            strings.extend(iter_string_values(inner))
    elif isinstance(value, str):
        strings.append(value)
    return strings


def validate_core_env(env: dict[str, str]) -> list[str]:
    errors: list[str] = []

    for key in ("TW_E2E_ADMIN_PASSWORD", "TW_LLM_PROVIDER", "TW_LLM_MODEL"):
        value = env.get(key, "").strip()
        if not value:
            errors.append(f"Missing required env var: {key}")
        elif looks_like_placeholder(value):
            errors.append(f"Env var still looks like a placeholder: {key}")

    provider = env.get("TW_LLM_PROVIDER", "").strip().lower()
    has_generic_key = bool(env.get("TW_LLM_API_KEY", "").strip())
    has_openai_key = bool(env.get("OPENAI_API_KEY", "").strip())
    has_anthropic_key = bool(env.get("ANTHROPIC_API_KEY", "").strip())

    if provider == "openai" and not (has_generic_key or has_openai_key):
        errors.append("TW_LLM_PROVIDER=openai requires OPENAI_API_KEY or TW_LLM_API_KEY")
    elif provider == "anthropic" and not (has_generic_key or has_anthropic_key):
        errors.append(
            "TW_LLM_PROVIDER=anthropic requires ANTHROPIC_API_KEY or TW_LLM_API_KEY"
        )

    return errors


def validate_connector_env(
    connectors: list[dict[str, Any]],
    env: dict[str, str],
) -> tuple[list[str], list[dict[str, Any]]]:
    errors: list[str] = []
    resolved_connectors: list[dict[str, Any]] = []

    for connector in connectors:
        missing: set[str] = set()
        resolved = {
            "name": connector["name"],
            "connector_type": connector["connector_type"],
            "verify": bool(connector.get("verify", True)),
            "config": resolve_value(connector["config"], env, missing),
        }

        if missing:
            errors.append(
                f"{connector['name']} is missing env vars: {', '.join(sorted(missing))}"
            )
            continue

        for string_value in iter_string_values(resolved["config"]):
            if looks_like_placeholder(string_value):
                errors.append(
                    f"{connector['name']} contains a placeholder-like value: {string_value}"
                )
                break

        resolved_connectors.append(resolved)

    return errors, resolved_connectors


def command_validate(args: argparse.Namespace) -> int:
    env = load_env(args.env_file)
    errors = validate_core_env(env)

    connectors: list[dict[str, Any]] = []
    if args.require_connectors:
        if args.connector_config is None:
            errors.append("--require-connectors needs --connector-config")
        else:
            connectors = load_connector_config(args.connector_config)
    elif args.connector_config is not None:
        connectors = load_connector_config(args.connector_config)

    if connectors:
        connector_errors, _ = validate_connector_env(connectors, env)
        errors.extend(connector_errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    provider = env.get("TW_LLM_PROVIDER", "").strip()
    connector_count = len(connectors)
    print(
        f"Real E2E configuration valid: provider={provider}, connectors={connector_count}",
        file=sys.stdout,
    )
    return 0


def command_render_connectors(args: argparse.Namespace) -> int:
    env = load_env(args.env_file)
    connectors = load_connector_config(args.connector_config)
    errors, resolved_connectors = validate_connector_env(connectors, env)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    for connector in resolved_connectors:
        config_json = json.dumps(connector["config"], separators=(",", ":"), sort_keys=True)
        print(
            "\t".join(
                [
                    connector["name"],
                    connector["connector_type"],
                    "true" if connector["verify"] else "false",
                    config_json,
                ]
            )
        )

    return 0


def main() -> int:
    args = parse_args()
    try:
        if args.command == "validate":
            return command_validate(args)
        if args.command == "render-connectors":
            return command_render_connectors(args)
        print(f"Unsupported command: {args.command}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
