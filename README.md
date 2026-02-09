# Triage Warden

[![CI](https://github.com/zachyking/triage-warden/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/zachyking/triage-warden/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

AI-augmented SOC triage and response platform with Rust APIs/workflows and Python AI services.

## What It Does

- Ingests and normalizes alerts from security tooling.
- Runs enrichment and triage pipelines with policy guardrails.
- Supports approvals, audit trails, and incident response actions.
- Exposes a REST API, web dashboard, and CLI.

## Monorepo Layout

```text
crates/
  tw-api/            # Axum API + dashboard routes
  tw-core/           # Core domain models, workflows, repositories
  tw-policy/         # Guardrails and policy engine
  tw-connectors/     # Connector implementations
  tw-actions/        # Response action implementations
  tw-cli/            # `triage-warden` CLI binary
python/
  tw_ai/             # AI agent, RAG, orchestration, evaluation
tw-bridge/           # PyO3 bridge package + Python tests
docs-site/           # mdBook documentation source
```

## CI Coverage

Main workflow: `.github/workflows/ci.yml`

- Rust quality gates: `fmt`, `clippy`, `check`, unit/integration tests
- Python quality gates: `ruff`, `black --check`, `mypy`, pytest suites
- Bridge tests: `tw-bridge` wheel build + Python tests
- Security/quality: `cargo audit`, Rust coverage (Tarpaulin), docs build

## Local Development

### Prerequisites

- Rust (stable toolchain)
- Python 3.11+
- `uv` (Python dependency/task runner)

### Build

```bash
cargo build --workspace --exclude tw-bridge
cd python && uv sync --extra dev
```

### Run

```bash
# API server (default binds on 0.0.0.0:8080 unless overridden)
cargo run -p tw-api

# CLI help
cargo run -p tw-cli -- --help
```

### Test

```bash
# Rust
cargo fmt --all -- --check
cargo clippy --workspace --exclude tw-bridge -- -D warnings
cargo test --workspace --exclude tw-bridge

# Python
cd python
uv run ruff check tw_ai
uv run black --check tw_ai
uv run mypy tw_ai --ignore-missing-imports
uv run pytest tests/ -v --tb=short

# tw-bridge
cd ../tw-bridge
python -m pytest python/tests -v
```

## Documentation

- Docs source: `docs-site/src/`
- Build docs locally:

```bash
mdbook build docs-site
```

- Open generated docs: `docs-site/book/index.html`

## License

MIT
