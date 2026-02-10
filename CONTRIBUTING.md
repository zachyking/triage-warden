# Contributing to Triage Warden

Thanks for your interest in contributing! This guide covers everything you need to get started.

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| [Rust](https://rustup.rs/) | 1.75+ | Backend services |
| [Python](https://www.python.org/) | 3.11+ | AI/ML components |
| [uv](https://docs.astral.sh/uv/) | latest | Python package management |
| SQLite | 3.x | Development database |

## Development Setup

```bash
# Clone the repository
git clone https://github.com/zachyking/triage-warden.git
cd triage-warden

# Build Rust workspace
cargo build

# Install Python dependencies
cd python && uv sync && cd ..

# Enable the pre-commit hook
git config core.hooksPath .githooks
```

## Code Style

### Rust

- `cargo fmt --all` — formatting (enforced in CI)
- `cargo clippy --workspace --exclude tw-bridge -- -D warnings` — lints
- Document public APIs with `///` doc comments
- Prefer `pub(crate)` over `#[allow(dead_code)]` for internal helpers

### Python

- `ruff check tw_ai` — linting (PEP 8 + import sorting)
- `black tw_ai` — formatting
- `mypy tw_ai` — type checking (strict mode)
- Type hints required for all public functions

## Pre-commit Hook

The project ships a pre-commit hook at `.githooks/pre-commit` that runs all of the above checks automatically on `git commit`. Enable it once with:

```bash
git config core.hooksPath .githooks
```

The hook only checks files you changed — Rust checks run when `.rs`/`.toml` files are staged, Python checks run when `.py` files are staged.

## Branch & PR Workflow

All changes go through branches and pull requests:

```bash
git checkout -b feat/my-feature    # create a branch
# ... make changes ...
git commit -m "feat: add my feature"
git push -u origin feat/my-feature
# Open a PR on GitHub
```

### Conventional Commits

We use [Conventional Commits](https://www.conventionalcommits.org/) for commit messages:

```
type(scope): short description

[optional body]
```

| Type | When to use |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `test` | Adding or updating tests |
| `chore` | Build, CI, or tooling changes |

## Testing

### Rust

```bash
cargo test                           # full workspace
cargo test -p tw-api                 # single crate
cargo test -- --nocapture            # with stdout
```

### Python (AI components)

```bash
cd python
uv run pytest                        # all tests
uv run pytest tests/test_agents.py   # specific file
uv run pytest --cov=tw_ai           # with coverage
```

### Integration Tests

Integration tests require external services (Qdrant, etc.) and are run in CI. See `.github/workflows/ci.yml` for the full matrix.

## Project Layout

```
crates/
  tw-core/          # Domain models, workflows, repositories
  tw-api/           # Axum API + HTMX dashboard
  tw-policy/        # Guardrails and policy engine
  tw-connectors/    # Connector trait implementations
  tw-actions/       # Response action implementations
  tw-observability/ # Metrics, tracing, health checks
  tw-cli/           # CLI binary entrypoint
python/
  tw_ai/            # AI agent, RAG, analysis, validation
tw-bridge/          # PyO3 Rust-Python bridge
config/             # Default configuration files
deploy/             # Docker, Helm, infrastructure
docs-site/          # mdBook documentation source
```

For architecture details, build the docs locally:

```bash
cd docs-site && mdbook serve
```

## Issue Reporting

1. Search existing issues first
2. Include: version, steps to reproduce, expected vs actual behavior, relevant logs
3. Use issue labels (`bug`, `enhancement`, `question`)

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
