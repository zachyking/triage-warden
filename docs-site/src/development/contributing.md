# Contributing

Guide to contributing to Triage Warden.

## Getting Started

1. Fork the repository
2. Clone your fork
3. Set up the development environment
4. Create a branch for your changes
5. Submit a pull request

## Development Setup

### Prerequisites

- Rust 1.75+
- Python 3.11+
- uv (Python package manager)
- SQLite (for development)

### Initial Setup

```bash
# Clone repository
git clone https://github.com/your-username/triage-warden.git
cd triage-warden

# Install Rust dependencies
cargo build

# Install Python dependencies
cd python
uv sync
cd ..

# Run tests
cargo test
cd python && uv run pytest
```

## Code Style

### Rust

- Follow standard Rust conventions
- Run `cargo fmt` before committing
- Run `cargo clippy` and fix warnings
- Document public APIs with doc comments

### Python

- Follow PEP 8
- Run `ruff check` and `black` before committing
- Type hints required (mypy strict mode)
- Docstrings for public functions

## Pre-commit Hooks

Install pre-commit hooks:

```bash
# The project has pre-commit configured in .git/hooks
# It runs automatically on commit:
# - cargo fmt
# - cargo clippy
# - ruff
# - black
# - mypy
```

## Pull Request Process

1. **Create a branch**
   ```bash
   git checkout -b feature/my-feature
   ```

2. **Make changes**
   - Write code
   - Add tests
   - Update documentation

3. **Run checks**
   ```bash
   cargo fmt && cargo clippy
   cargo test
   cd python && uv run pytest
   ```

4. **Commit**
   ```bash
   git commit -m "feat: add new feature"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/my-feature
   ```

6. **Address review feedback**

## Commit Messages

Follow conventional commits:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

## Testing

### Rust Tests

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p tw-api

# Run with output
cargo test -- --nocapture
```

### Python Tests

```bash
cd python
uv run pytest

# Run specific tests
uv run pytest tests/test_agents.py

# With coverage
uv run pytest --cov=tw_ai
```

### Integration Tests

```bash
# Start test server
cargo run --bin tw-api &

# Run integration tests
./scripts/integration-tests.sh
```

## Documentation

- Update docs for API changes
- Add examples for new features
- Keep README.md current

Build docs locally:

```bash
cd docs-site
mdbook serve
```

## Issue Reporting

When reporting issues:

1. Search existing issues first
2. Use issue templates
3. Include:
   - Version information
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs

## Questions

- Open a GitHub Discussion
- Check existing discussions first
- Tag appropriately

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
