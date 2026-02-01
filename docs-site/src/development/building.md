# Building from Source

Complete guide to building Triage Warden.

## Prerequisites

### Rust

```bash
# Install Rust via rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify installation
rustc --version  # Should be 1.75+
```

### Python

```bash
# Install uv
curl -LsSf https://astral.sh/uv/install.sh | sh

# Verify installation
uv --version
```

### System Dependencies

#### macOS

```bash
brew install openssl pkg-config
```

#### Ubuntu/Debian

```bash
sudo apt-get install build-essential pkg-config libssl-dev
```

#### Fedora

```bash
sudo dnf install gcc openssl-devel pkgconfig
```

## Building

### Debug Build

```bash
cargo build
```

Outputs:
- `target/debug/tw-api`
- `target/debug/tw-cli`

### Release Build

```bash
cargo build --release
```

Outputs:
- `target/release/tw-api`
- `target/release/tw-cli`

### Python Package

```bash
cd python
uv sync
uv build
```

### PyO3 Bridge

The bridge is built automatically with cargo:

```bash
cd tw-bridge
cargo build --release
```

## Build Options

### Feature Flags

```bash
# Build with PostgreSQL support only
cargo build --no-default-features --features postgres

# Build with all features
cargo build --all-features
```

### Cross-Compilation

```bash
# For Linux (from macOS)
rustup target add x86_64-unknown-linux-gnu
cargo build --release --target x86_64-unknown-linux-gnu

# For musl (static binary)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

## Docker Build

### Build Image

```bash
docker build -t triage-warden .
```

### Multi-Stage Dockerfile

```dockerfile
# Builder stage
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /app/target/release/tw-api /usr/local/bin/
CMD ["tw-api"]
```

## Verification

### Run Tests

```bash
# Rust tests
cargo test

# Python tests
cd python && uv run pytest

# All tests
./scripts/test-all.sh
```

### Linting

```bash
# Rust
cargo fmt --check
cargo clippy -- -D warnings

# Python
cd python
uv run ruff check
uv run black --check .
uv run mypy .
```

### Smoke Test

```bash
# Start server
./target/release/tw-api &

# Health check
curl http://localhost:8080/api/health

# Stop server
kill %1
```

## Troubleshooting

### OpenSSL Errors

```bash
# macOS
export OPENSSL_DIR=$(brew --prefix openssl)

# Linux
export OPENSSL_DIR=/usr
```

### PyO3 Build Issues

```bash
# Ensure Python is found
export PYO3_PYTHON=$(which python3)

# Clean and rebuild
cargo clean -p tw-bridge
cargo build -p tw-bridge
```

### Out of Memory

```bash
# Reduce parallel jobs
cargo build -j 2
```
