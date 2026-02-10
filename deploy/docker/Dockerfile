# Triage Warden Dockerfile
# Multi-stage build: Rust binary + Python AI in a single image

# ── Stage 1: Rust build ───────────────────────────────────────────
FROM rust:1-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/tw-core/Cargo.toml crates/tw-core/
COPY crates/tw-api/Cargo.toml crates/tw-api/
COPY crates/tw-cli/Cargo.toml crates/tw-cli/
COPY crates/tw-policy/Cargo.toml crates/tw-policy/
COPY crates/tw-connectors/Cargo.toml crates/tw-connectors/
COPY crates/tw-actions/Cargo.toml crates/tw-actions/
COPY crates/tw-observability/Cargo.toml crates/tw-observability/
COPY tw-bridge/Cargo.toml tw-bridge/

# Patched vendor crates required by [patch.crates-io]
COPY vendor/ vendor/

# Create dummy source files for dependency compilation
RUN mkdir -p crates/tw-core/src crates/tw-api/src crates/tw-cli/src \
    crates/tw-policy/src crates/tw-connectors/src crates/tw-actions/src \
    crates/tw-observability/src tw-bridge/src && \
    echo "fn main() {}" > crates/tw-cli/src/main.rs && \
    touch crates/tw-core/src/lib.rs crates/tw-api/src/lib.rs \
    crates/tw-policy/src/lib.rs crates/tw-connectors/src/lib.rs \
    crates/tw-actions/src/lib.rs crates/tw-observability/src/lib.rs \
    tw-bridge/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release --bin triage-warden && \
    rm -rf crates/*/src

# Copy actual source code
COPY crates/ crates/

# Touch to update timestamps and rebuild
RUN touch crates/*/src/*.rs crates/*/src/**/*.rs 2>/dev/null || true

# Build the actual application
RUN cargo build --release --bin triage-warden

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies (including Python for AI components)
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Create Python venv
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install tw_ai Python package
COPY python/ /tmp/python/
RUN pip install --no-cache-dir /tmp/python/ && rm -rf /tmp/python/

# Install tw_bridge wheel (pre-built by CI, placed in dist/)
COPY dist/tw_bridge-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/tw_bridge-*.whl && rm -f /tmp/tw_bridge-*.whl

# Create non-root user
RUN useradd -r -s /bin/false -U triage

# Copy binary from builder
COPY --from=builder /app/target/release/triage-warden /usr/local/bin/

# Copy static assets and templates
COPY --from=builder /app/crates/tw-api/templates /app/templates
COPY --from=builder /app/crates/tw-api/static /app/static

# Create directories
RUN mkdir -p /app/config /app/data && \
    chown -R triage:triage /app

# Switch to non-root user
USER triage

# Environment defaults
ENV RUST_LOG=info
ENV TW_BIND_ADDRESS=0.0.0.0:8080

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
ENTRYPOINT ["triage-warden"]
CMD ["serve"]
