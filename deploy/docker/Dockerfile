# Triage Warden Dockerfile
# Multi-stage build for minimal production image

# Stage 1: Build
FROM rust:1.75-bookworm as builder

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

# Create dummy source files for dependency compilation
RUN mkdir -p crates/tw-core/src crates/tw-api/src crates/tw-cli/src \
    crates/tw-policy/src crates/tw-connectors/src crates/tw-actions/src && \
    echo "fn main() {}" > crates/tw-cli/src/main.rs && \
    touch crates/tw-core/src/lib.rs crates/tw-api/src/lib.rs \
    crates/tw-policy/src/lib.rs crates/tw-connectors/src/lib.rs \
    crates/tw-actions/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release --bin triage-warden && \
    rm -rf crates/*/src

# Copy actual source code
COPY crates/ crates/

# Touch to update timestamps and rebuild
RUN touch crates/*/src/*.rs crates/*/src/**/*.rs 2>/dev/null || true

# Build the actual application
RUN cargo build --release --bin triage-warden

# Stage 2: Runtime
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

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
