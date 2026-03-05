#!/usr/bin/env bash
#
# Integration Test Runner for Triage Warden
#
# This script orchestrates running the full integration test suite:
# 1. Starts test containers with Docker Compose
# 2. Waits for all services to be healthy
# 3. Runs Rust integration tests
# 4. Runs Python integration tests
# 5. Cleans up containers
#
# Usage:
#   ./scripts/run-integration-tests.sh [options]
#
# Options:
#   --skip-rust       Skip Rust integration tests
#   --skip-python     Skip Python integration tests
#   --preserve-state  Reuse the existing compose stack without tearing it down
#   --keep-containers Keep containers running after tests
#   --verbose         Enable verbose output
#   --help            Show this help message

set -e

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Default options
SKIP_RUST=false
SKIP_PYTHON=false
PRESERVE_STATE=false
KEEP_CONTAINERS=false
VERBOSE=false

# Host port overrides (match deploy/docker/docker-compose.test.yml defaults)
TW_E2E_POSTGRES_PORT="${TW_E2E_POSTGRES_PORT:-5433}"
TW_E2E_QDRANT_HTTP_PORT="${TW_E2E_QDRANT_HTTP_PORT:-6335}"
TW_E2E_QDRANT_GRPC_PORT="${TW_E2E_QDRANT_GRPC_PORT:-6336}"
TW_E2E_REDIS_PORT="${TW_E2E_REDIS_PORT:-6380}"
TW_E2E_API_PORT="${TW_E2E_API_PORT:-8081}"
TW_E2E_TRIAGE_PORT="${TW_E2E_TRIAGE_PORT:-8092}"
export TW_E2E_POSTGRES_PORT TW_E2E_QDRANT_HTTP_PORT TW_E2E_QDRANT_GRPC_PORT
export TW_E2E_REDIS_PORT TW_E2E_API_PORT TW_E2E_TRIAGE_PORT

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-rust)
            SKIP_RUST=true
            shift
            ;;
        --skip-python)
            SKIP_PYTHON=true
            shift
            ;;
        --preserve-state)
            PRESERVE_STATE=true
            shift
            ;;
        --keep-containers)
            KEEP_CONTAINERS=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        --help)
            head -25 "$0" | tail -20
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Cleanup function
cleanup() {
    if [ "$PRESERVE_STATE" = true ] || [ "$KEEP_CONTAINERS" = true ]; then
        if [ "$PRESERVE_STATE" = true ]; then
            log_info "Preserving test containers (--preserve-state specified)"
        else
            log_info "Keeping containers running (--keep-containers specified)"
        fi
    else
        log_info "Cleaning up test containers..."
        cd "$PROJECT_ROOT/deploy/docker"
        $COMPOSE_CMD -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
    fi
}

# Set up trap for cleanup
trap cleanup EXIT

# Change to project root
cd "$PROJECT_ROOT"

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed"
    exit 1
fi

# Use docker compose or docker-compose depending on what's available
if docker compose version &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Start test containers
log_info "Starting test containers..."
cd "$PROJECT_ROOT/deploy/docker"

if [ "$PRESERVE_STATE" = true ]; then
    log_info "Reusing existing compose stack without resetting volumes"
    $COMPOSE_CMD -f docker-compose.test.yml up -d
else
    $COMPOSE_CMD -f docker-compose.test.yml down -v --remove-orphans 2>/dev/null || true
    $COMPOSE_CMD -f docker-compose.test.yml up -d
fi

# Wait for services to be healthy
log_info "Waiting for services to be healthy..."

wait_for_healthy() {
    local service=$1
    local max_attempts=30
    local attempt=1

    while [ $attempt -le $max_attempts ]; do
        if $COMPOSE_CMD -f docker-compose.test.yml ps "$service" 2>/dev/null | grep -q "healthy"; then
            return 0
        fi

        if [ "$VERBOSE" = true ]; then
            echo "  Waiting for $service (attempt $attempt/$max_attempts)..."
        fi

        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "Service $service did not become healthy"
    return 1
}

wait_for_healthy postgres-test
wait_for_healthy qdrant-test
wait_for_healthy redis-test
wait_for_healthy tw-triage-test
wait_for_healthy tw-api-test

log_info "All services are healthy"

# Export environment variables for tests
export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgres://test:test@localhost:${TW_E2E_POSTGRES_PORT}/triage_warden_test}"
export TEST_QDRANT_URL="${TEST_QDRANT_URL:-http://localhost:${TW_E2E_QDRANT_HTTP_PORT}}"
export TEST_REDIS_URL="${TEST_REDIS_URL:-redis://localhost:${TW_E2E_REDIS_PORT}}"
export TEST_API_URL="${TEST_API_URL:-http://localhost:${TW_E2E_API_PORT}}"

# Track test results
RUST_RESULT=0
PYTHON_RESULT=0

# Run Rust integration tests
if [ "$SKIP_RUST" = false ]; then
    log_info "Running Rust integration tests..."
    cd "$PROJECT_ROOT"

    if [ "$VERBOSE" = true ]; then
        cargo test --package tw-api --test integration_tests -- --ignored --nocapture || RUST_RESULT=$?
    else
        cargo test --package tw-api --test integration_tests -- --ignored || RUST_RESULT=$?
    fi

    if [ $RUST_RESULT -eq 0 ]; then
        log_info "Rust integration tests passed"
    else
        log_error "Rust integration tests failed"
    fi
else
    log_warn "Skipping Rust integration tests"
fi

# Run Python integration tests
if [ "$SKIP_PYTHON" = false ]; then
    log_info "Running Python integration tests..."
    cd "$PROJECT_ROOT/python"

    if [ "$VERBOSE" = true ]; then
        uv run pytest tests/integration/ -v --tb=long -m integration || PYTHON_RESULT=$?
    else
        uv run pytest tests/integration/ -v --tb=short -m integration || PYTHON_RESULT=$?
    fi

    if [ $PYTHON_RESULT -eq 0 ]; then
        log_info "Python integration tests passed"
    else
        log_error "Python integration tests failed"
    fi
else
    log_warn "Skipping Python integration tests"
fi

# Summary
echo ""
echo "=================================="
echo "Integration Test Summary"
echo "=================================="

if [ "$SKIP_RUST" = false ]; then
    if [ $RUST_RESULT -eq 0 ]; then
        echo -e "Rust tests:   ${GREEN}PASSED${NC}"
    else
        echo -e "Rust tests:   ${RED}FAILED${NC}"
    fi
else
    echo -e "Rust tests:   ${YELLOW}SKIPPED${NC}"
fi

if [ "$SKIP_PYTHON" = false ]; then
    if [ $PYTHON_RESULT -eq 0 ]; then
        echo -e "Python tests: ${GREEN}PASSED${NC}"
    else
        echo -e "Python tests: ${RED}FAILED${NC}"
    fi
else
    echo -e "Python tests: ${YELLOW}SKIPPED${NC}"
fi

echo "=================================="

# Exit with appropriate code
if [ $RUST_RESULT -ne 0 ] || [ $PYTHON_RESULT -ne 0 ]; then
    exit 1
fi

exit 0
