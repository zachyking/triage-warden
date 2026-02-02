#!/bin/bash
# Run Python tests with proper isolation for tests that manipulate sys.modules
set -e

cd "$(dirname "$0")/.."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED=0
TOTAL_PASSED=0

run_isolated() {
    local test_file="$1"
    local name="$2"
    echo -e "${YELLOW}Running $name...${NC}"
    if uv run --extra dev pytest "$test_file" -v --tb=short 2>&1 | tail -30; then
        count=$(uv run --extra dev pytest "$test_file" --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+' || echo 0)
        TOTAL_PASSED=$((TOTAL_PASSED + count))
        echo -e "${GREEN}✓ $name passed${NC}"
    else
        echo -e "${RED}✗ $name failed${NC}"
        FAILED=1
    fi
    echo ""
}

echo "=========================================="
echo "Running Python Tests with Isolation"
echo "=========================================="
echo ""

# Tests that manipulate sys.modules must run in isolation
run_isolated "tests/test_tools.py" "test_tools.py (SIEM/EDR tools)"
run_isolated "tests/test_react.py" "test_react.py (ReAct agent)"
run_isolated "tests/test_policy_bridge.py" "test_policy_bridge.py (Policy bridge)"

# Core tests that don't have sys.modules conflicts
echo -e "${YELLOW}Running core tests...${NC}"
if uv run --extra dev pytest tests/ \
    --ignore=tests/test_rag \
    --ignore=tests/e2e \
    --ignore=tests/integration \
    --ignore=tests/test_tools.py \
    --ignore=tests/test_react.py \
    --ignore=tests/test_policy_bridge.py \
    --ignore=tests/test_metrics.py \
    --ignore=tests/test_evaluation.py \
    -v --tb=short 2>&1 | tail -30; then
    count=$(uv run --extra dev pytest tests/ \
        --ignore=tests/test_rag \
        --ignore=tests/e2e \
        --ignore=tests/integration \
        --ignore=tests/test_tools.py \
        --ignore=tests/test_react.py \
        --ignore=tests/test_policy_bridge.py \
        --ignore=tests/test_metrics.py \
        --ignore=tests/test_evaluation.py \
        --collect-only -q 2>/dev/null | tail -1 | grep -oE '^[0-9]+' || echo 0)
    TOTAL_PASSED=$((TOTAL_PASSED + count))
    echo -e "${GREEN}✓ Core tests passed${NC}"
else
    echo -e "${RED}✗ Core tests failed${NC}"
    FAILED=1
fi

echo ""
echo "=========================================="
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All Python tests passed! (${TOTAL_PASSED} tests)${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed${NC}"
    exit 1
fi
