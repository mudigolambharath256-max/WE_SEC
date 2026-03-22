#!/bin/bash
# Test runner script for llmrt
# Runs different test suites based on arguments

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=================================="
echo "llmrt Test Suite"
echo "=================================="
echo ""

# Parse arguments
TEST_TYPE="${1:-all}"
COVERAGE="${2:-no}"

# Function to run tests
run_tests() {
    local marker="$1"
    local description="$2"
    
    echo -e "${YELLOW}Running $description...${NC}"
    
    if [ "$COVERAGE" = "coverage" ]; then
        pytest -m "$marker" --cov=python --cov-report=html --cov-report=term
    else
        pytest -m "$marker"
    fi
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ $description passed${NC}"
    else
        echo -e "${RED}✗ $description failed${NC}"
        exit 1
    fi
    echo ""
}

# Run tests based on type
case "$TEST_TYPE" in
    unit)
        echo "Running unit tests only..."
        run_tests "unit" "Unit Tests"
        ;;
    
    integration)
        echo "Running integration tests only..."
        echo -e "${YELLOW}Note: Integration tests require mock servers to be running${NC}"
        echo "Start mock servers with: docker-compose --profile testing up -d"
        echo ""
        run_tests "integration" "Integration Tests"
        ;;
    
    fast)
        echo "Running fast tests only (unit tests, no slow tests)..."
        run_tests "unit and not slow" "Fast Tests"
        ;;
    
    slow)
        echo "Running slow tests only..."
        run_tests "slow" "Slow Tests"
        ;;
    
    all)
        echo "Running all tests..."
        run_tests "unit" "Unit Tests"
        
        echo -e "${YELLOW}Checking if mock servers are running...${NC}"
        if curl -s http://localhost:9999/health > /dev/null 2>&1; then
            echo -e "${GREEN}Mock servers are running${NC}"
            run_tests "integration" "Integration Tests"
        else
            echo -e "${YELLOW}Mock servers not running, skipping integration tests${NC}"
            echo "To run integration tests, start mock servers with:"
            echo "  docker-compose --profile testing up -d"
        fi
        ;;
    
    coverage)
        echo "Running all tests with coverage..."
        pytest --cov=python --cov-report=html --cov-report=term --cov-report=xml
        echo ""
        echo -e "${GREEN}Coverage report generated in htmlcov/index.html${NC}"
        ;;
    
    *)
        echo -e "${RED}Unknown test type: $TEST_TYPE${NC}"
        echo ""
        echo "Usage: $0 [test_type] [coverage]"
        echo ""
        echo "Test types:"
        echo "  unit         - Run unit tests only (fast)"
        echo "  integration  - Run integration tests only (requires services)"
        echo "  fast         - Run fast tests only (unit, no slow)"
        echo "  slow         - Run slow tests only"
        echo "  all          - Run all tests (default)"
        echo "  coverage     - Run all tests with coverage report"
        echo ""
        echo "Coverage:"
        echo "  coverage     - Generate coverage report"
        echo ""
        echo "Examples:"
        echo "  $0 unit"
        echo "  $0 integration"
        echo "  $0 all coverage"
        echo "  $0 coverage"
        exit 1
        ;;
esac

echo "=================================="
echo -e "${GREEN}All tests completed successfully!${NC}"
echo "=================================="
