#!/bin/bash
# Final validation script for llmrt
# Validates that all components are working correctly

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

echo "=========================================="
echo "llmrt Final Validation"
echo "=========================================="
echo ""

# Function to check command exists
check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $1 is installed"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $1 is not installed"
        ((FAILED++))
        return 1
    fi
}

# Function to check file exists
check_file() {
    if [ -f "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 exists"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $1 not found"
        ((FAILED++))
        return 1
    fi
}

# Function to check directory exists
check_dir() {
    if [ -d "$1" ]; then
        echo -e "${GREEN}✓${NC} $1 exists"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $1 not found"
        ((FAILED++))
        return 1
    fi
}

# Function to run command and check exit code
run_check() {
    local description="$1"
    shift
    
    if "$@" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $description"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} $description"
        ((FAILED++))
        return 1
    fi
}

echo -e "${BLUE}=== Checking Prerequisites ===${NC}"
check_command "go"
check_command "python3"
check_command "docker"
check_command "docker-compose"
check_command "protoc"
echo ""

echo -e "${BLUE}=== Checking Repository Structure ===${NC}"
check_dir "go"
check_dir "python"
check_dir "proto"
check_dir "config"
check_dir "data"
check_dir "tests"
check_file "README.md"
check_file "Makefile"
check_file ".env.example"
check_file "docker-compose.yml"
echo ""

echo -e "${BLUE}=== Checking Go Files ===${NC}"
check_file "go/go.mod"
check_file "go/cmd/probe_server/main.go"
check_file "go/cmd/recon_server/main.go"
check_file "go/cmd/mcp_server/main.go"
check_dir "go/internal/transport"
check_dir "go/internal/proberunner"
check_dir "go/internal/reconrunner"
check_dir "go/internal/mcprunner"
echo ""

echo -e "${BLUE}=== Checking Python Files ===${NC}"
check_file "pyproject.toml"
check_dir "python/core"
check_dir "python/prompt_attacks"
check_dir "python/rag_attacks"
check_dir "python/mcp_attacks"
check_dir "python/evidence"
check_dir "python/reporting"
check_dir "python/api"
check_dir "python/cli"
echo ""

echo -e "${BLUE}=== Checking Configuration Files ===${NC}"
check_file "config/scope.yaml"
check_file "config/default.yaml"
check_file "config/profiles/chatbot.yaml"
check_file "config/profiles/rag_app.yaml"
check_file "config/profiles/mcp_agent.yaml"
check_file "config/profiles/ide_assistant.yaml"
echo ""

echo -e "${BLUE}=== Checking Data Files ===${NC}"
check_file "data/payload_corpora/setup.sh"
check_file "data/flipattack_templates.jsonl"
check_file "data/mcp_sqli_handler_templates.jsonl"
check_dir "data/nuclei_templates/llm"
check_dir "data/nuclei_templates/mcp"
echo ""

echo -e "${BLUE}=== Checking Nuclei Templates ===${NC}"
check_file "data/nuclei_templates/llm/prompt-injection.yaml"
check_file "data/nuclei_templates/llm/rce-probe.yaml"
check_file "data/nuclei_templates/llm/pii-leakage.yaml"
check_file "data/nuclei_templates/llm/jailbreak.yaml"
check_file "data/nuclei_templates/llm/oob-exfiltration.yaml"
check_file "data/nuclei_templates/mcp/tool-injection.yaml"
check_file "data/nuclei_templates/mcp/lethal-trifecta.yaml"
check_file "data/nuclei_templates/mcp/rug-pull.yaml"
check_file "data/nuclei_templates/mcp/oauth-vulnerabilities.yaml"
check_file "data/nuclei_templates/mcp/privilege-escalation.yaml"
echo ""

echo -e "${BLUE}=== Checking Test Files ===${NC}"
check_file "tests/conftest.py"
check_file "pytest.ini"
check_dir "tests/unit"
check_dir "tests/integration"
check_file "tests/mock_server/app.py"
check_file "tests/mock_server/mcp_server.py"
echo ""

echo -e "${BLUE}=== Checking Docker Files ===${NC}"
check_file "Dockerfile.go"
check_file "Dockerfile.python"
check_file "Dockerfile.shannon"
check_file ".dockerignore"
echo ""

echo -e "${BLUE}=== Checking CI/CD Files ===${NC}"
check_dir ".github/workflows"
check_file ".github/workflows/test.yml"
check_file ".github/workflows/build.yml"
check_file ".github/workflows/release.yml"
echo ""

echo -e "${BLUE}=== Building Go Services ===${NC}"
cd go
if run_check "Go modules download" go mod download; then
    run_check "Build probe_server" go build -o ../bin/probe_server ./cmd/probe_server
    run_check "Build recon_server" go build -o ../bin/recon_server ./cmd/recon_server
    run_check "Build mcp_server" go build -o ../bin/mcp_server ./cmd/mcp_server
fi
cd ..
echo ""

echo -e "${BLUE}=== Validating Python Package ===${NC}"
if run_check "Python package installation" pip install -e . --quiet; then
    run_check "Import core modules" python -c "from python.core import orchestrator"
    run_check "Import evidence modules" python -c "from python.evidence import store"
    run_check "Import reporting modules" python -c "from python.reporting import generator"
fi
echo ""

echo -e "${BLUE}=== Running Tests ===${NC}"
if check_command "pytest"; then
    run_check "Unit tests" pytest -m unit --tb=short -q
else
    echo -e "${YELLOW}⚠${NC} pytest not installed, skipping tests"
    ((WARNINGS++))
fi
echo ""

echo -e "${BLUE}=== Validating Docker Configuration ===${NC}"
run_check "Docker Compose config validation" docker-compose config
run_check "Docker Compose testing profile" docker-compose --profile testing config
echo ""

echo -e "${BLUE}=== Checking Documentation ===${NC}"
check_file "README.md"
check_file "BUILD_STATUS.md"
check_file "DOCKER.md"
check_file "tests/README.md"
check_file ".github/workflows/README.md"
echo ""

echo "=========================================="
echo "Validation Summary"
echo "=========================================="
echo -e "${GREEN}Passed:${NC}   $PASSED"
echo -e "${RED}Failed:${NC}   $FAILED"
echo -e "${YELLOW}Warnings:${NC} $WARNINGS"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All validations passed!${NC}"
    echo ""
    echo "llmrt is ready for deployment."
    echo ""
    echo "Next steps:"
    echo "  1. Configure .env file with your API keys"
    echo "  2. Start services: docker-compose up -d"
    echo "  3. Run a test campaign: llmrt scan --target <url>"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Validation failed with $FAILED errors${NC}"
    echo ""
    echo "Please fix the errors above before deploying."
    echo ""
    exit 1
fi
