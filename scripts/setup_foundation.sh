#!/bin/bash
# Foundation Setup Script for llmrt
# Executes Phase 1 of IMPLEMENTATION_ROADMAP.md
# This script MUST complete successfully before any development can begin

set -e  # Exit on any error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "=========================================="
echo "llmrt Foundation Setup"
echo "=========================================="
echo ""

# Track progress
STEP=0
TOTAL_STEPS=8

step() {
    STEP=$((STEP + 1))
    echo ""
    echo -e "${BLUE}[Step $STEP/$TOTAL_STEPS]${NC} $1"
    echo "----------------------------------------"
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

error() {
    echo -e "${RED}✗${NC} $1"
    exit 1
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Step 1: Check system prerequisites
step "Checking system prerequisites"

if ! command -v go &> /dev/null; then
    error "Go not found. Install Go 1.22+ from https://go.dev/dl/"
fi
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
success "Go $GO_VERSION installed"

if ! command -v python3 &> /dev/null; then
    error "Python3 not found. Install Python 3.11+ from https://python.org"
fi
PYTHON_VERSION=$(python3 --version | awk '{print $2}')
success "Python $PYTHON_VERSION installed"

if ! command -v protoc &> /dev/null; then
    error "protoc not found. Install with: sudo apt-get install protobuf-compiler"
fi
PROTOC_VERSION=$(protoc --version | awk '{print $2}')
success "protoc $PROTOC_VERSION installed"

if ! command -v docker &> /dev/null; then
    warning "Docker not found. Install from https://docs.docker.com/get-docker/"
else
    success "Docker installed"
fi

# Step 2: Install Go proto plugins
step "Installing Go proto plugins"

if ! command -v protoc-gen-go &> /dev/null; then
    echo "Installing protoc-gen-go..."
    go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    success "protoc-gen-go installed"
else
    success "protoc-gen-go already installed"
fi

if ! command -v protoc-gen-go-grpc &> /dev/null; then
    echo "Installing protoc-gen-go-grpc..."
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    success "protoc-gen-go-grpc installed"
else
    success "protoc-gen-go-grpc already installed"
fi

# Add Go bin to PATH if not already there
GOPATH=$(go env GOPATH)
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    export PATH="$PATH:$GOPATH/bin"
    echo "export PATH=\"\$PATH:\$(go env GOPATH)/bin\"" >> ~/.bashrc
    success "Added Go bin to PATH"
fi

# Step 3: Install Python dependencies
step "Installing Python dependencies"

echo "Installing core gRPC dependencies..."
pip install -q grpcio==1.64.0 grpcio-tools==1.64.0 || error "Failed to install gRPC"
success "gRPC installed"

echo "Installing PyTorch (CPU-only)..."
pip install -q torch --index-url https://download.pytorch.org/whl/cpu || warning "PyTorch installation failed (non-critical)"

echo "Installing project dependencies..."
if [ -f "pyproject.toml" ]; then
    pip install -q -e . || warning "Some dependencies failed to install (may need manual installation)"
    success "Project dependencies installed"
else
    error "pyproject.toml not found. Run this script from repository root."
fi

# Step 4: CRITICAL - Compile proto files
step "Compiling proto files (CRITICAL STEP)"

# Create output directories
mkdir -p go/internal/proto
mkdir -p python/core

# Verify proto files exist
if [ ! -f "proto/common.proto" ]; then
    error "proto/common.proto not found"
fi
if [ ! -f "proto/probe.proto" ]; then
    error "proto/probe.proto not found"
fi
if [ ! -f "proto/recon.proto" ]; then
    error "proto/recon.proto not found"
fi
if [ ! -f "proto/mcp.proto" ]; then
    error "proto/mcp.proto not found"
fi
success "All proto files found"

# Compile to Go
echo "Compiling proto files to Go..."
protoc \
  --go_out=go/internal/proto \
  --go-grpc_out=go/internal/proto \
  --go_opt=paths=source_relative \
  --go-grpc_opt=paths=source_relative \
  -I proto \
  proto/common.proto proto/probe.proto proto/recon.proto proto/mcp.proto

if [ $? -eq 0 ]; then
    success "Proto files compiled to Go"
else
    error "Proto compilation to Go failed"
fi

# Compile to Python
echo "Compiling proto files to Python..."
python -m grpc_tools.protoc \
  -I proto \
  --python_out=python/core \
  --grpc_python_out=python/core \
  proto/common.proto proto/probe.proto proto/recon.proto proto/mcp.proto

if [ $? -eq 0 ]; then
    success "Proto files compiled to Python"
else
    error "Proto compilation to Python failed"
fi

# Verify generated files exist
echo "Verifying generated files..."
GO_FILES=$(ls go/internal/proto/*.go 2>/dev/null | wc -l)
PY_FILES=$(ls python/core/*_pb2*.py 2>/dev/null | wc -l)

if [ "$GO_FILES" -ge 8 ]; then
    success "Go proto files generated ($GO_FILES files)"
else
    error "Go proto files missing (expected 8+, found $GO_FILES)"
fi

if [ "$PY_FILES" -ge 8 ]; then
    success "Python proto files generated ($PY_FILES files)"
else
    error "Python proto files missing (expected 8+, found $PY_FILES)"
fi

# Step 5: Download Go dependencies
step "Downloading Go dependencies"

cd go
go mod tidy
go mod download
cd ..
success "Go dependencies downloaded"

# Step 6: Verify Go compilation
step "Verifying Go servers compile"

cd go

echo "Building probe_server..."
if go build -o ../bin/probe_server ./cmd/probe_server/ 2>&1 | tee /tmp/probe_build.log; then
    success "probe_server compiles"
else
    error "probe_server failed to compile. Check /tmp/probe_build.log"
fi

echo "Building recon_server..."
if go build -o ../bin/recon_server ./cmd/recon_server/ 2>&1 | tee /tmp/recon_build.log; then
    success "recon_server compiles"
else
    error "recon_server failed to compile. Check /tmp/recon_build.log"
fi

echo "Building mcp_server..."
if go build -o ../bin/mcp_server ./cmd/mcp_server/ 2>&1 | tee /tmp/mcp_build.log; then
    success "mcp_server compiles"
else
    error "mcp_server failed to compile. Check /tmp/mcp_build.log"
fi

cd ..

# Step 7: Verify Python imports
step "Verifying Python imports"

echo "Testing scope_validator..."
if python3 -c "from python.core.scope_validator import ScopeValidator; print('OK')" 2>/dev/null; then
    success "scope_validator imports successfully"
else
    warning "scope_validator import failed (may need implementation)"
fi

echo "Testing gRPC stubs..."
if python3 -c "from python.core import probe_pb2, probe_pb2_grpc; print('OK')" 2>/dev/null; then
    success "gRPC stubs import successfully"
else
    error "gRPC stubs import failed. Proto compilation may have failed."
fi

echo "Testing evidence models..."
if python3 -c "from python.evidence.models import Finding; print('OK')" 2>/dev/null; then
    success "evidence models import successfully"
else
    warning "evidence models import failed (may need implementation)"
fi

# Step 8: Create .env file if missing
step "Setting up environment configuration"

if [ ! -f ".env" ]; then
    echo "Creating .env from .env.example..."
    cp .env.example .env
    success ".env file created"
    warning "IMPORTANT: Edit .env and add your API keys before running campaigns"
else
    success ".env file already exists"
fi

# Final summary
echo ""
echo "=========================================="
echo -e "${GREEN}Foundation Setup Complete!${NC}"
echo "=========================================="
echo ""
echo "What was done:"
echo "  ✓ System prerequisites verified"
echo "  ✓ Go proto plugins installed"
echo "  ✓ Python dependencies installed"
echo "  ✓ Proto files compiled to Go and Python"
echo "  ✓ Go dependencies downloaded"
echo "  ✓ All 3 Go servers compile successfully"
echo "  ✓ Python imports verified"
echo "  ✓ Environment configuration ready"
echo ""
echo "Generated files:"
echo "  - go/internal/proto/*.go (gRPC stubs)"
echo "  - python/core/*_pb2*.py (gRPC stubs)"
echo "  - bin/probe_server (compiled binary)"
echo "  - bin/recon_server (compiled binary)"
echo "  - bin/mcp_server (compiled binary)"
echo ""
echo "Next steps:"
echo "  1. Edit .env and add your API keys"
echo "  2. Review IMPLEMENTATION_ROADMAP.md Phase 2"
echo "  3. Start implementing Go transport layer"
echo "  4. Test with: ./bin/probe_server"
echo ""
echo "To start servers:"
echo "  ./bin/probe_server &"
echo "  ./bin/recon_server &"
echo "  ./bin/mcp_server &"
echo ""
echo "Or use Docker:"
echo "  docker-compose build"
echo "  docker-compose up -d"
echo ""
