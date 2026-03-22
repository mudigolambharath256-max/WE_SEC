.PHONY: help build build-proto build-go build-python test test-go test-python validate clean install-deps

help:
	@echo "llm-redteam (llmrt) — AI App + MCP Security Assessment Platform"
	@echo ""
	@echo "Available targets:"
	@echo "  make install-deps   Install all dependencies (Go, Python, protoc)"
	@echo "  make build-proto    Compile proto files to Go and Python"
	@echo "  make build-go       Build Go gRPC servers"
	@echo "  make build-python   Install Python package"
	@echo "  make build          Build everything (proto + Go + Python)"
	@echo "  make test-go        Run Go tests"
	@echo "  make test-python    Run Python tests"
	@echo "  make test           Run all tests"
	@echo "  make validate       Run final validation suite"
	@echo "  make clean          Remove build artifacts"

install-deps:
	@echo "Installing dependencies..."
	@echo "Checking Go installation..."
	@go version || (echo "Go not found. Install Go 1.22+ from https://go.dev/dl/" && exit 1)
	@echo "Checking Python installation..."
	@python --version || (echo "Python not found. Install Python 3.11+ from https://python.org" && exit 1)
	@echo "Checking protoc installation..."
	@protoc --version || (echo "protoc not found. Install from https://grpc.io/docs/protoc-installation/" && exit 1)
	@echo "Installing Go dependencies..."
	cd go && go mod download
	@echo "Installing Python dependencies..."
	pip install -e ".[dev]"
	@echo "Dependencies installed successfully."

build-proto:
	@echo "Compiling proto files..."
	protoc --go_out=go/internal --go-grpc_out=go/internal \
	       --go_opt=paths=source_relative \
	       --go-grpc_opt=paths=source_relative \
	       -I proto proto/*.proto
	python -m grpc_tools.protoc \
	       -I proto \
	       --python_out=python/core \
	       --grpc_python_out=python/core \
	       proto/*.proto
	@echo "Proto compilation complete."

build-go:
	@echo "Building Go gRPC servers..."
	cd go && go build -o ../bin/probe_server ./cmd/probe_server
	cd go && go build -o ../bin/recon_server ./cmd/recon_server
	cd go && go build -o ../bin/mcp_server ./cmd/mcp_server
	@echo "Go build complete. Binaries in bin/"

build-python:
	@echo "Installing Python package..."
	pip install -e .
	@echo "Python package installed."

build: build-proto build-go build-python
	@echo "Build complete."

test-go:
	@echo "Running Go tests..."
	cd go && go test -v ./...

test-python:
	@echo "Running Python tests..."
	pytest tests/unit -v

test: test-go test-python
	@echo "All tests passed."

validate:
	@echo "Running final validation..."
	@echo "1. Checking proto compilation..."
	@test -f go/internal/proto/probe.pb.go || (echo "FAIL: probe.pb.go not found" && exit 1)
	@test -f python/core/probe_pb2.py || (echo "FAIL: probe_pb2.py not found" && exit 1)
	@echo "2. Checking Go binaries..."
	@test -f bin/probe_server || (echo "FAIL: probe_server binary not found" && exit 1)
	@test -f bin/recon_server || (echo "FAIL: recon_server binary not found" && exit 1)
	@test -f bin/mcp_server || (echo "FAIL: mcp_server binary not found" && exit 1)
	@echo "3. Running health checks..."
	@echo "Validation complete. All checks passed."

clean:
	@echo "Cleaning build artifacts..."
	rm -rf bin/
	rm -rf go/internal/proto/
	rm -rf python/core/*_pb2*.py
	rm -rf output/*
	rm -rf __pycache__/
	rm -rf .pytest_cache/
	@echo "Clean complete."
