# llmrt Implementation Roadmap

**Status**: Blueprint Complete → Implementation Required  
**Estimated Time**: 2-4 weeks full-time development  
**Priority**: Execute in exact order listed below

---

## Executive Summary

The llmrt project has a **complete architectural blueprint** with all files, structure, and interfaces defined. However, most modules contain stubs rather than working implementations.

**Root Cause**: Proto files were never compiled, so gRPC communication doesn't work.

**Critical Path**: 
1. Compile proto files → 2. Implement Go servers → 3. Implement Python core → 4. Implement attack modules

---

## Phase 1: Foundation Setup (Day 1)

### 1.1 System Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
    protobuf-compiler \
    golang-goprotobuf-dev \
    nmap \
    libfuzzy-dev \
    libsqlcipher-dev \
    libpango-1.0-0 \
    curl wget git

# Verify versions
go version      # Must be >= 1.22
python3 --version  # Must be >= 3.11
protoc --version   # Must be >= 3.0
```

### 1.2 Go Proto Plugins

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

export PATH="$PATH:$(go env GOPATH)/bin"
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
```

### 1.3 Python Dependencies

```bash
pip install grpcio==1.64.0 grpcio-tools==1.64.0
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e ".[all]"
playwright install chromium --with-deps
```

### 1.4 **CRITICAL: Compile Proto Files**

```bash
# Create common.proto if missing
cat > proto/common.proto << 'EOF'
syntax = "proto3";
package llmrt;
option go_package = "github.com/llmrt/llm-redteam/go/internal/proto";

message HealthRequest {}
message HealthResponse {
  bool ok = 1;
  string version = 2;
}
EOF

# Compile to Go
mkdir -p go/internal/proto
protoc \
  --go_out=go/internal/proto \
  --go-grpc_out=go/internal/proto \
  --go_opt=paths=source_relative \
  --go-grpc_opt=paths=source_relative \
  -I proto \
  proto/*.proto

# Compile to Python
python -m grpc_tools.protoc \
  -I proto \
  --python_out=python/core \
  --grpc_python_out=python/core \
  proto/*.proto

# Verify
ls go/internal/proto/*.go
ls python/core/*_pb2.py
```

### 1.5 Go Dependencies

```bash
cd go
go mod tidy
go mod download
cd ..
```

### 1.6 Verification

```bash
# Test Go compilation
cd go
go build ./cmd/probe_server/
go build ./cmd/recon_server/
go build ./cmd/mcp_server/
cd ..

# Test Python imports
python -c "from python.core.scope_validator import ScopeValidator; print('OK')"
```

**Checkpoint**: If any of the above fails, STOP and fix before proceeding.

---

## Phase 2: Go Speed Layer (Days 2-5)

### Priority Order:
1. transport/rate_limiter.go
2. transport/adapter.go
3. proberunner/runner.go
4. cmd/probe_server/main.go
5. cmd/recon_server/main.go
6. cmd/mcp_server/main.go

### 2.1 Implement rate_limiter.go

**File**: `go/internal/transport/rate_limiter.go`  
**Status**: Stub exists  
**Action**: Replace with token bucket implementation  
**Reference**: See llmrt_next_steps.md T2-A for complete code  
**Test**: Unit test with concurrent goroutines

### 2.2 Implement adapter.go

**File**: `go/internal/transport/adapter.go`  
**Status**: Stub exists  
**Action**: Implement HTTP client with:
- JSON body injection ($PAYLOAD replacement)
- Proxy support (PROXY_BACKEND env)
- 30s timeout
- Auth header injection

**Reference**: See llmrt_next_steps.md T2-B  
**Test**: Fire test request to httpbin.org

### 2.3 Implement runner.go

**File**: `go/internal/proberunner/runner.go`  
**Status**: Stub exists  
**Action**: Implement goroutine pool with:
- Concurrent execution (configurable concurrency)
- Rate limiting integration
- ChatInject/FlipAttack transforms
- Result streaming

**Reference**: See llmrt_next_steps.md T2-C  
**Test**: Fire 100 payloads, verify rate limiting works

### 2.4 Implement probe_server/main.go

**File**: `go/cmd/probe_server/main.go`  
**Status**: Stub exists  
**Action**: Implement gRPC server with:
- FireBatch streaming RPC
- HealthCheck RPC
- Graceful shutdown

**Reference**: See llmrt_next_steps.md T2-D  
**Test**: Start server, call HealthCheck via grpcurl

### 2.5 Implement recon_server/main.go

**File**: `go/cmd/recon_server/main.go`  
**Status**: Stub exists  
**Action**: Similar to probe_server but for recon RPCs  
**Test**: Start server, verify health check

### 2.6 Implement mcp_server/main.go

**File**: `go/cmd/mcp_server/main.go`  
**Status**: Stub exists  
**Action**: Similar to probe_server but for MCP RPCs  
**Test**: Start server, verify health check

**Checkpoint**: All 3 Go servers should start and respond to health checks.

---

## Phase 3: Python Core (Days 6-8)

### Priority Order:
1. core/grpc_clients.py
2. evidence/store.py
3. core/response_classifier.py
4. evidence/scorer.py
5. evidence/deduplicator.py
6. evidence/verifier.py

### 3.1 Implement grpc_clients.py

**File**: `python/core/grpc_clients.py`  
**Status**: Stub exists  
**Action**: Implement gRPC client wrappers for all 3 services  
**Reference**: See llmrt_next_steps.md T3-A  
**Test**: Connect to running Go servers, call health checks

### 3.2 Implement store.py

**File**: `python/evidence/store.py`  
**Status**: Partial stub  
**Action**: Implement SQLCipher encrypted database  
**Reference**: See llmrt_next_steps.md T3-B  
**Dependencies**: `pip install pysqlcipher3`  
**Test**: Create campaign, save finding, retrieve it

### 3.3 Implement response_classifier.py

**File**: `python/core/response_classifier.py`  
**Status**: Likely complete (rule-based)  
**Action**: Verify 5-state classification works  
**Test**: Unit tests with sample responses

### 3.4 Implement scorer.py

**File**: `python/evidence/scorer.py`  
**Status**: Stub exists  
**Action**: Implement CVSS 4.0 scoring  
**Test**: Score sample findings, verify CVSS vectors

### 3.5 Implement deduplicator.py

**File**: `python/evidence/deduplicator.py`  
**Status**: Stub exists  
**Action**: Implement ssdeep fuzzy hashing  
**Dependencies**: `pip install ssdeep`  
**Test**: Check duplicate detection with similar findings

### 3.6 Implement verifier.py

**File**: `python/evidence/verifier.py`  
**Status**: Stub exists  
**Action**: Implement 4-layer FP verification  
**Test**: Verify false positive detection

**Checkpoint**: Python core should be able to connect to Go, save findings to encrypted DB.

---

## Phase 4: External Tools (Days 9-10)

### 4.1 Clone External Repositories

```bash
cd external/

# White-box analysis
git clone https://github.com/dreadnode/shannon.git
git clone https://github.com/dreadnode/vulnhuntr.git

# LLM security tools
git clone https://github.com/leondz/garak.git
git clone https://github.com/Azure/PyRIT.git pyrit

# RAG security
git clone https://github.com/deadbits/llamator.git

# Additional tools (if repos exist)
# git clone <augustus-repo>
# git clone <deepteam-repo>
# git clone <artkit-repo>
# git clone <rigging-repo>
# git clone <promptfoo-repo>
```

### 4.2 Install External Tools

```bash
# Shannon
cd external/shannon
pip install -r requirements.txt
cd ../..

# Vulnhuntr
cd external/vulnhuntr
pip install -r requirements.txt
cd ../..

# Garak
cd external/garak
pip install -e .
cd ../..

# PyRIT
cd external/pyrit
pip install -e .
cd ../..
```

### 4.3 Implement Runner Wrappers

For each external tool, implement the Python wrapper:
- `python/recon/shannon_runner.py`
- `python/recon/vulnhuntr_runner.py`
- `python/prompt_attacks/garak_runner.py`
- `python/prompt_attacks/pyrit_runner.py`
- `python/rag_attacks/llamator_runner.py`

**Pattern**: Each runner should:
1. Validate scope
2. Call external tool via subprocess
3. Parse output
4. Return normalized findings

---

## Phase 5: Attack Modules (Days 11-15)

### Priority Order (implement in this sequence):

1. **Prompt Attacks** (Days 11-12)
   - corpus_runner.py
   - oob_detector.py
   - unicode_injection_runner.py
   - rce_probe_runner.py
   - flipattack_runner.py

2. **MCP Attacks** (Days 13-14)
   - lethal_trifecta_detector.py
   - rug_pull_tester.py
   - mcp_tool_llm_scanner.py
   - sql_inject_mcp.py

3. **RAG Attacks** (Day 15)
   - doc_injector.py
   - vector_db_attacker.py
   - memory_poison_tester.py

### Implementation Pattern for Each Module:

```python
"""
Module: <attack_name>_runner.py

Description: <what attack this implements>
"""

from python.core.scope_validator import ScopeValidator, OutOfScopeError
from python.core.grpc_clients import GRPCClients
import logging

logger = logging.getLogger(__name__)

async def run_attack(
    target_url: str,
    scope_validator: ScopeValidator,
    grpc_clients: GRPCClients,
    config: dict
) -> list[dict]:
    """
    Execute <attack_name> against target.
    
    Args:
        target_url: Target endpoint URL
        scope_validator: Scope validator instance
        grpc_clients: gRPC client connections
        config: Attack configuration
    
    Returns:
        List of findings
    
    Raises:
        OutOfScopeError: If target is out of scope
    """
    # 1. Validate scope
    scope_validator.validate_or_raise(target_url)
    
    # 2. Load payloads
    payloads = load_payloads(config)
    
    # 3. Fire via gRPC
    findings = []
    for result in grpc_clients.probe.fire_batch(request):
        if is_vulnerable(result):
            findings.append(normalize_finding(result))
    
    return findings
```

---

## Phase 6: Orchestration (Days 16-18)

### 6.1 Implement orchestrator.py

**File**: `python/core/orchestrator.py`  
**Status**: Stub exists  
**Action**: Implement campaign controller with:
- Phase gating (recon → attack → report)
- Attack module selection
- Evidence collection
- Error handling

### 6.2 Implement adaptive_orchestrator.py

**File**: `python/core/adaptive_orchestrator.py`  
**Status**: Stub exists  
**Action**: Implement dynamic strategy selection based on recon results

### 6.3 Implement progressive_prober.py

**File**: `python/core/progressive_prober.py`  
**Status**: Stub exists  
**Action**: Implement 5-level escalation strategy

---

## Phase 7: Reporting (Days 19-20)

### 7.1 Implement Framework Mappers

- mitre_mapper.py
- owasp_llm_mapper.py
- adversa_mcp_mapper.py
- hardening_advisor.py

### 7.2 Implement generator.py

**File**: `python/reporting/generator.py`  
**Status**: Stub exists  
**Action**: Implement multi-format report generation (HTML, PDF, JSON, MD)

---

## Phase 8: API & CLI (Days 21-22)

### 8.1 Implement FastAPI Application

**File**: `python/api/app.py`  
**Status**: Stub exists  
**Action**: Implement REST API endpoints

### 8.2 Implement CLI

**File**: `python/cli/main.py`  
**Status**: Stub exists  
**Action**: Implement Typer CLI commands

---

## Phase 9: Docker & Testing (Days 23-25)

### 9.1 Build Docker Images

```bash
docker-compose build
```

### 9.2 Integration Testing

```bash
docker-compose --profile testing up -d
pytest -m integration
```

### 9.3 End-to-End Testing

```bash
# Test against mock servers
llmrt scan --target http://localhost:9999 --profile chatbot
llmrt scan --target http://localhost:9998 --profile mcp_agent
```

---

## Phase 10: Documentation & Polish (Days 26-28)

### 10.1 Update Documentation
- README.md with actual usage examples
- API documentation
- Troubleshooting guide

### 10.2 Performance Optimization
- Profile bottlenecks
- Optimize rate limiting
- Tune concurrency

### 10.3 Security Hardening
- Review auth handling
- Audit secret management
- Test scope validation

---

## Success Criteria

### Minimum Viable Product (MVP):
- [ ] All 3 Go servers start and respond to health checks
- [ ] Python can connect via gRPC
- [ ] Can fire basic prompt injection probes
- [ ] Findings saved to encrypted database
- [ ] Basic HTML report generated

### Full Feature Complete:
- [ ] All 42 attack modules implemented
- [ ] All external tools integrated
- [ ] Docker deployment works
- [ ] CI/CD pipeline passes
- [ ] Documentation complete
- [ ] Can run full campaign end-to-end

---

## Risk Mitigation

### High-Risk Areas:
1. **Proto compilation** - If this fails, nothing works
2. **SQLCipher** - May have platform-specific issues
3. **External tools** - May not exist or be incompatible
4. **gRPC streaming** - Complex error handling needed

### Mitigation Strategies:
1. Test proto compilation on multiple platforms
2. Provide fallback to unencrypted SQLite for dev
3. Make external tools optional (graceful degradation)
4. Implement robust gRPC error handling and retries

---

## Resource Requirements

### Development Team:
- 1 Go developer (Go servers)
- 1 Python developer (Core + attack modules)
- 1 Security researcher (Attack logic validation)
- 1 DevOps engineer (Docker + CI/CD)

### Infrastructure:
- Development machines with 16GB+ RAM
- Docker with 8GB+ memory allocation
- API keys: Anthropic, NVD, Shodan (optional)

---

## Next Immediate Actions

**RIGHT NOW** (in this order):

1. ✅ Read llmrt_next_steps.md (DONE)
2. ⏭️ Execute Phase 1.4: Compile proto files
3. ⏭️ Verify Go servers compile
4. ⏭️ Implement rate_limiter.go
5. ⏭️ Implement adapter.go

**DO NOT** proceed to attack modules until Go servers are working.

---

## Conclusion

This is a **high-quality architectural blueprint** that needs **systematic implementation**. The structure is excellent, the design is sound, but the code needs to be written.

**Estimated Timeline**: 2-4 weeks with focused development  
**Current Value**: Saves 2-3 months of architecture and design work  
**Next Step**: Execute Phase 1.4 (compile proto files)
