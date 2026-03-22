# llmrt — Gap Analysis & Next Steps
# Based on current build state analysis
# Prioritised action plan — execute in order

---

## REALITY CHECK SUMMARY

| Layer | Status | Blocking? |
|---|---|---|
| Directory structure | ✅ Complete | No |
| Proto files (.proto) | ✅ Exist | — |
| Proto compilation (generated code) | ❌ NOT compiled | **YES — nothing works** |
| Go implementations | ⚠️ Partial stubs | **YES — servers won't start** |
| Python core implementations | ⚠️ Partial stubs | **YES — orchestrator broken** |
| Python attack modules | ❌ Stubs only | YES |
| External tool repos | ❌ NOT cloned | YES |
| Python pip dependencies | ❌ NOT installed | **YES** |
| Go mod dependencies | ❌ NOT downloaded | **YES** |
| Data files (KEV, corpora) | ❌ NOT downloaded | YES |
| Docker images | ❌ NOT built | YES |
| Tests | ⚠️ Scaffolded, would fail | No (dev phase) |

**Root cause: The proto files were never compiled. This means the gRPC stubs
(Go + Python) do not exist. Without them, nothing can start.**

Fix proto compilation first. Everything else depends on it.

---

## TIER 1 — FOUNDATION (Do these first, in order, before anything else)

### T1-A: Install system prerequisites

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y \
    protobuf-compiler \
    golang-goprotobuf-dev \
    nmap \
    libfuzzy-dev \
    libsqlcipher-dev \
    libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
    curl wget git unzip

# Verify Go 1.22+
go version   # must be >= 1.22

# Verify Python 3.11+
python3 --version   # must be >= 3.11

# Verify Node.js 18+
node --version   # must be >= 18
```

### T1-B: Install Go proto plugins (one-time)

```bash
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Add to PATH if not already there
export PATH="$PATH:$(go env GOPATH)/bin"
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.bashrc
```

### T1-C: Install Python dependencies

```bash
# From repo root
pip install grpcio==1.64.0 grpcio-tools==1.64.0

# CPU-only torch (saves ~2GB vs CUDA version)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Install everything else
pip install -e ".[all]"

# Playwright browser
playwright install chromium --with-deps

# Verify key packages installed
python -c "import grpc; print('gRPC OK')"
python -c "import anthropic; print('Anthropic OK')"
python -c "from sentence_transformers import SentenceTransformer; print('SentenceTransformers OK')"
```

### T1-D: COMPILE PROTO FILES — THIS IS THE CRITICAL STEP

```bash
# From repo root — run this exact command
mkdir -p go/internal/proto

# Compile to Go
protoc \
  --go_out=go/internal/proto \
  --go-grpc_out=go/internal/proto \
  --go_opt=paths=source_relative \
  --go-grpc_opt=paths=source_relative \
  -I proto \
  proto/common.proto proto/probe.proto proto/recon.proto proto/mcp.proto

# Compile to Python
python -m grpc_tools.protoc \
  -I proto \
  --python_out=python/core \
  --grpc_python_out=python/core \
  proto/common.proto proto/probe.proto proto/recon.proto proto/mcp.proto

# Verify — these files MUST exist after compilation:
ls go/internal/proto/*.go          # should show probe.pb.go, recon.pb.go, mcp.pb.go etc.
ls python/core/*_pb2.py            # should show probe_pb2.py, recon_pb2.py, mcp_pb2.py

# If proto/common.proto doesn't exist, create it first:
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
```

### T1-E: Update Go module imports to point at generated proto

After proto compilation, each Go cmd/main.go and internal package that uses gRPC
must import from the correct path. Verify go.mod has:

```
module github.com/llmrt/llm-redteam
```

And internal packages import as:
```go
import pb "github.com/llmrt/llm-redteam/go/internal/proto"
```

Download Go dependencies:
```bash
cd go
go mod tidy
go mod download
cd ..
```

### T1-F: Verify foundation compiles

```bash
# Go — all 3 servers must compile without errors
cd go
go build ./cmd/probe_server/   # must succeed
go build ./cmd/recon_server/   # must succeed
go build ./cmd/mcp_server/     # must succeed
cd ..

# Python — core imports must work
python -c "from python.core.scope_validator import ScopeValidator; print('scope_validator OK')"
python -c "from python.core.grpc_clients import ProbeClient; print('grpc_clients OK')"
python -c "from python.evidence.models import Finding; print('evidence models OK')"

# If any import fails — that module needs implementation (see Tier 2)
```

---

## TIER 2 — GO SERVER IMPLEMENTATIONS

The Go servers have stubs. These are the highest priority because Python cannot
fire any probes without them. Implement in this order:

### T2-A: go/internal/transport/rate_limiter.go

Replace stub with this complete implementation:

```go
package transport

import (
    "context"
    "sync"
    "time"
)

// RateLimiter implements a token bucket rate limiter safe for concurrent use.
// All probe goroutines call Wait() before firing — this enforces the per-campaign
// rate limit and prevents unintentional DoS of the target.
type RateLimiter struct {
    mu       sync.Mutex
    tokens   float64
    maxBurst float64
    rps      float64
    lastTime time.Time
}

// NewRateLimiter creates a rate limiter.
// rps: requests per second (e.g. 5.0 for 5 req/s)
// burst: maximum burst size (use same value as rps for strict limiting)
func NewRateLimiter(rps float64, burst int) *RateLimiter {
    return &RateLimiter{
        tokens:   float64(burst),
        maxBurst: float64(burst),
        rps:      rps,
        lastTime: time.Now(),
    }
}

// Wait blocks until a token is available or ctx is cancelled.
// Returns ctx.Err() if cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
    for {
        r.mu.Lock()
        now := time.Now()
        elapsed := now.Sub(r.lastTime).Seconds()
        r.tokens = min(r.maxBurst, r.tokens+(elapsed*r.rps))
        r.lastTime = now

        if r.tokens >= 1.0 {
            r.tokens -= 1.0
            r.mu.Unlock()
            return nil
        }
        // Calculate wait time for next token
        waitMs := time.Duration((1.0-r.tokens)/r.rps*1000) * time.Millisecond
        r.mu.Unlock()

        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-time.After(waitMs):
        }
    }
}

// SetRate dynamically adjusts the rate limit during a campaign.
func (r *RateLimiter) SetRate(rps float64) {
    r.mu.Lock()
    defer r.mu.Unlock()
    r.rps = rps
    r.maxBurst = rps
}

func min(a, b float64) float64 {
    if a < b {
        return a
    }
    return b
}
```

### T2-B: go/internal/transport/adapter.go — critical path

The adapter is what actually fires HTTP requests to the target. Key requirements:
- Supports JSON body injection, form body, SSE, WebSocket
- Body template: replaces `$PAYLOAD` placeholder
- Respects proxy setting from PROXY_BACKEND env var
- 30s timeout hard limit
- Returns: response_body string, status_code int, latency_ms int64, error

```go
package transport

import (
    "bytes"
    "context"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "strings"
    "time"
)

type Adapter struct {
    EndpointURL string
    Method      string
    BodySchema  string     // JSON template with $PAYLOAD placeholder
    BaseHeaders map[string]string
    client      *http.Client
}

func NewAdapter(endpointURL, method, bodySchema string, headers map[string]string) *Adapter {
    transport := &http.Transport{}
    
    // Honour PROXY_BACKEND env var
    if proxyURL := os.Getenv("PROXY_BACKEND"); proxyURL != "" {
        if parsed, err := url.Parse("http://localhost:" + getProxyPort(proxyURL)); err == nil {
            transport.Proxy = http.ProxyURL(parsed)
        }
    }
    
    return &Adapter{
        EndpointURL: endpointURL,
        Method:      method,
        BodySchema:  bodySchema,
        BaseHeaders: headers,
        client:      &http.Client{Transport: transport, Timeout: 30 * time.Second},
    }
}

// Inject fires one HTTP request with payload injected into the body template.
func (a *Adapter) Inject(ctx context.Context, payload string, auth map[string]string) (
    responseBody string, statusCode int, latencyMs int64, err error) {

    body := strings.ReplaceAll(a.BodySchema, "$PAYLOAD", payload)
    
    req, err := http.NewRequestWithContext(ctx, a.Method, a.EndpointURL, 
        bytes.NewBufferString(body))
    if err != nil {
        return "", 0, 0, fmt.Errorf("request creation failed: %w", err)
    }
    
    // Apply base headers
    for k, v := range a.BaseHeaders {
        req.Header.Set(k, v)
    }
    // Apply auth headers (override base if conflict)
    for k, v := range auth {
        req.Header.Set(k, v)
    }
    if req.Header.Get("Content-Type") == "" {
        req.Header.Set("Content-Type", "application/json")
    }
    
    start := time.Now()
    resp, err := a.client.Do(req)
    latencyMs = time.Since(start).Milliseconds()
    
    if err != nil {
        return "", 0, latencyMs, fmt.Errorf("request failed: %w", err)
    }
    defer resp.Body.Close()
    
    respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB limit
    if err != nil {
        return "", resp.StatusCode, latencyMs, fmt.Errorf("response read failed: %w", err)
    }
    
    return string(respBytes), resp.StatusCode, latencyMs, nil
}

func getProxyPort(backend string) string {
    switch backend {
    case "mitmproxy":
        if p := os.Getenv("MITMPROXY_PORT"); p != "" {
            return p
        }
        return "8080"
    case "zap":
        if p := os.Getenv("ZAP_PORT"); p != "" {
            return p
        }
        return "8090"
    default:
        return "8080"
    }
}
```

### T2-C: go/internal/proberunner/runner.go — the goroutine pool

This is the core of the Go speed layer. Without this, FireBatch() does nothing.

```go
package proberunner

import (
    "context"
    "fmt"
    "log"
    "sync"
    "sync/atomic"
    "time"
    
    pb "github.com/llmrt/llm-redteam/go/internal/proto"
    "github.com/llmrt/llm-redteam/go/internal/transport"
)

// Runner executes probe batches using a goroutine pool.
// It applies ChatInject and FlipAttack transforms before firing.
type Runner struct {
    concurrency int
    rateLimiter *transport.RateLimiter
}

func NewRunner(concurrency int, rps float64) *Runner {
    return &Runner{
        concurrency: concurrency,
        rateLimiter: transport.NewRateLimiter(rps, concurrency),
    }
}

// FireBatch executes all payloads in the request concurrently.
// Results are sent to the results channel as they arrive.
// The function blocks until all payloads are processed or ctx is cancelled.
func (r *Runner) FireBatch(
    ctx context.Context,
    req *pb.ProbeBatchRequest,
    results chan<- *pb.ProbeResult,
) error {
    adapter := transport.NewAdapter(
        req.EndpointUrl,
        req.Method,
        req.BodySchema,
        req.Headers,
    )
    
    // Build full payload list with transforms applied
    allPayloads := r.expandPayloads(req)
    
    sem := make(chan struct{}, r.concurrency)
    var wg sync.WaitGroup
    var errCount int64
    var successCount int64
    
    // Throughput logging
    ticker := time.NewTicker(10 * time.Second)
    go func() {
        for range ticker.C {
            log.Printf("[runner] campaign=%s throughput: success=%d errors=%d",
                req.CampaignId, atomic.LoadInt64(&successCount), atomic.LoadInt64(&errCount))
        }
    }()
    defer ticker.Stop()
    
    for _, payload := range allPayloads {
        payload := payload // capture loop var
        
        select {
        case <-ctx.Done():
            break
        default:
        }
        
        if err := r.rateLimiter.Wait(ctx); err != nil {
            break // context cancelled
        }
        
        sem <- struct{}{}
        wg.Add(1)
        
        go func() {
            defer wg.Done()
            defer func() { <-sem }()
            
            body, status, latency, err := adapter.Inject(ctx, payload.text, req.Headers)
            
            result := &pb.ProbeResult{
                Payload:     payload.original,
                StatusCode:  int32(status),
                LatencyMs:   latency,
                ProbeFamily: payload.family,
            }
            
            if err != nil {
                result.ErrorMessage = err.Error()
                atomic.AddInt64(&errCount, 1)
            } else {
                result.ResponseBody = body
                atomic.AddInt64(&successCount, 1)
            }
            
            select {
            case results <- result:
            case <-ctx.Done():
            }
        }()
    }
    
    wg.Wait()
    
    if errCount > 0 && successCount == 0 {
        return fmt.Errorf("all %d probes failed — check target connectivity and auth", errCount)
    }
    return nil
}

type expandedPayload struct {
    text     string
    original string
    family   string
}

func (r *Runner) expandPayloads(req *pb.ProbeBatchRequest) []expandedPayload {
    var out []expandedPayload
    for _, p := range req.Payloads {
        // Always include original
        out = append(out, expandedPayload{text: p, original: p, family: "original"})
        
        if req.ApplyChatinject && req.TemplateId != "" {
            wrapped := WrapPayload(p, req.TemplateId)
            out = append(out, expandedPayload{text: wrapped, original: p, family: "chatinject_" + req.TemplateId})
        }
        
        if req.ApplyFlipattack {
            fcs := ApplyFCS(p)
            fcw := ApplyFCW(p)
            fwo := ApplyFWO(p)
            out = append(out,
                expandedPayload{text: fcs, original: p, family: "flipattack_fcs"},
                expandedPayload{text: fcw, original: p, family: "flipattack_fcw"},
                expandedPayload{text: fwo, original: p, family: "flipattack_fwo"},
            )
        }
    }
    return out
}
```

### T2-D: Go gRPC server entrypoints — probe_server/main.go

Each cmd/X_server/main.go must start the gRPC server, register the service, 
and handle graceful shutdown. Template for probe_server:

```go
package main

import (
    "context"
    "log"
    "net"
    "os"
    "os/signal"
    "syscall"
    
    "google.golang.org/grpc"
    pb "github.com/llmrt/llm-redteam/go/internal/proto"
    "github.com/llmrt/llm-redteam/go/internal/proberunner"
)

type probeServer struct {
    pb.UnimplementedProbeServiceServer
    runner *proberunner.Runner
}

func (s *probeServer) FireBatch(
    req *pb.ProbeBatchRequest,
    stream pb.ProbeService_FireBatchServer,
) error {
    results := make(chan *pb.ProbeResult, 100)
    ctx := stream.Context()
    
    go func() {
        defer close(results)
        if err := s.runner.FireBatch(ctx, req, results); err != nil {
            log.Printf("FireBatch error: %v", err)
        }
    }()
    
    for result := range results {
        if err := stream.Send(result); err != nil {
            return err
        }
    }
    return nil
}

func (s *probeServer) HealthCheck(
    ctx context.Context, req *pb.HealthRequest,
) (*pb.HealthResponse, error) {
    return &pb.HealthResponse{Ok: true, Version: "1.0.0"}, nil
}

func main() {
    port := os.Getenv("PROBE_PORT")
    if port == "" {
        port = "50051"
    }
    
    rps := 5.0
    concurrency := 500
    
    lis, err := net.Listen("tcp", ":"+port)
    if err != nil {
        log.Fatalf("failed to listen on :%s: %v", port, err)
    }
    
    srv := grpc.NewServer(
        grpc.MaxRecvMsgSize(50*1024*1024),
        grpc.MaxSendMsgSize(50*1024*1024),
    )
    
    pb.RegisterProbeServiceServer(srv, &probeServer{
        runner: proberunner.NewRunner(concurrency, rps),
    })
    
    log.Printf("probe-server listening on :%s (concurrency=%d, rps=%.1f)", port, concurrency, rps)
    
    // Graceful shutdown
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    go func() {
        <-quit
        log.Println("probe-server shutting down...")
        srv.GracefulStop()
    }()
    
    if err := srv.Serve(lis); err != nil {
        log.Fatalf("serve failed: %v", err)
    }
}
```

Apply the same pattern for recon_server/main.go and mcp_server/main.go.

---

## TIER 3 — PYTHON CORE IMPLEMENTATIONS (Priority order)

These modules are the foundation of the intelligence layer. 
Implement in this exact sequence — each depends on the previous.

### T3-A: python/core/grpc_clients.py — connects Python to Go

This is likely a stub. It needs real gRPC channel management:

```python
"""
gRPC client wrappers for the 3 Go speed-layer services.

Each client holds one persistent gRPC channel opened at campaign start
and closed on completion. Auth context is passed on every call — Go servers
are stateless and never store campaign state.

Usage:
    clients = GRPCClients.from_env()
    async for result in clients.probe.fire_batch(request):
        process(result)
"""

import os
import grpc
from typing import AsyncIterator

# These imports only work after proto compilation (T1-D)
from python.core import probe_pb2, probe_pb2_grpc
from python.core import recon_pb2, recon_pb2_grpc
from python.core import mcp_pb2, mcp_pb2_grpc


class ProbeClient:
    """Client for ProbeService — fires HTTP probe batches via Go goroutine pool."""
    
    def __init__(self, address: str):
        self.channel = grpc.insecure_channel(
            address,
            options=[
                ('grpc.max_send_message_length', 50 * 1024 * 1024),
                ('grpc.max_receive_message_length', 50 * 1024 * 1024),
            ]
        )
        self.stub = probe_pb2_grpc.ProbeServiceStub(self.channel)
    
    def fire_batch(self, request: probe_pb2.ProbeBatchRequest):
        """Stream probe results from Go goroutine pool. Blocks until all done."""
        return self.stub.FireBatch(request)
    
    def health_check(self) -> bool:
        try:
            resp = self.stub.HealthCheck(probe_pb2.HealthRequest())
            return resp.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        self.channel.close()


class ReconClient:
    """Client for ReconService — port scanning and endpoint fuzzing."""
    
    def __init__(self, address: str):
        self.channel = grpc.insecure_channel(address)
        self.stub = recon_pb2_grpc.ReconServiceStub(self.channel)
    
    def scan_ports(self, host: str) -> recon_pb2.PortScanResult:
        return self.stub.ScanPorts(recon_pb2.PortScanRequest(host=host))
    
    def fuzz_endpoints(self, request: recon_pb2.FuzzRequest) -> recon_pb2.FuzzResult:
        return self.stub.FuzzEndpoints(request)
    
    def health_check(self) -> bool:
        try:
            resp = self.stub.HealthCheck(recon_pb2.HealthRequest())
            return resp.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        self.channel.close()


class MCPClient:
    """Client for MCPService — MCP protocol enumeration and attack battery."""
    
    def __init__(self, address: str):
        self.channel = grpc.insecure_channel(address)
        self.stub = mcp_pb2_grpc.MCPServiceStub(self.channel)
    
    def enumerate_tools(self, request: mcp_pb2.MCPEnumRequest) -> mcp_pb2.MCPSchema:
        return self.stub.EnumerateTools(request)
    
    def fire_mcp_attacks(self, request: mcp_pb2.MCPAttackRequest):
        return self.stub.FireMCPAttacks(request)
    
    def health_check(self) -> bool:
        try:
            resp = self.stub.HealthCheck(mcp_pb2.HealthRequest())
            return resp.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        self.channel.close()


class GRPCClients:
    """Container for all 3 gRPC clients. Open once per campaign, close on done."""
    
    def __init__(self, probe_addr: str, recon_addr: str, mcp_addr: str):
        self.probe = ProbeClient(probe_addr)
        self.recon = ReconClient(recon_addr)
        self.mcp = MCPClient(mcp_addr)
    
    @classmethod
    def from_env(cls) -> "GRPCClients":
        """Create clients from PROBE_GRPC, RECON_GRPC, MCP_GRPC env vars."""
        return cls(
            probe_addr=os.environ.get("PROBE_GRPC", "localhost:50051"),
            recon_addr=os.environ.get("RECON_GRPC", "localhost:50052"),
            mcp_addr=os.environ.get("MCP_GRPC", "localhost:50053"),
        )
    
    def health_check_all(self) -> dict[str, bool]:
        """Returns health status of all 3 Go services."""
        return {
            "probe_server": self.probe.health_check(),
            "recon_server": self.recon.health_check(),
            "mcp_server":   self.mcp.health_check(),
        }
    
    def close(self):
        """Close all channels. Call on campaign completion or abort."""
        self.probe.close()
        self.recon.close()
        self.mcp.close()
```

### T3-B: python/evidence/store.py — the SQLCipher evidence database

This is the most critical Python module. Everything gets written here.
The stub likely has create_tables() but not the actual encrypted connection.

```python
"""
Evidence store — SQLCipher-encrypted SQLite database.

All findings, campaign metadata, sessions, and OOB callbacks are stored here.
The database is encrypted at rest using SQLCipher. The encryption key is read
from CAMPAIGN_ENCRYPT_KEY — never hardcoded.

SQLCipher requires pysqlcipher3: pip install pysqlcipher3
System: apt-get install libsqlcipher-dev
"""

import os
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import create_engine, text, Column, String, Float, Boolean, DateTime, Integer, JSON
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


def _get_engine(campaign_id: str, db_path: Optional[str] = None):
    """
    Create a SQLCipher-encrypted SQLite engine.
    
    The connection string uses pysqlcipher3 dialect.
    Key is derived from CAMPAIGN_ENCRYPT_KEY env var.
    If CAMPAIGN_ENCRYPT_KEY is not set, it is auto-generated and the operator
    is instructed to save it to .env.
    
    Args:
        campaign_id: Used for DB file path
        db_path: Override default path (used in tests)
    
    Returns:
        SQLAlchemy engine connected to encrypted database
    
    Raises:
        RuntimeError: If SQLCipher is not available
    """
    key = os.environ.get("CAMPAIGN_ENCRYPT_KEY")
    if not key:
        import secrets
        key = secrets.token_hex(32)
        logger.warning(
            f"CAMPAIGN_ENCRYPT_KEY not set. Auto-generated key: {key}\n"
            f"Add this to your .env file: CAMPAIGN_ENCRYPT_KEY={key}\n"
            f"WITHOUT THIS KEY YOU CANNOT OPEN THE DATABASE LATER."
        )
        os.environ["CAMPAIGN_ENCRYPT_KEY"] = key
    
    if db_path is None:
        db_dir = Path(f"output/campaigns/{campaign_id}")
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = str(db_dir / "findings.db")
    
    # SQLCipher connection via pysqlcipher3
    try:
        connection_string = f"sqlite+pysqlcipher://:{key}@/{db_path}"
        engine = create_engine(
            connection_string,
            connect_args={"check_same_thread": False},
        )
        logger.info(f"Evidence store opened: {db_path}")
        return engine
    except Exception as e:
        raise RuntimeError(
            f"Failed to open encrypted evidence store: {e}\n"
            f"Ensure pysqlcipher3 is installed: pip install pysqlcipher3\n"
            f"System: apt-get install libsqlcipher-dev"
        ) from e


class EvidenceStore:
    """
    Thread-safe encrypted evidence store for a single campaign.
    
    Usage:
        store = EvidenceStore(campaign_id="abc123")
        store.save_finding(finding)
        findings = store.get_confirmed_findings()
    """
    
    def __init__(self, campaign_id: str, db_path: Optional[str] = None):
        self.campaign_id = campaign_id
        self.engine = _get_engine(campaign_id, db_path)
        Base.metadata.create_all(self.engine)
        self.SessionFactory = sessionmaker(bind=self.engine)
        logger.info(f"Evidence store initialised for campaign {campaign_id}")
    
    def save_finding(self, finding) -> str:
        """
        Save a Finding model to the database.
        
        Args:
            finding: Finding Pydantic model instance
        
        Returns:
            finding.id on success
        
        Raises:
            ValueError: If finding fails validation
        """
        with Session(self.engine) as session:
            row = FindingRow(
                id=finding.id,
                campaign_id=finding.campaign_id,
                finding_hash=finding.finding_hash,
                finding_type=finding.finding_type,
                raw_family=finding.raw_family,
                source=finding.source,
                phase=finding.phase,
                endpoint=finding.endpoint,
                probe_payload=finding.probe_payload[:10000],  # truncate giant payloads
                response_body=finding.response_body[:10000],
                status_code=finding.status_code,
                latency_ms=finding.latency_ms,
                classifier_state=finding.classifier_state,
                severity=finding.severity,
                exploitability_score=finding.exploitability_score,
                impact_score=finding.impact_score,
                reliability_score=finding.reliability_score,
                reach_score=finding.reach_score,
                l2_similarity_score=finding.l2_similarity_score,
                l3_confidence=finding.l3_confidence,
                l3_judge_verdict=finding.l3_judge_verdict,
                cvss_score=finding.cvss_score,
                kev_match=finding.kev_match,
                promoted_to_critical=finding.promoted_to_critical,
                confirmed=finding.confirmed,
                false_positive=finding.false_positive,
                needs_review=finding.needs_review,
                cve_ids=finding.cve_ids,
                mitre_techniques=finding.mitre_techniques,
                owasp_llm_ids=finding.owasp_llm_ids,
                created_at=finding.created_at,
            )
            session.merge(row)  # merge = upsert (handles re-verification updates)
            session.commit()
            return finding.id
    
    def get_confirmed_findings(self) -> list:
        """Return all confirmed, non-false-positive findings for this campaign."""
        with Session(self.engine) as session:
            rows = session.query(FindingRow).filter(
                FindingRow.campaign_id == self.campaign_id,
                FindingRow.confirmed == True,
                FindingRow.false_positive == False,
            ).all()
            return rows
    
    def is_duplicate(self, finding_hash: str) -> bool:
        """Check if a finding with this hash already exists in the campaign."""
        with Session(self.engine) as session:
            count = session.query(FindingRow).filter(
                FindingRow.campaign_id == self.campaign_id,
                FindingRow.finding_hash == finding_hash,
            ).count()
            return count > 0
    
    def mark_reviewed(self, finding_id: str, confirmed: bool, notes: str = ""):
        """Human review decision: confirm or dismiss a finding."""
        with Session(self.engine) as session:
            session.query(FindingRow).filter(
                FindingRow.id == finding_id
            ).update({
                "confirmed": confirmed,
                "false_positive": not confirmed,
                "needs_review": False,
                "review_notes": notes,
            })
            session.commit()
    
    def auto_delete_old(self, retain_days: int = 30):
        """Delete campaign databases older than retain_days. Call from make clean-old."""
        cutoff = datetime.utcnow() - timedelta(days=retain_days)
        campaigns_dir = Path("output/campaigns")
        if not campaigns_dir.exists():
            return
        for campaign_dir in campaigns_dir.iterdir():
            db_file = campaign_dir / "findings.db"
            if db_file.exists():
                mtime = datetime.fromtimestamp(db_file.stat().st_mtime)
                if mtime < cutoff:
                    import shutil
                    shutil.rmtree(campaign_dir)
                    logger.info(f"Auto-deleted old campaign: {campaign_dir.name}")


class FindingRow(Base):
    """SQLAlchemy ORM model for the findings table."""
    __tablename__ = "findings"
    
    id = Column(String, primary_key=True)
    campaign_id = Column(String, nullable=False, index=True)
    finding_hash = Column(String, nullable=False, index=True)
    finding_type = Column(String, nullable=False)
    raw_family = Column(String)
    source = Column(String)
    phase = Column(String)
    endpoint = Column(String)
    probe_payload = Column(String)
    response_body = Column(String)
    status_code = Column(Integer)
    latency_ms = Column(Integer)
    classifier_state = Column(String)
    severity = Column(String, default="info")
    exploitability_score = Column(Float, default=0.0)
    impact_score = Column(Float, default=0.0)
    reliability_score = Column(Float, default=0.0)
    reach_score = Column(Float, default=0.0)
    l2_similarity_score = Column(Float, default=0.0)
    l3_confidence = Column(Float, default=0.0)
    l3_judge_verdict = Column(String)
    cvss_score = Column(Float)
    kev_match = Column(Boolean, default=False)
    promoted_to_critical = Column(Boolean, default=False)
    confirmed = Column(Boolean, default=False)
    false_positive = Column(Boolean, default=False)
    needs_review = Column(Boolean, default=False)
    review_notes = Column(String)
    cve_ids = Column(JSON, default=list)
    mitre_techniques = Column(JSON, default=list)
    owasp_llm_ids = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)
```

### T3-C: python/core/orchestrator.py — the campaign controller

The orchestrator is the top-level coordinator. The stub has the phase structure
but likely missing the gate logic, error handling, and gRPC client wiring.

Key things to implement in the stub:
1. Phase gate: `if not recon_result.llm_detected: raise CampaignAborted("No LLM detected")`
2. gRPC client init with health check before campaign starts
3. Evidence store init with campaign_id
4. Phase 1→2→3→4→5→6 sequential execution with error isolation
5. Graceful abort on KeyboardInterrupt (close gRPC channels)
6. Campaign summary logged on completion

---

## TIER 4 — CLONE EXTERNAL TOOLS

Run these commands from the repo root. Some repos may need verification first.

```bash
cd external/

# 1. garak — LLM vulnerability scanner (pip install is better than clone)
pip install garak  # installs as a package, use via: python -m garak

# 2. PyRIT — Microsoft's red team toolkit
pip install pyrit   # pip-installable

# 3. DeepTeam — OWASP-mapped adversarial testing
pip install deepteam

# 4. ARTKIT — BCG multi-turn challenger
pip install artkit

# 5. rigging — dreadnode agent-vs-agent
pip install rigging

# 6. llamator — RAG security testing
pip install llamator

# 7. promptfoo — regression baseline (Node.js)
npm install -g promptfoo

# 8. shannon — white-box AI pentester (clone + npm install)
git clone https://github.com/KeygraphHQ/shannon.git shannon/
cd shannon && npm install && cd ..

# 9. vulnhuntr — needs Python 3.10 separate venv
# First ensure pyenv is installed: https://github.com/pyenv/pyenv
pyenv install 3.10.14
pyenv local 3.10.14
python -m venv ../venv_vulnhuntr
source ../venv_vulnhuntr/bin/activate
pip install git+https://github.com/protectai/vulnhuntr.git
deactivate
pyenv local --unset

# 10. InjecAgent dataset (payload corpora)
git clone https://github.com/injecagent/InjecAgent.git injecagent/

cd ..  # back to repo root
```

**Verify external tool availability:**
```bash
python -c "import garak; print('garak OK')"
python -c "import pyrit; print('pyrit OK')"
python -c "import deepteam; print('deepteam OK')"
python -c "import artkit; print('artkit OK')"
python -c "import rigging; print('rigging OK')"
python -c "import llamator; print('llamator OK')"
promptfoo --version
```

**IMPORTANT — package name corrections:**
Some packages in pyproject.toml may have wrong names. Verify:
```bash
# deepteam might be: pip install deepeval  (check: https://github.com/confident-ai/deepteam)
# artkit might be: pip install artkit-ai or pip install bcg-artkit
# rigging might be: pip install rigging-ai
# Always check the GitHub README for the correct pip install command
```

---

## TIER 5 — DOWNLOAD DATA FILES

```bash
# 1. CISA KEV catalog (required for CVE enrichment)
curl -o data/cisa_kev.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
echo "KEV entries: $(python -c "import json; print(len(json.load(open('data/cisa_kev.json'))['vulnerabilities']))")"

# 2. OWASP framework JSON files (create manually if not present)
# These should be created as static JSON files in data/

# 3. InjecAgent payload corpora (if cloned above)
cp external/injecagent/data/attack_data_dh.json \
   data/payload_corpora/injecagent_dh.jsonl 2>/dev/null || \
   echo "InjecAgent data not found — check clone path"

# 4. Nuclei templates
nuclei -update-templates    # downloads official community templates
# Then copy custom templates from data/nuclei_templates/ to ~/.config/nuclei/templates/custom/

# 5. Download semgrep AI security rules
mkdir -p data/semgrep_rules
# Custom rules should be in data/semgrep_rules/ — these are written manually
# based on the patterns defined in the architecture spec
```

---

## TIER 6 — VERIFY INTEGRATION END-TO-END

### T6-A: Build and start Go servers

```bash
# Build
make build-go
# Or manually:
cd go
go build -o ../bin/probe_server ./cmd/probe_server/
go build -o ../bin/recon_server ./cmd/recon_server/
go build -o ../bin/mcp_server ./cmd/mcp_server/
cd ..

# Start (3 separate terminals or background)
./bin/probe_server &
./bin/recon_server &
./bin/mcp_server &

# Verify health
sleep 2
grpc_health_probe -addr=:50051 || \
  python -c "
import grpc
from python.core import probe_pb2, probe_pb2_grpc
ch = grpc.insecure_channel('localhost:50051')
stub = probe_pb2_grpc.ProbeServiceStub(ch)
r = stub.HealthCheck(probe_pb2.HealthRequest())
print('probe-server:', 'OK' if r.ok else 'FAIL')
"
```

### T6-B: Start mock servers and run validation

```bash
# Terminal 1: start mock chatbot
uvicorn tests.mock_server.app:app --port 9999 &

# Terminal 2: start mock MCP server  
uvicorn tests.mock_server.mcp_server:app --port 9998 &

sleep 2

# Run Python unit tests
pytest tests/unit/ -v --tb=short

# Run integration test against mock server
python -m python.cli.main scan \
  --target http://localhost:9999 \
  --profile chatbot \
  --scope config/scope.yaml \
  --dry-run     # add --dry-run flag to test without firing real probes
```

### T6-C: Docker Compose full-stack test

```bash
# Build images
docker-compose build

# Start all services
docker-compose up -d

# Check all services healthy
docker-compose ps

# Check logs for errors
docker-compose logs probe-server
docker-compose logs orchestrator

# Run validation against mock server
docker-compose --profile testing up test-runner

# Tear down
docker-compose down
```

---

## TIER 7 — IMPLEMENT REMAINING ATTACK MODULES

Once the foundation (T1-T3) is working, implement attack modules in this order:

### Priority 1 (needed for any campaign to produce findings):
- `python/prompt_attacks/corpus_runner.py` — loads payload JSONL, fires via ProbeClient
- `python/prompt_attacks/flipattack_runner.py` — applies FCS/FCW/FWO from templates
- `python/evidence/verifier.py` — 4-layer FP verification (the stub needs real logic)
- `python/evidence/scorer.py` — CVSS-style 4-axis scoring

### Priority 2 (MCP campaign support):
- `python/mcp_attacks/lethal_trifecta_detector.py` — check 3 capabilities
- `python/mcp_attacks/mcp_tool_llm_scanner.py` — call Claude API with tool defs
- `python/mcp_attacks/rug_pull_tester.py` — call MCPClient.enumerate twice

### Priority 3 (intelligence enrichment):
- `python/intelligence/cve_enricher.py` — nvdlib calls + KEV check
- `python/reporting/generator.py` — load findings, render Jinja2 template, WeasyPrint PDF

### Priority 4 (advanced attack runners):
- All remaining prompt_attacks/ modules
- All rag_attacks/ modules
- Remaining mcp_attacks/ modules

---

## CRITICAL PACKAGE NAME FIXES

Some packages in pyproject.toml may be wrong. Verify each one:

```bash
# Test each import before writing runner code that depends on it

python -c "import garak"         # package: garak
python -c "import pyrit"         # package: pyrit-ai (NOT pyrit)
python -c "import deepteam"      # may need: deepeval
python -c "import artkit"        # may need: artkit (check BCG GitHub)
python -c "import rigging"       # package: rigging
python -c "import llamator"      # package: llamator
python -c "import nvdlib"        # package: nvdlib  
python -c "import shodan"        # package: shodan
python -c "import mitmproxy"     # package: mitmproxy
python -c "import ssdeep"        # requires: libfuzzy-dev system dep

# If pyrit import fails:
pip install pyrit-ai
python -c "from pyrit.orchestrator import CrescendoOrchestrator; print('pyrit OK')"
```

---

## KNOWN GOTCHAS (from the architecture design)

| Issue | Root Cause | Fix |
|---|---|---|
| `pysqlcipher3` install fails | Missing `libsqlcipher-dev` | `apt-get install libsqlcipher-dev` |
| `ssdeep` import fails | Missing `libfuzzy-dev` | `apt-get install libfuzzy-dev` |
| Proto import fails in Python | `*_pb2.py` not generated | Re-run T1-D |
| Go build fails: `undefined: pb.XxxRequest` | Proto not compiled to Go | Re-run T1-D |
| `torch` too large | Default install pulls CUDA | `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| `vulnhuntr` requires Python 3.10 | Strict version requirement | Use pyenv venv (T4 step 9) |
| Shannon needs Node.js 18+ | npm ci fails on older node | `nvm use 18` or update node |
| `playwright install` fails in Docker | Missing chromium system deps | Add `--with-deps` flag |
| SQLCipher DB locked | Multiple processes opening same file | One EvidenceStore per campaign |
| gRPC channel timeout | Go server not started | Check `./bin/probe_server` is running |

---

## SPRINT PLAN (suggested 2-week execution)

### Week 1 — Foundation + Go + Core Python
- Day 1: T1-A through T1-F (proto compilation, dependency install, verify compiles)
- Day 2: T2-A, T2-B (rate_limiter.go, adapter.go fully implemented)
- Day 3: T2-C, T2-D (runner.go goroutine pool, all 3 main.go servers)
- Day 4: T2-D complete + T3-A (grpc_clients.py fully working)
- Day 5: T3-B (evidence store — SQLCipher write/read/dedup verified)

### Week 2 — Python Core + Attack Modules + Integration
- Day 6: T3-C (orchestrator.py phase gates wired) + T4 (external tools)
- Day 7: T5 (data files) + corpus_runner.py + flipattack_runner.py
- Day 8: verifier.py (4-layer FP) + scorer.py + cve_enricher.py
- Day 9: T6-A, T6-B (end-to-end test: mock server → findings.db → report)
- Day 10: T6-C (Docker) + remaining attack modules + report generation

### Milestone check (end of Day 5):
```
make build-go   # all 3 binaries compile
pytest tests/unit/ -v   # all unit tests pass
python -c "
from python.core.grpc_clients import GRPCClients
from python.evidence.store import EvidenceStore
print('Core layer: OK')
"
```

### Milestone check (end of Day 10):
```
# Start mock servers
uvicorn tests.mock_server.app:app --port 9999 &
# Run full campaign against mock
python -m python.cli.main scan --target http://localhost:9999 --profile chatbot --scope config/scope.yaml
# Check output
ls output/campaigns/*/  # should show findings.db, report.html, report.pdf
```

---

## FILE-LEVEL IMPLEMENTATION STATUS TRACKER

Copy this into BUILD_STATUS.md and update as you implement:

```
## T1 Foundation
- [ ] T1-A: System prerequisites installed
- [ ] T1-B: Go proto plugins installed
- [ ] T1-C: Python dependencies installed
- [ ] T1-D: Proto files compiled (Go + Python)
- [ ] T1-E: Go module imports correct
- [ ] T1-F: Foundation compiles clean

## T2 Go Servers
- [ ] transport/rate_limiter.go: Complete
- [ ] transport/adapter.go: Complete
- [ ] transport/auth.go: Complete
- [ ] transport/oob.go: Complete
- [ ] proberunner/runner.go: Complete
- [ ] proberunner/chatinject.go: Complete
- [ ] proberunner/flipattack.go: Complete
- [ ] proberunner/unicode_inject.go: Complete
- [ ] proberunner/rce_probe.go: Complete
- [ ] reconrunner/port_scan.go: Complete
- [ ] reconrunner/endpoint_fuzz.go: Complete
- [ ] mcprunner/enumerator.go: Complete
- [ ] mcprunner/rug_pull.go: Complete
- [ ] mcprunner/sql_inject_mcp.go: Complete
- [ ] cmd/probe_server/main.go: Complete + starts
- [ ] cmd/recon_server/main.go: Complete + starts
- [ ] cmd/mcp_server/main.go: Complete + starts

## T3 Python Core
- [ ] core/grpc_clients.py: Complete
- [ ] core/scope_validator.py: Complete
- [ ] core/response_classifier.py: Complete
- [ ] core/finding_normaliser.py: FAMILY_MAP complete
- [ ] core/context_profiler.py: Complete
- [ ] core/progressive_prober.py: Complete
- [ ] core/adaptive_orchestrator.py: Complete
- [ ] core/orchestrator.py: All phases wired
- [ ] evidence/models.py: Complete
- [ ] evidence/store.py: SQLCipher verified
- [ ] evidence/verifier.py: 4-layer complete
- [ ] evidence/scorer.py: Complete
- [ ] evidence/deduplicator.py: Complete

## T4 External Tools
- [ ] garak: pip installed + import verified
- [ ] pyrit: pip installed + import verified
- [ ] deepteam: pip installed + import verified
- [ ] artkit: pip installed + import verified
- [ ] rigging: pip installed + import verified
- [ ] llamator: pip installed + import verified
- [ ] promptfoo: npm installed + version check
- [ ] shannon: cloned + npm install
- [ ] vulnhuntr: Python 3.10 venv created + installed

## T5 Data Files
- [ ] data/cisa_kev.json: Downloaded
- [ ] data/payload_corpora/injecagent_dh.jsonl: Present
- [ ] data/payload_corpora/flipattack_templates.jsonl: Present
- [ ] data/nuclei_templates/: Templates downloaded

## T6 Integration
- [ ] All 3 Go servers start and pass health check
- [ ] Python can call ProbeClient.fire_batch() and receive results
- [ ] Evidence store creates encrypted DB and saves a test finding
- [ ] Full campaign against mock_server produces findings.db
- [ ] Report generates (HTML + PDF + JSON)
- [ ] Docker Compose full stack starts cleanly

## Attack Modules (implement after T6 milestone)
- [ ] prompt_attacks/corpus_runner.py
- [ ] prompt_attacks/flipattack_runner.py
- [ ] mcp_attacks/lethal_trifecta_detector.py
- [ ] mcp_attacks/mcp_tool_llm_scanner.py
- [ ] intelligence/cve_enricher.py
- [ ] reporting/generator.py
- [ ] (remaining 60+ modules)
```
