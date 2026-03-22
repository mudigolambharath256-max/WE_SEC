# llmrt Integration Summary

## Complete Directory Structure

```
llm-redteam/
├── .env.example                          # Environment variables template
├── .gitignore                            # Git ignore rules
├── .dockerignore                         # Docker ignore rules
├── README.md                             # Main documentation
├── BUILD_STATUS.md                       # Build progress tracking
├── DOCKER.md                             # Docker deployment guide
├── CONTRIBUTING.md                       # Contribution guidelines
├── Makefile                              # Build automation
├── pyproject.toml                        # Python package configuration
├── pytest.ini                            # Pytest configuration
├── docker-compose.yml                    # Multi-service orchestration
├── Dockerfile.go                         # Go services container
├── Dockerfile.python                     # Python services container
├── Dockerfile.shannon                    # Shannon analysis container
│
├── .github/
│   └── workflows/
│       ├── test.yml                      # CI: Testing pipeline
│       ├── build.yml                     # CI: Build validation
│       ├── release.yml                   # CI: Release automation
│       └── README.md                     # CI/CD documentation
│
├── .kiro/                                # Kiro IDE configuration (if present)
│
├── bin/                                  # Compiled Go binaries (gitignored)
│   ├── probe_server                      # HTTP probe execution server
│   ├── recon_server                      # Reconnaissance server
│   └── mcp_server                        # MCP attack server
│
├── config/                               # Configuration files
│   ├── scope.yaml                        # Scope definition template
│   ├── default.yaml                      # Default configuration
│   └── profiles/
│       ├── chatbot.yaml                  # Chatbot testing profile
│       ├── rag_app.yaml                  # RAG application profile
│       ├── mcp_agent.yaml                # MCP agent profile
│       └── ide_assistant.yaml            # IDE assistant profile
│
├── data/                                 # Attack data and templates
│   ├── nuclei_templates/
│   │   ├── llm/
│   │   │   ├── prompt-injection.yaml     # Prompt injection detection
│   │   │   ├── rce-probe.yaml            # RCE detection
│   │   │   ├── pii-leakage.yaml          # PII leakage detection
│   │   │   ├── jailbreak.yaml            # Jailbreak detection
│   │   │   └── oob-exfiltration.yaml     # OOB exfiltration detection
│   │   └── mcp/
│   │       ├── tool-injection.yaml       # MCP tool injection
│   │       ├── lethal-trifecta.yaml      # Lethal trifecta detection
│   │       ├── rug-pull.yaml             # Rug pull detection
│   │       ├── oauth-vulnerabilities.yaml # OAuth vulnerabilities
│   │       └── privilege-escalation.yaml # Privilege escalation
│   ├── payload_corpora/
│   │   └── setup.sh                      # Payload corpus setup script
│   ├── flipattack_templates.jsonl        # FlipAttack templates (30 variants)
│   ├── mcp_sqli_handler_templates.jsonl  # SQL injection templates (40 patterns)
│   └── semgrep_rules/                    # Semgrep rules (to be populated)
│
├── external/                             # External tool repositories (EMPTY - needs cloning)
│   ├── shannon/                          # [MISSING] White-box analysis
│   ├── vulnhuntr/                        # [MISSING] Vulnerability detection
│   ├── garak/                            # [MISSING] LLM vulnerability scanner
│   ├── pyrit/                            # [MISSING] Microsoft PyRIT
│   ├── augustus/                         # [MISSING] Prompt injection framework
│   ├── deepteam/                         # [MISSING] Adversarial testing
│   ├── artkit/                           # [MISSING] Robustness toolkit
│   ├── rigging/                          # [MISSING] Agent testing
│   ├── llamator/                         # [MISSING] RAG security testing
│   └── promptfoo/                        # [MISSING] LLM evaluation
│
├── go/                                   # Go speed layer
│   ├── go.mod                            # Go module definition
│   ├── go.sum                            # Go dependency checksums
│   ├── cmd/                              # Command entrypoints
│   │   ├── probe_server/
│   │   │   └── main.go                   # Probe gRPC server
│   │   ├── recon_server/
│   │   │   └── main.go                   # Recon gRPC server
│   │   └── mcp_server/
│   │       └── main.go                   # MCP gRPC server
│   └── internal/                         # Internal packages
│       ├── proto/                        # [GENERATED] gRPC code (EMPTY - needs protoc)
│       ├── transport/
│       │   ├── adapter.go                # HTTP/SSE/WebSocket adapter
│       │   ├── auth.go                   # Authentication handling
│       │   ├── oob.go                    # Out-of-band detection
│       │   └── rate_limiter.go           # Token bucket rate limiter
│       ├── proberunner/
│       │   ├── runner.go                 # Goroutine pool executor
│       │   ├── corpus.go                 # Payload corpus management
│       │   ├── chatinject.go             # ChatInject technique
│       │   ├── flipattack.go             # FlipAttack variants
│       │   ├── unicode_inject.go         # Unicode injection
│       │   └── rce_probe.go              # RCE probing
│       ├── reconrunner/
│       │   ├── port_scan.go              # Nmap wrapper
│       │   ├── endpoint_fuzz.go          # Endpoint discovery
│       │   ├── network_binding.go        # Network misconfiguration
│       │   └── har_parser.go             # HAR file parsing
│       └── mcprunner/
│           ├── enumerator.go             # MCP JSON-RPC client
│           ├── rug_pull.go               # Rug pull detection
│           └── sql_inject_mcp.go         # SQL injection in MCP
│
├── output/                               # Campaign results (gitignored)
│   ├── campaigns/
│   │   └── {campaign_id}/
│   │       ├── findings.db               # Encrypted SQLCipher database
│   │       ├── report.html               # HTML report
│   │       ├── report.pdf                # PDF report
│   │       └── report.json               # JSON report
│   └── shannon/                          # Shannon analysis results
│
├── proto/                                # gRPC protocol definitions
│   ├── common.proto                      # Common message types
│   ├── probe.proto                       # Probe service definition
│   ├── recon.proto                       # Recon service definition
│   └── mcp.proto                         # MCP service definition
│
├── python/                               # Python intelligence layer
│   ├── __init__.py
│   ├── api/                              # REST API
│   │   ├── __init__.py
│   │   ├── app.py                        # FastAPI application
│   │   └── websocket.py                  # WebSocket real-time updates
│   ├── browser/                          # Browser automation
│   │   ├── __init__.py
│   │   ├── playwright_driver.py          # Playwright automation
│   │   ├── selenium_driver.py            # Selenium fallback
│   │   ├── stealth.py                    # Anti-detection techniques
│   │   └── tampermonkey_scripts/
│   │       ├── endpoint_interceptor.user.js
│   │       ├── quick_probe_panel.user.js
│   │       └── mcp_config_harvester.user.js
│   ├── cli/                              # Command-line interface
│   │   ├── __init__.py
│   │   ├── main.py                       # Typer CLI entrypoint
│   │   └── commands/                     # CLI commands (to be implemented)
│   ├── core/                             # Core orchestration
│   │   ├── __init__.py
│   │   ├── target.py                     # Target definition
│   │   ├── config_schema.py              # Pydantic configuration models
│   │   ├── scope_validator.py            # Scope validation
│   │   ├── session_manager.py            # Session lifecycle
│   │   ├── grpc_clients.py               # gRPC client wrappers
│   │   ├── response_classifier.py        # 5-state classifier
│   │   ├── finding_normaliser.py         # Finding normalization
│   │   ├── context_profiler.py           # Target profiling
│   │   ├── chat_template_injector.py     # Template injection
│   │   ├── progressive_prober.py         # Progressive probing
│   │   ├── adaptive_orchestrator.py      # Adaptive strategy
│   │   ├── orchestrator.py               # Campaign controller
│   │   └── *_pb2*.py                     # [GENERATED] gRPC stubs (MISSING)
│   ├── evidence/                         # Evidence management
│   │   ├── __init__.py
│   │   ├── models.py                     # SQLAlchemy ORM models
│   │   ├── store.py                      # SQLCipher evidence store
│   │   ├── scorer.py                     # CVSS 4.0 scoring
│   │   ├── deduplicator.py               # ssdeep deduplication
│   │   └── verifier.py                   # 4-layer FP verification
│   ├── intelligence/                     # CVE intelligence
│   │   ├── __init__.py
│   │   ├── cve_cache.py                  # NVD API integration
│   │   ├── cve_enricher.py               # CVE correlation
│   │   ├── tech_cve_scanner.py           # Technology scanning
│   │   └── kev_monitor.py                # CISA KEV monitoring
│   ├── mcp_attacks/                      # MCP security modules (17 files)
│   │   ├── __init__.py
│   │   ├── lethal_trifecta_detector.py
│   │   ├── mcp_tool_llm_scanner.py
│   │   ├── mcp_sampling_attacker.py
│   │   ├── cross_tool_orchestration_injector.py
│   │   ├── mcp_remote_oauth_injector.py
│   │   ├── claude_code_config_injector.py
│   │   ├── permission_inheritance_tester.py
│   │   ├── oauth_endpoint_xss_tester.py
│   │   ├── session_id_url_harvester.py
│   │   ├── oauth_confused_deputy.py
│   │   ├── token_passthrough_tester.py
│   │   ├── rug_pull_tester.py
│   │   ├── tool_name_spoofer.py
│   │   ├── context_bleeder.py
│   │   ├── cross_tenant_tester.py
│   │   ├── privilege_escalator.py
│   │   └── agent_memory_attacker.py
│   ├── prompt_attacks/                   # Prompt injection modules (18 files)
│   │   ├── __init__.py
│   │   ├── corpus_runner.py
│   │   ├── oob_detector.py
│   │   ├── unicode_injection_runner.py
│   │   ├── rce_probe_runner.py
│   │   ├── flipattack_runner.py
│   │   ├── adversarial_poetry_runner.py
│   │   ├── multilingual_runner.py
│   │   ├── idor_llm_chain_tester.py
│   │   ├── timing_attack_tester.py
│   │   ├── env_injection_tester.py
│   │   ├── upload_path_traversal_tester.py
│   │   ├── augustus_runner.py
│   │   ├── garak_runner.py
│   │   ├── pyrit_runner.py
│   │   ├── deepteam_runner.py
│   │   ├── artkit_runner.py
│   │   ├── rigging_agent_runner.py
│   │   └── promptfoo_runner.py
│   ├── proxy/                            # Traffic interception
│   │   ├── __init__.py
│   │   ├── mitmproxy_addon.py
│   │   ├── zap_integration.py
│   │   ├── burp_integration.py
│   │   └── burpmcp_websocket_integration.py
│   ├── rag_attacks/                      # RAG security modules (7 files)
│   │   ├── __init__.py
│   │   ├── llamator_runner.py
│   │   ├── doc_injector.py
│   │   ├── code_file_injector.py
│   │   ├── stored_prompt_injector.py
│   │   ├── vector_db_attacker.py
│   │   ├── memory_poison_tester.py
│   │   └── context_monitor.py
│   ├── recon/                            # Reconnaissance modules (16 files)
│   │   ├── __init__.py
│   │   ├── triggered_crawler.py
│   │   ├── selenium_fallback.py
│   │   ├── stealth.py
│   │   ├── static_analyzer.py
│   │   ├── llmsmith_runner.py
│   │   ├── gguf_template_scanner.py
│   │   ├── fingerprinter.py
│   │   ├── shodan_enricher.py
│   │   ├── network_binding_checker.py
│   │   ├── mcp_detector.py
│   │   ├── mcp_package_auditor.py
│   │   ├── supply_chain_scanner.py
│   │   ├── surface_report.py
│   │   ├── shannon_runner.py
│   │   ├── vulnhuntr_runner.py
│   │   └── xvulnhuntr_runner.py
│   └── reporting/                        # Report generation
│       ├── __init__.py
│       ├── mitre_mapper.py               # MITRE ATT&CK mapping
│       ├── owasp_llm_mapper.py           # OWASP LLM Top 10
│       ├── agentic_owasp_mapper.py       # Agentic OWASP
│       ├── owasp_mcp_top10_mapper.py     # OWASP MCP Top 10
│       ├── adversa_mcp_mapper.py         # Adversa MCP Top 25
│       ├── hardening_advisor.py          # Remediation guidance
│       ├── generator.py                  # Multi-format generation
│       └── templates/
│           └── report.html.jinja         # HTML report template
│
├── scripts/                              # Utility scripts
│   └── validate.sh                       # Validation script
│
└── tests/                                # Test suite
    ├── __init__.py
    ├── conftest.py                       # Pytest fixtures
    ├── pytest.ini                        # Pytest configuration
    ├── run_tests.sh                      # Test runner
    ├── README.md                         # Test documentation
    ├── integration/                      # Integration tests
    │   ├── __init__.py
    │   └── test_mock_servers.py
    ├── unit/                             # Unit tests
    │   ├── __init__.py
    │   ├── test_scope_validator.py
    │   ├── test_response_classifier.py
    │   ├── test_finding_normaliser.py
    │   ├── test_evidence_store.py
    │   ├── test_cvss_scorer.py
    │   └── test_deduplicator.py
    └── mock_server/                      # Mock vulnerable servers
        ├── README.md
        ├── app.py                        # Vulnerable LLM app
        └── mcp_server.py                 # Vulnerable MCP server
```

## Integration Workflow

### Phase 1: Service Startup Flow

```
1. Docker Compose Start
   └─> docker-compose up -d
       │
       ├─> probe-server (Go) :50051
       │   └─> Loads rate limiter
       │   └─> Initializes HTTP client pool
       │   └─> Starts gRPC server
       │
       ├─> recon-server (Go) :50052
       │   └─> Loads Nmap wrapper
       │   └─> Initializes endpoint fuzzer
       │   └─> Starts gRPC server
       │
       ├─> mcp-server (Go) :50053
       │   └─> Loads MCP JSON-RPC client
       │   └─> Initializes attack modules
       │   └─> Starts gRPC server
       │
       └─> orchestrator (Python) :8000
           └─> Loads configuration
           └─> Connects to gRPC servers
           └─> Initializes evidence store
           └─> Starts FastAPI server
```

### Phase 2: Campaign Execution Flow

```
User Request
    │
    ├─> CLI: llmrt scan --target <url> --profile chatbot
    │   OR
    └─> API: POST /api/campaigns
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Python Orchestrator (orchestrator.py)                     │
│                                                            │
│ 1. Load scope.yaml                                        │
│ 2. Validate target URL (scope_validator.py)              │
│ 3. Load profile configuration                             │
│ 4. Initialize campaign in evidence store                  │
│ 5. Create session                                         │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 1: Reconnaissance                                   │
│                                                            │
│ Python: context_profiler.py                              │
│    └─> gRPC call to recon-server                         │
│        └─> Go: port_scan.go (Nmap)                       │
│        └─> Go: endpoint_fuzz.go                          │
│        └─> Go: network_binding.go                        │
│                                                            │
│ Python: recon/fingerprinter.py                           │
│    └─> Detect technology stack                           │
│    └─> intelligence/cve_enricher.py                      │
│        └─> Query NVD API for CVEs                        │
│        └─> Check CISA KEV catalog                        │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 2: Adaptive Strategy Selection                      │
│                                                            │
│ Python: adaptive_orchestrator.py                         │
│    └─> Analyze recon results                             │
│    └─> Select attack modules based on:                   │
│        - Target type (chatbot/RAG/MCP)                   │
│        - Detected technologies                            │
│        - Profile configuration                            │
│    └─> Generate attack plan                              │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 3: Attack Execution (Progressive Probing)          │
│                                                            │
│ Python: progressive_prober.py                            │
│    └─> Level 1: Corpus-based probes                      │
│        │                                                  │
│        ├─> prompt_attacks/corpus_runner.py               │
│        │   └─> Load payloads from data/payload_corpora/  │
│        │   └─> gRPC call to probe-server                 │
│        │       └─> Go: proberunner/runner.go             │
│        │           └─> Go: transport/adapter.go          │
│        │               └─> HTTP POST to target           │
│        │                   └─> Response                  │
│        │                       └─> Go: Return to Python  │
│        │                           └─> Python: response_classifier.py
│        │                               └─> Classify: HARD_REFUSAL/SOFT/DEFLECTION/PARTIAL/FULL
│        │
│        ├─> If PARTIAL or FULL compliance detected:       │
│        │   └─> Level 2: Template injection               │
│        │       └─> prompt_attacks/flipattack_runner.py   │
│        │           └─> Apply FCS/FCW/FWO variants        │
│        │           └─> gRPC call to probe-server         │
│        │
│        ├─> If still successful:                          │
│        │   └─> Level 3: Unicode injection                │
│        │       └─> prompt_attacks/unicode_injection_runner.py
│        │           └─> Zero-width, BiDi, homoglyph       │
│        │
│        ├─> Level 4: Code execution probes                │
│        │   └─> prompt_attacks/rce_probe_runner.py        │
│        │       └─> LLMSmith patterns                     │
│        │       └─> MD5 verification                      │
│        │
│        └─> Level 5: OOB detection                        │
│            └─> prompt_attacks/oob_detector.py            │
│                └─> Register with Interactsh              │
│                └─> Inject OOB payload                    │
│                └─> Poll for callbacks                    │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 4: MCP-Specific Attacks (if MCP detected)          │
│                                                            │
│ Python: mcp_attacks/lethal_trifecta_detector.py          │
│    └─> gRPC call to mcp-server                           │
│        └─> Go: mcprunner/enumerator.go                   │
│            └─> MCP JSON-RPC: tools/list                  │
│            └─> Check for write + exec + network          │
│                                                            │
│ Python: mcp_attacks/rug_pull_tester.py                   │
│    └─> gRPC call to mcp-server                           │
│        └─> Go: mcprunner/rug_pull.go                     │
│            └─> Enumerate tools (T0)                      │
│            └─> Wait 5 seconds                            │
│            └─> Enumerate tools (T1)                      │
│            └─> Compare descriptions                      │
│                                                            │
│ Python: mcp_attacks/sql_inject_mcp.py                    │
│    └─> gRPC call to mcp-server                           │
│        └─> Go: mcprunner/sql_inject_mcp.go               │
│            └─> Load templates from data/mcp_sqli_handler_templates.jsonl
│            └─> Inject into tool parameters               │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 5: Evidence Processing                              │
│                                                            │
│ For each response:                                        │
│    │                                                      │
│    ├─> Python: response_classifier.py                    │
│    │   └─> Classify response state                       │
│    │                                                      │
│    ├─> Python: finding_normaliser.py                     │
│    │   └─> Normalize to standard format                  │
│    │   └─> Map to OWASP/MITRE families                  │
│    │                                                      │
│    ├─> Python: evidence/scorer.py                        │
│    │   └─> Calculate CVSS 4.0 score                     │
│    │                                                      │
│    ├─> Python: evidence/deduplicator.py                  │
│    │   └─> Check for duplicates (ssdeep)                │
│    │   └─> Skip if duplicate                             │
│    │                                                      │
│    ├─> Python: evidence/verifier.py                      │
│    │   └─> Layer 1: Consistency check                    │
│    │   └─> Layer 2: Echo detection                       │
│    │   └─> Layer 3: Semantic analysis                    │
│    │   └─> Layer 4: Reproducibility test                 │
│    │   └─> Mark as verified or false positive           │
│    │                                                      │
│    └─> Python: evidence/store.py                         │
│        └─> Save to SQLCipher database                    │
│            └─> Encrypted with CAMPAIGN_ENCRYPT_KEY       │
└───────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────────────────────────────────────────────┐
│ Phase 6: Report Generation                                │
│                                                            │
│ Python: reporting/generator.py                           │
│    │                                                      │
│    ├─> Load findings from evidence store                 │
│    │                                                      │
│    ├─> reporting/mitre_mapper.py                         │
│    │   └─> Map to MITRE ATT&CK techniques               │
│    │                                                      │
│    ├─> reporting/owasp_llm_mapper.py                     │
│    │   └─> Map to OWASP LLM Top 10                      │
│    │                                                      │
│    ├─> reporting/adversa_mcp_mapper.py                   │
│    │   └─> Map to Adversa MCP Top 25                    │
│    │                                                      │
│    ├─> reporting/hardening_advisor.py                    │
│    │   └─> Generate remediation guidance                 │
│    │                                                      │
│    └─> Render report                                     │
│        ├─> HTML: templates/report.html.jinja            │
│        ├─> PDF: WeasyPrint conversion                    │
│        ├─> JSON: Structured export                       │
│        └─> Markdown: Text export                         │
│                                                            │
│    └─> Save to output/campaigns/{campaign_id}/           │
└───────────────────────────────────────────────────────────┘
        │
        ▼
    Campaign Complete
```

### Phase 3: Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Data Flow Diagram                       │
└─────────────────────────────────────────────────────────────┘

User Input (CLI/API)
    │
    ├─> scope.yaml (config/)
    ├─> profile.yaml (config/profiles/)
    └─> .env (API keys)
        │
        ▼
┌──────────────────────┐
│ Python Orchestrator  │
│   (Port 8000)        │
└──────────────────────┘
        │
        ├─────────────────────────────────────┐
        │                                     │
        ▼                                     ▼
┌──────────────────────┐          ┌──────────────────────┐
│  gRPC: probe-server  │          │ gRPC: recon-server   │
│    (Port 50051)      │          │   (Port 50052)       │
│                      │          │                      │
│ • HTTP probing       │          │ • Port scanning      │
│ • Rate limiting      │          │ • Endpoint fuzzing   │
│ • ChatInject         │          │ • HAR parsing        │
│ • FlipAttack         │          │                      │
└──────────────────────┘          └──────────────────────┘
        │                                     │
        └─────────────────┬───────────────────┘
                          │
                          ▼
                  ┌──────────────────────┐
                  │  gRPC: mcp-server    │
                  │    (Port 50053)      │
                  │                      │
                  │ • MCP enumeration    │
                  │ • Rug pull detection │
                  │ • SQL injection      │
                  └──────────────────────┘
                          │
                          ▼
                    Target System
                  (AI App / MCP Server)
                          │
                          ▼
                    HTTP Responses
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Response Processing Pipeline                 │
│                                                           │
│  1. response_classifier.py → 5-state classification      │
│  2. finding_normaliser.py → Standardization              │
│  3. scorer.py → CVSS 4.0 scoring                         │
│  4. deduplicator.py → Duplicate detection                │
│  5. verifier.py → False positive filtering               │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Evidence Store (SQLCipher)                   │
│                                                           │
│  output/campaigns/{campaign_id}/findings.db              │
│  • Encrypted with CAMPAIGN_ENCRYPT_KEY                   │
│  • Tables: campaigns, sessions, findings, oob_callbacks  │
└──────────────────────────────────────────────────────────┘
                          │
                          ▼
┌──────────────────────────────────────────────────────────┐
│              Report Generation                            │
│                                                           │
│  • MITRE ATT&CK mapping                                  │
│  • OWASP framework mapping                               │
│  • Adversa MCP mapping                                   │
│  • Hardening recommendations                             │
│                                                           │
│  Output formats:                                         │
│  • report.html (Jinja2 template)                         │
│  • report.pdf (WeasyPrint)                               │
│  • report.json (Structured data)                         │
│  • report.md (Markdown)                                  │
└──────────────────────────────────────────────────────────┘
```

### Phase 4: External Tool Integration Points

```
┌─────────────────────────────────────────────────────────────┐
│              External Tools Integration                      │
└─────────────────────────────────────────────────────────────┘

Python Orchestrator
    │
    ├─> Recon Phase
    │   │
    │   ├─> recon/shannon_runner.py
    │   │   └─> Subprocess: external/shannon/
    │   │       └─> White-box source code analysis
    │   │       └─> Returns: Vulnerability findings
    │   │
    │   ├─> recon/vulnhuntr_runner.py
    │   │   └─> Subprocess: external/vulnhuntr/
    │   │       └─> LLM-powered vulnerability detection
    │   │       └─> Returns: Code vulnerabilities
    │   │
    │   └─> recon/static_analyzer.py
    │       └─> Subprocess: semgrep
    │           └─> Rules: data/semgrep_rules/
    │           └─> Returns: Static analysis findings
    │
    ├─> Prompt Attack Phase
    │   │
    │   ├─> prompt_attacks/garak_runner.py
    │   │   └─> Subprocess: external/garak/
    │   │       └─> 60+ LLM vulnerability probes
    │   │       └─> Returns: Garak findings
    │   │
    │   ├─> prompt_attacks/pyrit_runner.py
    │   │   └─> Subprocess: external/pyrit/
    │   │       └─> Microsoft PyRIT toolkit
    │   │       └─> Returns: PyRIT findings
    │   │
    │   ├─> prompt_attacks/augustus_runner.py
    │   │   └─> Subprocess: external/augustus/
    │   │       └─> Prompt injection framework
    │   │       └─> Returns: Augustus findings
    │   │
    │   └─> prompt_attacks/promptfoo_runner.py
    │       └─> Subprocess: external/promptfoo/
    │           └─> LLM evaluation
    │           └─> Returns: Evaluation results
    │
    ├─> RAG Attack Phase
    │   │
    │   └─> rag_attacks/llamator_runner.py
    │       └─> Subprocess: external/llamator/
    │           └─> RAG security testing
    │           └─> Returns: RAG vulnerabilities
    │
    └─> Intelligence Phase
        │
        ├─> intelligence/cve_cache.py
        │   └─> HTTP API: NVD API (api.nvd.nist.gov)
        │       └─> Query CVE database
        │       └─> Returns: CVE details
        │
        ├─> intelligence/kev_monitor.py
        │   └─> HTTP API: CISA KEV (cisa.gov)
        │       └─> Download KEV catalog
        │       └─> Returns: Known exploited vulnerabilities
        │
        └─> recon/shodan_enricher.py
            └─> HTTP API: Shodan API
                └─> Query for exposed services
                └─> Returns: Network intelligence
```

### Phase 5: Missing Integration Components

```
┌─────────────────────────────────────────────────────────────┐
│          CRITICAL: What Needs to Be Done                     │
└─────────────────────────────────────────────────────────────┘

1. Clone External Repositories
   ─────────────────────────────
   cd external/
   git clone https://github.com/dreadnode/shannon.git
   git clone https://github.com/dreadnode/vulnhuntr.git
   git clone https://github.com/leondz/garak.git
   git clone https://github.com/Azure/PyRIT.git pyrit
   # ... clone remaining 6 tools

2. Compile Proto Files
   ────────────────────
   cd proto/
   protoc --go_out=../go/internal --go-grpc_out=../go/internal \
          --go_opt=paths=source_relative \
          --go-grpc_opt=paths=source_relative \
          *.proto
   
   python -m grpc_tools.protoc -I. \
          --python_out=../python/core \
          --grpc_python_out=../python/core \
          *.proto

3. Install Dependencies
   ────────────────────
   # Python
   pip install -e .
   
   # Go
   cd go && go mod download
   
   # System
   apt-get install nmap protobuf-compiler
   playwright install chromium

4. Download Data Files
   ───────────────────
   cd data/payload_corpora/
   chmod +x setup.sh
   ./setup.sh
   
   # Download CISA KEV
   curl -o data/cisa_kev.json \
     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

5. Implement Core Logic
   ────────────────────
   # Each Python module needs actual implementation
   # Each Go package needs complete logic
   # Estimated: 2-4 weeks of development

6. Build Docker Images
   ───────────────────
   docker-compose build

7. Run Integration Tests
   ─────────────────────
   docker-compose --profile testing up -d
   pytest -m integration

8. Validate Complete System
   ────────────────────────
   ./scripts/validate.sh
```

## Summary

**What Exists**: Complete architectural blueprint with all files, structure, and interfaces defined.

**What's Missing**: 
- External tool repositories (10 repos)
- Compiled gRPC code
- Actual implementation logic in most modules
- Installed dependencies
- Downloaded data files
- Built Docker images

**Estimated Completion Time**: 2-4 weeks of full-time development to make fully functional.

**Current Value**: Extremely high for a development team - saves months of architecture and design work. Provides clear roadmap for implementation.
