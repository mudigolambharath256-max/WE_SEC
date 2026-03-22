# llm-redteam (llmrt)

**Enterprise-Grade AI/LLM/MCP Security Assessment Platform**

llmrt is an authorised security testing platform for AI applications, LLM systems, and Model Context Protocol (MCP) servers. Built with a polyglot architecture combining Go's speed with Python's intelligence.

[![Build Status](https://img.shields.io/badge/build-93%25-green)]()
[![License](https://img.shields.io/badge/license-MIT-blue)]()
[![Go Version](https://img.shields.io/badge/go-1.22+-00ADD8)]()
[![Python Version](https://img.shields.io/badge/python-3.11+-3776AB)]()

## ⚠️ Legal Notice

**AUTHORISED TESTING ONLY**

This tool is designed for authorised security assessments only. You must have explicit written permission to test any target system. Unauthorised testing is illegal and unethical.

Every campaign requires a scope.yaml file defining allowed targets. Out-of-scope requests are blocked automatically.

## Features

### 🎯 Comprehensive Attack Coverage

- **Prompt Injection**: 330+ payloads including ChatInject, FlipAttack, Unicode injection
- **Jailbreak Detection**: Multi-technique bypass attempts with adaptive strategies
- **Code Execution**: LLMSmith RCE patterns with MD5 verification
- **RAG Attacks**: Document poisoning, vector DB manipulation, memory poisoning
- **MCP Security**: Lethal Trifecta detection, rug pull testing, OAuth vulnerabilities
- **SQL Injection**: 40+ templates including Aurora DSQL bypass patterns
- **PII Leakage**: Automated detection of sensitive data exposure
- **OOB Exfiltration**: Interactsh integration for out-of-band detection

### 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Python Intelligence Layer                   │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Orchestrator │→ │  Adaptive    │→ │  Response    │      │
│  │ (Phase Gate) │  │ Orchestrator │  │ Classifier   │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         ↓ gRPC                                               │
├─────────────────────────────────────────────────────────────┤
│                     Go Speed Layer                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Probe Server │  │ Recon Server │  │  MCP Server  │      │
│  │   (50051)    │  │   (50052)    │  │   (50053)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│         ↓ HTTP                                               │
└─────────────────────────────────────────────────────────────┘
                            ↓
                    ┌──────────────┐
                    │   Target     │
                    │  (AI App)    │
                    └──────────────┘
```

### 🔬 Intelligence & Analysis

- **CVE Enrichment**: NVD API integration with CISA KEV monitoring
- **Technology Fingerprinting**: Automated tech stack detection
- **White-Box Analysis**: Shannon, Vulnhuntr, xVulnhuntr integration
- **Static Analysis**: Semgrep rules for AI-specific vulnerabilities
- **Supply Chain**: Dependency auditing and package vulnerability scanning

### 📊 Reporting & Frameworks

- **MITRE ATT&CK for LLMs**: Automated technique mapping
- **OWASP LLM Top 10**: v1.1 compliance mapping
- **Agentic OWASP**: AI agent security framework
- **OWASP MCP Top 10**: MCP-specific vulnerabilities
- **Adversa MCP Top 25**: Comprehensive MCP attack taxonomy
- **CVSS 4.0 Scoring**: Automated severity calculation
- **Multi-Format Reports**: HTML, PDF, JSON, Markdown

### 🛡️ Security Features

- **Scope Validation**: Automatic out-of-scope blocking
- **Rate Limiting**: Token bucket with 5 req/s default
- **Encrypted Evidence**: SQLCipher database encryption
- **4-Layer FP Pipeline**: Consistency, echo, semantic, reproducibility checks
- **Deduplication**: ssdeep fuzzy hashing (80% threshold)
- **Auth Management**: 5 auth types with automatic refresh

## Quick Start

### Prerequisites

- Go 1.22+
- Python 3.11+
- Docker & Docker Compose (optional)
- API keys: Anthropic (required), NVD, Shodan (optional)

### Installation

#### Option 1: Docker (Recommended)

```bash
# Clone repository
git clone https://github.com/yourusername/llm-redteam.git
cd llm-redteam

# Configure environment
cp .env.example .env
nano .env  # Add your API keys

# Start services
docker-compose up -d

# Verify
curl http://localhost:8000/health
```

#### Option 2: Local Build

```bash
# Clone repository
git clone https://github.com/yourusername/llm-redteam.git
cd llm-redteam

# Build Go services
cd go
go build ./cmd/probe_server
go build ./cmd/recon_server
go build ./cmd/mcp_server

# Install Python dependencies
cd ..
pip install -e .

# Generate gRPC stubs
make build-proto

# Start services
./go/probe_server &
./go/recon_server &
./go/mcp_server &
uvicorn python.api.app:app --host 0.0.0.0 --port 8000
```

### Basic Usage

#### 1. Create Scope File

```yaml
# config/my_scope.yaml
scope_boundaries:
  allowed_domains:
    - example.com
    - api.example.com
  excluded_paths:
    - /admin
    - /internal
  excluded_extensions:
    - .jpg
    - .png
```

#### 2. Run Campaign

```bash
# CLI
llmrt scan --target https://example.com/api/chat --profile chatbot --scope config/my_scope.yaml

# API
curl -X POST http://localhost:8000/api/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Example Campaign",
    "target_url": "https://example.com/api/chat",
    "profile": "chatbot",
    "scope_file": "config/my_scope.yaml"
  }'
```

#### 3. View Results

```bash
# CLI
llmrt report --campaign-id abc123 --format html

# API
curl http://localhost:8000/api/campaigns/abc123/report > report.html
```

## Profiles

Pre-configured testing profiles for common scenarios:

- **chatbot**: General chatbot applications
- **rag_app**: RAG-based applications
- **mcp_agent**: MCP servers and agents
- **ide_assistant**: IDE coding assistants

## Attack Modules

### Prompt Attacks (18 modules)
- corpus_runner.py - Corpus-based injection
- oob_detector.py - Out-of-band exfiltration
- unicode_injection_runner.py - Zero-width, BiDi, homoglyph
- rce_probe_runner.py - Code execution detection
- flipattack_runner.py - FCS, FCW, FWO obfuscation
- adversarial_poetry_runner.py - Poetic obfuscation
- multilingual_runner.py - Non-English injection
- idor_llm_chain_tester.py - Authorization bypass
- timing_attack_tester.py - Response timing analysis
- env_injection_tester.py - Environment variable exfiltration
- upload_path_traversal_tester.py - Path traversal
- garak_runner.py - Garak integration (60+ probes)
- pyrit_runner.py - Microsoft PyRIT
- augustus_runner.py - Augustus framework
- deepteam_runner.py - DeepTeam testing
- artkit_runner.py - ArtKit robustness
- rigging_agent_runner.py - Rigging framework
- promptfoo_runner.py - Promptfoo evaluation

### RAG Attacks (7 modules)
- llamator_runner.py - Llamator framework
- doc_injector.py - Document poisoning
- code_file_injector.py - Code poisoning
- stored_prompt_injector.py - Persistent injection
- vector_db_attacker.py - Vector DB manipulation
- memory_poison_tester.py - Memory poisoning
- context_monitor.py - Context analysis

### MCP Attacks (17 modules)
- lethal_trifecta_detector.py - Write + exec + network
- mcp_tool_llm_scanner.py - Tool vulnerability scanning
- mcp_sampling_attacker.py - Sampling attacks
- cross_tool_orchestration_injector.py - Tool chaining
- mcp_remote_oauth_injector.py - OAuth injection
- claude_code_config_injector.py - Config injection
- permission_inheritance_tester.py - Permission flaws
- oauth_endpoint_xss_tester.py - XSS in OAuth
- session_id_url_harvester.py - Session harvesting
- oauth_confused_deputy.py - Confused deputy
- token_passthrough_tester.py - Token leakage
- rug_pull_tester.py - Rug pull detection
- tool_name_spoofer.py - Tool spoofing
- context_bleeder.py - Context bleeding
- cross_tenant_tester.py - Tenant isolation
- privilege_escalator.py - Privilege escalation
- agent_memory_attacker.py - Memory manipulation

## Configuration

### Environment Variables

```bash
# Required
ANTHROPIC_API_KEY=your_key
CAMPAIGN_ENCRYPT_KEY=your_32_char_key

# Optional
NVD_API_KEY=your_nvd_key
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_token
INTERACTSH_SERVER=your_interactsh_server
INTERACTSH_TOKEN=your_token

# Defaults
DEFAULT_RATE_LIMIT_MS=200
DEFAULT_CONCURRENCY=5
MAX_TURNS=10
```

### Scope Configuration

Every campaign requires a scope.yaml file:

```yaml
scope_boundaries:
  allowed_domains:
    - target.com
  excluded_paths:
    - /admin
  excluded_extensions:
    - .jpg

authorization:
  type: api_key  # api_key, session_cookie, jwt, oauth_bearer, none
  header_name: Authorization
  token: ${API_KEY}

rate_limiting:
  requests_per_second: 5
  burst: 10

campaign_settings:
  max_turns: 10
  concurrency: 5
  timeout_seconds: 30
```

## Testing

### Run Mock Servers

```bash
# Start vulnerable test servers
docker-compose --profile testing up -d

# Mock LLM app: http://localhost:9999
# Mock MCP server: http://localhost:9998
```

### Run Tests

```bash
# Unit tests
pytest tests/unit/

# Integration tests
pytest tests/integration/

# Test against mock servers
llmrt scan --target http://localhost:9999 --profile chatbot
llmrt scan --target http://localhost:9998 --profile mcp_agent
```

## Development

### Project Structure

```
llm-redteam/
├── go/                      # Go speed layer
│   ├── cmd/                 # gRPC servers
│   └── internal/            # Transport, runners
├── python/                  # Python intelligence layer
│   ├── core/                # Orchestration, classification
│   ├── prompt_attacks/      # Prompt injection modules
│   ├── rag_attacks/         # RAG security modules
│   ├── mcp_attacks/         # MCP security modules
│   ├── recon/               # Reconnaissance
│   ├── intelligence/        # CVE enrichment
│   ├── evidence/            # Evidence storage
│   ├── reporting/           # Report generation
│   ├── proxy/               # Traffic interception
│   ├── browser/             # Browser automation
│   ├── api/                 # FastAPI REST API
│   └── cli/                 # CLI interface
├── proto/                   # gRPC protocol definitions
├── config/                  # Configuration files
├── data/                    # Payloads, templates, rules
├── tests/                   # Tests and mock servers
└── output/                  # Campaign results
```

### Build from Source

```bash
# Build Go services
make build-go

# Generate gRPC stubs
make build-proto

# Install Python package
pip install -e .

# Run tests
make test

# Validate build
make validate
```

## Documentation

- [Docker Deployment Guide](DOCKER.md)
- [Build Status](BUILD_STATUS.md)
- [Complete Specification](llmrt_kiro_spec.md)

## Contributing

Contributions welcome! Please:

1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Ensure all tests pass

## Roadmap

- [x] Core orchestration and phase gating
- [x] Prompt injection attacks (18 modules)
- [x] RAG attacks (7 modules)
- [x] MCP attacks (17 modules)
- [x] CVE enrichment and intelligence
- [x] Multi-framework reporting
- [x] Docker deployment
- [ ] Unit and integration tests
- [ ] CI/CD pipeline
- [ ] Web UI dashboard
- [ ] Plugin system
- [ ] Cloud deployment templates

## Security

### Reporting Vulnerabilities

If you discover a security vulnerability in llmrt itself, please email security@example.com. Do not open a public issue.

### Responsible Use

llmrt is a powerful security testing tool. Use it responsibly:

- ✅ Only test systems you own or have written permission to test
- ✅ Define clear scope boundaries in scope.yaml
- ✅ Follow responsible disclosure practices
- ✅ Respect rate limits and system resources
- ❌ Never test production systems without approval
- ❌ Never use for malicious purposes
- ❌ Never bypass scope validation

## License

MIT License - see LICENSE file for details

## Acknowledgments

Built with:
- [Anthropic Claude](https://anthropic.com) - LLM API
- [Garak](https://github.com/leondz/garak) - LLM vulnerability scanner
- [PyRIT](https://github.com/Azure/PyRIT) - Microsoft red team toolkit
- [Shannon](https://github.com/dreadnode/shannon) - White-box analysis
- [Vulnhuntr](https://github.com/dreadnode/vulnhuntr) - Vulnerability detection
- [Semgrep](https://semgrep.dev) - Static analysis
- [Nuclei](https://nuclei.projectdiscovery.io) - Vulnerability scanning

Security frameworks:
- [MITRE ATT&CK for LLMs](https://atlas.mitre.org)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Adversa MCP Top 25](https://adversa.ai/mcp-top-25)

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](https://github.com/yourusername/llm-redteam/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/llm-redteam/discussions)

---

**Built with ❤️ for the AI security community**
