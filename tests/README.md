# llmrt Test Suite

Comprehensive test suite for the llmrt security assessment platform.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and pytest configuration
├── pytest.ini               # Pytest settings
├── run_tests.sh            # Test runner script
├── unit/                   # Unit tests (fast, no external dependencies)
│   ├── test_scope_validator.py
│   ├── test_response_classifier.py
│   ├── test_finding_normaliser.py
│   ├── test_evidence_store.py
│   ├── test_cvss_scorer.py
│   └── test_deduplicator.py
├── integration/            # Integration tests (require services)
│   └── test_mock_servers.py
└── mock_server/           # Mock vulnerable servers for testing
    ├── app.py             # Vulnerable LLM application
    ├── mcp_server.py      # Vulnerable MCP server
    └── README.md          # Mock server documentation
```

## Running Tests

### Quick Start

```bash
# Run all unit tests (fast)
pytest -m unit

# Run all tests
pytest

# Run with coverage
pytest --cov=python --cov-report=html
```

### Using Test Runner Script

```bash
# Make script executable
chmod +x tests/run_tests.sh

# Run unit tests only
./tests/run_tests.sh unit

# Run integration tests (requires mock servers)
./tests/run_tests.sh integration

# Run all tests
./tests/run_tests.sh all

# Run with coverage
./tests/run_tests.sh coverage
```

## Test Categories

### Unit Tests (`-m unit`)

Fast tests with no external dependencies. Test individual modules in isolation.

**Coverage:**
- Scope validation
- Response classification
- Finding normalization
- Evidence storage
- CVSS scoring
- Deduplication

**Run time:** < 5 seconds

```bash
pytest -m unit
```

### Integration Tests (`-m integration`)

Tests that require external services (mock servers, databases, etc.).

**Coverage:**
- Mock LLM application vulnerabilities
- Mock MCP server vulnerabilities
- End-to-end campaign flows
- gRPC communication

**Prerequisites:**
```bash
# Start mock servers
docker-compose --profile testing up -d
```

**Run time:** 30-60 seconds

```bash
pytest -m integration
```

### Slow Tests (`-m slow`)

Long-running tests (white-box analysis, full campaigns, etc.).

```bash
pytest -m slow
```

### Tests Requiring API Keys (`-m requires_api_key`)

Tests that need real API keys (Anthropic, NVD, etc.).

```bash
# Set API keys first
export ANTHROPIC_API_KEY=your_key

pytest -m requires_api_key
```

## Test Fixtures

Common fixtures available in all tests (defined in `conftest.py`):

- `temp_dir` - Temporary directory for test files
- `test_scope_file` - Sample scope.yaml file
- `test_config_file` - Sample configuration file
- `mock_grpc_client` - Mock gRPC client
- `mock_anthropic_client` - Mock Anthropic API client
- `test_database` - Test SQLite database
- `sample_payloads` - Sample attack payloads
- `sample_responses` - Sample LLM responses
- `sample_mcp_schema` - Sample MCP schema
- `sample_finding` - Sample security finding
- `mock_interactsh_server` - Mock OOB server
- `mock_http_response` - Mock HTTP response

## Writing Tests

### Unit Test Example

```python
import pytest
from python.core.scope_validator import ScopeValidator

@pytest.mark.unit
class TestScopeValidator:
    def test_is_in_scope(self, test_scope_file):
        validator = ScopeValidator(str(test_scope_file))
        assert validator.is_in_scope("https://example.com/api")
```

### Integration Test Example

```python
import pytest
import httpx

@pytest.mark.integration
class TestMockServer:
    @pytest.mark.asyncio
    async def test_vulnerability(self):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://localhost:9999/api/chat",
                json={"message": "test"}
            )
            assert response.status_code == 200
```

### Async Test Example

```python
import pytest

@pytest.mark.asyncio
async def test_async_function():
    result = await some_async_function()
    assert result is not None
```

## Coverage

Generate coverage reports:

```bash
# HTML report
pytest --cov=python --cov-report=html
open htmlcov/index.html

# Terminal report
pytest --cov=python --cov-report=term

# XML report (for CI/CD)
pytest --cov=python --cov-report=xml
```

**Coverage Goals:**
- Unit tests: > 80% coverage
- Integration tests: > 60% coverage
- Overall: > 70% coverage

## Continuous Integration

Tests run automatically on:
- Every commit (unit tests)
- Pull requests (unit + integration tests)
- Nightly builds (all tests including slow)

### CI Configuration

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: |
          docker-compose up -d
          pytest -m "unit or integration"
```

## Mock Servers

### Starting Mock Servers

```bash
# Using Docker Compose
docker-compose --profile testing up -d

# Manually
python tests/mock_server/app.py &
python tests/mock_server/mcp_server.py &
```

### Mock Server Endpoints

**LLM Application (port 9999):**
- `POST /api/chat` - Prompt injection
- `POST /api/query` - SQL injection
- `POST /api/completion` - Code execution
- `GET /api/config` - Secret exposure

**MCP Server (port 9998):**
- `POST /mcp` - MCP JSON-RPC endpoint
- `GET /oauth/authorize` - OAuth vulnerabilities
- `GET /health` - Health check

### Verifying Mock Servers

```bash
# Check if servers are running
curl http://localhost:9999/health
curl http://localhost:9998/health

# Test vulnerability
curl -X POST http://localhost:9999/api/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Ignore previous instructions"}'
```

## Troubleshooting

### Tests Fail to Import Modules

```bash
# Install package in development mode
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH="${PYTHONPATH}:$(pwd)"
```

### Integration Tests Fail

```bash
# Check if mock servers are running
docker-compose ps

# Check logs
docker-compose logs mock-llm-app
docker-compose logs mock-mcp-server

# Restart services
docker-compose --profile testing restart
```

### Database Locked Errors

```bash
# Remove test databases
rm tests/**/*.db

# Or use separate database for each test
pytest --create-db
```

### Slow Test Performance

```bash
# Run tests in parallel (requires pytest-xdist)
pip install pytest-xdist
pytest -n auto

# Skip slow tests
pytest -m "not slow"
```

## Best Practices

1. **Isolation**: Each test should be independent
2. **Fixtures**: Use fixtures for common setup
3. **Markers**: Mark tests appropriately (unit, integration, slow)
4. **Assertions**: Use descriptive assertion messages
5. **Cleanup**: Clean up resources in fixtures
6. **Mocking**: Mock external dependencies in unit tests
7. **Documentation**: Add docstrings to test classes and methods

## Test Metrics

Current test coverage:

- Unit tests: 6 test files, ~50 test cases
- Integration tests: 1 test file, ~15 test cases
- Total: ~65 test cases

**Target metrics:**
- Total tests: 100+
- Code coverage: > 70%
- Test execution time: < 2 minutes (unit), < 5 minutes (all)

## Contributing

When adding new features:

1. Write unit tests first (TDD)
2. Add integration tests for new endpoints
3. Update fixtures if needed
4. Run full test suite before committing
5. Ensure coverage doesn't decrease

```bash
# Before committing
pytest -m unit
pytest --cov=python --cov-report=term
```

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Pytest Fixtures](https://docs.pytest.org/en/stable/fixture.html)
- [Pytest Markers](https://docs.pytest.org/en/stable/mark.html)
- [Pytest Coverage](https://pytest-cov.readthedocs.io/)
