# Contributing to llmrt

Thank you for your interest in contributing to llmrt! This document provides guidelines and instructions for contributing.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Follow responsible disclosure for security issues

## Getting Started

### Prerequisites

- Go 1.22+
- Python 3.11+
- Docker & Docker Compose
- Git

### Development Setup

1. **Fork and clone the repository**:
```bash
git clone https://github.com/yourusername/llm-redteam.git
cd llm-redteam
```

2. **Set up Python environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e ".[dev]"
```

3. **Set up Go environment**:
```bash
cd go
go mod download
cd ..
```

4. **Configure environment**:
```bash
cp .env.example .env
# Edit .env with your API keys
```

5. **Run validation**:
```bash
chmod +x scripts/validate.sh
./scripts/validate.sh
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Test additions/improvements
- `refactor/` - Code refactoring

### 2. Make Changes

Follow the coding standards below and ensure:
- Code is well-documented
- Tests are added/updated
- No breaking changes (or clearly documented)

### 3. Test Your Changes

```bash
# Run unit tests
pytest -m unit

# Run integration tests
docker-compose --profile testing up -d
pytest -m integration

# Run Go tests
cd go && go test ./... && cd ..

# Run validation
./scripts/validate.sh
```

### 4. Commit Changes

Follow conventional commits:

```bash
git commit -m "feat: add new attack module for XYZ"
git commit -m "fix: resolve scope validation bug"
git commit -m "docs: update API documentation"
git commit -m "test: add tests for deduplicator"
```

Commit message format:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation
- `test` - Tests
- `refactor` - Code refactoring
- `perf` - Performance improvement
- `chore` - Maintenance

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear description of changes
- Link to related issues
- Screenshots/examples if applicable
- Test results

## Coding Standards

### Python

Follow PEP 8 and use these tools:

```bash
# Format code
black python/

# Lint code
ruff check python/

# Type checking
mypy python/ --ignore-missing-imports
```

**Standards:**
- Use type hints
- Write docstrings for all functions/classes
- Maximum line length: 100 characters
- Use f-strings for formatting
- Prefer explicit over implicit

**Example:**
```python
def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a security finding to standard format.
    
    Args:
        finding: Raw finding dictionary
        
    Returns:
        Normalized finding with standard fields
        
    Raises:
        ValueError: If finding is missing required fields
    """
    # Implementation
    pass
```

### Go

Follow Go conventions:

```bash
# Format code
go fmt ./...

# Lint code
golangci-lint run

# Vet code
go vet ./...
```

**Standards:**
- Use `gofmt` formatting
- Write godoc comments
- Handle all errors explicitly
- Use meaningful variable names
- Keep functions small and focused

**Example:**
```go
// FireProbe sends a single probe to the target endpoint.
// Returns the response body, status code, and any error encountered.
func FireProbe(ctx context.Context, payload string, endpoint string) (string, int, error) {
    // Implementation
    return "", 0, nil
}
```

### Documentation

- Use clear, concise language
- Include code examples
- Update README.md for user-facing changes
- Add inline comments for complex logic
- Keep documentation up-to-date

## Testing Guidelines

### Unit Tests

- Test individual functions/methods
- Mock external dependencies
- Fast execution (< 5 seconds total)
- High coverage (> 80%)

```python
@pytest.mark.unit
def test_scope_validator():
    validator = ScopeValidator("test_scope.yaml")
    assert validator.is_in_scope("https://example.com")
```

### Integration Tests

- Test component interactions
- Use mock servers
- Test realistic scenarios
- Mark as `@pytest.mark.integration`

```python
@pytest.mark.integration
@pytest.mark.asyncio
async def test_full_campaign():
    # Test complete workflow
    pass
```

### Test Coverage

Maintain coverage above 70%:

```bash
pytest --cov=python --cov-report=html
open htmlcov/index.html
```

## Adding New Features

### New Attack Module

1. **Create module file**:
```python
# python/prompt_attacks/new_attack_runner.py
"""
New attack module description.

This module implements XYZ attack technique...
"""

from python.core.scope_validator import ScopeValidator

async def run_attack(target_url: str, scope_validator: ScopeValidator):
    """Run the new attack."""
    # Validate scope first
    scope_validator.validate_or_raise(target_url)
    
    # Implementation
    pass
```

2. **Add tests**:
```python
# tests/unit/test_new_attack_runner.py
@pytest.mark.unit
def test_new_attack():
    # Test implementation
    pass
```

3. **Update documentation**:
- Add to README.md attack list
- Document in module docstring
- Add usage examples

### New Configuration Option

1. **Update schema**:
```python
# python/core/config_schema.py
class CampaignConfig(BaseModel):
    new_option: str = Field(default="value", description="...")
```

2. **Update default config**:
```yaml
# config/default.yaml
new_option: value
```

3. **Document in README.md**

## Pull Request Process

1. **Ensure all checks pass**:
   - Unit tests
   - Integration tests
   - Linting
   - Type checking

2. **Update documentation**:
   - README.md if user-facing
   - Docstrings
   - CHANGELOG.md

3. **Request review**:
   - Assign reviewers
   - Respond to feedback
   - Make requested changes

4. **Merge requirements**:
   - All CI checks pass
   - At least 1 approval
   - No merge conflicts
   - Up-to-date with main

## Security

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Instead:
1. Email security@example.com
2. Include detailed description
3. Provide reproduction steps
4. Wait for response before disclosure

### Security Guidelines

- Never commit secrets/API keys
- Validate all user input
- Use parameterized queries
- Follow principle of least privilege
- Keep dependencies updated

## Release Process

Releases are automated via GitHub Actions:

1. **Update version**:
```bash
# Update pyproject.toml and go.mod
git commit -m "chore: bump version to 1.1.0"
```

2. **Create tag**:
```bash
git tag v1.1.0
git push origin v1.1.0
```

3. **Automated release**:
   - GitHub release created
   - Docker images published
   - PyPI package published
   - Binaries attached

## Community

- **Discussions**: GitHub Discussions for questions
- **Issues**: GitHub Issues for bugs/features
- **Pull Requests**: For code contributions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Questions?

- Check existing issues and discussions
- Read the documentation
- Ask in GitHub Discussions
- Email maintainers

Thank you for contributing to llmrt!
