# CI/CD Workflows

GitHub Actions workflows for llmrt continuous integration and deployment.

## Workflows

### 1. Tests (`test.yml`)

Runs on every push and pull request to `main` and `develop` branches.

**Jobs:**
- `unit-tests` - Fast unit tests with coverage reporting
- `integration-tests` - Integration tests against mock servers
- `go-tests` - Go unit tests with race detection
- `lint` - Code quality checks (ruff, black, mypy, golangci-lint)

**Triggers:**
```yaml
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
```

**Status Badge:**
```markdown
![Tests](https://github.com/yourusername/llm-redteam/workflows/Tests/badge.svg)
```

### 2. Build (`build.yml`)

Builds all components and validates Docker images.

**Jobs:**
- `build-go` - Compile Go binaries for all platforms
- `build-docker` - Build and validate Docker images
- `build-python` - Build Python package
- `security-scan` - Trivy vulnerability scanning

**Triggers:**
```yaml
on:
  push:
    branches: [ main, develop ]
    tags: [ 'v*' ]
  pull_request:
    branches: [ main ]
```

**Artifacts:**
- Go binaries (7 days retention)
- Python wheel/sdist (7 days retention)

### 3. Release (`release.yml`)

Automated release process triggered by version tags.

**Jobs:**
- `create-release` - Create GitHub release with changelog
- `build-and-push-docker` - Push Docker images to GHCR
- `publish-python-package` - Publish to PyPI
- `build-binaries` - Build cross-platform binaries

**Triggers:**
```yaml
on:
  push:
    tags: [ 'v*' ]
```

**Release Process:**
1. Tag a new version: `git tag v1.0.0 && git push origin v1.0.0`
2. Workflow creates GitHub release
3. Docker images pushed to `ghcr.io`
4. Python package published to PyPI
5. Binaries attached to release

## Setup

### Required Secrets

Configure these secrets in GitHub repository settings:

```
PYPI_API_TOKEN          # PyPI token for package publishing
CODECOV_TOKEN           # Codecov token for coverage reporting (optional)
```

### Required Permissions

Workflows need these permissions:
- `contents: write` - Create releases
- `packages: write` - Push to GHCR

### Branch Protection

Recommended branch protection rules for `main`:

- Require pull request reviews (1 reviewer)
- Require status checks to pass:
  - `unit-tests`
  - `integration-tests`
  - `go-tests`
  - `lint`
- Require branches to be up to date
- Require signed commits (optional)

## Local Testing

Test workflows locally using [act](https://github.com/nektos/act):

```bash
# Install act
brew install act  # macOS
# or
curl https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash

# Run unit tests workflow
act -j unit-tests

# Run all test jobs
act -W .github/workflows/test.yml

# Run with secrets
act -j unit-tests --secret-file .secrets
```

## Workflow Status

Check workflow status:

```bash
# Using GitHub CLI
gh run list
gh run view <run-id>
gh run watch

# View logs
gh run view <run-id> --log
```

## Caching

Workflows use caching to speed up builds:

- **Python dependencies**: `pip` cache
- **Go dependencies**: `go.sum` cache
- **Docker layers**: GitHub Actions cache

Cache is automatically invalidated when dependencies change.

## Coverage Reporting

Coverage reports are uploaded to Codecov:

- Unit tests: `flags: unittests`
- Go tests: `flags: gotests`

View coverage at: `https://codecov.io/gh/yourusername/llm-redteam`

## Troubleshooting

### Workflow Fails on Integration Tests

**Problem**: Mock servers not starting properly

**Solution**:
```yaml
- name: Wait for services
  run: |
    timeout 60 bash -c 'until curl -f http://localhost:9999/health; do sleep 2; done'
```

### Docker Build Fails

**Problem**: Out of disk space

**Solution**: Clean up Docker cache
```yaml
- name: Clean up Docker
  run: docker system prune -af
```

### Go Tests Fail with Race Detector

**Problem**: Race conditions detected

**Solution**: Fix race conditions or disable race detector temporarily
```yaml
run: go test -v ./...  # Without -race flag
```

### Python Package Build Fails

**Problem**: Missing dependencies

**Solution**: Ensure all dependencies in `pyproject.toml`
```yaml
- name: Install build dependencies
  run: pip install build wheel setuptools
```

## Optimization

### Speed Up Workflows

1. **Use caching**:
```yaml
- uses: actions/cache@v3
  with:
    path: ~/.cache/pip
    key: ${{ runner.os }}-pip-${{ hashFiles('**/pyproject.toml') }}
```

2. **Run jobs in parallel**:
```yaml
jobs:
  test-unit:
    # ...
  test-integration:
    # ...
  # Both run simultaneously
```

3. **Use matrix builds**:
```yaml
strategy:
  matrix:
    python-version: ['3.11', '3.12']
    os: [ubuntu-latest, macos-latest]
```

4. **Skip redundant runs**:
```yaml
on:
  push:
    paths-ignore:
      - '**.md'
      - 'docs/**'
```

### Reduce Costs

1. **Use self-hosted runners** for private repos
2. **Cancel redundant runs**:
```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

3. **Limit artifact retention**:
```yaml
- uses: actions/upload-artifact@v4
  with:
    retention-days: 7  # Instead of default 90
```

## Security

### Secrets Management

- Never commit secrets to repository
- Use GitHub Secrets for sensitive data
- Rotate secrets regularly
- Use environment-specific secrets

### Dependency Scanning

Workflows include security scanning:

- **Trivy**: Container vulnerability scanning
- **Safety**: Python dependency scanning
- **Dependabot**: Automated dependency updates

### SARIF Upload

Security scan results uploaded to GitHub Security:

```yaml
- name: Upload Trivy results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

View results in: Repository → Security → Code scanning alerts

## Monitoring

### Workflow Metrics

Track workflow performance:

- Average run time
- Success rate
- Failure patterns
- Resource usage

### Notifications

Configure notifications:

1. **Email**: GitHub settings → Notifications
2. **Slack**: Use GitHub Slack app
3. **Custom**: Use workflow webhooks

```yaml
- name: Notify on failure
  if: failure()
  uses: 8398a7/action-slack@v3
  with:
    status: ${{ job.status }}
    webhook_url: ${{ secrets.SLACK_WEBHOOK }}
```

## Best Practices

1. **Keep workflows DRY**: Use reusable workflows
2. **Pin action versions**: Use specific versions, not `@main`
3. **Test locally**: Use `act` before pushing
4. **Document changes**: Update this README when modifying workflows
5. **Monitor costs**: Check Actions usage in billing
6. **Use matrix builds**: Test multiple versions/platforms
7. **Fail fast**: Use `fail-fast: true` in matrix
8. **Clean up**: Remove old artifacts and caches

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Workflow Syntax](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions)
- [GitHub Actions Marketplace](https://github.com/marketplace?type=actions)
- [Act - Local Testing](https://github.com/nektos/act)
