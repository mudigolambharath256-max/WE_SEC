# llmrt Docker Deployment Guide

This guide covers deploying llmrt using Docker and Docker Compose.

## Architecture

llmrt uses a microservices architecture with the following containers:

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Network (llmrt-network)           │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ probe-server │  │ recon-server │  │  mcp-server  │     │
│  │   (Go)       │  │   (Go)       │  │   (Go)       │     │
│  │   :50051     │  │   :50052     │  │   :50053     │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│         ↑                 ↑                 ↑               │
│         └─────────────────┴─────────────────┘               │
│                           │                                 │
│                    ┌──────────────┐                         │
│                    │ orchestrator │                         │
│                    │   (Python)   │                         │
│                    │    :8000     │                         │
│                    └──────────────┘                         │
│                                                              │
│  Optional Services:                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │   shannon    │  │  mitmproxy   │  │     zap      │     │
│  │  (whitebox)  │  │   (proxy)    │  │   (proxy)    │     │
│  └──────────────┘  └──────────────┘  └──────────────┘     │
│                                                              │
│  Testing Services:                                          │
│  ┌──────────────┐  ┌──────────────┐                        │
│  │ mock-llm-app │  │mock-mcp-srv  │                        │
│  │   :9999      │  │   :9998      │                        │
│  └──────────────┘  └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- 4GB+ RAM available
- 10GB+ disk space

## Quick Start

### 1. Configure Environment

Copy the example environment file and fill in your API keys:

```bash
cp .env.example .env
nano .env
```

Required variables:
```bash
ANTHROPIC_API_KEY=your_key_here
CAMPAIGN_ENCRYPT_KEY=your_32_char_encryption_key
```

Optional variables:
```bash
NVD_API_KEY=your_nvd_key
SHODAN_API_KEY=your_shodan_key
GITHUB_TOKEN=your_github_token
```

### 2. Build Images

```bash
# Build all images
docker-compose build

# Build specific service
docker-compose build orchestrator
```

### 3. Start Core Services

```bash
# Start core services (probe, recon, mcp, orchestrator)
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f orchestrator
```

### 4. Access Services

- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## Service Profiles

Docker Compose uses profiles to organize optional services:

### Core Services (default)
Always started with `docker-compose up`:
- `probe-server` - HTTP probe execution
- `recon-server` - Reconnaissance and scanning
- `mcp-server` - MCP attack execution
- `orchestrator` - Intelligence layer and API

### Whitebox Profile
For white-box source code analysis:
```bash
docker-compose --profile whitebox up -d shannon
```

### Proxy Profile
For traffic interception and analysis:
```bash
docker-compose --profile proxy up -d mitmproxy zap
```

Access:
- **mitmproxy web**: http://localhost:8081
- **ZAP API**: http://localhost:8090

### Testing Profile
For running mock vulnerable servers:
```bash
docker-compose --profile testing up -d mock-llm-app mock-mcp-server
```

Access:
- **Mock LLM App**: http://localhost:9999
- **Mock MCP Server**: http://localhost:9998

### Intelligence Profile
For CVE enrichment services:
```bash
docker-compose --profile intelligence up -d mcp-nvd
```

### All Services
Start everything:
```bash
docker-compose --profile whitebox --profile proxy --profile testing --profile intelligence up -d
```

## Usage Examples

### Run a Campaign via API

```bash
# Create campaign
curl -X POST http://localhost:8000/api/campaigns \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Campaign",
    "target_url": "https://example.com/api/chat",
    "profile": "chatbot"
  }'

# Get campaign status
curl http://localhost:8000/api/campaigns/{campaign_id}

# Download report
curl http://localhost:8000/api/campaigns/{campaign_id}/report > report.html
```

### Run CLI Commands

```bash
# Execute CLI command in container
docker-compose exec orchestrator llmrt scan --target https://example.com --profile chatbot

# Run specific attack
docker-compose exec orchestrator llmrt attack prompt-injection --target https://example.com/api/chat

# Generate report
docker-compose exec orchestrator llmrt report --campaign-id abc123 --format pdf
```

### Test Against Mock Servers

```bash
# Start testing profile
docker-compose --profile testing up -d

# Run scan against mock LLM app
docker-compose exec orchestrator llmrt scan \
  --target http://mock-llm-app:9999 \
  --profile chatbot

# Run MCP attacks against mock MCP server
docker-compose exec orchestrator llmrt scan \
  --target http://mock-mcp-server:9998 \
  --profile mcp_agent
```

### White-Box Analysis with Shannon

```bash
# Start Shannon
docker-compose --profile whitebox up -d shannon

# Run Shannon analysis
docker-compose exec shannon python -m shannon.cli \
  --repo https://github.com/example/llm-app \
  --output /shannon/workspace/results
```

### Traffic Interception with mitmproxy

```bash
# Start proxy
docker-compose --profile proxy up -d mitmproxy

# Configure target to use proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# View traffic at http://localhost:8081
```

## Data Persistence

### Output Directory
Campaign results are stored in `./output/` which is mounted as a volume:

```bash
./output/
├── campaigns/
│   └── {campaign_id}/
│       ├── findings.db (encrypted)
│       ├── report.html
│       ├── report.pdf
│       └── report.json
└── shannon/
    └── {analysis_id}/
```

### Database Encryption
The findings database is encrypted using SQLCipher with the key from `CAMPAIGN_ENCRYPT_KEY`.

## Scaling

### Horizontal Scaling

Scale probe execution for high-throughput campaigns:

```bash
# Scale probe servers
docker-compose up -d --scale probe-server=3

# Update orchestrator to use multiple probe servers
# (requires load balancer configuration)
```

### Resource Limits

Set resource limits in docker-compose.yml:

```yaml
services:
  orchestrator:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

## Monitoring

### Health Checks

All services include health checks:

```bash
# Check all services
docker-compose ps

# Check specific service
docker inspect llmrt-orchestrator | jq '.[0].State.Health'
```

### Logs

```bash
# View all logs
docker-compose logs -f

# View specific service
docker-compose logs -f orchestrator

# View last 100 lines
docker-compose logs --tail=100 probe-server

# Follow logs with timestamps
docker-compose logs -f -t orchestrator
```

### Metrics

Access container metrics:

```bash
# Container stats
docker stats

# Specific container
docker stats llmrt-orchestrator
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs orchestrator

# Rebuild image
docker-compose build --no-cache orchestrator

# Remove and recreate
docker-compose down
docker-compose up -d
```

### gRPC Connection Issues

```bash
# Test gRPC connectivity
docker-compose exec orchestrator nc -zv probe-server 50051

# Check network
docker network inspect llmrt-network
```

### Permission Issues

```bash
# Fix output directory permissions
sudo chown -R 1000:1000 ./output

# Check container user
docker-compose exec orchestrator id
```

### Out of Memory

```bash
# Increase Docker memory limit (Docker Desktop)
# Settings → Resources → Memory → 8GB

# Or set limits in docker-compose.yml
```

## Security Considerations

### Production Deployment

⚠️ **DO NOT expose these ports to the internet without proper security:**

1. **Use reverse proxy with authentication**:
   ```yaml
   services:
     nginx:
       image: nginx:alpine
       ports:
         - "443:443"
       volumes:
         - ./nginx.conf:/etc/nginx/nginx.conf:ro
   ```

2. **Enable TLS**:
   - Use Let's Encrypt for certificates
   - Configure TLS in nginx/traefik

3. **Network isolation**:
   - Use internal networks for service communication
   - Only expose API through reverse proxy

4. **Secrets management**:
   - Use Docker secrets instead of environment variables
   - Rotate API keys regularly

5. **Update regularly**:
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

### Testing Environment

For testing, the mock servers are intentionally vulnerable:

⚠️ **NEVER expose mock servers to the internet**

```bash
# Only bind to localhost
ports:
  - "127.0.0.1:9999:9999"
```

## Backup and Restore

### Backup Campaign Data

```bash
# Backup output directory
tar -czf llmrt-backup-$(date +%Y%m%d).tar.gz ./output/

# Backup to remote
rsync -avz ./output/ user@backup-server:/backups/llmrt/
```

### Restore Campaign Data

```bash
# Restore from backup
tar -xzf llmrt-backup-20240101.tar.gz

# Set permissions
chown -R 1000:1000 ./output/
```

## Cleanup

### Stop Services

```bash
# Stop all services
docker-compose down

# Stop and remove volumes
docker-compose down -v

# Stop specific profile
docker-compose --profile testing down
```

### Remove Images

```bash
# Remove llmrt images
docker-compose down --rmi all

# Remove all unused images
docker image prune -a
```

### Clean Everything

```bash
# Nuclear option - removes everything
docker-compose down -v --rmi all
docker system prune -a --volumes
```

## Development

### Local Development with Docker

```bash
# Mount source code for live reload
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up

# Run tests in container
docker-compose exec orchestrator pytest tests/
```

### Build Custom Images

```bash
# Build with custom tag
docker build -f Dockerfile.python -t llmrt-python:custom .

# Use custom image in docker-compose
docker-compose up -d
```

## Support

For issues with Docker deployment:
1. Check logs: `docker-compose logs`
2. Verify environment: `docker-compose config`
3. Test connectivity: `docker-compose exec orchestrator ping probe-server`
4. Review health checks: `docker-compose ps`

## License

llmrt Docker deployment is part of the llmrt project.
