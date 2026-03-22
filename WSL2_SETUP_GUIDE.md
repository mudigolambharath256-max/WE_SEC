# WSL2 Setup Guide for llmrt Development

**Recommendation**: Migrate to WSL2 for optimal development experience.

---

## Why WSL2?

### Current Status (Windows Native)
✅ Phase 1 complete - Proto compilation works  
✅ Go servers running and accessible  
✅ Python gRPC connections verified  

### Upcoming Blockers on Windows
❌ **SQLCipher** - `pysqlcipher3` requires complex Windows compilation  
❌ **External Tools** - Shannon, Vulnhuntr, Garak expect Linux  
❌ **Nmap** - Requires admin privileges, limited functionality  
❌ **Bash Scripts** - `scripts/setup_foundation.sh` and Makefile won't work in PowerShell  
❌ **Performance** - File I/O on Windows is 5-10x slower than WSL2 native  

### Benefits of WSL2
✅ All Linux tools work natively (no compilation issues)  
✅ 5-10x faster file I/O on native WSL2 filesystem  
✅ Bash scripts and Makefile work without modification  
✅ Nmap works without admin privileges  
✅ Docker integration is seamless  
✅ VS Code WSL extension provides native Windows editing experience  

---

## Installation Steps

### 1. Install WSL2 with Ubuntu 24.04

```powershell
# Run in PowerShell as Administrator
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2

# Verify installation
wsl --list --verbose
# Should show Ubuntu-24.04 with VERSION 2
```

### 2. Initial Ubuntu Setup

```bash
# Open Ubuntu terminal (search "Ubuntu" in Start menu)
# First launch will ask you to create a username and password

# Update system
sudo apt-get update && sudo apt-get upgrade -y

# Install essential build tools
sudo apt-get install -y \
    build-essential \
    git \
    curl \
    wget \
    unzip
```

### 3. Install Go 1.22+

```bash
# Download and install Go
cd /tmp
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz

# Add to PATH
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Verify
go version  # Should show go1.22.0 or higher
```

### 4. Install Python 3.11+

```bash
# Ubuntu 24.04 comes with Python 3.12
sudo apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Verify
python3 --version  # Should show Python 3.11+ or 3.12+
```

### 5. Install System Dependencies

```bash
# Install all required system packages
sudo apt-get install -y \
    protobuf-compiler \
    golang-goprotobuf-dev \
    nmap \
    libfuzzy-dev \
    libsqlcipher-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libssl-dev \
    libffi-dev

# Verify protoc
protoc --version  # Should show libprotoc 3.x or higher
```

### 6. Clone Repository (CRITICAL: Use WSL2 Native Filesystem)

```bash
# DO THIS - Clone to WSL2 native filesystem (~/ is fast)
cd ~
git clone <your-repo-url> llm-redteam
cd llm-redteam

# DON'T DO THIS - Avoid Windows filesystem (/mnt/c/ is 5-10x slower)
# cd /mnt/c/Users/acer/Desktop/LLM  # ❌ SLOW
```

**Why this matters**: The Windows filesystem mounted at `/mnt/c/` has significant I/O overhead. WSL2's native filesystem (`~/` which is `/home/username/`) is 5-10x faster.

### 7. Run Foundation Setup

```bash
# Now the bash script works perfectly
bash scripts/setup_foundation.sh

# This will:
# - Install Go proto plugins
# - Install Python dependencies
# - Compile proto files
# - Build all 3 Go servers
# - Verify everything works
```

---

## VS Code Integration

### Install VS Code WSL Extension

1. Open VS Code on Windows
2. Install "WSL" extension (ms-vscode-remote.remote-wsl)
3. From WSL terminal, run:
   ```bash
   cd ~/llm-redteam
   code .
   ```
4. VS Code opens connected to WSL2 - you can edit files as if they're local

### Benefits
- Edit files in Windows UI
- Terminal runs in WSL2 (all Linux commands work)
- Git integration works seamlessly
- Extensions run in WSL2 context
- No file sync issues

---

## Migration from Windows to WSL2

### Option A: Fresh Start (Recommended)

```bash
# 1. In WSL2, clone fresh copy
cd ~
git clone <your-repo-url> llm-redteam
cd llm-redteam

# 2. Run setup script
bash scripts/setup_foundation.sh

# 3. Start servers
./bin/probe_server &
./bin/recon_server &
./bin/mcp_server &

# 4. Test connection
python3 test_grpc_connection.py
```

**Time**: 20-30 minutes  
**Advantage**: Clean slate, no Windows artifacts

### Option B: Copy Existing Work

```bash
# 1. Copy from Windows to WSL2
cd ~
cp -r /mnt/c/Users/acer/Desktop/LLM llm-redteam
cd llm-redteam

# 2. Clean Windows build artifacts
rm -rf go/internal/proto/*.go
rm -rf python/core/*_pb2*.py
rm -rf bin/*.exe

# 3. Run setup script
bash scripts/setup_foundation.sh

# 4. Rebuild everything
cd go
go build -o ../bin/probe_server ./cmd/probe_server/
go build -o ../bin/recon_server ./cmd/recon_server/
go build -o ../bin/mcp_server ./cmd/mcp_server/
```

**Time**: 15-20 minutes  
**Advantage**: Keeps your existing work

---

## Development Workflow in WSL2

### Daily Workflow

```bash
# 1. Open WSL2 terminal
wsl

# 2. Navigate to project
cd ~/llm-redteam

# 3. Start servers
make start-servers  # Or manually start each

# 4. Open VS Code
code .

# 5. Run tests
make test

# 6. Stop servers
make stop-servers
```

### Accessing from Windows

```bash
# WSL2 services are accessible from Windows
# If probe_server runs on localhost:50051 in WSL2,
# Windows can access it at localhost:50051

# Test from Windows PowerShell:
Test-NetConnection -ComputerName localhost -Port 50051
```

---

## Docker Integration

### Install Docker in WSL2

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Start Docker service
sudo service docker start

# Verify
docker --version
docker-compose --version
```

### Use Docker Compose

```bash
# Build all services
docker-compose build

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f probe-server

# Stop all services
docker-compose down
```

---

## Troubleshooting

### WSL2 Not Starting

```powershell
# Enable WSL2 features (PowerShell as Admin)
dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart

# Restart computer, then:
wsl --set-default-version 2
```

### Slow Performance

```bash
# Check if you're on native filesystem
pwd
# Should show /home/username/... NOT /mnt/c/...

# If on /mnt/c/, move to native:
cd ~
cp -r /mnt/c/Users/acer/Desktop/LLM llm-redteam
cd llm-redteam
```

### Port Already in Use

```bash
# Find process using port
sudo lsof -i :50051

# Kill process
sudo kill -9 <PID>
```

### SQLCipher Installation Fails

```bash
# Install dependencies
sudo apt-get install -y libsqlcipher-dev libssl-dev

# Reinstall pysqlcipher3
pip3 install --no-cache-dir pysqlcipher3
```

---

## Performance Comparison

### File I/O Benchmark

```bash
# Test on Windows filesystem (/mnt/c/)
cd /mnt/c/Users/acer/Desktop/LLM
time go build ./cmd/probe_server/
# Real: ~15-20 seconds

# Test on WSL2 native filesystem (~/)
cd ~/llm-redteam
time go build ./cmd/probe_server/
# Real: ~2-3 seconds

# 5-7x faster on native filesystem!
```

---

## Next Steps After WSL2 Setup

Once WSL2 is set up and foundation script completes:

### 1. Verify Everything Works
```bash
# Start servers
./bin/probe_server &
./bin/recon_server &
./bin/mcp_server &

# Test connection
python3 test_grpc_connection.py
# Should show: ✓ ALL TESTS PASSED
```

### 2. Continue with Phase 2
```bash
# Implement Python gRPC clients
vim python/core/grpc_clients.py

# Implement evidence store
vim python/evidence/store.py

# Run tests
pytest tests/
```

### 3. External Tools (Phase 4)
```bash
# Clone external repos (now works perfectly)
cd external/
git clone https://github.com/dreadnode/shannon.git
git clone https://github.com/dreadnode/vulnhuntr.git
# ... etc
```

---

## Recommendation

**For Development**: Use WSL2 (faster, all tools work natively)  
**For Production**: Use Docker Compose (portable, isolated, scalable)  
**For Quick Tests**: Use native Windows (what we did in Phase 1)

Since you're now moving into Phase 2+ with SQLCipher, external tools, and heavy development, **WSL2 is the clear winner**.

---

## Time Investment

- **WSL2 Setup**: 20-30 minutes
- **Migration**: 15-20 minutes
- **Total**: ~45 minutes

**ROI**: Saves hours/days of fighting Windows-specific issues in Phase 2-5.

---

## Commands Summary

```bash
# Install WSL2
wsl --install -d Ubuntu-24.04

# In WSL2 terminal
cd ~
git clone <repo> llm-redteam
cd llm-redteam
bash scripts/setup_foundation.sh

# Open VS Code
code .

# Start development
make start-servers
python3 test_grpc_connection.py
```

That's it! You're now in a Linux environment with all tools working natively, 5-10x faster file I/O, and zero Windows-specific issues.
