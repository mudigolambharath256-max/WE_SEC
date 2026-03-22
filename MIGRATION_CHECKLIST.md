# Migration Checklist: Windows → WSL2

**Current Status**: Phase 1 complete on Windows, ready to migrate for Phase 2+

---

## Pre-Migration (What We Accomplished on Windows)

- [x] Proto files compiled (Go + Python)
- [x] All 3 Go servers built and running
- [x] Python gRPC connection verified
- [x] Test script created and passing

**Files to preserve**:
- `PHASE1_COMPLETE.md` - Documentation of Phase 1 work
- `PHASE2_PROGRESS.md` - Current progress tracking
- `test_grpc_connection.py` - Working test script
- `WSL2_SETUP_GUIDE.md` - This migration guide

---

## Migration Steps

### Step 1: Install WSL2 (5 minutes)

```powershell
# In PowerShell as Administrator
wsl --install -d Ubuntu-24.04
wsl --set-default-version 2

# Restart computer if prompted
# Open "Ubuntu" from Start menu
```

- [ ] WSL2 installed
- [ ] Ubuntu 24.04 running
- [ ] Username/password created

### Step 2: Install Prerequisites (10 minutes)

```bash
# In WSL2 Ubuntu terminal
sudo apt-get update && sudo apt-get upgrade -y

# Install Go
cd /tmp
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

# Install system dependencies
sudo apt-get install -y \
    build-essential \
    git \
    protobuf-compiler \
    golang-goprotobuf-dev \
    nmap \
    libfuzzy-dev \
    libsqlcipher-dev \
    libpango-1.0-0 \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev

# Verify
go version
python3 --version
protoc --version
```

- [ ] Go 1.22+ installed
- [ ] Python 3.11+ installed
- [ ] Protoc installed
- [ ] All system dependencies installed

### Step 3: Clone Repository (2 minutes)

**Option A: Fresh Clone (Recommended)**
```bash
cd ~
git clone <your-repo-url> llm-redteam
cd llm-redteam
```

**Option B: Copy from Windows**
```bash
cd ~
cp -r /mnt/c/Users/acer/Desktop/LLM llm-redteam
cd llm-redteam

# Clean Windows artifacts
rm -rf go/internal/proto/*.go
rm -rf python/core/*_pb2*.py
rm -rf bin/*.exe
```

- [ ] Repository in WSL2 native filesystem (`~/llm-redteam`)
- [ ] NOT in `/mnt/c/` (slow)

### Step 4: Run Foundation Setup (5 minutes)

```bash
cd ~/llm-redteam
bash scripts/setup_foundation.sh
```

Expected output:
```
[Step 1/8] Checking system prerequisites
✓ Go 1.22.0 installed
✓ Python 3.12.0 installed
✓ protoc 3.21.12 installed
...
[Step 8/8] Setting up environment configuration
✓ .env file created
==========================================
✓ Foundation Setup Complete!
==========================================
```

- [ ] Script completed successfully
- [ ] All 3 Go servers compiled
- [ ] Proto files generated
- [ ] Python dependencies installed

### Step 5: Start Servers (1 minute)

```bash
# Start all 3 servers
./bin/probe_server &
./bin/recon_server &
./bin/mcp_server &

# Verify they're running
ps aux | grep _server
```

- [ ] probe_server running on :50051
- [ ] recon_server running on :50052
- [ ] mcp_server running on :50053

### Step 6: Test Connection (1 minute)

```bash
python3 test_grpc_connection.py
```

Expected output:
```
============================================================
gRPC Connection Test - Phase 1 Verification
============================================================

Testing probe_server connection...
✓ probe_server: OK (version 1.0.0)

Testing recon_server connection...
✓ recon_server: OK (version 1.0.0)

Testing mcp_server connection...
✓ mcp_server: OK (version 1.0.0)

============================================================
✓ ALL TESTS PASSED - Phase 1 Complete!
============================================================
```

- [ ] All 3 servers respond to health checks
- [ ] Python gRPC connection works

### Step 7: VS Code Setup (5 minutes)

```bash
# Install VS Code WSL extension in Windows
# Then from WSL2 terminal:
cd ~/llm-redteam
code .
```

- [ ] VS Code opens connected to WSL2
- [ ] Can edit files in Windows UI
- [ ] Terminal runs in WSL2 context

---

## Post-Migration Verification

### Checklist

- [ ] All servers start without errors
- [ ] gRPC connections work
- [ ] Can edit files in VS Code
- [ ] Git works (can commit/push)
- [ ] Python imports work
- [ ] Go builds work

### Performance Test

```bash
# Test build speed
cd ~/llm-redteam/go
time go build ./cmd/probe_server/

# Should be 2-3 seconds (vs 15-20 on /mnt/c/)
```

- [ ] Build time < 5 seconds (fast)

---

## What to Do Next

### Immediate (Phase 2 Continuation)

1. **Implement Python gRPC Clients**
   ```bash
   vim python/core/grpc_clients.py
   # Copy implementation from llmrt_next_steps.md section T3-A
   ```

2. **Implement Evidence Store**
   ```bash
   # Install SQLCipher (now works perfectly on Linux)
   pip3 install pysqlcipher3
   
   vim python/evidence/store.py
   # Copy implementation from llmrt_next_steps.md section T3-B
   ```

3. **Test End-to-End**
   ```bash
   # Create simple test
   python3 -c "
   from python.core.grpc_clients import GRPCClients
   clients = GRPCClients.from_env()
   print(clients.health_check_all())
   "
   ```

### Phase 3-5 (Next Week)

- [ ] Implement classifiers and scorers
- [ ] Clone external tools (Shannon, Vulnhuntr, etc.)
- [ ] Implement 42 attack modules
- [ ] End-to-end campaign testing

---

## Rollback Plan (If Needed)

If something goes wrong, you can always go back to Windows:

```powershell
# In Windows PowerShell
cd C:\Users\acer\Desktop\LLM

# Servers are still there
.\bin\probe_server.exe
.\bin\recon_server.exe
.\bin\mcp_server.exe

# Test still works
py test_grpc_connection.py
```

But you'll hit the same blockers (SQLCipher, external tools, etc.)

---

## Time Estimate

| Step | Time | Cumulative |
|------|------|------------|
| Install WSL2 | 5 min | 5 min |
| Install prerequisites | 10 min | 15 min |
| Clone repository | 2 min | 17 min |
| Run foundation setup | 5 min | 22 min |
| Start servers | 1 min | 23 min |
| Test connection | 1 min | 24 min |
| VS Code setup | 5 min | 29 min |

**Total: ~30 minutes**

---

## Success Criteria

Migration is successful when:

1. ✅ All 3 Go servers running in WSL2
2. ✅ Python gRPC connection test passes
3. ✅ VS Code connected to WSL2
4. ✅ Build time < 5 seconds
5. ✅ Can install pysqlcipher3 without errors

---

## Support

If you encounter issues:

1. Check `WSL2_SETUP_GUIDE.md` troubleshooting section
2. Verify you're on native filesystem: `pwd` should show `/home/...` not `/mnt/c/...`
3. Check server logs: `journalctl -xe` or `dmesg`
4. Test individual components:
   - Go: `go version`
   - Python: `python3 --version`
   - Protoc: `protoc --version`
   - Servers: `ps aux | grep _server`

---

## Final Notes

**Why migrate now?**
- Phase 1 proved the architecture works
- Phase 2+ requires Linux-specific tools (SQLCipher, Nmap, external repos)
- WSL2 is 5-10x faster than Windows filesystem
- All bash scripts and Makefile commands work without modification

**What you keep:**
- All your work (documentation, test scripts, configurations)
- Same codebase (just running in Linux)
- Same workflow (VS Code, Git, etc.)

**What you gain:**
- Native Linux tool support
- 5-10x faster builds
- No compilation issues
- Seamless external tool integration
- Production-like environment

**Bottom line**: 30 minutes of migration saves days of fighting Windows-specific issues.
