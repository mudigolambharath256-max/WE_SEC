#!/usr/bin/env python3
"""
Test script to verify gRPC connection to all 3 Go servers.
This validates that Phase 1 proto compilation was successful.
"""

import sys
from python.core import probe_pb2, probe_pb2_grpc
from python.core import recon_pb2, recon_pb2_grpc
from python.core import mcp_pb2, mcp_pb2_grpc
from python.core import common_pb2
import grpc


def test_probe_server():
    """Test connection to probe_server on port 50051."""
    print("Testing probe_server connection...")
    try:
        channel = grpc.insecure_channel('localhost:50051')
        stub = probe_pb2_grpc.ProbeServiceStub(channel)
        
        # Call HealthCheck
        request = common_pb2.HealthRequest()
        response = stub.HealthCheck(request, timeout=5)
        
        if response.ok:
            print(f"✓ probe_server: OK (version {response.version})")
            return True
        else:
            print("✗ probe_server: Health check failed")
            return False
    except Exception as e:
        print(f"✗ probe_server: Connection failed - {e}")
        return False
    finally:
        channel.close()


def test_recon_server():
    """Test connection to recon_server on port 50052."""
    print("Testing recon_server connection...")
    try:
        channel = grpc.insecure_channel('localhost:50052')
        stub = recon_pb2_grpc.ReconServiceStub(channel)
        
        # Call HealthCheck
        request = common_pb2.HealthRequest()
        response = stub.HealthCheck(request, timeout=5)
        
        if response.ok:
            print(f"✓ recon_server: OK (version {response.version})")
            return True
        else:
            print("✗ recon_server: Health check failed")
            return False
    except Exception as e:
        print(f"✗ recon_server: Connection failed - {e}")
        return False
    finally:
        channel.close()


def test_mcp_server():
    """Test connection to mcp_server on port 50053."""
    print("Testing mcp_server connection...")
    try:
        channel = grpc.insecure_channel('localhost:50053')
        stub = mcp_pb2_grpc.MCPServiceStub(channel)
        
        # Call HealthCheck
        request = common_pb2.HealthRequest()
        response = stub.HealthCheck(request, timeout=5)
        
        if response.ok:
            print(f"✓ mcp_server: OK (version {response.version})")
            return True
        else:
            print("✗ mcp_server: Health check failed")
            return False
    except Exception as e:
        print(f"✗ mcp_server: Connection failed - {e}")
        return False
    finally:
        channel.close()


def main():
    print("=" * 60)
    print("gRPC Connection Test - Phase 1 Verification")
    print("=" * 60)
    print()
    
    results = []
    results.append(test_probe_server())
    print()
    results.append(test_recon_server())
    print()
    results.append(test_mcp_server())
    
    print()
    print("=" * 60)
    if all(results):
        print("✓ ALL TESTS PASSED - Phase 1 Complete!")
        print("=" * 60)
        print()
        print("Next Steps:")
        print("  1. Implement Python gRPC clients (python/core/grpc_clients.py)")
        print("  2. Implement evidence store (python/evidence/store.py)")
        print("  3. Implement attack modules")
        return 0
    else:
        print("✗ SOME TESTS FAILED")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
