"""
gRPC client wrappers for communicating with Go services.

Provides Python interfaces to the probe, recon, and MCP gRPC servers.
"""

import logging
import os
from typing import Dict, List, Iterator, Optional

import grpc
from . import probe_pb2, probe_pb2_grpc
from . import recon_pb2, recon_pb2_grpc
from . import mcp_pb2, mcp_pb2_grpc

logger = logging.getLogger(__name__)


class ProbeClient:
    """
    Client for ProbeService gRPC server.
    
    Handles probe execution requests to the Go probe runner.
    """
    
    def __init__(self, server_address: Optional[str] = None):
        """
        Initialize probe client.
        
        Args:
            server_address: gRPC server address (default from env)
        """
        if server_address is None:
            server_address = os.getenv("PROBE_GRPC", "localhost:50051")
        
        self.server_address = server_address
        self.channel = grpc.insecure_channel(server_address)
        self.stub = probe_pb2_grpc.ProbeServiceStub(self.channel)
        
        logger.info(f"ProbeClient connected to {server_address}")
    
    def fire_batch(
        self,
        payloads: List[str],
        endpoint_url: str,
        method: str,
        headers: Dict[str, str],
        body_schema: str,
        campaign_id: str,
        template_id: str = "",
        concurrency: int = 5,
        delay_ms: int = 200,
        apply_chatinject: bool = True,
        apply_flipattack: bool = True,
        oob_server: str = ""
    ) -> Iterator[probe_pb2.ProbeResult]:
        """
        Execute a batch of probes (streaming).
        
        Args:
            payloads: List of payload strings
            endpoint_url: Target endpoint URL
            method: HTTP method
            headers: HTTP headers
            body_schema: Body template with $PAYLOAD placeholder
            campaign_id: Campaign identifier
            template_id: Chat template ID (optional)
            concurrency: Number of concurrent probes
            delay_ms: Delay between probes in milliseconds
            apply_chatinject: Apply ChatInject transformation
            apply_flipattack: Apply FlipAttack transformation
            oob_server: OOB server URL (optional)
            
        Yields:
            ProbeResult: Streaming probe results
        """
        request = probe_pb2.ProbeBatchRequest(
            payloads=payloads,
            endpoint_url=endpoint_url,
            method=method,
            headers=headers,
            body_schema=body_schema,
            template_id=template_id,
            concurrency=concurrency,
            delay_ms=delay_ms,
            campaign_id=campaign_id,
            apply_chatinject=apply_chatinject,
            apply_flipattack=apply_flipattack,
            oob_server=oob_server
        )
        
        logger.info(f"Firing batch: {len(payloads)} payloads to {endpoint_url}")
        
        try:
            for result in self.stub.FireBatch(request):
                yield result
        except grpc.RpcError as e:
            logger.error(f"FireBatch RPC error: {e}")
            raise
    
    def fire_single(
        self,
        payload: str,
        endpoint_url: str,
        method: str,
        headers: Dict[str, str],
        body_schema: str,
        campaign_id: str
    ) -> probe_pb2.ProbeResult:
        """
        Execute a single probe.
        
        Args:
            payload: Payload string
            endpoint_url: Target endpoint URL
            method: HTTP method
            headers: HTTP headers
            body_schema: Body template
            campaign_id: Campaign identifier
            
        Returns:
            ProbeResult: Probe result
        """
        request = probe_pb2.ProbeRequest(
            payload=payload,
            endpoint_url=endpoint_url,
            method=method,
            headers=headers,
            body_schema=body_schema,
            campaign_id=campaign_id
        )
        
        try:
            return self.stub.FireSingle(request)
        except grpc.RpcError as e:
            logger.error(f"FireSingle RPC error: {e}")
            raise
    
    def health_check(self) -> bool:
        """
        Check if probe server is healthy.
        
        Returns:
            bool: True if healthy
        """
        try:
            response = self.stub.HealthCheck(probe_pb2.HealthRequest())
            return response.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        """Close gRPC channel."""
        self.channel.close()


class ReconClient:
    """
    Client for ReconService gRPC server.
    
    Handles reconnaissance requests to the Go recon runner.
    """
    
    def __init__(self, server_address: Optional[str] = None):
        """
        Initialize recon client.
        
        Args:
            server_address: gRPC server address (default from env)
        """
        if server_address is None:
            server_address = os.getenv("RECON_GRPC", "localhost:50052")
        
        self.server_address = server_address
        self.channel = grpc.insecure_channel(server_address)
        self.stub = recon_pb2_grpc.ReconServiceStub(self.channel)
        
        logger.info(f"ReconClient connected to {server_address}")
    
    def scan_ports(self, host: str, ports: List[int]) -> recon_pb2.PortScanResult:
        """
        Scan ports on target host.
        
        Args:
            host: Target host
            ports: List of ports to scan
            
        Returns:
            PortScanResult: Scan results
        """
        request = recon_pb2.PortScanRequest(host=host, ports=ports)
        
        try:
            return self.stub.ScanPorts(request)
        except grpc.RpcError as e:
            logger.error(f"ScanPorts RPC error: {e}")
            raise
    
    def fuzz_endpoints(
        self,
        base_url: str,
        wordlist: str = "ai-endpoints",
        concurrency: int = 10,
        delay_ms: int = 100
    ) -> recon_pb2.FuzzResult:
        """
        Fuzz endpoints on target.
        
        Args:
            base_url: Base URL to fuzz
            wordlist: Wordlist name or path
            concurrency: Number of concurrent requests
            delay_ms: Delay between requests
            
        Returns:
            FuzzResult: Discovered endpoints
        """
        request = recon_pb2.FuzzRequest(
            base_url=base_url,
            wordlist=wordlist,
            concurrency=concurrency,
            delay_ms=delay_ms
        )
        
        try:
            return self.stub.FuzzEndpoints(request)
        except grpc.RpcError as e:
            logger.error(f"FuzzEndpoints RPC error: {e}")
            raise
    
    def check_binding(self, host: str, port: int) -> recon_pb2.BindingResult:
        """
        Check network binding for a port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            BindingResult: Binding information
        """
        request = recon_pb2.BindingRequest(host=host, port=port)
        
        try:
            return self.stub.CheckBinding(request)
        except grpc.RpcError as e:
            logger.error(f"CheckBinding RPC error: {e}")
            raise
    
    def parse_har(self, har_data: bytes) -> recon_pb2.EndpointMap:
        """
        Parse HAR file.
        
        Args:
            har_data: HAR file content as bytes
            
        Returns:
            EndpointMap: Discovered endpoints and auth type
        """
        request = recon_pb2.HARRequest(har_data=har_data)
        
        try:
            return self.stub.ParseHAR(request)
        except grpc.RpcError as e:
            logger.error(f"ParseHAR RPC error: {e}")
            raise
    
    def health_check(self) -> bool:
        """Check if recon server is healthy."""
        try:
            response = self.stub.HealthCheck(recon_pb2.HealthRequest())
            return response.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        """Close gRPC channel."""
        self.channel.close()


class MCPClient:
    """
    Client for MCPService gRPC server.
    
    Handles MCP-specific attack requests to the Go MCP runner.
    """
    
    def __init__(self, server_address: Optional[str] = None):
        """
        Initialize MCP client.
        
        Args:
            server_address: gRPC server address (default from env)
        """
        if server_address is None:
            server_address = os.getenv("MCP_GRPC", "localhost:50053")
        
        self.server_address = server_address
        self.channel = grpc.insecure_channel(server_address)
        self.stub = mcp_pb2_grpc.MCPServiceStub(self.channel)
        
        logger.info(f"MCPClient connected to {server_address}")
    
    def enumerate_tools(
        self,
        server_url: str,
        auth: Dict[str, str],
        campaign_id: str
    ) -> mcp_pb2.MCPSchema:
        """
        Enumerate MCP tools, resources, and prompts.
        
        Args:
            server_url: MCP server URL
            auth: Authentication context
            campaign_id: Campaign identifier
            
        Returns:
            MCPSchema: Complete MCP schema
        """
        request = mcp_pb2.MCPEnumRequest(
            server_url=server_url,
            auth=auth,
            campaign_id=campaign_id
        )
        
        try:
            return self.stub.EnumerateTools(request)
        except grpc.RpcError as e:
            logger.error(f"EnumerateTools RPC error: {e}")
            raise
    
    def fire_mcp_attacks(
        self,
        attack_type: str,
        schema: mcp_pb2.MCPSchema,
        server_url: str,
        auth: Dict[str, str],
        campaign_id: str,
        oob_server: str = ""
    ) -> Iterator[mcp_pb2.MCPFinding]:
        """
        Execute MCP attacks (streaming).
        
        Args:
            attack_type: Attack type (rug_pull, sql_injection, etc.)
            schema: MCP schema
            server_url: MCP server URL
            auth: Authentication context
            campaign_id: Campaign identifier
            oob_server: OOB server URL (optional)
            
        Yields:
            MCPFinding: Streaming attack findings
        """
        request = mcp_pb2.MCPAttackRequest(
            attack_type=attack_type,
            schema=schema,
            server_url=server_url,
            auth=auth,
            campaign_id=campaign_id,
            oob_server=oob_server
        )
        
        logger.info(f"Firing MCP attacks: {attack_type} on {server_url}")
        
        try:
            for finding in self.stub.FireMCPAttacks(request):
                yield finding
        except grpc.RpcError as e:
            logger.error(f"FireMCPAttacks RPC error: {e}")
            raise
    
    def health_check(self) -> bool:
        """Check if MCP server is healthy."""
        try:
            response = self.stub.HealthCheck(mcp_pb2.HealthRequest())
            return response.ok
        except grpc.RpcError:
            return False
    
    def close(self):
        """Close gRPC channel."""
        self.channel.close()
