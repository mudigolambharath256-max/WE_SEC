"""
BurpMCP WebSocket integration for llmrt.

Provides integration with BurpMCP (Burp Suite MCP extension) for real-time
security testing of MCP servers through WebSocket connections. Enables
interception, modification, and analysis of MCP JSON-RPC traffic.

Features:
- WebSocket connection to BurpMCP
- Real-time MCP traffic interception
- JSON-RPC message manipulation
- MCP-specific vulnerability detection
- Integration with llmrt evidence store

Note: Requires BurpMCP extension installed in Burp Suite.

Usage:
    burpmcp = BurpMCPWebSocketIntegration(ws_url="ws://localhost:8081/mcp")
    await burpmcp.connect()
    await burpmcp.intercept_mcp_traffic("https://mcp-server.com")
"""

import logging
from typing import List, Dict, Optional, Callable
import websockets
import json
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


class BurpMCPWebSocketIntegration:
    """
    BurpMCP WebSocket integration for llmrt.

    Provides real-time MCP traffic interception and analysis through
    WebSocket connection to BurpMCP extension.

    Args:
        ws_url: WebSocket URL for BurpMCP (default: ws://localhost:8081/mcp)
        api_key: API key for authentication (optional)

    Raises:
        ConnectionError: If cannot connect to BurpMCP
    """

    def __init__(self, ws_url: str = "ws://localhost:8081/mcp", api_key: Optional[str] = None):
        """Initializes BurpMCP WebSocket integration."""
        self.ws_url = ws_url
        self.api_key = api_key
        self.websocket = None
        self.connected = False
        
        # Message handlers
        self.message_handlers: List[Callable] = []
        
        # Intercepted messages
        self.intercepted_messages: List[Dict] = []
        
        logger.info(f"BurpMCP WebSocket integration initialized for {ws_url}")

    async def connect(self):
        """
        Connects to BurpMCP WebSocket.

        Raises:
            ConnectionError: If connection fails
        """
        logger.info(f"Connecting to BurpMCP at {self.ws_url}")
        
        try:
            # Build connection headers
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
            
            # Connect to WebSocket
            self.websocket = await websockets.connect(
                self.ws_url,
                extra_headers=headers,
                ping_interval=30,
                ping_timeout=10
            )
            
            self.connected = True
            logger.info("Successfully connected to BurpMCP")
            
            # Start message receiver
            asyncio.create_task(self._receive_messages())
            
        except Exception as e:
            logger.error(f"Failed to connect to BurpMCP: {e}")
            raise ConnectionError(f"Cannot connect to BurpMCP: {e}")

    async def disconnect(self):
        """Disconnects from BurpMCP WebSocket."""
        if self.websocket and self.connected:
            logger.info("Disconnecting from BurpMCP")
            await self.websocket.close()
            self.connected = False
            logger.info("Disconnected from BurpMCP")

    async def _receive_messages(self):
        """
        Receives messages from BurpMCP WebSocket.

        Runs in background task to continuously receive messages.
        """
        logger.info("Starting message receiver")
        
        try:
            async for message in self.websocket:
                await self._handle_message(message)
        except websockets.exceptions.ConnectionClosed:
            logger.warning("WebSocket connection closed")
            self.connected = False
        except Exception as e:
            logger.error(f"Error receiving messages: {e}")
            self.connected = False

    async def _handle_message(self, message: str):
        """
        Handles received message from BurpMCP.

        Args:
            message: Raw message string
        """
        try:
            # Parse JSON message
            msg_data = json.loads(message)
            
            # Add timestamp
            msg_data["received_at"] = datetime.utcnow().isoformat()
            
            # Store intercepted message
            self.intercepted_messages.append(msg_data)
            
            # Log message
            msg_type = msg_data.get("type", "unknown")
            logger.debug(f"Received message type: {msg_type}")
            
            # Call registered handlers
            for handler in self.message_handlers:
                try:
                    await handler(msg_data)
                except Exception as e:
                    logger.error(f"Message handler error: {e}")
                    
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message JSON: {e}")
        except Exception as e:
            logger.error(f"Error handling message: {e}")

    def register_handler(self, handler: Callable):
        """
        Registers message handler callback.

        Args:
            handler: Async callback function that receives message dict
        """
        self.message_handlers.append(handler)
        logger.info(f"Registered message handler: {handler.__name__}")

    async def send_command(self, command: str, params: Optional[Dict] = None) -> Dict:
        """
        Sends command to BurpMCP.

        Args:
            command: Command name
            params: Command parameters (optional)

        Returns:
            dict: Command response

        Raises:
            RuntimeError: If send fails or not connected
        """
        if not self.connected or not self.websocket:
            raise RuntimeError("Not connected to BurpMCP")
        
        logger.debug(f"Sending command: {command}")
        
        try:
            # Build command message
            message = {
                "type": "command",
                "command": command,
                "params": params or {},
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Send message
            await self.websocket.send(json.dumps(message))
            
            # Wait for response (simplified - real implementation would use request IDs)
            # For now, return success
            return {"status": "sent", "command": command}
            
        except Exception as e:
            logger.error(f"Failed to send command: {e}")
            raise RuntimeError(f"Command send failed: {e}")

    async def intercept_mcp_traffic(self, mcp_server_url: str) -> List[Dict]:
        """
        Intercepts MCP traffic for target server.

        Args:
            mcp_server_url: MCP server URL to intercept

        Returns:
            list: List of intercepted MCP messages

        Raises:
            RuntimeError: If interception fails
        """
        logger.info(f"Starting MCP traffic interception for {mcp_server_url}")
        
        try:
            # Send interception start command
            await self.send_command("start_intercept", {
                "target": mcp_server_url,
                "protocol": "mcp"
            })
            
            logger.info(f"MCP traffic interception started for {mcp_server_url}")
            
            # Return current intercepted messages
            return self.intercepted_messages
            
        except Exception as e:
            logger.error(f"Failed to start interception: {e}")
            raise RuntimeError(f"MCP interception failed: {e}")

    async def stop_intercept(self):
        """
        Stops MCP traffic interception.

        Raises:
            RuntimeError: If stop fails
        """
        logger.info("Stopping MCP traffic interception")
        
        try:
            await self.send_command("stop_intercept")
            logger.info("MCP traffic interception stopped")
            
        except Exception as e:
            logger.error(f"Failed to stop interception: {e}")
            raise RuntimeError(f"Stop interception failed: {e}")

    async def modify_mcp_request(self, request_id: str, modifications: Dict) -> Dict:
        """
        Modifies intercepted MCP request before forwarding.

        Args:
            request_id: Request ID to modify
            modifications: Modifications to apply

        Returns:
            dict: Modified request

        Raises:
            RuntimeError: If modification fails
        """
        logger.info(f"Modifying MCP request {request_id}")
        
        try:
            # Send modification command
            response = await self.send_command("modify_request", {
                "request_id": request_id,
                "modifications": modifications
            })
            
            logger.info(f"MCP request {request_id} modified")
            return response
            
        except Exception as e:
            logger.error(f"Failed to modify request: {e}")
            raise RuntimeError(f"Request modification failed: {e}")

    async def inject_mcp_payload(self, tool_name: str, payload: Dict) -> Dict:
        """
        Injects malicious payload into MCP tool call.

        Args:
            tool_name: MCP tool name to target
            payload: Payload to inject

        Returns:
            dict: Injection result

        Raises:
            RuntimeError: If injection fails
        """
        logger.info(f"Injecting payload into MCP tool: {tool_name}")
        
        try:
            # Build injection request
            injection = {
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": payload
                }
            }
            
            # Send injection command
            response = await self.send_command("inject_payload", {
                "injection": injection
            })
            
            logger.info(f"Payload injected into {tool_name}")
            return response
            
        except Exception as e:
            logger.error(f"Failed to inject payload: {e}")
            raise RuntimeError(f"Payload injection failed: {e}")

    async def detect_mcp_vulnerabilities(self) -> List[Dict]:
        """
        Analyzes intercepted traffic for MCP vulnerabilities.

        Returns:
            list: List of detected vulnerabilities

        Raises:
            RuntimeError: If analysis fails
        """
        logger.info("Analyzing intercepted traffic for MCP vulnerabilities")
        
        vulnerabilities = []
        
        try:
            for message in self.intercepted_messages:
                # Check for common MCP vulnerabilities
                vulns = self._analyze_message_for_vulns(message)
                vulnerabilities.extend(vulns)
            
            logger.info(f"Detected {len(vulnerabilities)} potential vulnerabilities")
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Vulnerability detection failed: {e}")
            raise RuntimeError(f"Vulnerability analysis failed: {e}")

    def _analyze_message_for_vulns(self, message: Dict) -> List[Dict]:
        """
        Analyzes single message for vulnerabilities.

        Args:
            message: MCP message to analyze

        Returns:
            list: List of vulnerabilities found
        """
        vulnerabilities = []
        
        # Check for unencrypted sensitive data
        if self._contains_sensitive_data(message):
            vulnerabilities.append({
                "type": "sensitive_data_exposure",
                "severity": "high",
                "message_id": message.get("id"),
                "description": "Sensitive data transmitted without encryption"
            })
        
        # Check for missing authentication
        if not message.get("auth") and message.get("type") == "request":
            vulnerabilities.append({
                "type": "missing_authentication",
                "severity": "medium",
                "message_id": message.get("id"),
                "description": "MCP request without authentication"
            })
        
        # Check for SQL injection patterns in tool arguments
        if self._contains_sqli_pattern(message):
            vulnerabilities.append({
                "type": "sql_injection",
                "severity": "critical",
                "message_id": message.get("id"),
                "description": "Potential SQL injection in tool arguments"
            })
        
        # Check for command injection patterns
        if self._contains_command_injection(message):
            vulnerabilities.append({
                "type": "command_injection",
                "severity": "critical",
                "message_id": message.get("id"),
                "description": "Potential command injection in tool arguments"
            })
        
        return vulnerabilities

    def _contains_sensitive_data(self, message: Dict) -> bool:
        """Checks if message contains sensitive data."""
        sensitive_keywords = ["password", "api_key", "token", "secret", "credential"]
        message_str = json.dumps(message).lower()
        return any(keyword in message_str for keyword in sensitive_keywords)

    def _contains_sqli_pattern(self, message: Dict) -> bool:
        """Checks if message contains SQL injection patterns."""
        sqli_patterns = ["' OR '", "UNION SELECT", "DROP TABLE", "--", "/*", "*/"]
        message_str = json.dumps(message)
        return any(pattern in message_str for pattern in sqli_patterns)

    def _contains_command_injection(self, message: Dict) -> bool:
        """Checks if message contains command injection patterns."""
        cmd_patterns = [";", "&&", "||", "|", "`", "$(", "${"]
        message_str = json.dumps(message)
        return any(pattern in message_str for pattern in cmd_patterns)

    async def export_intercepted_traffic(self, output_path: str):
        """
        Exports intercepted traffic to file.

        Args:
            output_path: Path to save traffic file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting intercepted traffic to {output_path}")
        
        try:
            from pathlib import Path
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Export as JSON
            with open(output_file, "w") as f:
                json.dump(self.intercepted_messages, f, indent=2)
            
            logger.info(f"Exported {len(self.intercepted_messages)} messages to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export traffic: {e}")
            raise RuntimeError(f"Traffic export failed: {e}")

    def get_statistics(self) -> Dict:
        """
        Gets statistics about intercepted traffic.

        Returns:
            dict: Traffic statistics
        """
        total_messages = len(self.intercepted_messages)
        
        # Count message types
        type_counts = {}
        for msg in self.intercepted_messages:
            msg_type = msg.get("type", "unknown")
            type_counts[msg_type] = type_counts.get(msg_type, 0) + 1
        
        return {
            "total_messages": total_messages,
            "message_types": type_counts,
            "connected": self.connected,
            "ws_url": self.ws_url
        }


logger.info("BurpMCP WebSocket integration module loaded")
