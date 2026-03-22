"""
Lethal Trifecta detector (Adversa MCP Top 25 #1).

Detects the Lethal Trifecta vulnerability pattern:
1. MCP tool with dangerous capabilities (file system, network, exec)
2. Insufficient input validation
3. LLM-controllable parameters

This combination allows LLM prompt injection to trigger dangerous
tool operations.
"""

import logging
from typing import List, Dict, Any

from ..core.scope_validator import ScopeValidator
from ..core.grpc_clients import MCPClient

logger = logging.getLogger(__name__)


class LethalTrifectaDetector:
    """
    Lethal Trifecta detector (Adversa MCP Top 25 #1).

    Detects dangerous MCP tool configurations that allow LLM-triggered
    exploitation.

    Args:
        scope_validator: Scope validator instance
        mcp_client: gRPC MCP client

    Usage:
        detector = LethalTrifectaDetector(scope_validator, mcp_client)
        findings = detector.detect(server_url, campaign_id)
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        mcp_client: MCPClient,
    ):
        """Initializes Lethal Trifecta detector."""
        self.scope_validator = scope_validator
        self.mcp_client = mcp_client
        
        # Dangerous tool patterns
        self.dangerous_patterns = {
            "file_system": ["read_file", "write_file", "delete_file", "execute_command"],
            "network": ["http_request", "fetch_url", "send_email", "webhook"],
            "execution": ["exec", "eval", "run_code", "shell"],
            "database": ["query", "execute_sql", "update_db"],
        }
        
        logger.info("Lethal Trifecta detector initialized")

    def detect(
        self,
        server_url: str,
        campaign_id: str,
        auth: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Detects Lethal Trifecta vulnerabilities.

        Args:
            server_url: MCP server URL
            campaign_id: Campaign identifier
            auth: Authentication context (optional)

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        self.scope_validator.validate_or_raise(server_url)
        
        logger.info(f"Detecting Lethal Trifecta: {server_url}")
        
        # Enumerate MCP tools
        schema = self.mcp_client.enumerate_tools(
            server_url=server_url,
            auth=auth or {},
            campaign_id=campaign_id,
        )
        
        findings = []
        
        for tool in schema.get("tools", []):
            # Check if tool has dangerous capabilities
            dangerous_category = self._check_dangerous_tool(tool)
            
            if dangerous_category:
                # Check for insufficient validation
                has_weak_validation = self._check_weak_validation(tool)
                
                # Check for LLM-controllable parameters
                has_llm_params = self._check_llm_controllable(tool)
                
                if has_weak_validation and has_llm_params:
                    finding = {
                        "finding_family": "mcp_tool_poisoning",
                        "finding_type": "lethal_trifecta",
                        "tool_name": tool.get("name", "unknown"),
                        "dangerous_category": dangerous_category,
                        "description": f"Tool '{tool['name']}' exhibits Lethal Trifecta pattern",
                        "severity": "critical",
                        "evidence": {
                            "tool_description": tool.get("description", ""),
                            "input_schema": tool.get("input_schema", {}),
                        },
                    }
                    findings.append(finding)
                    logger.warning(f"Lethal Trifecta detected: {tool['name']}")
        
        logger.info(f"Lethal Trifecta detection complete: {len(findings)} findings")
        return findings

    def _check_dangerous_tool(self, tool: Dict[str, Any]) -> Optional[str]:
        """
        Checks if tool has dangerous capabilities.

        Args:
            tool: MCP tool definition

        Returns:
            Optional[str]: Dangerous category or None
        """
        tool_name = tool.get("name", "").lower()
        tool_desc = tool.get("description", "").lower()
        
        for category, patterns in self.dangerous_patterns.items():
            for pattern in patterns:
                if pattern in tool_name or pattern in tool_desc:
                    return category
        
        return None

    def _check_weak_validation(self, tool: Dict[str, Any]) -> bool:
        """
        Checks if tool has weak input validation.

        Args:
            tool: MCP tool definition

        Returns:
            bool: True if validation is weak
        """
        input_schema = tool.get("input_schema", {})
        
        # Check for missing required fields
        required = input_schema.get("required", [])
        if not required:
            return True
        
        # Check for overly permissive types (string without pattern/enum)
        properties = input_schema.get("properties", {})
        for prop_name, prop_def in properties.items():
            if prop_def.get("type") == "string":
                # No pattern or enum = weak validation
                if "pattern" not in prop_def and "enum" not in prop_def:
                    return True
        
        return False

    def _check_llm_controllable(self, tool: Dict[str, Any]) -> bool:
        """
        Checks if tool parameters are LLM-controllable.

        Args:
            tool: MCP tool definition

        Returns:
            bool: True if parameters are LLM-controllable
        """
        input_schema = tool.get("input_schema", {})
        properties = input_schema.get("properties", {})
        
        # LLM-controllable if it accepts string parameters
        for prop_def in properties.values():
            if prop_def.get("type") in ["string", "object", "array"]:
                return True
        
        return False


logger.info("Lethal Trifecta detector module loaded")
