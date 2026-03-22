"""
Target configuration module.

Represents a target system for security assessment, including
endpoint URLs, authentication, and scope boundaries.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse


@dataclass
class Target:
    """
    Represents a target system for security assessment.
    
    Attributes:
        name: Human-readable target name
        base_url: Base URL of the target (e.g., https://api.example.com)
        endpoints: List of specific endpoints to test
        auth: Authentication configuration
        scope: Scope boundaries (allowed domains, excluded paths)
        metadata: Additional metadata about the target
    """
    name: str
    base_url: str
    endpoints: List[str] = field(default_factory=list)
    auth: Dict[str, str] = field(default_factory=dict)
    scope: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate target configuration after initialization."""
        if not self.base_url:
            raise ValueError("base_url is required")
        
        # Parse and validate base URL
        parsed = urlparse(self.base_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError(f"Invalid base_url: {self.base_url}")
        
        # Set default scope if not provided
        if not self.scope:
            self.scope = {
                "allowed_domains": [parsed.netloc],
                "excluded_paths": [],
                "excluded_extensions": [".jpg", ".png", ".gif", ".css", ".js"]
            }
    
    @property
    def domain(self) -> str:
        """Extract domain from base URL."""
        return urlparse(self.base_url).netloc
    
    @property
    def scheme(self) -> str:
        """Extract scheme from base URL."""
        return urlparse(self.base_url).scheme
    
    def is_in_scope(self, url: str) -> bool:
        """
        Check if a URL is within the target's scope.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL is in scope
        """
        parsed = urlparse(url)
        
        # Check allowed domains
        allowed_domains = self.scope.get("allowed_domains", [])
        if parsed.netloc not in allowed_domains:
            return False
        
        # Check excluded paths
        excluded_paths = self.scope.get("excluded_paths", [])
        for excluded in excluded_paths:
            if parsed.path.startswith(excluded):
                return False
        
        # Check excluded extensions
        excluded_extensions = self.scope.get("excluded_extensions", [])
        for ext in excluded_extensions:
            if parsed.path.endswith(ext):
                return False
        
        return True
    
    def add_endpoint(self, endpoint: str):
        """
        Add an endpoint to the target.
        
        Args:
            endpoint: Endpoint path (e.g., /api/chat)
        """
        if endpoint not in self.endpoints:
            self.endpoints.append(endpoint)
    
    def get_full_url(self, endpoint: str) -> str:
        """
        Construct full URL from base URL and endpoint.
        
        Args:
            endpoint: Endpoint path
            
        Returns:
            str: Full URL
        """
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        
        # Remove trailing slash from base_url and leading slash from endpoint
        base = self.base_url.rstrip("/")
        path = endpoint.lstrip("/")
        
        return f"{base}/{path}"
    
    def to_dict(self) -> Dict:
        """Convert target to dictionary."""
        return {
            "name": self.name,
            "base_url": self.base_url,
            "endpoints": self.endpoints,
            "auth": self.auth,
            "scope": self.scope,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "Target":
        """
        Create target from dictionary.
        
        Args:
            data: Dictionary with target configuration
            
        Returns:
            Target: Configured target instance
        """
        return cls(
            name=data["name"],
            base_url=data["base_url"],
            endpoints=data.get("endpoints", []),
            auth=data.get("auth", {}),
            scope=data.get("scope", {}),
            metadata=data.get("metadata", {})
        )


@dataclass
class MCPTarget(Target):
    """
    Represents an MCP server target.
    
    Extends Target with MCP-specific configuration.
    """
    transport: str = "http"  # http, sse, or stdio
    capabilities: Dict[str, bool] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate MCP target configuration."""
        super().__post_init__()
        
        if self.transport not in ["http", "sse", "stdio"]:
            raise ValueError(f"Invalid transport: {self.transport}")
    
    def to_dict(self) -> Dict:
        """Convert MCP target to dictionary."""
        data = super().to_dict()
        data["transport"] = self.transport
        data["capabilities"] = self.capabilities
        return data
    
    @classmethod
    def from_dict(cls, data: Dict) -> "MCPTarget":
        """Create MCP target from dictionary."""
        return cls(
            name=data["name"],
            base_url=data["base_url"],
            endpoints=data.get("endpoints", []),
            auth=data.get("auth", {}),
            scope=data.get("scope", {}),
            metadata=data.get("metadata", {}),
            transport=data.get("transport", "http"),
            capabilities=data.get("capabilities", {})
        )
