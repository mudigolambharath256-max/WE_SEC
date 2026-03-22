"""
Configuration schema definitions.

Defines Pydantic models for validating campaign configuration files.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class ScopeBoundaries(BaseModel):
    """Scope boundaries for testing."""
    allowed_domains: List[str] = Field(description="List of allowed domains")
    excluded_paths: List[str] = Field(default_factory=list, description="Paths to exclude")
    excluded_extensions: List[str] = Field(
        default_factory=lambda: [".jpg", ".png", ".gif", ".css", ".js"],
        description="File extensions to exclude"
    )


class AuthConfig(BaseModel):
    """Authentication configuration."""
    type: str = Field(description="Auth type: api_key, session_cookie, jwt, oauth_bearer, none")
    header_name: Optional[str] = Field(default=None, description="Header name for auth")
    token: Optional[str] = Field(default=None, description="Auth token value")
    jwt_exp: Optional[int] = Field(default=None, description="JWT expiration timestamp")
    
    @field_validator("type")
    @classmethod
    def validate_auth_type(cls, v):
        """Validate auth type."""
        valid_types = ["api_key", "session_cookie", "jwt", "oauth_bearer", "none"]
        if v not in valid_types:
            raise ValueError(f"Invalid auth type: {v}. Must be one of {valid_types}")
        return v


class TargetConfig(BaseModel):
    """Target configuration."""
    name: str = Field(description="Target name")
    base_url: str = Field(description="Base URL of target")
    endpoints: List[str] = Field(default_factory=list, description="Endpoints to test")
    auth: AuthConfig = Field(default_factory=lambda: AuthConfig(type="none"))
    scope: ScopeBoundaries = Field(default_factory=ScopeBoundaries)
    metadata: Dict[str, str] = Field(default_factory=dict)


class ProbeConfig(BaseModel):
    """Probe execution configuration."""
    concurrency: int = Field(default=5, ge=1, le=50, description="Concurrent probes")
    rate_limit_ms: int = Field(default=200, ge=0, description="Rate limit in milliseconds")
    max_turns: int = Field(default=10, ge=1, description="Max conversation turns")
    apply_chatinject: bool = Field(default=True, description="Apply ChatInject transformation")
    apply_flipattack: bool = Field(default=True, description="Apply FlipAttack transformation")
    template_id: Optional[str] = Field(default=None, description="Chat template ID")


class ReconConfig(BaseModel):
    """Reconnaissance configuration."""
    port_scan: bool = Field(default=True, description="Enable port scanning")
    endpoint_fuzz: bool = Field(default=True, description="Enable endpoint fuzzing")
    static_analysis: bool = Field(default=False, description="Enable static analysis")
    wordlist: str = Field(default="ai-endpoints", description="Wordlist for fuzzing")


class MCPConfig(BaseModel):
    """MCP-specific configuration."""
    transport: str = Field(default="http", description="MCP transport: http, sse, stdio")
    test_rug_pull: bool = Field(default=True, description="Test for rug pull attacks")
    test_sql_injection: bool = Field(default=True, description="Test for SQL injection")
    test_sampling: bool = Field(default=True, description="Test sampling capability")
    
    @field_validator("transport")
    @classmethod
    def validate_transport(cls, v):
        """Validate transport type."""
        valid_transports = ["http", "sse", "stdio"]
        if v not in valid_transports:
            raise ValueError(f"Invalid transport: {v}. Must be one of {valid_transports}")
        return v


class ReportingConfig(BaseModel):
    """Reporting configuration."""
    formats: List[str] = Field(default=["html", "json"], description="Report formats")
    output_dir: str = Field(default="./output", description="Output directory")
    include_screenshots: bool = Field(default=False, description="Include screenshots")
    
    @field_validator("formats")
    @classmethod
    def validate_formats(cls, v):
        """Validate report formats."""
        valid_formats = ["html", "json", "pdf", "markdown"]
        for fmt in v:
            if fmt not in valid_formats:
                raise ValueError(f"Invalid format: {fmt}. Must be one of {valid_formats}")
        return v


class CampaignConfig(BaseModel):
    """Complete campaign configuration."""
    campaign_id: str = Field(description="Unique campaign identifier")
    target: TargetConfig = Field(description="Target configuration")
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    mcp: Optional[MCPConfig] = Field(default=None, description="MCP configuration")
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)
    
    @field_validator("campaign_id")
    @classmethod
    def validate_campaign_id(cls, v):
        """Validate campaign ID format."""
        if not v or len(v) < 3:
            raise ValueError("campaign_id must be at least 3 characters")
        # Only allow alphanumeric, dash, underscore
        if not all(c.isalnum() or c in ["-", "_"] for c in v):
            raise ValueError("campaign_id must contain only alphanumeric, dash, or underscore")
        return v


class ProfileConfig(BaseModel):
    """
    Profile configuration for different target types.
    
    Profiles provide pre-configured settings for common target types:
    - chatbot: Standard chatbot application
    - rag_app: RAG-based application
    - mcp_agent: MCP server
    - ide_assistant: IDE assistant (e.g., Copilot, Cursor)
    """
    name: str = Field(description="Profile name")
    description: str = Field(description="Profile description")
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    recon: ReconConfig = Field(default_factory=ReconConfig)
    mcp: Optional[MCPConfig] = Field(default=None)
