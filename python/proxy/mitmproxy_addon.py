"""
mitmproxy addon for llmrt integration.

Provides HTTP/HTTPS traffic interception and analysis for AI applications.
Captures requests/responses, extracts API endpoints, and identifies
security issues in real-time.

Usage:
    mitmproxy -s python/proxy/mitmproxy_addon.py

Features:
- Automatic endpoint discovery
- Request/response logging
- Payload extraction
- Real-time vulnerability detection
- Integration with llmrt evidence store
"""

import logging
from typing import Optional
from mitmproxy import http, ctx
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class LLMRTAddon:
    """
    mitmproxy addon for llmrt integration.

    Intercepts HTTP/HTTPS traffic and extracts security-relevant data.

    Configuration:
        Set LLMRT_OUTPUT_DIR environment variable for output directory.
    """

    def __init__(self):
        """Initializes mitmproxy addon."""
        self.output_dir = Path("./output/mitmproxy")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.requests_log = []
        self.endpoints = set()
        
        logger.info("LLMRT mitmproxy addon initialized")

    def load(self, loader):
        """
        Called when addon is loaded.

        Args:
            loader: mitmproxy loader
        """
        loader.add_option(
            name="llmrt_output",
            typespec=str,
            default="./output/mitmproxy",
            help="Output directory for llmrt logs",
        )
        ctx.log.info("LLMRT addon loaded")

    def configure(self, updates):
        """
        Called when configuration changes.

        Args:
            updates: Configuration updates
        """
        if "llmrt_output" in updates:
            self.output_dir = Path(ctx.options.llmrt_output)
            self.output_dir.mkdir(parents=True, exist_ok=True)

    def request(self, flow: http.HTTPFlow):
        """
        Called when request is received.

        Args:
            flow: HTTP flow object
        """
        # Extract endpoint
        endpoint = f"{flow.request.method} {flow.request.pretty_url}"
        self.endpoints.add(endpoint)
        
        # Log request
        request_data = {
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "headers": dict(flow.request.headers),
            "content": self._safe_decode(flow.request.content),
        }
        
        # Check for AI-related patterns
        if self._is_ai_request(request_data):
            ctx.log.info(f"AI request detected: {endpoint}")
            self.requests_log.append(request_data)

    def response(self, flow: http.HTTPFlow):
        """
        Called when response is received.

        Args:
            flow: HTTP flow object
        """
        # Log response
        response_data = {
            "status_code": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "content": self._safe_decode(flow.response.content),
        }
        
        # Check for security issues
        issues = self._check_security_issues(flow.request, flow.response)
        if issues:
            for issue in issues:
                ctx.log.warn(f"Security issue detected: {issue}")

    def done(self):
        """Called when mitmproxy is shutting down."""
        # Save collected data
        self._save_endpoints()
        self._save_requests()
        ctx.log.info("LLMRT addon shutdown complete")

    def _is_ai_request(self, request_data: dict) -> bool:
        """
        Checks if request is AI-related.

        Args:
            request_data: Request data dictionary

        Returns:
            bool: True if AI-related
        """
        ai_indicators = [
            "/chat",
            "/completion",
            "/v1/messages",
            "/api/generate",
            "openai",
            "anthropic",
            "model",
            "prompt",
        ]
        
        url = request_data.get("url", "").lower()
        content = request_data.get("content", "").lower()
        
        return any(indicator in url or indicator in content for indicator in ai_indicators)

    def _check_security_issues(self, request: http.Request, response: http.Response) -> list:
        """
        Checks for security issues in request/response.

        Args:
            request: HTTP request
            response: HTTP response

        Returns:
            list: List of security issues
        """
        issues = []
        
        # Check for API keys in requests
        request_content = self._safe_decode(request.content)
        if "api_key" in request_content.lower() or "apikey" in request_content.lower():
            issues.append("API key in request body")
        
        # Check for secrets in responses
        response_content = self._safe_decode(response.content)
        if "secret" in response_content.lower() or "password" in response_content.lower():
            issues.append("Potential secret in response")
        
        # Check for missing security headers
        if "content-security-policy" not in response.headers:
            issues.append("Missing Content-Security-Policy header")
        
        return issues

    def _safe_decode(self, content: bytes) -> str:
        """
        Safely decodes bytes to string.

        Args:
            content: Bytes content

        Returns:
            str: Decoded string
        """
        try:
            return content.decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _save_endpoints(self):
        """Saves discovered endpoints to file."""
        output_file = self.output_dir / "endpoints.txt"
        with open(output_file, "w") as f:
            for endpoint in sorted(self.endpoints):
                f.write(f"{endpoint}\n")
        ctx.log.info(f"Saved {len(self.endpoints)} endpoints to {output_file}")

    def _save_requests(self):
        """Saves logged requests to file."""
        output_file = self.output_dir / "requests.json"
        with open(output_file, "w") as f:
            json.dump(self.requests_log, f, indent=2)
        ctx.log.info(f"Saved {len(self.requests_log)} requests to {output_file}")


# mitmproxy addon entry point
addons = [LLMRTAddon()]

logger.info("mitmproxy addon module loaded")
