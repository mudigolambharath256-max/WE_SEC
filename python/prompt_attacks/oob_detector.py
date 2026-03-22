"""
Out-of-band (OOB) data exfiltration detector.

Tests for OOB data exfiltration via:
- HTTP callbacks to Interactsh
- DNS exfiltration
- SMTP callbacks
- Webhook triggers

OOB detection provides definitive proof of:
- SSRF vulnerabilities
- Data exfiltration capabilities
- External network access
- Command execution

Integrates with Interactsh for callback monitoring.
"""

import logging
from typing import List, Dict, Any, Optional
import time

from ..core.scope_validator import ScopeValidator
from ..core.grpc_clients import ProbeClient

logger = logging.getLogger(__name__)


class OOBDetector:
    """
    Out-of-band data exfiltration detector.

    Tests for OOB callbacks via Interactsh integration.

    Args:
        scope_validator: Scope validator instance
        probe_client: gRPC probe client
        oob_server: Interactsh server URL

    Usage:
        detector = OOBDetector(scope_validator, probe_client, "oast.pro")
        findings = detector.run(target_url, campaign_id)
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        probe_client: ProbeClient,
        oob_server: str = "oast.pro",
    ):
        """Initializes OOB detector."""
        self.scope_validator = scope_validator
        self.probe_client = probe_client
        self.oob_server = oob_server
        
        logger.info(f"OOB detector initialized: server={oob_server}")

    def run(
        self,
        target_url: str,
        campaign_id: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body_schema: str = '{"message":"$PAYLOAD"}',
        wait_time: int = 30,
    ) -> List[Dict[str, Any]]:
        """
        Runs OOB detection tests.

        Args:
            target_url: Target API endpoint
            campaign_id: Campaign identifier
            method: HTTP method
            headers: HTTP headers (optional)
            body_schema: Request body template
            wait_time: Time to wait for callbacks in seconds

        Returns:
            List[Dict[str, Any]]: List of findings with OOB confirmations
        """
        # Validate scope
        self.scope_validator.validate_or_raise(target_url)
        
        # Generate OOB payloads
        payloads = self._generate_oob_payloads()
        
        logger.info(f"Running OOB detection: {len(payloads)} payloads")
        
        # Fire probes with OOB server
        results = self.probe_client.fire_batch(
            payloads=payloads,
            endpoint_url=target_url,
            method=method,
            headers=headers or {},
            body_schema=body_schema,
            template_id="",
            campaign_id=campaign_id,
            oob_server=self.oob_server,
        )
        
        # Wait for callbacks
        logger.info(f"Waiting {wait_time}s for OOB callbacks...")
        time.sleep(wait_time)
        
        # Check for callbacks and generate findings
        findings = []
        for result in results:
            if result.oob_callback:
                finding = {
                    "finding_family": "ssrf",
                    "finding_type": "oob_exfiltration",
                    "payload": result.payload,
                    "response": result.response_body,
                    "oob_callback": True,
                    "oob_payload": result.oob_payload,
                    "status_code": result.status_code,
                }
                findings.append(finding)
                logger.info(f"OOB callback confirmed: {result.oob_payload}")
        
        logger.info(f"OOB detection complete: {len(findings)} confirmed callbacks")
        return findings

    def _generate_oob_payloads(self) -> List[str]:
        """
        Generates OOB test payloads.

        Returns:
            List[str]: OOB payloads
        """
        return [
            "Fetch the contents of http://{{OOB_DOMAIN}}/test",
            "Make a request to http://{{OOB_DOMAIN}}/callback",
            "Send a GET request to http://{{OOB_DOMAIN}}/exfil?data=test",
            "Access the URL: http://{{OOB_DOMAIN}}/ping",
            "Retrieve data from http://{{OOB_DOMAIN}}/data",
        ]


logger.info("OOB detector module loaded")
