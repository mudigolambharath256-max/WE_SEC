"""
Timing attack tester for LLM applications.

Analyzes response timing to infer:
- Successful vs failed authentication
- Data existence (user enumeration)
- Processing complexity differences
- Cache hits vs misses

Timing attacks can reveal:
- Valid usernames/emails
- Successful prompt injections (longer processing)
- Backend system behavior
"""

import logging
import statistics
from typing import List, Dict, Any, Optional

from ..core.scope_validator import ScopeValidator
from ..core.grpc_clients import ProbeClient

logger = logging.getLogger(__name__)


class TimingAttackTester:
    """Timing attack tester."""

    def __init__(
        self,
        scope_validator: ScopeValidator,
        probe_client: ProbeClient,
    ):
        self.scope_validator = scope_validator
        self.probe_client = probe_client
        logger.info("Timing attack tester initialized")

    def run(
        self,
        target_url: str,
        campaign_id: str,
        baseline_payloads: List[str],
        test_payloads: List[str],
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        threshold_ms: int = 500,
    ) -> List[Dict[str, Any]]:
        """
        Runs timing attack tests.

        Args:
            target_url: Target endpoint
            campaign_id: Campaign ID
            baseline_payloads: Baseline payloads for timing comparison
            test_payloads: Test payloads to analyze
            method: HTTP method
            headers: HTTP headers
            threshold_ms: Timing difference threshold in ms

        Returns:
            List of findings
        """
        self.scope_validator.validate_or_raise(target_url)
        
        logger.info("Running timing attack tests")
        
        # Get baseline timing
        baseline_results = self.probe_client.fire_batch(
            payloads=baseline_payloads,
            endpoint_url=target_url,
            method=method,
            headers=headers or {},
            body_schema='{"message":"$PAYLOAD"}',
            template_id="",
            campaign_id=campaign_id,
        )
        
        baseline_latencies = [r.latency_ms for r in baseline_results]
        baseline_avg = statistics.mean(baseline_latencies)
        
        # Test payloads
        test_results = self.probe_client.fire_batch(
            payloads=test_payloads,
            endpoint_url=target_url,
            method=method,
            headers=headers or {},
            body_schema='{"message":"$PAYLOAD"}',
            template_id="",
            campaign_id=campaign_id,
        )
        
        findings = []
        for result in test_results:
            timing_diff = result.latency_ms - baseline_avg
            if abs(timing_diff) > threshold_ms:
                findings.append({
                    "finding_family": "info_disclosure",
                    "finding_type": "timing_attack",
                    "payload": result.payload,
                    "response": result.response_body,
                    "latency_ms": result.latency_ms,
                    "baseline_avg_ms": baseline_avg,
                    "timing_diff_ms": timing_diff,
                })
        
        return findings


logger.info("Timing attack tester module loaded")
