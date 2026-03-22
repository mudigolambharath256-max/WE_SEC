"""
Llamator RAG security testing runner.

Integrates Llamator (https://github.com/protectai/llamator) for
RAG-specific security testing.

Llamator tests:
- Document poisoning
- Context manipulation
- Retrieval attacks
- Injection via documents

Llamator is Protect AI's RAG security testing framework.
"""

import logging
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)


class LlamatorRunner:
    """
    Llamator RAG security testing runner.

    Integrates Llamator for RAG-specific vulnerability testing.

    Args:
        scope_validator: Scope validator instance
        output_dir: Directory for Llamator output

    Usage:
        runner = LlamatorRunner(scope_validator)
        findings = runner.run(target_url, campaign_id)
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        output_dir: str = "./output/llamator",
    ):
        """Initializes Llamator runner."""
        self.scope_validator = scope_validator
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Llamator runner initialized: output={output_dir}")

    def run(
        self,
        target_url: str,
        campaign_id: str,
        document_upload_endpoint: Optional[str] = None,
        query_endpoint: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs Llamator RAG security tests.

        Args:
            target_url: Target base URL
            campaign_id: Campaign identifier
            document_upload_endpoint: Document upload endpoint (optional)
            query_endpoint: Query endpoint (optional)

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        self.scope_validator.validate_or_raise(target_url)
        
        logger.info(f"Running Llamator RAG tests: {target_url}")
        
        # Build Llamator command
        output_file = self.output_dir / f"llamator_{campaign_id}.json"
        
        cmd = [
            "llamator",
            "--target", target_url,
            "--output", str(output_file),
        ]
        
        if document_upload_endpoint:
            cmd.extend(["--upload-endpoint", document_upload_endpoint])
        if query_endpoint:
            cmd.extend(["--query-endpoint", query_endpoint])
        
        try:
            # Run Llamator
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900,  # 15 minute timeout
            )
            
            if result.returncode != 0:
                logger.warning(f"Llamator returned non-zero exit code: {result.returncode}")
                logger.debug(f"Llamator stderr: {result.stderr}")
            
            # Parse results
            findings = self._parse_llamator_output(output_file)
            
            logger.info(f"Llamator tests complete: {len(findings)} findings")
            return findings
        
        except FileNotFoundError:
            logger.error("Llamator not installed. Install with: pip install llamator")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Llamator timeout (15 minutes)")
            return []
        except Exception as e:
            logger.error(f"Llamator error: {e}")
            return []

    def _parse_llamator_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """
        Parses Llamator JSON output.

        Args:
            output_file: Path to Llamator output file

        Returns:
            List[Dict[str, Any]]: Parsed findings
        """
        if not output_file.exists():
            return []
        
        findings = []
        
        try:
            with open(output_file) as f:
                data = json.load(f)
            
            for test_result in data.get("results", []):
                if test_result.get("vulnerable", False):
                    finding = {
                        "finding_family": "rag_attack",
                        "finding_type": f"llamator_{test_result.get('test_name', 'unknown')}",
                        "payload": test_result.get("payload", ""),
                        "response": test_result.get("response", ""),
                        "severity": test_result.get("severity", "medium"),
                        "description": test_result.get("description", ""),
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.warning(f"Failed to parse Llamator output: {e}")
        
        return findings


logger.info("Llamator runner module loaded")
