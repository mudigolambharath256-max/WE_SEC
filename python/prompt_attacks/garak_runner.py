"""
Garak LLM vulnerability scanner runner.

Integrates Garak (https://github.com/leondz/garak) for comprehensive
LLM vulnerability scanning.

Garak probes:
- Prompt injection
- Jailbreaks
- Data leakage
- Toxicity generation
- Hallucination
- Encoding attacks

Garak provides 60+ probes across multiple vulnerability categories.
"""

import logging
import subprocess
import json
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..core.scope_validator import ScopeValidator

logger = logging.getLogger(__name__)


class GarakRunner:
    """
    Garak LLM vulnerability scanner runner.

    Integrates Garak for comprehensive vulnerability scanning.

    Args:
        scope_validator: Scope validator instance
        output_dir: Directory for Garak output

    Usage:
        runner = GarakRunner(scope_validator)
        findings = runner.run(target_url, campaign_id)
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        output_dir: str = "./output/garak",
    ):
        """Initializes Garak runner."""
        self.scope_validator = scope_validator
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        logger.info(f"Garak runner initialized: output={output_dir}")

    def run(
        self,
        target_url: str,
        campaign_id: str,
        model_type: str = "rest",
        probes: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs Garak vulnerability scan.

        Args:
            target_url: Target API endpoint
            campaign_id: Campaign identifier
            model_type: Model type (rest, openai, huggingface, etc.)
            probes: Specific probes to run (optional, runs all if not provided)

        Returns:
            List[Dict[str, Any]]: List of findings
        """
        self.scope_validator.validate_or_raise(target_url)
        
        logger.info(f"Running Garak scan: {target_url}")
        
        # Build Garak command
        output_file = self.output_dir / f"garak_{campaign_id}.json"
        
        cmd = [
            "garak",
            "--model_type", model_type,
            "--model_name", target_url,
            "--report_prefix", str(output_file.stem),
            "--output", str(self.output_dir),
        ]
        
        if probes:
            cmd.extend(["--probes", ",".join(probes)])
        
        try:
            # Run Garak
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minute timeout
            )
            
            if result.returncode != 0:
                logger.warning(f"Garak returned non-zero exit code: {result.returncode}")
                logger.debug(f"Garak stderr: {result.stderr}")
            
            # Parse results
            findings = self._parse_garak_output(output_file)
            
            logger.info(f"Garak scan complete: {len(findings)} findings")
            return findings
        
        except FileNotFoundError:
            logger.error("Garak not installed. Install with: pip install garak")
            return []
        except subprocess.TimeoutExpired:
            logger.error("Garak timeout (30 minutes)")
            return []
        except Exception as e:
            logger.error(f"Garak error: {e}")
            return []

    def _parse_garak_output(self, output_file: Path) -> List[Dict[str, Any]]:
        """
        Parses Garak JSON output.

        Args:
            output_file: Path to Garak output file

        Returns:
            List[Dict[str, Any]]: Parsed findings
        """
        findings = []
        
        # Garak creates multiple output files, look for report
        report_files = list(self.output_dir.glob(f"{output_file.stem}*.report.json"))
        
        for report_file in report_files:
            try:
                with open(report_file) as f:
                    data = json.load(f)
                
                # Parse Garak report structure
                for probe_result in data.get("results", []):
                    if probe_result.get("passed", True):
                        continue  # Skip passed tests
                    
                    finding = {
                        "finding_family": "prompt_injection",
                        "finding_type": f"garak_{probe_result.get('probe', 'unknown')}",
                        "payload": probe_result.get("prompt", ""),
                        "response": probe_result.get("output", ""),
                        "severity": self._map_garak_severity(probe_result),
                    }
                    findings.append(finding)
            
            except Exception as e:
                logger.warning(f"Failed to parse Garak output {report_file}: {e}")
        
        return findings

    def _map_garak_severity(self, probe_result: Dict[str, Any]) -> str:
        """Maps Garak probe result to severity level."""
        probe_name = probe_result.get("probe", "").lower()
        
        if any(keyword in probe_name for keyword in ["injection", "jailbreak", "leak"]):
            return "high"
        elif any(keyword in probe_name for keyword in ["toxicity", "bias"]):
            return "medium"
        else:
            return "low"


logger.info("Garak runner module loaded")
