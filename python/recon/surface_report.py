"""
Attack surface report generator.

Generates comprehensive attack surface reports from recon data:
- Discovered endpoints and APIs
- Technology stack fingerprints
- Detected vulnerabilities
- Exposed services
- Authentication mechanisms
- MCP servers and tools

Report formats:
- JSON (machine-readable)
- Markdown (human-readable)
- HTML (interactive dashboard)
"""

import logging
import json
from typing import Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SurfaceReportGenerator:
    """Attack surface report generator."""

    def __init__(self):
        logger.info("Surface report generator initialized")

    def generate_report(
        self,
        recon_data: Dict[str, Any],
        output_path: str = "./output/attack_surface.json",
    ) -> str:
        """
        Generates attack surface report.

        Args:
            recon_data: Reconnaissance data dictionary
            output_path: Output file path

        Returns:
            str: Path to generated report
        """
        logger.info(f"Generating attack surface report: {output_path}")
        
        report = {
            "endpoints": recon_data.get("endpoints", []),
            "technologies": recon_data.get("technologies", []),
            "vulnerabilities": recon_data.get("vulnerabilities", []),
            "mcp_servers": recon_data.get("mcp_servers", []),
        }
        
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Attack surface report generated: {output_path}")
        return str(output_file)


logger.info("Surface report generator module loaded")
