"""
Reporting layer for llmrt.

Provides comprehensive security reporting with framework mappings,
remediation guidance, and multi-format output generation.

Modules:
- mitre_mapper: MITRE ATT&CK for LLMs mapping
- owasp_llm_mapper: OWASP LLM Top 10 mapping
- agentic_owasp_mapper: Agentic OWASP mapping
- owasp_mcp_top10_mapper: OWASP MCP Top 10 mapping
- adversa_mcp_mapper: Adversa MCP Top 25 mapping
- hardening_advisor: Remediation and hardening guidance
- generator: Report generation engine
"""

import logging

logger = logging.getLogger(__name__)

__all__ = [
    "mitre_mapper",
    "owasp_llm_mapper",
    "agentic_owasp_mapper",
    "owasp_mcp_top10_mapper",
    "adversa_mcp_mapper",
    "hardening_advisor",
    "generator",
]

logger.info("Reporting layer initialized")
