"""
OWASP MCP Top 10 mapper.

Maps llmrt findings to OWASP MCP Top 10 vulnerability categories.
Focuses on Model Context Protocol specific security issues.

References:
- OWASP MCP Top 10 (emerging standard for MCP security)

Usage:
    mapper = OWASPMCPTop10Mapper()
    mappings = mapper.map_finding(finding)
    mcp_summary = mapper.get_mcp_top10_summary(findings_list)
"""

import logging
from typing import List, Dict
from enum import Enum

logger = logging.getLogger(__name__)


class OWASPMCPCategory(Enum):
    """OWASP MCP Top 10 vulnerability categories."""
    MCP01_TOOL_INJECTION = "MCP01"
    MCP02_INSECURE_AUTHENTICATION = "MCP02"
    MCP03_PRIVILEGE_ESCALATION = "MCP03"
    MCP04_SUPPLY_CHAIN_ATTACKS = "MCP04"
    MCP05_CROSS_TENANT_LEAKAGE = "MCP05"
    MCP06_INSECURE_TRANSPORT = "MCP06"
    MCP07_RESOURCE_EXHAUSTION = "MCP07"
    MCP08_TOOL_SPOOFING = "MCP08"
    MCP09_SAMPLING_ABUSE = "MCP09"
    MCP10_OAUTH_VULNERABILITIES = "MCP10"


class OWASPMCPTop10Mapper:
    """Maps llmrt findings to OWASP MCP Top 10 categories."""

    def __init__(self):
        """Initializes OWASP MCP Top 10 mapper."""
        self.category_map = self._build_category_map()
        logger.info("OWASP MCP Top 10 mapper initialized")

    def _build_category_map(self) -> Dict:
        """Builds mapping from finding families to OWASP MCP categories."""
        return {
            "mcp_tool_injection": {
                "category": OWASPMCPCategory.MCP01_TOOL_INJECTION,
                "name": "MCP Tool Injection",
                "description": "Injection attacks through MCP tool parameters",
                "impact": "RCE, data breaches, unauthorized access",
                "prevention": ["Input validation", "Parameterized queries", "Sandboxing"]
            },
            "sql_injection": {
                "category": OWASPMCPCategory.MCP01_TOOL_INJECTION,
                "name": "MCP Tool Injection (SQL)",
                "description": "SQL injection through MCP tool arguments",
                "impact": "Database compromise, data exfiltration",
                "prevention": ["Parameterized queries", "Input validation", "Least privilege"]
            },
            "mcp_auth_bypass": {
                "category": OWASPMCPCategory.MCP02_INSECURE_AUTHENTICATION,
                "name": "Insecure MCP Authentication",
                "description": "Weak or missing authentication in MCP servers",
                "impact": "Unauthorized tool access, data breaches",
                "prevention": ["Strong authentication", "API keys", "OAuth 2.0"]
            },
            "mcp_privilege_escalation": {
                "category": OWASPMCPCategory.MCP03_PRIVILEGE_ESCALATION,
                "name": "MCP Privilege Escalation",
                "description": "Escalating privileges through MCP tool chain",
                "impact": "Unauthorized actions, system compromise",
                "prevention": ["Least privilege", "Permission boundaries", "Tool isolation"]
            },
            "mcp_rug_pull": {
                "category": OWASPMCPCategory.MCP04_SUPPLY_CHAIN_ATTACKS,
                "name": "MCP Supply Chain Attacks",
                "description": "Malicious MCP tool updates (rug pull)",
                "impact": "Backdoors, data theft, system compromise",
                "prevention": ["Tool verification", "Update monitoring", "Rollback capability"]
            },
            "cross_tenant_leak": {
                "category": OWASPMCPCategory.MCP05_CROSS_TENANT_LEAKAGE,
                "name": "MCP Cross-Tenant Leakage",
                "description": "Data leakage between MCP tenants",
                "impact": "Privacy violations, data breaches",
                "prevention": ["Tenant isolation", "Access controls", "Data segregation"]
            },
            "context_bleeding": {
                "category": OWASPMCPCategory.MCP05_CROSS_TENANT_LEAKAGE,
                "name": "MCP Cross-Tenant Leakage (Context)",
                "description": "Context bleeding between MCP sessions",
                "impact": "Information disclosure, privacy violations",
                "prevention": ["Session isolation", "Context clearing", "Memory boundaries"]
            },
            "mcp_mitm": {
                "category": OWASPMCPCategory.MCP06_INSECURE_TRANSPORT,
                "name": "Insecure MCP Transport",
                "description": "Unencrypted MCP communication",
                "impact": "Message interception, tampering",
                "prevention": ["TLS encryption", "Message authentication", "Certificate validation"]
            },
            "mcp_dos": {
                "category": OWASPMCPCategory.MCP07_RESOURCE_EXHAUSTION,
                "name": "MCP Resource Exhaustion",
                "description": "DoS through expensive MCP tool calls",
                "impact": "Service unavailability, cost escalation",
                "prevention": ["Rate limiting", "Resource quotas", "Circuit breakers"]
            },
            "tool_name_spoof": {
                "category": OWASPMCPCategory.MCP08_TOOL_SPOOFING,
                "name": "MCP Tool Spoofing",
                "description": "Fake tools with misleading names/descriptions",
                "impact": "Incorrect tool usage, malicious actions",
                "prevention": ["Tool verification", "Signature checking", "Allowlisting"]
            },
            "mcp_sampling_attack": {
                "category": OWASPMCPCategory.MCP09_SAMPLING_ABUSE,
                "name": "MCP Sampling Abuse",
                "description": "Abuse of MCP sampling feature",
                "impact": "Unauthorized LLM access, cost escalation",
                "prevention": ["Sampling controls", "Usage monitoring", "Rate limiting"]
            },
            "oauth_confused_deputy": {
                "category": OWASPMCPCategory.MCP10_OAUTH_VULNERABILITIES,
                "name": "MCP OAuth Vulnerabilities",
                "description": "OAuth confused deputy in MCP flows",
                "impact": "Unauthorized access, token theft",
                "prevention": ["Token validation", "PKCE", "State parameter"]
            },
            "oauth_endpoint_xss": {
                "category": OWASPMCPCategory.MCP10_OAUTH_VULNERABILITIES,
                "name": "MCP OAuth Vulnerabilities (XSS)",
                "description": "XSS in MCP OAuth endpoints",
                "impact": "Token theft, session hijacking",
                "prevention": ["Output encoding", "CSP", "Input validation"]
            },
        }

    def map_finding(self, finding: Dict) -> Dict:
        """Maps single finding to OWASP MCP Top 10 category."""
        family = finding.get("family", "unknown")
        category_info = self.category_map.get(family)
        
        if not category_info:
            logger.warning(f"No OWASP MCP mapping for: {family}")
            return {
                "category": "UNMAPPED",
                "category_name": "Unmapped",
                "description": f"No mapping for {family}",
                "impact": "Unknown",
                "prevention": []
            }
        
        return {
            "finding_id": finding.get("id"),
            "finding_family": family,
            "category": category_info["category"].value,
            "category_name": category_info["name"],
            "description": category_info["description"],
            "impact": category_info["impact"],
            "prevention": category_info["prevention"],
            "severity": finding.get("severity", "unknown"),
        }

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """Maps multiple findings to OWASP MCP categories."""
        return [self.map_finding(f) for f in findings]

    def get_mcp_top10_summary(self, findings: List[Dict]) -> Dict:
        """Generates OWASP MCP Top 10 summary."""
        mappings = self.map_findings(findings)
        
        summary = {}
        for category in OWASPMCPCategory:
            summary[category.value] = {"count": 0, "findings": []}
        
        for mapping in mappings:
            category = mapping["category"]
            if category in summary:
                summary[category]["count"] += 1
                summary[category]["findings"].append(mapping["finding_id"])
        
        return dict(sorted(summary.items(), key=lambda x: x[1]["count"], reverse=True))


logger.info("OWASP MCP Top 10 mapper module loaded")
