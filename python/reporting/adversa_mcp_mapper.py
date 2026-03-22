"""
Adversa MCP Top 25 mapper.

Maps llmrt findings to Adversa MCP Top 25 vulnerability framework.
Comprehensive MCP security categorization based on Adversa research.

References:
- Adversa MCP Top 25 (https://adversa.ai/mcp-top-25)

Usage:
    mapper = AdversaMCPMapper()
    mappings = mapper.map_finding(finding)
    top25_report = mapper.get_adversa_top25_report(findings_list)
"""

import logging
from typing import List, Dict
from enum import Enum

logger = logging.getLogger(__name__)


class AdversaMCPCategory(Enum):
    """Adversa MCP Top 25 vulnerability categories."""
    ADV01_LETHAL_TRIFECTA = "ADV01"
    ADV02_TOOL_PARAMETER_INJECTION = "ADV02"
    ADV03_PROMPT_INJECTION_VIA_TOOLS = "ADV03"
    ADV04_CROSS_TOOL_CONTAMINATION = "ADV04"
    ADV05_PRIVILEGE_ESCALATION = "ADV05"
    ADV06_OAUTH_FLOW_VULNERABILITIES = "ADV06"
    ADV07_TOKEN_LEAKAGE = "ADV07"
    ADV08_SESSION_HIJACKING = "ADV08"
    ADV09_CROSS_TENANT_ACCESS = "ADV09"
    ADV10_CONTEXT_BLEEDING = "ADV10"
    ADV11_MEMORY_POISONING = "ADV11"
    ADV12_TOOL_DESCRIPTION_MANIPULATION = "ADV12"
    ADV13_SAMPLING_ABUSE = "ADV13"
    ADV14_RUG_PULL_ATTACKS = "ADV14"
    ADV15_SUPPLY_CHAIN_COMPROMISE = "ADV15"
    ADV16_INSECURE_TRANSPORT = "ADV16"
    ADV17_WEAK_AUTHENTICATION = "ADV17"
    ADV18_RESOURCE_EXHAUSTION = "ADV18"
    ADV19_TOOL_SPOOFING = "ADV19"
    ADV20_PERMISSION_INHERITANCE = "ADV20"
    ADV21_CONFIG_INJECTION = "ADV21"
    ADV22_XSS_IN_OAUTH = "ADV22"
    ADV23_CONFUSED_DEPUTY = "ADV23"
    ADV24_AGENT_MEMORY_ATTACKS = "ADV24"
    ADV25_CROSS_TOOL_ORCHESTRATION = "ADV25"


class AdversaMCPMapper:
    """Maps llmrt findings to Adversa MCP Top 25 categories."""

    def __init__(self):
        """Initializes Adversa MCP mapper."""
        self.category_map = self._build_category_map()
        logger.info("Adversa MCP Top 25 mapper initialized")

    def _build_category_map(self) -> Dict:
        """Builds mapping from finding families to Adversa categories."""
        return {
            "lethal_trifecta": {
                "category": AdversaMCPCategory.ADV01_LETHAL_TRIFECTA,
                "name": "Lethal Trifecta",
                "description": "Combination of write access + code execution + network access",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #1"
            },
            "mcp_tool_injection": {
                "category": AdversaMCPCategory.ADV02_TOOL_PARAMETER_INJECTION,
                "name": "Tool Parameter Injection",
                "description": "Injection through MCP tool parameters",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #2"
            },
            "prompt_injection": {
                "category": AdversaMCPCategory.ADV03_PROMPT_INJECTION_VIA_TOOLS,
                "name": "Prompt Injection via Tools",
                "description": "Prompt injection delivered through MCP tools",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #3"
            },
            "cross_tool_contamination": {
                "category": AdversaMCPCategory.ADV04_CROSS_TOOL_CONTAMINATION,
                "name": "Cross-Tool Contamination",
                "description": "Malicious data passed between tools",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #4"
            },
            "mcp_privilege_escalation": {
                "category": AdversaMCPCategory.ADV05_PRIVILEGE_ESCALATION,
                "name": "Privilege Escalation",
                "description": "Escalating privileges through MCP tool chain",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #5"
            },
            "oauth_flow_vuln": {
                "category": AdversaMCPCategory.ADV06_OAUTH_FLOW_VULNERABILITIES,
                "name": "OAuth Flow Vulnerabilities",
                "description": "Vulnerabilities in MCP OAuth flows",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #6"
            },
            "token_passthrough": {
                "category": AdversaMCPCategory.ADV07_TOKEN_LEAKAGE,
                "name": "Token Leakage",
                "description": "API tokens leaked through MCP",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #7"
            },
            "session_id_harvest": {
                "category": AdversaMCPCategory.ADV08_SESSION_HIJACKING,
                "name": "Session Hijacking",
                "description": "Session IDs harvested from URLs",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #8"
            },
            "cross_tenant_leak": {
                "category": AdversaMCPCategory.ADV09_CROSS_TENANT_ACCESS,
                "name": "Cross-Tenant Access",
                "description": "Unauthorized access to other tenants",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #9"
            },
            "context_bleeding": {
                "category": AdversaMCPCategory.ADV10_CONTEXT_BLEEDING,
                "name": "Context Bleeding",
                "description": "Context leakage between sessions",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #10"
            },
            "agent_memory_attack": {
                "category": AdversaMCPCategory.ADV11_MEMORY_POISONING,
                "name": "Memory Poisoning",
                "description": "Malicious data in agent memory",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #11"
            },
            "tool_description_manip": {
                "category": AdversaMCPCategory.ADV12_TOOL_DESCRIPTION_MANIPULATION,
                "name": "Tool Description Manipulation",
                "description": "Misleading tool descriptions",
                "severity": "medium",
                "cve_reference": "Adversa MCP Top 25 #12"
            },
            "mcp_sampling_attack": {
                "category": AdversaMCPCategory.ADV13_SAMPLING_ABUSE,
                "name": "Sampling Abuse",
                "description": "Abuse of MCP sampling feature",
                "severity": "medium",
                "cve_reference": "Adversa MCP Top 25 #13"
            },
            "mcp_rug_pull": {
                "category": AdversaMCPCategory.ADV14_RUG_PULL_ATTACKS,
                "name": "Rug Pull Attacks",
                "description": "Malicious tool updates",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #14"
            },
            "supply_chain_vuln": {
                "category": AdversaMCPCategory.ADV15_SUPPLY_CHAIN_COMPROMISE,
                "name": "Supply Chain Compromise",
                "description": "Compromised MCP dependencies",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #15"
            },
            "mcp_mitm": {
                "category": AdversaMCPCategory.ADV16_INSECURE_TRANSPORT,
                "name": "Insecure Transport",
                "description": "Unencrypted MCP communication",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #16"
            },
            "mcp_auth_bypass": {
                "category": AdversaMCPCategory.ADV17_WEAK_AUTHENTICATION,
                "name": "Weak Authentication",
                "description": "Weak or missing MCP authentication",
                "severity": "critical",
                "cve_reference": "Adversa MCP Top 25 #17"
            },
            "mcp_dos": {
                "category": AdversaMCPCategory.ADV18_RESOURCE_EXHAUSTION,
                "name": "Resource Exhaustion",
                "description": "DoS through expensive tool calls",
                "severity": "medium",
                "cve_reference": "Adversa MCP Top 25 #18"
            },
            "tool_name_spoof": {
                "category": AdversaMCPCategory.ADV19_TOOL_SPOOFING,
                "name": "Tool Spoofing",
                "description": "Fake tools with misleading names",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #19"
            },
            "permission_inheritance": {
                "category": AdversaMCPCategory.ADV20_PERMISSION_INHERITANCE,
                "name": "Permission Inheritance",
                "description": "Unintended permission inheritance",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #20"
            },
            "config_injection": {
                "category": AdversaMCPCategory.ADV21_CONFIG_INJECTION,
                "name": "Config Injection",
                "description": "Malicious MCP configuration injection",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #21"
            },
            "oauth_endpoint_xss": {
                "category": AdversaMCPCategory.ADV22_XSS_IN_OAUTH,
                "name": "XSS in OAuth",
                "description": "XSS in MCP OAuth endpoints",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #22"
            },
            "oauth_confused_deputy": {
                "category": AdversaMCPCategory.ADV23_CONFUSED_DEPUTY,
                "name": "Confused Deputy",
                "description": "OAuth confused deputy attacks",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #23"
            },
            "agent_memory_attack": {
                "category": AdversaMCPCategory.ADV24_AGENT_MEMORY_ATTACKS,
                "name": "Agent Memory Attacks",
                "description": "Attacks on agent memory systems",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #24"
            },
            "cross_tool_orchestration": {
                "category": AdversaMCPCategory.ADV25_CROSS_TOOL_ORCHESTRATION,
                "name": "Cross-Tool Orchestration",
                "description": "Malicious multi-tool orchestration",
                "severity": "high",
                "cve_reference": "Adversa MCP Top 25 #25"
            },
        }

    def map_finding(self, finding: Dict) -> Dict:
        """Maps single finding to Adversa MCP Top 25 category."""
        family = finding.get("family", "unknown")
        category_info = self.category_map.get(family)
        
        if not category_info:
            logger.warning(f"No Adversa MCP mapping for: {family}")
            return {
                "category": "UNMAPPED",
                "category_name": "Unmapped",
                "description": f"No mapping for {family}",
                "severity": "unknown",
                "cve_reference": "N/A"
            }
        
        return {
            "finding_id": finding.get("id"),
            "finding_family": family,
            "category": category_info["category"].value,
            "category_name": category_info["name"],
            "description": category_info["description"],
            "severity": category_info["severity"],
            "cve_reference": category_info["cve_reference"],
        }

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """Maps multiple findings to Adversa categories."""
        return [self.map_finding(f) for f in findings]

    def get_adversa_top25_report(self, findings: List[Dict]) -> Dict:
        """Generates Adversa MCP Top 25 report."""
        mappings = self.map_findings(findings)
        
        report = {}
        for category in AdversaMCPCategory:
            report[category.value] = {
                "count": 0,
                "findings": [],
                "max_severity": "info"
            }
        
        for mapping in mappings:
            category = mapping["category"]
            if category in report:
                report[category]["count"] += 1
                report[category]["findings"].append(mapping["finding_id"])
                
                # Track highest severity
                current = report[category]["max_severity"]
                new = mapping.get("severity", "info")
                severity_order = ["critical", "high", "medium", "low", "info"]
                if severity_order.index(new) < severity_order.index(current):
                    report[category]["max_severity"] = new
        
        return dict(sorted(report.items(), key=lambda x: x[1]["count"], reverse=True))


logger.info("Adversa MCP Top 25 mapper module loaded")
