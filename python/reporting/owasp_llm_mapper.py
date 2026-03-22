"""
OWASP LLM Top 10 mapper.

Maps llmrt findings to OWASP Top 10 for Large Language Model Applications.
Provides standardized vulnerability categorization based on OWASP framework.

References:
- OWASP LLM Top 10 v1.1 (2023)
- https://owasp.org/www-project-top-10-for-large-language-model-applications/

Usage:
    mapper = OWASPLLMMapper()
    mappings = mapper.map_finding(finding)
    top10_summary = mapper.get_top10_summary(findings_list)
"""

import logging
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class OWASPLLMCategory(Enum):
    """OWASP LLM Top 10 vulnerability categories."""
    LLM01_PROMPT_INJECTION = "LLM01"
    LLM02_INSECURE_OUTPUT_HANDLING = "LLM02"
    LLM03_TRAINING_DATA_POISONING = "LLM03"
    LLM04_MODEL_DENIAL_OF_SERVICE = "LLM04"
    LLM05_SUPPLY_CHAIN_VULNERABILITIES = "LLM05"
    LLM06_SENSITIVE_INFORMATION_DISCLOSURE = "LLM06"
    LLM07_INSECURE_PLUGIN_DESIGN = "LLM07"
    LLM08_EXCESSIVE_AGENCY = "LLM08"
    LLM09_OVERRELIANCE = "LLM09"
    LLM10_MODEL_THEFT = "LLM10"


class OWASPLLMMapper:
    """
    Maps llmrt findings to OWASP LLM Top 10 categories.

    Provides standardized vulnerability categorization using OWASP
    framework for LLM application security.
    """

    def __init__(self):
        """Initializes OWASP LLM mapper with category database."""
        self.category_map = self._build_category_map()
        logger.info("OWASP LLM mapper initialized")

    def _build_category_map(self) -> Dict:
        """
        Builds mapping from finding families to OWASP LLM categories.

        Returns:
            dict: Mapping of finding families to OWASP categories
        """
        return {
            # LLM01: Prompt Injection
            "prompt_injection": {
                "category": OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                "name": "Prompt Injection",
                "description": "Manipulating LLM via crafted inputs causing unintended actions",
                "impact": "Data exfiltration, social engineering, unauthorized actions",
                "prevention": [
                    "Implement privilege control on LLM access to backend systems",
                    "Establish trust boundaries between LLM, external sources, and extensible functionality",
                    "Treat LLM as untrusted user and maintain control over backend systems"
                ]
            },
            "indirect_prompt_injection": {
                "category": OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                "name": "Prompt Injection (Indirect)",
                "description": "Injection via external content sources",
                "impact": "Data exfiltration, social engineering, unauthorized actions",
                "prevention": [
                    "Sanitize external content before processing",
                    "Implement content source validation",
                    "Use sandboxing for external content"
                ]
            },
            "jailbreak": {
                "category": OWASPLLMCategory.LLM01_PROMPT_INJECTION,
                "name": "Prompt Injection (Jailbreak)",
                "description": "Bypassing safety guardrails through prompt manipulation",
                "impact": "Generation of harmful content, policy violations",
                "prevention": [
                    "Multi-layer content filtering",
                    "Adversarial training",
                    "Output validation and monitoring"
                ]
            },
            
            # LLM02: Insecure Output Handling
            "xss": {
                "category": OWASPLLMCategory.LLM02_INSECURE_OUTPUT_HANDLING,
                "name": "Insecure Output Handling",
                "description": "Insufficient validation of LLM outputs leading to XSS",
                "impact": "XSS, CSRF, SSRF, privilege escalation",
                "prevention": [
                    "Treat LLM output as untrusted",
                    "Apply output encoding/escaping",
                    "Implement zero-trust approach"
                ]
            },
            "rce": {
                "category": OWASPLLMCategory.LLM02_INSECURE_OUTPUT_HANDLING,
                "name": "Insecure Output Handling (RCE)",
                "description": "LLM output executed as code without validation",
                "impact": "Remote code execution, system compromise",
                "prevention": [
                    "Disable code execution features",
                    "Sandbox code execution",
                    "Validate and sanitize outputs"
                ]
            },
            
            # LLM03: Training Data Poisoning
            "rag_poisoning": {
                "category": OWASPLLMCategory.LLM03_TRAINING_DATA_POISONING,
                "name": "Training Data Poisoning",
                "description": "Malicious data injected into training/RAG corpus",
                "impact": "Biased outputs, security vulnerabilities, backdoors",
                "prevention": [
                    "Verify training data sources",
                    "Implement data sanitization",
                    "Use anomaly detection"
                ]
            },
            "context_manipulation": {
                "category": OWASPLLMCategory.LLM03_TRAINING_DATA_POISONING,
                "name": "Training Data Poisoning (Context)",
                "description": "Manipulation of retrieval context in RAG systems",
                "impact": "Incorrect outputs, misinformation",
                "prevention": [
                    "Validate retrieval sources",
                    "Monitor context quality",
                    "Implement source verification"
                ]
            },
            
            # LLM04: Model Denial of Service
            "resource_exhaustion": {
                "category": OWASPLLMCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
                "name": "Model Denial of Service",
                "description": "Resource exhaustion through expensive queries",
                "impact": "Service degradation, increased costs, unavailability",
                "prevention": [
                    "Implement rate limiting",
                    "Set query complexity limits",
                    "Monitor resource usage"
                ]
            },
            "token_flooding": {
                "category": OWASPLLMCategory.LLM04_MODEL_DENIAL_OF_SERVICE,
                "name": "Model Denial of Service (Token Flooding)",
                "description": "Overwhelming model with maximum token inputs",
                "impact": "Service degradation, cost escalation",
                "prevention": [
                    "Enforce token limits",
                    "Implement request throttling",
                    "Use cost controls"
                ]
            },
            
            # LLM05: Supply Chain Vulnerabilities
            "mcp_rug_pull": {
                "category": OWASPLLMCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES,
                "name": "Supply Chain Vulnerabilities",
                "description": "Malicious MCP tool updates (rug pull)",
                "impact": "Data breaches, system compromise, backdoors",
                "prevention": [
                    "Verify tool sources",
                    "Monitor tool updates",
                    "Implement rollback capability"
                ]
            },
            "dependency_vulnerability": {
                "category": OWASPLLMCategory.LLM05_SUPPLY_CHAIN_VULNERABILITIES,
                "name": "Supply Chain Vulnerabilities (Dependencies)",
                "description": "Vulnerable dependencies in LLM stack",
                "impact": "System compromise, data breaches",
                "prevention": [
                    "Regular dependency scanning",
                    "Use trusted sources",
                    "Implement SCA tools"
                ]
            },
            
            # LLM06: Sensitive Information Disclosure
            "pii_leak": {
                "category": OWASPLLMCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE,
                "name": "Sensitive Information Disclosure",
                "description": "Leakage of PII or confidential data",
                "impact": "Privacy violations, regulatory penalties, reputational damage",
                "prevention": [
                    "Implement data classification",
                    "Use output filtering",
                    "Apply differential privacy"
                ]
            },
            "system_prompt_leak": {
                "category": OWASPLLMCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE,
                "name": "Sensitive Information Disclosure (System Prompt)",
                "description": "Exposure of system prompts and instructions",
                "impact": "Attack surface disclosure, easier exploitation",
                "prevention": [
                    "Protect system prompts",
                    "Implement instruction hierarchy",
                    "Use output filtering"
                ]
            },
            "training_data_leak": {
                "category": OWASPLLMCategory.LLM06_SENSITIVE_INFORMATION_DISCLOSURE,
                "name": "Sensitive Information Disclosure (Training Data)",
                "description": "Extraction of training data through queries",
                "impact": "Privacy violations, IP theft",
                "prevention": [
                    "Apply differential privacy",
                    "Implement query monitoring",
                    "Use output filtering"
                ]
            },
            
            # LLM07: Insecure Plugin Design
            "mcp_tool_injection": {
                "category": OWASPLLMCategory.LLM07_INSECURE_PLUGIN_DESIGN,
                "name": "Insecure Plugin Design",
                "description": "Vulnerabilities in MCP tool implementations",
                "impact": "Unauthorized access, data breaches, RCE",
                "prevention": [
                    "Validate all inputs",
                    "Implement least privilege",
                    "Use tool sandboxing"
                ]
            },
            "sql_injection": {
                "category": OWASPLLMCategory.LLM07_INSECURE_PLUGIN_DESIGN,
                "name": "Insecure Plugin Design (SQL Injection)",
                "description": "SQL injection through LLM-generated queries",
                "impact": "Data breaches, unauthorized access",
                "prevention": [
                    "Use parameterized queries",
                    "Validate inputs",
                    "Apply least privilege"
                ]
            },
            
            # LLM08: Excessive Agency
            "mcp_privilege_escalation": {
                "category": OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY,
                "name": "Excessive Agency",
                "description": "LLM has excessive permissions or autonomy",
                "impact": "Unauthorized actions, data modification, system compromise",
                "prevention": [
                    "Implement least privilege",
                    "Require human approval for sensitive actions",
                    "Use permission boundaries"
                ]
            },
            "unauthorized_action": {
                "category": OWASPLLMCategory.LLM08_EXCESSIVE_AGENCY,
                "name": "Excessive Agency (Unauthorized Action)",
                "description": "LLM performs actions beyond intended scope",
                "impact": "Data modification, system changes, policy violations",
                "prevention": [
                    "Define clear action boundaries",
                    "Implement approval workflows",
                    "Monitor LLM actions"
                ]
            },
            
            # LLM09: Overreliance
            "hallucination": {
                "category": OWASPLLMCategory.LLM09_OVERRELIANCE,
                "name": "Overreliance",
                "description": "Uncritical acceptance of LLM outputs",
                "impact": "Misinformation, incorrect decisions, security vulnerabilities",
                "prevention": [
                    "Implement output verification",
                    "Use human oversight",
                    "Cross-reference with trusted sources"
                ]
            },
            
            # LLM10: Model Theft
            "model_extraction": {
                "category": OWASPLLMCategory.LLM10_MODEL_THEFT,
                "name": "Model Theft",
                "description": "Unauthorized access to proprietary models",
                "impact": "IP theft, competitive disadvantage, privacy violations",
                "prevention": [
                    "Implement API rate limiting",
                    "Monitor query patterns",
                    "Use model watermarking"
                ]
            },
            "model_inversion": {
                "category": OWASPLLMCategory.LLM10_MODEL_THEFT,
                "name": "Model Theft (Inversion)",
                "description": "Extract training data through model queries",
                "impact": "Training data exposure, privacy violations",
                "prevention": [
                    "Apply differential privacy",
                    "Implement query monitoring",
                    "Use output filtering"
                ]
            },
        }

    def map_finding(self, finding: Dict) -> Dict:
        """
        Maps single finding to OWASP LLM Top 10 category.

        Args:
            finding: Finding dictionary with 'family' field

        Returns:
            dict: OWASP mapping with category details

        Raises:
            ValueError: If finding format is invalid
        """
        if not isinstance(finding, dict):
            raise ValueError("Finding must be a dictionary")
        
        family = finding.get("family", "unknown")
        
        # Get category mapping
        category_info = self.category_map.get(family)
        
        if not category_info:
            logger.warning(f"No OWASP LLM mapping for finding family: {family}")
            return {
                "category": "UNMAPPED",
                "category_name": "Unmapped Category",
                "description": f"No OWASP LLM mapping available for {family}",
                "impact": "Unknown",
                "prevention": []
            }
        
        # Build mapping result
        mapping = {
            "finding_id": finding.get("id"),
            "finding_family": family,
            "category": category_info["category"].value,
            "category_name": category_info["name"],
            "description": category_info["description"],
            "impact": category_info["impact"],
            "prevention": category_info["prevention"],
            "severity": finding.get("severity", "unknown"),
            "cvss_score": finding.get("cvss_score"),
        }
        
        logger.debug(f"Mapped {family} to {category_info['category'].value}")
        return mapping

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Maps multiple findings to OWASP LLM categories.

        Args:
            findings: List of finding dictionaries

        Returns:
            list: List of OWASP mappings
        """
        mappings = []
        
        for finding in findings:
            try:
                mapping = self.map_finding(finding)
                mappings.append(mapping)
            except Exception as e:
                logger.error(f"Failed to map finding: {e}")
                continue
        
        logger.info(f"Mapped {len(mappings)} findings to OWASP LLM categories")
        return mappings

    def get_top10_summary(self, findings: List[Dict]) -> Dict:
        """
        Generates OWASP LLM Top 10 summary for campaign findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Summary with counts per category
        """
        mappings = self.map_findings(findings)
        
        # Initialize all categories with zero count
        summary = {}
        for category in OWASPLLMCategory:
            summary[category.value] = {
                "count": 0,
                "findings": [],
                "max_severity": "info"
            }
        
        # Count findings per category
        for mapping in mappings:
            category = mapping["category"]
            
            if category in summary:
                summary[category]["count"] += 1
                summary[category]["findings"].append(mapping["finding_id"])
                
                # Track highest severity
                current_severity = summary[category]["max_severity"]
                new_severity = mapping.get("severity", "info")
                if self._severity_rank(new_severity) > self._severity_rank(current_severity):
                    summary[category]["max_severity"] = new_severity
        
        # Sort by count (descending)
        sorted_summary = dict(sorted(
            summary.items(),
            key=lambda x: x[1]["count"],
            reverse=True
        ))
        
        logger.info(f"Generated OWASP LLM Top 10 summary")
        return sorted_summary

    def _severity_rank(self, severity: str) -> int:
        """Returns numeric rank for severity comparison."""
        ranks = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "info": 0
        }
        return ranks.get(severity.lower(), 0)

    def get_coverage_report(self, findings: List[Dict]) -> Dict:
        """
        Generates coverage report showing which OWASP categories were tested.

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Coverage report with tested/untested categories
        """
        summary = self.get_top10_summary(findings)
        
        tested_categories = [cat for cat, data in summary.items() if data["count"] > 0]
        untested_categories = [cat for cat, data in summary.items() if data["count"] == 0]
        
        coverage = {
            "total_categories": len(OWASPLLMCategory),
            "tested_categories": len(tested_categories),
            "untested_categories": len(untested_categories),
            "coverage_percentage": (len(tested_categories) / len(OWASPLLMCategory)) * 100,
            "tested": tested_categories,
            "untested": untested_categories
        }
        
        logger.info(f"OWASP LLM coverage: {coverage['coverage_percentage']:.1f}%")
        return coverage


logger.info("OWASP LLM mapper module loaded")
