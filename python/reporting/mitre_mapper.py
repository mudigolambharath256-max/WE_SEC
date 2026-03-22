"""
MITRE ATT&CK for LLMs mapper.

Maps llmrt findings to MITRE ATT&CK framework tactics and techniques
specifically adapted for LLM applications. Provides standardized
threat categorization and attack pattern identification.

References:
- MITRE ATLAS (Adversarial Threat Landscape for AI Systems)
- MITRE ATT&CK for Enterprise (adapted for LLM context)

Usage:
    mapper = MITREMapper()
    mappings = mapper.map_finding(finding)
    tactics = mapper.get_tactics_for_campaign(findings_list)
"""

import logging
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class MITRETactic(Enum):
    """MITRE ATT&CK tactics adapted for LLM applications."""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    ML_MODEL_ACCESS = "ml_model_access"  # ATLAS-specific


class MITREMapper:
    """
    Maps llmrt findings to MITRE ATT&CK framework.

    Provides standardized threat categorization using MITRE ATT&CK
    tactics and techniques adapted for LLM security context.
    """

    def __init__(self):
        """Initializes MITRE mapper with technique database."""
        self.technique_map = self._build_technique_map()
        logger.info("MITRE mapper initialized with technique database")

    def _build_technique_map(self) -> Dict:
        """
        Builds mapping from finding families to MITRE techniques.

        Returns:
            dict: Mapping of finding families to MITRE techniques

        Note:
            Techniques are based on MITRE ATLAS and ATT&CK frameworks
            adapted for LLM application security context.
        """
        return {
            # Prompt Injection
            "prompt_injection": {
                "technique_id": "AML.T0051",
                "technique_name": "LLM Prompt Injection",
                "tactic": MITRETactic.INITIAL_ACCESS,
                "description": "Adversary crafts malicious prompts to manipulate LLM behavior",
                "mitigations": ["Input validation", "Prompt filtering", "Output sanitization"]
            },
            "indirect_prompt_injection": {
                "technique_id": "AML.T0051.001",
                "technique_name": "Indirect Prompt Injection",
                "tactic": MITRETactic.INITIAL_ACCESS,
                "description": "Injection via external data sources (documents, web pages)",
                "mitigations": ["Content sanitization", "Source validation", "Sandboxing"]
            },
            
            # Code Execution
            "rce": {
                "technique_id": "T1059",
                "technique_name": "Command and Scripting Interpreter",
                "tactic": MITRETactic.EXECUTION,
                "description": "Adversary executes arbitrary code through LLM",
                "mitigations": ["Disable code execution", "Sandboxing", "Least privilege"]
            },
            "llmsmith_rce": {
                "technique_id": "T1059.006",
                "technique_name": "Python Interpreter Abuse",
                "tactic": MITRETactic.EXECUTION,
                "description": "LLM executes malicious Python code",
                "mitigations": ["Disable Python execution", "Code review", "Sandboxing"]
            },
            
            # Data Exfiltration
            "oob_exfil": {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": MITRETactic.EXFILTRATION,
                "description": "Data exfiltration via out-of-band channels",
                "mitigations": ["Network monitoring", "Egress filtering", "DNS monitoring"]
            },
            "pii_leak": {
                "technique_id": "T1530",
                "technique_name": "Data from Cloud Storage",
                "tactic": MITRETactic.COLLECTION,
                "description": "Unauthorized access to sensitive data via LLM",
                "mitigations": ["Access controls", "Data classification", "Encryption"]
            },
            
            # Model Manipulation
            "model_inversion": {
                "technique_id": "AML.T0043",
                "technique_name": "Model Inversion",
                "tactic": MITRETactic.ML_MODEL_ACCESS,
                "description": "Extract training data through model queries",
                "mitigations": ["Query rate limiting", "Differential privacy", "Output filtering"]
            },
            "model_extraction": {
                "technique_id": "AML.T0024",
                "technique_name": "Exfiltration via ML Inference API",
                "tactic": MITRETactic.EXFILTRATION,
                "description": "Steal model weights through API queries",
                "mitigations": ["API rate limiting", "Query monitoring", "Watermarking"]
            },
            
            # Jailbreak
            "jailbreak": {
                "technique_id": "AML.T0054",
                "technique_name": "LLM Jailbreak",
                "tactic": MITRETactic.DEFENSE_EVASION,
                "description": "Bypass safety guardrails and content filters",
                "mitigations": ["Multi-layer filtering", "Adversarial training", "Output validation"]
            },
            "role_play_jailbreak": {
                "technique_id": "AML.T0054.001",
                "technique_name": "Role-Play Jailbreak",
                "tactic": MITRETactic.DEFENSE_EVASION,
                "description": "Use role-playing scenarios to bypass restrictions",
                "mitigations": ["Context-aware filtering", "Instruction hierarchy", "Refusal training"]
            },
            
            # RAG Attacks
            "rag_poisoning": {
                "technique_id": "AML.T0020",
                "technique_name": "Poison Training Data",
                "tactic": MITRETactic.RESOURCE_DEVELOPMENT,
                "description": "Inject malicious content into RAG knowledge base",
                "mitigations": ["Content validation", "Source verification", "Sandboxing"]
            },
            "context_manipulation": {
                "technique_id": "AML.T0018",
                "technique_name": "Backdoor ML Model",
                "tactic": MITRETactic.PERSISTENCE,
                "description": "Manipulate retrieval context to influence outputs",
                "mitigations": ["Context validation", "Retrieval monitoring", "Output verification"]
            },
            
            # MCP Attacks
            "mcp_tool_injection": {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": MITRETactic.INITIAL_ACCESS,
                "description": "Exploit vulnerabilities in MCP tool implementations",
                "mitigations": ["Input validation", "Least privilege", "Tool sandboxing"]
            },
            "mcp_privilege_escalation": {
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "tactic": MITRETactic.PRIVILEGE_ESCALATION,
                "description": "Escalate privileges through MCP tool chain",
                "mitigations": ["Permission boundaries", "Tool isolation", "Audit logging"]
            },
            "mcp_rug_pull": {
                "technique_id": "T1195.002",
                "technique_name": "Compromise Software Supply Chain",
                "tactic": MITRETactic.INITIAL_ACCESS,
                "description": "Malicious MCP tool update (rug pull attack)",
                "mitigations": ["Tool verification", "Update monitoring", "Rollback capability"]
            },
            
            # SQL Injection
            "sql_injection": {
                "technique_id": "T1190.001",
                "technique_name": "SQL Injection",
                "tactic": MITRETactic.INITIAL_ACCESS,
                "description": "SQL injection through LLM-generated queries",
                "mitigations": ["Parameterized queries", "Input validation", "Least privilege"]
            },
            
            # SSRF
            "ssrf": {
                "technique_id": "T1090",
                "technique_name": "Proxy",
                "tactic": MITRETactic.COMMAND_AND_CONTROL,
                "description": "Server-side request forgery via LLM",
                "mitigations": ["URL validation", "Network segmentation", "Allowlisting"]
            },
            
            # Information Disclosure
            "system_prompt_leak": {
                "technique_id": "T1592",
                "technique_name": "Gather Victim Host Information",
                "tactic": MITRETactic.RECONNAISSANCE,
                "description": "Extract system prompts and instructions",
                "mitigations": ["Prompt protection", "Output filtering", "Instruction hierarchy"]
            },
            "training_data_leak": {
                "technique_id": "T1213",
                "technique_name": "Data from Information Repositories",
                "tactic": MITRETactic.COLLECTION,
                "description": "Extract training data through targeted queries",
                "mitigations": ["Differential privacy", "Output filtering", "Query monitoring"]
            },
            
            # Denial of Service
            "resource_exhaustion": {
                "technique_id": "T1499",
                "technique_name": "Endpoint Denial of Service",
                "tactic": MITRETactic.IMPACT,
                "description": "Exhaust LLM resources through expensive queries",
                "mitigations": ["Rate limiting", "Query complexity limits", "Resource quotas"]
            },
            
            # Unicode/Encoding Attacks
            "unicode_injection": {
                "technique_id": "T1027.010",
                "technique_name": "Command Obfuscation",
                "tactic": MITRETactic.DEFENSE_EVASION,
                "description": "Use unicode tricks to evade detection",
                "mitigations": ["Unicode normalization", "Character filtering", "Encoding validation"]
            },
        }

    def map_finding(self, finding: Dict) -> Dict:
        """
        Maps single finding to MITRE ATT&CK technique.

        Args:
            finding: Finding dictionary with 'family' field

        Returns:
            dict: MITRE mapping with technique details

        Raises:
            ValueError: If finding format is invalid
        """
        if not isinstance(finding, dict):
            raise ValueError("Finding must be a dictionary")
        
        family = finding.get("family", "unknown")
        
        # Get technique mapping
        technique = self.technique_map.get(family)
        
        if not technique:
            logger.warning(f"No MITRE mapping for finding family: {family}")
            return {
                "technique_id": "UNMAPPED",
                "technique_name": "Unmapped Technique",
                "tactic": MITRETactic.IMPACT.value,
                "description": f"No MITRE mapping available for {family}",
                "mitigations": []
            }
        
        # Build mapping result
        mapping = {
            "finding_id": finding.get("id"),
            "finding_family": family,
            "technique_id": technique["technique_id"],
            "technique_name": technique["technique_name"],
            "tactic": technique["tactic"].value,
            "description": technique["description"],
            "mitigations": technique["mitigations"],
            "severity": finding.get("severity", "unknown"),
            "cvss_score": finding.get("cvss_score"),
        }
        
        logger.debug(f"Mapped {family} to {technique['technique_id']}")
        return mapping

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Maps multiple findings to MITRE techniques.

        Args:
            findings: List of finding dictionaries

        Returns:
            list: List of MITRE mappings
        """
        mappings = []
        
        for finding in findings:
            try:
                mapping = self.map_finding(finding)
                mappings.append(mapping)
            except Exception as e:
                logger.error(f"Failed to map finding: {e}")
                continue
        
        logger.info(f"Mapped {len(mappings)} findings to MITRE techniques")
        return mappings

    def get_tactics_summary(self, findings: List[Dict]) -> Dict:
        """
        Generates tactics summary for campaign findings.

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Summary of tactics with counts and techniques
        """
        mappings = self.map_findings(findings)
        
        # Group by tactic
        tactics_summary = {}
        
        for mapping in mappings:
            tactic = mapping["tactic"]
            
            if tactic not in tactics_summary:
                tactics_summary[tactic] = {
                    "count": 0,
                    "techniques": [],
                    "findings": []
                }
            
            tactics_summary[tactic]["count"] += 1
            
            # Add technique if not already present
            technique_id = mapping["technique_id"]
            if technique_id not in [t["id"] for t in tactics_summary[tactic]["techniques"]]:
                tactics_summary[tactic]["techniques"].append({
                    "id": technique_id,
                    "name": mapping["technique_name"]
                })
            
            tactics_summary[tactic]["findings"].append(mapping["finding_id"])
        
        logger.info(f"Generated tactics summary with {len(tactics_summary)} tactics")
        return tactics_summary

    def get_attack_path(self, findings: List[Dict]) -> List[Dict]:
        """
        Constructs attack path from findings based on tactic order.

        Args:
            findings: List of finding dictionaries

        Returns:
            list: Ordered attack path with tactics and techniques
        """
        mappings = self.map_findings(findings)
        
        # Define tactic order (kill chain)
        tactic_order = [
            MITRETactic.RECONNAISSANCE,
            MITRETactic.RESOURCE_DEVELOPMENT,
            MITRETactic.INITIAL_ACCESS,
            MITRETactic.EXECUTION,
            MITRETactic.PERSISTENCE,
            MITRETactic.PRIVILEGE_ESCALATION,
            MITRETactic.DEFENSE_EVASION,
            MITRETactic.CREDENTIAL_ACCESS,
            MITRETactic.DISCOVERY,
            MITRETactic.LATERAL_MOVEMENT,
            MITRETactic.COLLECTION,
            MITRETactic.EXFILTRATION,
            MITRETactic.IMPACT,
            MITRETactic.ML_MODEL_ACCESS,
        ]
        
        # Group mappings by tactic
        tactic_groups = {}
        for mapping in mappings:
            tactic = mapping["tactic"]
            if tactic not in tactic_groups:
                tactic_groups[tactic] = []
            tactic_groups[tactic].append(mapping)
        
        # Build ordered attack path
        attack_path = []
        for tactic in tactic_order:
            tactic_value = tactic.value
            if tactic_value in tactic_groups:
                attack_path.append({
                    "tactic": tactic_value,
                    "tactic_name": tactic.name.replace("_", " ").title(),
                    "techniques": tactic_groups[tactic_value]
                })
        
        logger.info(f"Constructed attack path with {len(attack_path)} stages")
        return attack_path

    def export_mitre_navigator(self, findings: List[Dict], output_path: str):
        """
        Exports findings as MITRE ATT&CK Navigator layer.

        Args:
            output_path: Path to save Navigator JSON file
            findings: List of finding dictionaries

        Raises:
            RuntimeError: If export fails
        """
        import json
        from pathlib import Path
        
        logger.info(f"Exporting MITRE Navigator layer to {output_path}")
        
        try:
            mappings = self.map_findings(findings)
            
            # Build Navigator layer format
            techniques = []
            for mapping in mappings:
                techniques.append({
                    "techniqueID": mapping["technique_id"],
                    "tactic": mapping["tactic"],
                    "score": mapping.get("cvss_score", 5.0),
                    "color": self._get_severity_color(mapping.get("severity", "medium")),
                    "comment": mapping["description"],
                    "enabled": True
                })
            
            navigator_layer = {
                "name": "llmrt Campaign Findings",
                "versions": {
                    "attack": "13",
                    "navigator": "4.8.0",
                    "layer": "4.4"
                },
                "domain": "enterprise-attack",
                "description": f"MITRE ATT&CK mapping for llmrt campaign with {len(findings)} findings",
                "techniques": techniques,
                "gradient": {
                    "colors": ["#ff6666", "#ffe766", "#8ec843"],
                    "minValue": 0,
                    "maxValue": 10
                }
            }
            
            # Save to file
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, "w") as f:
                json.dump(navigator_layer, f, indent=2)
            
            logger.info(f"MITRE Navigator layer exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export Navigator layer: {e}")
            raise RuntimeError(f"Navigator export failed: {e}")

    def _get_severity_color(self, severity: str) -> str:
        """Maps severity to color for Navigator visualization."""
        color_map = {
            "critical": "#ff0000",
            "high": "#ff6666",
            "medium": "#ffcc00",
            "low": "#ffff99",
            "info": "#cccccc"
        }
        return color_map.get(severity.lower(), "#cccccc")


logger.info("MITRE mapper module loaded")
