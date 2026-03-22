"""
Agentic OWASP mapper.

Maps llmrt findings to Agentic OWASP security framework for AI agents.
Focuses on agent-specific vulnerabilities and attack patterns.

References:
- Agentic OWASP framework (emerging standard for AI agent security)
- Agent-specific threat modeling

Usage:
    mapper = AgenticOWASPMapper()
    mappings = mapper.map_finding(finding)
    agent_risks = mapper.get_agent_risk_profile(findings_list)
"""

import logging
from typing import List, Dict, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class AgenticOWASPCategory(Enum):
    """Agentic OWASP vulnerability categories for AI agents."""
    A01_AGENT_PROMPT_INJECTION = "A01"
    A02_TOOL_MANIPULATION = "A02"
    A03_MEMORY_POISONING = "A03"
    A04_EXCESSIVE_AUTONOMY = "A04"
    A05_CROSS_AGENT_CONTAMINATION = "A05"
    A06_AGENT_IDENTITY_SPOOFING = "A06"
    A07_INSECURE_AGENT_COMMUNICATION = "A07"
    A08_AGENT_RESOURCE_EXHAUSTION = "A08"
    A09_AGENT_GOAL_HIJACKING = "A09"
    A10_AGENT_CHAIN_VULNERABILITIES = "A10"


class AgenticOWASPMapper:
    """
    Maps llmrt findings to Agentic OWASP categories.

    Provides agent-specific vulnerability categorization for
    multi-agent systems and autonomous AI agents.
    """

    def __init__(self):
        """Initializes Agentic OWASP mapper."""
        self.category_map = self._build_category_map()
        logger.info("Agentic OWASP mapper initialized")

    def _build_category_map(self) -> Dict:
        """
        Builds mapping from finding families to Agentic OWASP categories.

        Returns:
            dict: Mapping of finding families to Agentic categories
        """
        return {
            # A01: Agent Prompt Injection
            "prompt_injection": {
                "category": AgenticOWASPCategory.A01_AGENT_PROMPT_INJECTION,
                "name": "Agent Prompt Injection",
                "description": "Malicious prompts that hijack agent behavior",
                "agent_impact": "Agent performs unintended actions, goal deviation",
                "prevention": [
                    "Implement agent instruction hierarchy",
                    "Use prompt isolation per agent",
                    "Apply agent-level input validation"
                ]
            },
            "indirect_prompt_injection": {
                "category": AgenticOWASPCategory.A01_AGENT_PROMPT_INJECTION,
                "name": "Agent Prompt Injection (Indirect)",
                "description": "Injection via agent's external data sources",
                "agent_impact": "Agent contamination through environment",
                "prevention": [
                    "Sanitize agent inputs from external sources",
                    "Implement source trust levels",
                    "Use agent sandboxing"
                ]
            },
            
            # A02: Tool Manipulation
            "mcp_tool_injection": {
                "category": AgenticOWASPCategory.A02_TOOL_MANIPULATION,
                "name": "Tool Manipulation",
                "description": "Malicious manipulation of agent tools",
                "agent_impact": "Agent uses tools incorrectly or maliciously",
                "prevention": [
                    "Validate tool inputs at agent level",
                    "Implement tool permission boundaries",
                    "Monitor tool usage patterns"
                ]
            },
            "tool_name_spoof": {
                "category": AgenticOWASPCategory.A02_TOOL_MANIPULATION,
                "name": "Tool Manipulation (Spoofing)",
                "description": "Agent deceived by fake tool names/descriptions",
                "agent_impact": "Agent calls wrong tools, incorrect actions",
                "prevention": [
                    "Verify tool signatures",
                    "Use tool allowlisting",
                    "Implement tool verification"
                ]
            },
            "mcp_rug_pull": {
                "category": AgenticOWASPCategory.A02_TOOL_MANIPULATION,
                "name": "Tool Manipulation (Rug Pull)",
                "description": "Tool behavior changes after agent trusts it",
                "agent_impact": "Agent compromised by malicious tool update",
                "prevention": [
                    "Monitor tool behavior changes",
                    "Implement tool versioning",
                    "Use rollback capability"
                ]
            },
            
            # A03: Memory Poisoning
            "agent_memory_attack": {
                "category": AgenticOWASPCategory.A03_MEMORY_POISONING,
                "name": "Memory Poisoning",
                "description": "Malicious data injected into agent memory",
                "agent_impact": "Agent behavior permanently altered",
                "prevention": [
                    "Validate memory writes",
                    "Implement memory integrity checks",
                    "Use memory sandboxing"
                ]
            },
            "rag_poisoning": {
                "category": AgenticOWASPCategory.A03_MEMORY_POISONING,
                "name": "Memory Poisoning (RAG)",
                "description": "Poisoning agent's knowledge base",
                "agent_impact": "Agent retrieves and uses malicious information",
                "prevention": [
                    "Validate knowledge base sources",
                    "Implement content verification",
                    "Monitor retrieval patterns"
                ]
            },
            
            # A04: Excessive Autonomy
            "mcp_privilege_escalation": {
                "category": AgenticOWASPCategory.A04_EXCESSIVE_AUTONOMY,
                "name": "Excessive Autonomy",
                "description": "Agent has too much decision-making power",
                "agent_impact": "Agent performs high-risk actions without oversight",
                "prevention": [
                    "Implement human-in-the-loop for critical actions",
                    "Define agent authority boundaries",
                    "Use approval workflows"
                ]
            },
            "unauthorized_action": {
                "category": AgenticOWASPCategory.A04_EXCESSIVE_AUTONOMY,
                "name": "Excessive Autonomy (Unauthorized Action)",
                "description": "Agent exceeds intended scope of actions",
                "agent_impact": "Unintended system modifications, data changes",
                "prevention": [
                    "Define clear action boundaries",
                    "Implement action logging",
                    "Use permission checks"
                ]
            },
            
            # A05: Cross-Agent Contamination
            "cross_tenant_leak": {
                "category": AgenticOWASPCategory.A05_CROSS_AGENT_CONTAMINATION,
                "name": "Cross-Agent Contamination",
                "description": "Information leaks between agents",
                "agent_impact": "Agent A accesses agent B's data/context",
                "prevention": [
                    "Implement agent isolation",
                    "Use separate memory spaces",
                    "Apply tenant boundaries"
                ]
            },
            "context_bleeding": {
                "category": AgenticOWASPCategory.A05_CROSS_AGENT_CONTAMINATION,
                "name": "Cross-Agent Contamination (Context Bleeding)",
                "description": "Context leaks between agent sessions",
                "agent_impact": "Agent exposes previous session data",
                "prevention": [
                    "Clear context between sessions",
                    "Implement context isolation",
                    "Use session boundaries"
                ]
            },
            
            # A06: Agent Identity Spoofing
            "agent_impersonation": {
                "category": AgenticOWASPCategory.A06_AGENT_IDENTITY_SPOOFING,
                "name": "Agent Identity Spoofing",
                "description": "Attacker impersonates legitimate agent",
                "agent_impact": "Unauthorized actions performed as trusted agent",
                "prevention": [
                    "Implement agent authentication",
                    "Use agent identity verification",
                    "Apply cryptographic signatures"
                ]
            },
            
            # A07: Insecure Agent Communication
            "mcp_mitm": {
                "category": AgenticOWASPCategory.A07_INSECURE_AGENT_COMMUNICATION,
                "name": "Insecure Agent Communication",
                "description": "Unencrypted or unauthenticated agent-to-agent communication",
                "agent_impact": "Message interception, tampering, replay attacks",
                "prevention": [
                    "Use TLS for agent communication",
                    "Implement message authentication",
                    "Apply message encryption"
                ]
            },
            
            # A08: Agent Resource Exhaustion
            "resource_exhaustion": {
                "category": AgenticOWASPCategory.A08_AGENT_RESOURCE_EXHAUSTION,
                "name": "Agent Resource Exhaustion",
                "description": "Agent consumes excessive resources",
                "agent_impact": "Agent unavailability, cost escalation",
                "prevention": [
                    "Implement resource quotas per agent",
                    "Monitor agent resource usage",
                    "Use circuit breakers"
                ]
            },
            "infinite_loop": {
                "category": AgenticOWASPCategory.A08_AGENT_RESOURCE_EXHAUSTION,
                "name": "Agent Resource Exhaustion (Infinite Loop)",
                "description": "Agent stuck in infinite reasoning loop",
                "agent_impact": "Agent hangs, resource exhaustion",
                "prevention": [
                    "Implement iteration limits",
                    "Use timeout mechanisms",
                    "Monitor agent execution time"
                ]
            },
            
            # A09: Agent Goal Hijacking
            "goal_manipulation": {
                "category": AgenticOWASPCategory.A09_AGENT_GOAL_HIJACKING,
                "name": "Agent Goal Hijacking",
                "description": "Attacker changes agent's goals or objectives",
                "agent_impact": "Agent pursues malicious objectives",
                "prevention": [
                    "Protect goal definitions",
                    "Implement goal verification",
                    "Monitor goal changes"
                ]
            },
            "reward_hacking": {
                "category": AgenticOWASPCategory.A09_AGENT_GOAL_HIJACKING,
                "name": "Agent Goal Hijacking (Reward Hacking)",
                "description": "Agent exploits reward function",
                "agent_impact": "Agent optimizes for wrong objectives",
                "prevention": [
                    "Design robust reward functions",
                    "Implement reward monitoring",
                    "Use multi-objective optimization"
                ]
            },
            
            # A10: Agent Chain Vulnerabilities
            "chain_injection": {
                "category": AgenticOWASPCategory.A10_AGENT_CHAIN_VULNERABILITIES,
                "name": "Agent Chain Vulnerabilities",
                "description": "Vulnerabilities in multi-agent workflows",
                "agent_impact": "Cascade failures, chain compromise",
                "prevention": [
                    "Validate data between agents",
                    "Implement chain isolation",
                    "Use error handling"
                ]
            },
            "cross_tool_orchestration": {
                "category": AgenticOWASPCategory.A10_AGENT_CHAIN_VULNERABILITIES,
                "name": "Agent Chain Vulnerabilities (Orchestration)",
                "description": "Malicious orchestration of agent tool calls",
                "agent_impact": "Complex multi-step attacks through agent chain",
                "prevention": [
                    "Monitor tool call sequences",
                    "Implement orchestration limits",
                    "Use anomaly detection"
                ]
            },
        }

    def map_finding(self, finding: Dict) -> Dict:
        """
        Maps single finding to Agentic OWASP category.

        Args:
            finding: Finding dictionary with 'family' field

        Returns:
            dict: Agentic OWASP mapping with category details

        Raises:
            ValueError: If finding format is invalid
        """
        if not isinstance(finding, dict):
            raise ValueError("Finding must be a dictionary")
        
        family = finding.get("family", "unknown")
        
        # Get category mapping
        category_info = self.category_map.get(family)
        
        if not category_info:
            logger.warning(f"No Agentic OWASP mapping for finding family: {family}")
            return {
                "category": "UNMAPPED",
                "category_name": "Unmapped Category",
                "description": f"No Agentic OWASP mapping available for {family}",
                "agent_impact": "Unknown",
                "prevention": []
            }
        
        # Build mapping result
        mapping = {
            "finding_id": finding.get("id"),
            "finding_family": family,
            "category": category_info["category"].value,
            "category_name": category_info["name"],
            "description": category_info["description"],
            "agent_impact": category_info["agent_impact"],
            "prevention": category_info["prevention"],
            "severity": finding.get("severity", "unknown"),
            "cvss_score": finding.get("cvss_score"),
        }
        
        logger.debug(f"Mapped {family} to {category_info['category'].value}")
        return mapping

    def map_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Maps multiple findings to Agentic OWASP categories.

        Args:
            findings: List of finding dictionaries

        Returns:
            list: List of Agentic OWASP mappings
        """
        mappings = []
        
        for finding in findings:
            try:
                mapping = self.map_finding(finding)
                mappings.append(mapping)
            except Exception as e:
                logger.error(f"Failed to map finding: {e}")
                continue
        
        logger.info(f"Mapped {len(mappings)} findings to Agentic OWASP categories")
        return mappings

    def get_agent_risk_profile(self, findings: List[Dict]) -> Dict:
        """
        Generates agent-specific risk profile.

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Agent risk profile with category breakdown
        """
        mappings = self.map_findings(findings)
        
        # Initialize all categories
        profile = {}
        for category in AgenticOWASPCategory:
            profile[category.value] = {
                "count": 0,
                "findings": [],
                "max_severity": "info",
                "risk_level": "low"
            }
        
        # Count findings per category
        for mapping in mappings:
            category = mapping["category"]
            
            if category in profile:
                profile[category]["count"] += 1
                profile[category]["findings"].append(mapping["finding_id"])
                
                # Track highest severity
                current_severity = profile[category]["max_severity"]
                new_severity = mapping.get("severity", "info")
                if self._severity_rank(new_severity) > self._severity_rank(current_severity):
                    profile[category]["max_severity"] = new_severity
                
                # Calculate risk level
                profile[category]["risk_level"] = self._calculate_risk_level(
                    profile[category]["count"],
                    profile[category]["max_severity"]
                )
        
        logger.info("Generated agent risk profile")
        return profile

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

    def _calculate_risk_level(self, count: int, max_severity: str) -> str:
        """Calculates overall risk level based on count and severity."""
        severity_rank = self._severity_rank(max_severity)
        
        if count == 0:
            return "none"
        elif count >= 5 and severity_rank >= 3:
            return "critical"
        elif count >= 3 and severity_rank >= 2:
            return "high"
        elif count >= 1 and severity_rank >= 1:
            return "medium"
        else:
            return "low"

    def get_agent_security_score(self, findings: List[Dict]) -> Dict:
        """
        Calculates agent security score (0-100).

        Args:
            findings: List of finding dictionaries

        Returns:
            dict: Security score with breakdown
        """
        profile = self.get_agent_risk_profile(findings)
        
        # Calculate score based on findings
        total_score = 100
        
        for category, data in profile.items():
            count = data["count"]
            severity = data["max_severity"]
            
            # Deduct points based on severity and count
            if severity == "critical":
                total_score -= count * 10
            elif severity == "high":
                total_score -= count * 5
            elif severity == "medium":
                total_score -= count * 2
            elif severity == "low":
                total_score -= count * 1
        
        # Ensure score doesn't go below 0
        total_score = max(0, total_score)
        
        # Determine grade
        if total_score >= 90:
            grade = "A"
        elif total_score >= 80:
            grade = "B"
        elif total_score >= 70:
            grade = "C"
        elif total_score >= 60:
            grade = "D"
        else:
            grade = "F"
        
        return {
            "score": total_score,
            "grade": grade,
            "total_findings": len(findings),
            "categories_affected": sum(1 for data in profile.values() if data["count"] > 0)
        }


logger.info("Agentic OWASP mapper module loaded")
