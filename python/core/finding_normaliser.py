"""
Finding normaliser — maps attack-specific findings to standardised families.

FAMILY_MAP provides a unified taxonomy for all findings, enabling
consistent reporting and deduplication across different attack types.
"""

from enum import Enum
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class FindingFamily(Enum):
    """Standardised finding families."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    PII_LEAKAGE = "pii_leakage"
    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    RCE = "rce"
    SSRF = "ssrf"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    
    # RAG-specific
    RAG_POISONING = "rag_poisoning"
    CONTEXT_INJECTION = "context_injection"
    MEMORY_POISONING = "memory_poisoning"
    
    # MCP-specific
    MCP_TOOL_ABUSE = "mcp_tool_abuse"
    MCP_RUG_PULL = "mcp_rug_pull"
    MCP_SAMPLING_ABUSE = "mcp_sampling_abuse"
    MCP_OAUTH_ABUSE = "mcp_oauth_abuse"
    MCP_SESSION_HIJACK = "mcp_session_hijack"
    
    # Configuration issues
    EXPOSED_SERVICE = "exposed_service"
    WEAK_AUTH = "weak_auth"
    MISCONFIGURATION = "misconfiguration"
    
    # Generic
    INFORMATION_DISCLOSURE = "information_disclosure"
    UNKNOWN = "unknown"


# FAMILY_MAP: Maps attack types to finding families
FAMILY_MAP: Dict[str, FindingFamily] = {
    # Prompt attacks
    "chatinject": FindingFamily.PROMPT_INJECTION,
    "flipattack": FindingFamily.JAILBREAK,
    "unicode_injection": FindingFamily.PROMPT_INJECTION,
    "adversarial_poetry": FindingFamily.JAILBREAK,
    "multilingual": FindingFamily.JAILBREAK,
    
    # Code execution
    "rce_probe": FindingFamily.RCE,
    "code_execution": FindingFamily.RCE,
    
    # Injection attacks
    "sql_injection": FindingFamily.SQL_INJECTION,
    "generic_sqli": FindingFamily.SQL_INJECTION,
    "readonly_bypass": FindingFamily.SQL_INJECTION,
    "ssrf": FindingFamily.SSRF,
    "xss": FindingFamily.XSS,
    
    # Access control
    "idor": FindingFamily.IDOR,
    "auth_bypass": FindingFamily.AUTH_BYPASS,
    "path_traversal": FindingFamily.PATH_TRAVERSAL,
    
    # Information disclosure
    "system_prompt_leak": FindingFamily.SYSTEM_PROMPT_LEAK,
    "pii_leakage": FindingFamily.PII_LEAKAGE,
    "information_disclosure": FindingFamily.INFORMATION_DISCLOSURE,
    
    # RAG attacks
    "rag_poisoning": FindingFamily.RAG_POISONING,
    "doc_injection": FindingFamily.RAG_POISONING,
    "context_injection": FindingFamily.CONTEXT_INJECTION,
    "memory_poisoning": FindingFamily.MEMORY_POISONING,
    
    # MCP attacks
    "rug_pull": FindingFamily.MCP_RUG_PULL,
    "mcp_tool_abuse": FindingFamily.MCP_TOOL_ABUSE,
    "mcp_sampling": FindingFamily.MCP_SAMPLING_ABUSE,
    "mcp_oauth": FindingFamily.MCP_OAUTH_ABUSE,
    "mcp_session": FindingFamily.MCP_SESSION_HIJACK,
    
    # Configuration
    "exposed_service": FindingFamily.EXPOSED_SERVICE,
    "weak_auth": FindingFamily.WEAK_AUTH,
    "misconfiguration": FindingFamily.MISCONFIGURATION,
}


def normalise_finding(attack_type: str, finding_type: str) -> FindingFamily:
    """
    Normalise a finding to a standard family.
    
    Args:
        attack_type: Type of attack that generated the finding
        finding_type: Specific finding type
        
    Returns:
        FindingFamily: Normalised finding family
    """
    # Try attack_type first
    if attack_type in FAMILY_MAP:
        return FAMILY_MAP[attack_type]
    
    # Try finding_type
    if finding_type in FAMILY_MAP:
        return FAMILY_MAP[finding_type]
    
    # Try lowercase versions
    attack_lower = attack_type.lower()
    finding_lower = finding_type.lower()
    
    if attack_lower in FAMILY_MAP:
        return FAMILY_MAP[attack_lower]
    
    if finding_lower in FAMILY_MAP:
        return FAMILY_MAP[finding_lower]
    
    # Unknown
    logger.warning(f"Unknown finding type: attack={attack_type}, finding={finding_type}")
    return FindingFamily.UNKNOWN


def get_family_severity(family: FindingFamily) -> str:
    """
    Get default severity for a finding family.
    
    Args:
        family: Finding family
        
    Returns:
        str: Severity level (critical, high, medium, low, info)
    """
    severity_map = {
        FindingFamily.RCE: "critical",
        FindingFamily.SQL_INJECTION: "critical",
        FindingFamily.AUTH_BYPASS: "critical",
        
        FindingFamily.SSRF: "high",
        FindingFamily.XSS: "high",
        FindingFamily.IDOR: "high",
        FindingFamily.SYSTEM_PROMPT_LEAK: "high",
        FindingFamily.MCP_RUG_PULL: "high",
        FindingFamily.MCP_OAUTH_ABUSE: "high",
        
        FindingFamily.PROMPT_INJECTION: "medium",
        FindingFamily.JAILBREAK: "medium",
        FindingFamily.PATH_TRAVERSAL: "medium",
        FindingFamily.RAG_POISONING: "medium",
        FindingFamily.MCP_TOOL_ABUSE: "medium",
        
        FindingFamily.PII_LEAKAGE: "low",
        FindingFamily.INFORMATION_DISCLOSURE: "low",
        FindingFamily.WEAK_AUTH: "low",
        
        FindingFamily.EXPOSED_SERVICE: "info",
        FindingFamily.MISCONFIGURATION: "info",
        FindingFamily.UNKNOWN: "info",
    }
    
    return severity_map.get(family, "medium")


def get_family_description(family: FindingFamily) -> str:
    """
    Get human-readable description for a finding family.
    
    Args:
        family: Finding family
        
    Returns:
        str: Description
    """
    descriptions = {
        FindingFamily.PROMPT_INJECTION: "Prompt injection vulnerability allowing attacker to manipulate model behavior",
        FindingFamily.JAILBREAK: "Jailbreak technique bypassing model safety guardrails",
        FindingFamily.RCE: "Remote code execution vulnerability",
        FindingFamily.SQL_INJECTION: "SQL injection vulnerability in database queries",
        FindingFamily.SSRF: "Server-side request forgery allowing internal network access",
        FindingFamily.XSS: "Cross-site scripting vulnerability",
        FindingFamily.IDOR: "Insecure direct object reference allowing unauthorized access",
        FindingFamily.AUTH_BYPASS: "Authentication bypass vulnerability",
        FindingFamily.PATH_TRAVERSAL: "Path traversal vulnerability allowing file system access",
        FindingFamily.SYSTEM_PROMPT_LEAK: "System prompt disclosure revealing internal instructions",
        FindingFamily.PII_LEAKAGE: "Personally identifiable information leakage",
        FindingFamily.RAG_POISONING: "RAG poisoning attack injecting malicious documents",
        FindingFamily.CONTEXT_INJECTION: "Context injection manipulating retrieval results",
        FindingFamily.MEMORY_POISONING: "Memory poisoning attack corrupting conversation history",
        FindingFamily.MCP_RUG_PULL: "MCP rug pull attack with tool description changes",
        FindingFamily.MCP_TOOL_ABUSE: "MCP tool abuse through malicious parameters",
        FindingFamily.MCP_SAMPLING_ABUSE: "MCP sampling capability abuse",
        FindingFamily.MCP_OAUTH_ABUSE: "MCP OAuth flow abuse",
        FindingFamily.MCP_SESSION_HIJACK: "MCP session hijacking",
        FindingFamily.EXPOSED_SERVICE: "Service exposed to network without proper protection",
        FindingFamily.WEAK_AUTH: "Weak or missing authentication",
        FindingFamily.MISCONFIGURATION: "Security misconfiguration",
        FindingFamily.INFORMATION_DISCLOSURE: "Information disclosure vulnerability",
        FindingFamily.UNKNOWN: "Unknown vulnerability type",
    }
    
    return descriptions.get(family, "Unknown vulnerability")


def get_family_remediation(family: FindingFamily) -> str:
    """
    Get remediation guidance for a finding family.
    
    Args:
        family: Finding family
        
    Returns:
        str: Remediation guidance
    """
    remediations = {
        FindingFamily.PROMPT_INJECTION: "Implement input validation, use structured outputs, apply prompt hardening techniques",
        FindingFamily.JAILBREAK: "Strengthen safety guardrails, implement multi-layer filtering, use constitutional AI",
        FindingFamily.RCE: "Disable code execution, sandbox execution environment, validate all inputs",
        FindingFamily.SQL_INJECTION: "Use parameterized queries, implement input validation, apply least privilege",
        FindingFamily.SSRF: "Validate and whitelist URLs, implement network segmentation, use egress filtering",
        FindingFamily.MCP_RUG_PULL: "Implement tool description versioning, monitor for changes, use tool signing",
        FindingFamily.RAG_POISONING: "Validate document sources, implement content filtering, use trusted document stores",
        FindingFamily.EXPOSED_SERVICE: "Bind services to localhost, implement firewall rules, use VPN/bastion",
    }
    
    return remediations.get(family, "Review security best practices for this vulnerability type")


def get_owasp_mapping(family: FindingFamily) -> Optional[str]:
    """
    Map finding family to OWASP LLM Top 10 category.
    
    Args:
        family: Finding family
        
    Returns:
        str: OWASP LLM category, or None
    """
    owasp_map = {
        FindingFamily.PROMPT_INJECTION: "LLM01:2025 Prompt Injection",
        FindingFamily.JAILBREAK: "LLM01:2025 Prompt Injection",
        FindingFamily.SYSTEM_PROMPT_LEAK: "LLM06:2025 Sensitive Information Disclosure",
        FindingFamily.PII_LEAKAGE: "LLM06:2025 Sensitive Information Disclosure",
        FindingFamily.RAG_POISONING: "LLM03:2025 Training Data Poisoning",
        FindingFamily.RCE: "LLM07:2025 Insecure Plugin Design",
        FindingFamily.SSRF: "LLM07:2025 Insecure Plugin Design",
        FindingFamily.AUTH_BYPASS: "LLM08:2025 Excessive Agency",
        FindingFamily.WEAK_AUTH: "LLM08:2025 Excessive Agency",
    }
    
    return owasp_map.get(family)
