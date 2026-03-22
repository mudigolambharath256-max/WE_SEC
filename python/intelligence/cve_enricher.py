"""
CVE enricher — enriches findings with CVE data and exploit availability.

Analyzes findings to identify potential CVE associations based on:
- Technology fingerprints (detected libraries, frameworks, versions)
- Vulnerability patterns (SQL injection, XSS, RCE, etc.)
- Error messages and stack traces
- Known vulnerability signatures

Enrichment process:
1. Extract technology identifiers from finding evidence
2. Query CVE cache for relevant CVEs
3. Match CVE descriptions against finding characteristics
4. Add CVE references to finding metadata
5. Flag findings with known exploits or KEV listing

This helps operators understand if a finding is a known vulnerability
with existing exploits or if it's a novel 0-day.
"""

import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

from .cve_cache import CVECache

logger = logging.getLogger(__name__)


@dataclass
class TechnologyFingerprint:
    """
    Represents a detected technology with version information.

    Attributes:
        name: Technology name (e.g., "flask", "django", "openai")
        version: Version string (e.g., "2.3.0")
        confidence: Detection confidence (0.0-1.0)
        source: Where this was detected (error_message, headers, response)
    """
    name: str
    version: Optional[str]
    confidence: float
    source: str


class CVEEnricher:
    """
    Enriches findings with CVE data and exploit availability.

    Analyzes finding evidence to identify potential CVE associations
    and adds relevant CVE metadata to findings.

    Args:
        cve_cache: CVE cache instance for lookups

    Usage:
        enricher = CVEEnricher(cve_cache)
        enriched = enricher.enrich_finding(
            finding_family="prompt_injection",
            finding_type="jailbreak",
            response="Error: OpenAI API v1.2.3 failed",
            evidence={"stack_trace": "..."},
        )
        if enriched["related_cves"]:
            print(f"Related CVEs: {enriched['related_cves']}")
    """

    def __init__(self, cve_cache: CVECache):
        """Initializes CVE enricher with cache."""
        self.cve_cache = cve_cache
        
        # Technology detection patterns
        self.tech_patterns = {
            # Python frameworks
            "flask": r"flask[/\s]+([\d.]+)",
            "django": r"django[/\s]+([\d.]+)",
            "fastapi": r"fastapi[/\s]+([\d.]+)",
            "starlette": r"starlette[/\s]+([\d.]+)",
            
            # LLM libraries
            "openai": r"openai[/\s]+([\d.]+)",
            "anthropic": r"anthropic[/\s]+([\d.]+)",
            "langchain": r"langchain[/\s]+([\d.]+)",
            "llama-index": r"llama[_-]index[/\s]+([\d.]+)",
            "transformers": r"transformers[/\s]+([\d.]+)",
            
            # Vector databases
            "chromadb": r"chroma[/\s]+([\d.]+)",
            "pinecone": r"pinecone[/\s]+([\d.]+)",
            "weaviate": r"weaviate[/\s]+([\d.]+)",
            "qdrant": r"qdrant[/\s]+([\d.]+)",
            
            # Web servers
            "nginx": r"nginx[/\s]+([\d.]+)",
            "apache": r"apache[/\s]+([\d.]+)",
            "uvicorn": r"uvicorn[/\s]+([\d.]+)",
            "gunicorn": r"gunicorn[/\s]+([\d.]+)",
            
            # Databases
            "postgresql": r"postgresql[/\s]+([\d.]+)",
            "mysql": r"mysql[/\s]+([\d.]+)",
            "mongodb": r"mongodb[/\s]+([\d.]+)",
            "redis": r"redis[/\s]+([\d.]+)",
        }
        
        # CVE keyword mappings for finding families
        self.family_cve_keywords = {
            "prompt_injection": ["prompt injection", "llm", "gpt", "language model"],
            "rce": ["remote code execution", "code injection", "command injection"],
            "ssrf": ["server-side request forgery", "ssrf"],
            "sql_injection": ["sql injection", "sqli"],
            "xss": ["cross-site scripting", "xss"],
            "path_traversal": ["path traversal", "directory traversal"],
            "idor": ["insecure direct object reference", "idor", "authorization"],
            "data_exfiltration": ["information disclosure", "data leak"],
            "mcp_tool_poisoning": ["mcp", "model context protocol", "tool"],
        }
        
        logger.info("CVE enricher initialized")

    def enrich_finding(
        self,
        finding_family: str,
        finding_type: str,
        response: str,
        evidence: Optional[Dict[str, Any]] = None,
        target_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enriches a finding with CVE data.

        Args:
            finding_family: Normalized finding family
            finding_type: Specific finding type
            response: Target response
            evidence: Additional evidence dictionary
            target_url: Target URL (optional)

        Returns:
            dict: Enrichment data with related_cves, technologies, exploit_available

        Example:
            enriched = enricher.enrich_finding(
                finding_family="prompt_injection",
                finding_type="jailbreak",
                response="Error in OpenAI API v1.2.3",
            )
            # Returns: {
            #   "related_cves": ["CVE-2024-1234"],
            #   "technologies": [{"name": "openai", "version": "1.2.3"}],
            #   "exploit_available": True,
            #   "kev_listed": False,
            # }
        """
        enrichment = {
            "related_cves": [],
            "technologies": [],
            "exploit_available": False,
            "kev_listed": False,
            "cve_details": [],
        }

        # Step 1: Extract technology fingerprints
        technologies = self._extract_technologies(response, evidence)
        enrichment["technologies"] = [
            {"name": tech.name, "version": tech.version, "confidence": tech.confidence}
            for tech in technologies
        ]

        # Step 2: Search for CVEs related to detected technologies
        tech_cves = self._find_technology_cves(technologies)
        enrichment["related_cves"].extend(tech_cves)

        # Step 3: Search for CVEs related to finding family
        family_cves = self._find_family_cves(finding_family, finding_type)
        enrichment["related_cves"].extend(family_cves)

        # Step 4: Deduplicate CVE list
        enrichment["related_cves"] = list(set(enrichment["related_cves"]))

        # Step 5: Fetch CVE details and check for exploits/KEV
        for cve_id in enrichment["related_cves"]:
            cve_data = self.cve_cache.get_cve(cve_id)
            if cve_data:
                enrichment["cve_details"].append({
                    "cve_id": cve_id,
                    "cvss_score": cve_data.get("cvss_v3_score") or cve_data.get("cvss_v2_score"),
                    "description": cve_data.get("description", "")[:200] + "...",
                    "exploit_available": cve_data.get("exploit_available", False),
                    "kev_listed": cve_data.get("kev_listed", False),
                })
                
                if cve_data.get("exploit_available"):
                    enrichment["exploit_available"] = True
                if cve_data.get("kev_listed"):
                    enrichment["kev_listed"] = True

        logger.info(
            f"Enriched finding {finding_family}/{finding_type}: "
            f"{len(enrichment['related_cves'])} CVEs, "
            f"{len(technologies)} technologies"
        )

        return enrichment

    def _extract_technologies(
        self,
        response: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> List[TechnologyFingerprint]:
        """
        Extracts technology fingerprints from response and evidence.

        Args:
            response: Target response
            evidence: Additional evidence dictionary

        Returns:
            List[TechnologyFingerprint]: Detected technologies
        """
        technologies = []
        
        # Search response for technology patterns
        for tech_name, pattern in self.tech_patterns.items():
            matches = re.finditer(pattern, response, re.IGNORECASE)
            for match in matches:
                version = match.group(1) if match.groups() else None
                technologies.append(TechnologyFingerprint(
                    name=tech_name,
                    version=version,
                    confidence=0.9,  # High confidence from direct version string
                    source="response",
                ))

        # Search evidence for technology patterns
        if evidence:
            for key, value in evidence.items():
                if isinstance(value, str):
                    for tech_name, pattern in self.tech_patterns.items():
                        matches = re.finditer(pattern, value, re.IGNORECASE)
                        for match in matches:
                            version = match.group(1) if match.groups() else None
                            technologies.append(TechnologyFingerprint(
                                name=tech_name,
                                version=version,
                                confidence=0.8,  # Slightly lower confidence from evidence
                                source=f"evidence.{key}",
                            ))

        # Deduplicate by name (keep highest confidence)
        seen = {}
        for tech in technologies:
            if tech.name not in seen or tech.confidence > seen[tech.name].confidence:
                seen[tech.name] = tech

        return list(seen.values())

    def _find_technology_cves(self, technologies: List[TechnologyFingerprint]) -> List[str]:
        """
        Finds CVEs related to detected technologies.

        This is a placeholder implementation. In production, you would:
        1. Query a CVE database with technology name + version
        2. Use CPE (Common Platform Enumeration) matching
        3. Integrate with vulnerability scanners

        Args:
            technologies: List of detected technologies

        Returns:
            List[str]: List of CVE IDs
        """
        cve_ids = []
        
        # For now, we just log detected technologies
        # In production, integrate with CVE-Search or similar
        for tech in technologies:
            logger.debug(
                f"Detected technology: {tech.name} {tech.version} "
                f"(confidence={tech.confidence:.2f}, source={tech.source})"
            )
            
            # Placeholder: In production, query CVE database here
            # Example: cve_ids.extend(query_cve_database(tech.name, tech.version))

        return cve_ids

    def _find_family_cves(self, finding_family: str, finding_type: str) -> List[str]:
        """
        Finds CVEs related to finding family.

        Searches CVE descriptions for keywords related to the finding family.
        This helps identify general vulnerability classes even without specific
        technology fingerprints.

        Args:
            finding_family: Normalized finding family
            finding_type: Specific finding type

        Returns:
            List[str]: List of CVE IDs
        """
        cve_ids = []
        
        # Get keywords for this finding family
        keywords = self.family_cve_keywords.get(finding_family, [])
        if not keywords:
            return cve_ids

        # Placeholder: In production, search CVE database by keywords
        # Example: cve_ids = search_cve_by_keywords(keywords)
        
        logger.debug(f"Searching CVEs for {finding_family} with keywords: {keywords}")

        return cve_ids

    def bulk_enrich_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Enriches multiple findings in batch.

        Args:
            findings: List of finding dictionaries with keys:
                - finding_family
                - finding_type
                - response
                - evidence (optional)

        Returns:
            List[Dict[str, Any]]: List of enrichment data dictionaries

        Example:
            findings = [
                {"finding_family": "prompt_injection", "response": "..."},
                {"finding_family": "rce", "response": "..."},
            ]
            enrichments = enricher.bulk_enrich_findings(findings)
        """
        enrichments = []
        
        for finding in findings:
            enrichment = self.enrich_finding(
                finding_family=finding.get("finding_family", "unknown"),
                finding_type=finding.get("finding_type", "unknown"),
                response=finding.get("response", ""),
                evidence=finding.get("evidence"),
                target_url=finding.get("target_url"),
            )
            enrichments.append(enrichment)

        logger.info(f"Bulk enriched {len(findings)} findings")
        return enrichments

    def extract_cve_from_text(self, text: str) -> List[str]:
        """
        Extracts CVE IDs from text using regex.

        Useful for parsing error messages, stack traces, or documentation
        that explicitly mention CVE IDs.

        Args:
            text: Text to search for CVE IDs

        Returns:
            List[str]: List of CVE IDs found in text

        Example:
            cves = enricher.extract_cve_from_text("This is CVE-2024-1234 and CVE-2023-5678")
            # Returns: ["CVE-2024-1234", "CVE-2023-5678"]
        """
        pattern = r"CVE-\d{4}-\d{4,7}"
        matches = re.findall(pattern, text, re.IGNORECASE)
        cve_ids = [cve.upper() for cve in matches]
        
        if cve_ids:
            logger.debug(f"Extracted CVE IDs from text: {cve_ids}")
        
        return cve_ids


logger.info("CVE enricher module loaded")
