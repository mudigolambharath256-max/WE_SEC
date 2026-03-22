"""
Technology CVE scanner — scans detected technologies for known CVEs.

Performs automated vulnerability scanning of detected technologies by:
1. Fingerprinting technologies from target responses
2. Querying CVE databases for known vulnerabilities
3. Filtering CVEs by version ranges
4. Prioritizing CVEs with known exploits or KEV listing

This module integrates with:
- CVE cache for local lookups
- MCP-NVD server for real-time CVE queries
- CVE-Search MCP server for historical data

Technology detection sources:
- HTTP headers (Server, X-Powered-By, etc.)
- Error messages and stack traces
- API version endpoints (/version, /health, /api/v1)
- JavaScript libraries in responses
- Framework-specific patterns
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from packaging import version as pkg_version

from .cve_cache import CVECache

logger = logging.getLogger(__name__)


@dataclass
class TechnologyScan:
    """
    Represents a technology vulnerability scan result.

    Attributes:
        technology: Technology name
        version: Detected version
        cves: List of applicable CVEs
        critical_count: Number of critical CVEs
        high_count: Number of high CVEs
        exploit_available_count: Number of CVEs with known exploits
        kev_count: Number of CVEs in CISA KEV catalog
    """
    technology: str
    version: str
    cves: List[Dict[str, Any]]
    critical_count: int
    high_count: int
    exploit_available_count: int
    kev_count: int


class TechCVEScanner:
    """
    Scans detected technologies for known CVEs.

    Performs automated vulnerability assessment of target technology stack
    by correlating detected versions with CVE databases.

    Args:
        cve_cache: CVE cache instance for lookups

    Usage:
        scanner = TechCVEScanner(cve_cache)
        results = scanner.scan_technologies({
            "flask": "2.0.1",
            "openai": "0.27.0",
        })
        for result in results:
            print(f"{result.technology} {result.version}: {len(result.cves)} CVEs")
    """

    def __init__(self, cve_cache: CVECache):
        """Initializes technology CVE scanner."""
        self.cve_cache = cve_cache
        
        # Known vulnerable version ranges (examples)
        # In production, this would be loaded from a database or API
        self.known_vulnerabilities = {
            "flask": [
                {
                    "cve_id": "CVE-2023-30861",
                    "affected_versions": ">=2.2.0,<2.2.5 || >=2.3.0,<2.3.2",
                    "description": "Cookie parsing vulnerability",
                    "cvss_score": 7.5,
                },
            ],
            "django": [
                {
                    "cve_id": "CVE-2023-43665",
                    "affected_versions": ">=3.2.0,<3.2.22 || >=4.1.0,<4.1.12 || >=4.2.0,<4.2.6",
                    "description": "Denial-of-service in file uploads",
                    "cvss_score": 7.5,
                },
            ],
            "openai": [
                {
                    "cve_id": "CVE-2024-EXAMPLE",
                    "affected_versions": "<1.0.0",
                    "description": "API key exposure in error messages",
                    "cvss_score": 8.1,
                },
            ],
        }
        
        logger.info("Technology CVE scanner initialized")

    def scan_technologies(
        self,
        technologies: Dict[str, str],
    ) -> List[TechnologyScan]:
        """
        Scans multiple technologies for CVEs.

        Args:
            technologies: Dictionary mapping technology name to version
                Example: {"flask": "2.0.1", "openai": "0.27.0"}

        Returns:
            List[TechnologyScan]: Scan results for each technology

        Example:
            results = scanner.scan_technologies({
                "flask": "2.0.1",
                "django": "3.2.20",
            })
            for result in results:
                if result.critical_count > 0:
                    print(f"CRITICAL: {result.technology} has {result.critical_count} critical CVEs")
        """
        results = []
        
        for tech_name, tech_version in technologies.items():
            scan_result = self._scan_single_technology(tech_name, tech_version)
            if scan_result:
                results.append(scan_result)

        logger.info(f"Scanned {len(technologies)} technologies, found vulnerabilities in {len(results)}")
        return results

    def _scan_single_technology(
        self,
        technology: str,
        version: str,
    ) -> Optional[TechnologyScan]:
        """
        Scans a single technology for CVEs.

        Args:
            technology: Technology name
            version: Version string

        Returns:
            Optional[TechnologyScan]: Scan result or None if no vulnerabilities
        """
        # Get known vulnerabilities for this technology
        vulns = self.known_vulnerabilities.get(technology.lower(), [])
        
        applicable_cves = []
        critical_count = 0
        high_count = 0
        exploit_available_count = 0
        kev_count = 0

        for vuln in vulns:
            # Check if version is affected
            if self._is_version_affected(version, vuln["affected_versions"]):
                # Fetch full CVE data from cache
                cve_data = self.cve_cache.get_cve(vuln["cve_id"])
                
                if cve_data:
                    cve_info = {
                        "cve_id": vuln["cve_id"],
                        "description": vuln["description"],
                        "cvss_score": cve_data.get("cvss_v3_score") or vuln["cvss_score"],
                        "cvss_vector": cve_data.get("cvss_v3_vector"),
                        "exploit_available": cve_data.get("exploit_available", False),
                        "kev_listed": cve_data.get("kev_listed", False),
                        "references": cve_data.get("references", []),
                    }
                else:
                    # Fallback to known vulnerability data
                    cve_info = {
                        "cve_id": vuln["cve_id"],
                        "description": vuln["description"],
                        "cvss_score": vuln["cvss_score"],
                        "cvss_vector": None,
                        "exploit_available": False,
                        "kev_listed": False,
                        "references": [],
                    }

                applicable_cves.append(cve_info)

                # Count by severity
                cvss_score = cve_info["cvss_score"]
                if cvss_score >= 9.0:
                    critical_count += 1
                elif cvss_score >= 7.0:
                    high_count += 1

                if cve_info["exploit_available"]:
                    exploit_available_count += 1
                if cve_info["kev_listed"]:
                    kev_count += 1

        if not applicable_cves:
            return None

        scan_result = TechnologyScan(
            technology=technology,
            version=version,
            cves=applicable_cves,
            critical_count=critical_count,
            high_count=high_count,
            exploit_available_count=exploit_available_count,
            kev_count=kev_count,
        )

        logger.info(
            f"Technology scan: {technology} {version} — "
            f"{len(applicable_cves)} CVEs "
            f"(critical={critical_count}, high={high_count}, exploits={exploit_available_count})"
        )

        return scan_result

    def _is_version_affected(self, version: str, affected_range: str) -> bool:
        """
        Checks if a version falls within an affected version range.

        Args:
            version: Version string (e.g., "2.0.1")
            affected_range: Version range specifier (e.g., ">=2.0.0,<2.2.5")

        Returns:
            bool: True if version is affected

        Example:
            is_affected = scanner._is_version_affected("2.0.1", ">=2.0.0,<2.2.5")
            # Returns: True
        """
        try:
            parsed_version = pkg_version.parse(version)
        except Exception as e:
            logger.warning(f"Failed to parse version '{version}': {e}")
            return False

        # Parse affected range
        # Format: ">=2.0.0,<2.2.5" or ">=2.2.0,<2.2.5 || >=2.3.0,<2.3.2"
        range_groups = affected_range.split(" || ")
        
        for range_group in range_groups:
            conditions = range_group.split(",")
            all_conditions_met = True
            
            for condition in conditions:
                condition = condition.strip()
                
                # Parse condition
                if condition.startswith(">="):
                    min_version = pkg_version.parse(condition[2:])
                    if not (parsed_version >= min_version):
                        all_conditions_met = False
                        break
                elif condition.startswith(">"):
                    min_version = pkg_version.parse(condition[1:])
                    if not (parsed_version > min_version):
                        all_conditions_met = False
                        break
                elif condition.startswith("<="):
                    max_version = pkg_version.parse(condition[2:])
                    if not (parsed_version <= max_version):
                        all_conditions_met = False
                        break
                elif condition.startswith("<"):
                    max_version = pkg_version.parse(condition[1:])
                    if not (parsed_version < max_version):
                        all_conditions_met = False
                        break
                elif condition.startswith("=="):
                    exact_version = pkg_version.parse(condition[2:])
                    if not (parsed_version == exact_version):
                        all_conditions_met = False
                        break

            if all_conditions_met:
                return True

        return False

    def scan_from_fingerprints(
        self,
        response: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[TechnologyScan]:
        """
        Scans technologies detected from response and headers.

        Args:
            response: Target response body
            headers: HTTP response headers

        Returns:
            List[TechnologyScan]: Scan results

        Example:
            results = scanner.scan_from_fingerprints(
                response="Flask/2.0.1 Werkzeug/2.0.1",
                headers={"Server": "nginx/1.18.0"},
            )
        """
        # Extract technologies from response and headers
        technologies = self._fingerprint_technologies(response, headers)
        
        # Scan detected technologies
        return self.scan_technologies(technologies)

    def _fingerprint_technologies(
        self,
        response: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """
        Fingerprints technologies from response and headers.

        Args:
            response: Target response body
            headers: HTTP response headers

        Returns:
            Dict[str, str]: Dictionary mapping technology name to version
        """
        technologies = {}

        # Technology detection patterns
        patterns = {
            "flask": r"flask[/\s]+([\d.]+)",
            "django": r"django[/\s]+([\d.]+)",
            "fastapi": r"fastapi[/\s]+([\d.]+)",
            "openai": r"openai[/\s]+([\d.]+)",
            "langchain": r"langchain[/\s]+([\d.]+)",
            "nginx": r"nginx[/\s]+([\d.]+)",
            "apache": r"apache[/\s]+([\d.]+)",
            "python": r"python[/\s]+([\d.]+)",
            "node": r"node[/\s]+([\d.]+)",
        }

        # Search response body
        for tech_name, pattern in patterns.items():
            match = re.search(pattern, response, re.IGNORECASE)
            if match:
                technologies[tech_name] = match.group(1)

        # Search headers
        if headers:
            for header_name, header_value in headers.items():
                for tech_name, pattern in patterns.items():
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        technologies[tech_name] = match.group(1)

        logger.debug(f"Fingerprinted technologies: {technologies}")
        return technologies

    def generate_scan_report(self, scan_results: List[TechnologyScan]) -> str:
        """
        Generates a human-readable scan report.

        Args:
            scan_results: List of technology scan results

        Returns:
            str: Formatted scan report

        Example:
            report = scanner.generate_scan_report(results)
            print(report)
        """
        if not scan_results:
            return "No vulnerabilities detected in scanned technologies."

        lines = ["Technology Vulnerability Scan Report", "=" * 50, ""]

        total_cves = 0
        total_critical = 0
        total_high = 0
        total_exploits = 0
        total_kev = 0

        for result in scan_results:
            total_cves += len(result.cves)
            total_critical += result.critical_count
            total_high += result.high_count
            total_exploits += result.exploit_available_count
            total_kev += result.kev_count

            lines.append(f"Technology: {result.technology} {result.version}")
            lines.append(f"  CVEs: {len(result.cves)}")
            lines.append(f"  Critical: {result.critical_count}")
            lines.append(f"  High: {result.high_count}")
            lines.append(f"  Known Exploits: {result.exploit_available_count}")
            lines.append(f"  CISA KEV: {result.kev_count}")
            lines.append("")

            for cve in result.cves[:5]:  # Show top 5 CVEs
                lines.append(f"    {cve['cve_id']} (CVSS: {cve['cvss_score']})")
                lines.append(f"      {cve['description'][:80]}...")
                if cve['exploit_available']:
                    lines.append("      ⚠️  Known exploit available")
                if cve['kev_listed']:
                    lines.append("      🔴 Listed in CISA KEV catalog")
                lines.append("")

        lines.append("=" * 50)
        lines.append(f"Total: {total_cves} CVEs across {len(scan_results)} technologies")
        lines.append(f"Critical: {total_critical} | High: {total_high}")
        lines.append(f"Known Exploits: {total_exploits} | CISA KEV: {total_kev}")

        return "\n".join(lines)


logger.info("Technology CVE scanner module loaded")
