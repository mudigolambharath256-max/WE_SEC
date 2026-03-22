"""
CISA KEV (Known Exploited Vulnerabilities) monitor.

Monitors findings against the CISA KEV catalog to identify vulnerabilities
that are actively exploited in the wild. KEV-listed vulnerabilities require
immediate remediation according to CISA directives.

CISA KEV catalog:
- Updated regularly by CISA (Cybersecurity and Infrastructure Security Agency)
- Contains CVEs with evidence of active exploitation
- Includes required action and due date for federal agencies
- Public catalog available at: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

KEV monitoring workflow:
1. Download KEV catalog (JSON format)
2. Cache locally with daily refresh
3. Check findings against KEV list
4. Flag KEV-listed findings with high priority
5. Include KEV status in reports

KEV-listed findings should be prioritized for remediation regardless of
CVSS score, as they represent real-world active exploitation.
"""

import os
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import httpx

logger = logging.getLogger(__name__)


class KEVMonitor:
    """
    CISA KEV (Known Exploited Vulnerabilities) monitor.

    Checks findings against the CISA KEV catalog to identify actively
    exploited vulnerabilities that require immediate remediation.

    Args:
        cache_path: Path to KEV catalog cache file
        auto_update: Automatically update KEV catalog on init

    Usage:
        monitor = KEVMonitor()
        is_kev = monitor.is_kev_listed("CVE-2024-1234")
        if is_kev:
            print("⚠️  This CVE is actively exploited in the wild!")
    """

    KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        cache_path: str = "./output/kev_catalog.json",
        auto_update: bool = True,
    ):
        """Initializes KEV monitor."""
        self.cache_path = Path(cache_path)
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.kev_catalog: Dict[str, Dict[str, Any]] = {}
        self.catalog_date: Optional[datetime] = None
        
        # Load cached catalog
        if self.cache_path.exists():
            self._load_cache()
        
        # Auto-update if cache is stale or missing
        if auto_update and self._is_cache_stale():
            try:
                self.update_catalog()
            except Exception as e:
                logger.warning(f"Failed to update KEV catalog: {e}")
                if not self.kev_catalog:
                    logger.error("No KEV catalog available (cache missing and update failed)")

        logger.info(f"KEV monitor initialized: {len(self.kev_catalog)} KEV entries")

    def update_catalog(self):
        """
        Downloads and caches the latest KEV catalog from CISA.

        Raises:
            Exception: If download fails
        """
        logger.info(f"Downloading KEV catalog from {self.KEV_CATALOG_URL}")
        
        try:
            response = httpx.get(self.KEV_CATALOG_URL, timeout=30.0, follow_redirects=True)
            response.raise_for_status()
            
            catalog_data = response.json()
            
            # Parse catalog
            self.catalog_date = datetime.fromisoformat(
                catalog_data.get("catalogVersion", datetime.utcnow().isoformat())
            )
            
            vulnerabilities = catalog_data.get("vulnerabilities", [])
            
            # Build lookup dictionary
            self.kev_catalog = {}
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if cve_id:
                    self.kev_catalog[cve_id] = {
                        "cve_id": cve_id,
                        "vendor_project": vuln.get("vendorProject", "Unknown"),
                        "product": vuln.get("product", "Unknown"),
                        "vulnerability_name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "short_description": vuln.get("shortDescription", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": vuln.get("notes", ""),
                    }
            
            # Save to cache
            self._save_cache(catalog_data)
            
            logger.info(
                f"KEV catalog updated: {len(self.kev_catalog)} entries "
                f"(catalog date: {self.catalog_date.date()})"
            )
            
        except Exception as e:
            logger.error(f"Failed to download KEV catalog: {e}")
            raise

    def is_kev_listed(self, cve_id: str) -> bool:
        """
        Checks if a CVE is listed in the CISA KEV catalog.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            bool: True if CVE is in KEV catalog

        Example:
            if monitor.is_kev_listed("CVE-2024-1234"):
                print("⚠️  Actively exploited vulnerability!")
        """
        cve_id = cve_id.upper().strip()
        return cve_id in self.kev_catalog

    def get_kev_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves KEV catalog details for a CVE.

        Args:
            cve_id: CVE identifier

        Returns:
            Optional[Dict[str, Any]]: KEV details or None if not listed

        Example:
            details = monitor.get_kev_details("CVE-2024-1234")
            if details:
                print(f"Required action: {details['required_action']}")
                print(f"Due date: {details['due_date']}")
        """
        cve_id = cve_id.upper().strip()
        return self.kev_catalog.get(cve_id)

    def check_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Checks multiple findings against KEV catalog.

        Args:
            findings: List of finding dictionaries with 'related_cves' key

        Returns:
            List[Dict[str, Any]]: List of KEV matches with finding context

        Example:
            findings = [
                {"finding_id": "123", "related_cves": ["CVE-2024-1234"]},
                {"finding_id": "456", "related_cves": ["CVE-2024-5678"]},
            ]
            kev_matches = monitor.check_findings(findings)
            for match in kev_matches:
                print(f"Finding {match['finding_id']} has KEV: {match['cve_id']}")
        """
        kev_matches = []
        
        for finding in findings:
            finding_id = finding.get("finding_id", "unknown")
            related_cves = finding.get("related_cves", [])
            
            for cve_id in related_cves:
                if self.is_kev_listed(cve_id):
                    kev_details = self.get_kev_details(cve_id)
                    kev_matches.append({
                        "finding_id": finding_id,
                        "cve_id": cve_id,
                        "kev_details": kev_details,
                        "finding_family": finding.get("finding_family"),
                        "finding_type": finding.get("finding_type"),
                    })

        logger.info(f"KEV check: {len(kev_matches)} KEV-listed CVEs found in {len(findings)} findings")
        return kev_matches

    def get_kev_summary(self) -> Dict[str, Any]:
        """
        Returns summary statistics about the KEV catalog.

        Returns:
            dict: KEV catalog statistics

        Example:
            summary = monitor.get_kev_summary()
            print(f"Total KEV entries: {summary['total_entries']}")
            print(f"Ransomware-related: {summary['ransomware_count']}")
        """
        ransomware_count = sum(
            1 for vuln in self.kev_catalog.values()
            if vuln.get("known_ransomware", "").lower() == "known"
        )
        
        # Count by vendor
        vendor_counts = {}
        for vuln in self.kev_catalog.values():
            vendor = vuln.get("vendor_project", "Unknown")
            vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
        
        top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_entries": len(self.kev_catalog),
            "catalog_date": self.catalog_date.isoformat() if self.catalog_date else None,
            "ransomware_count": ransomware_count,
            "top_vendors": top_vendors,
            "cache_path": str(self.cache_path),
            "cache_age_hours": self._get_cache_age_hours(),
        }

    def generate_kev_report(self, kev_matches: List[Dict[str, Any]]) -> str:
        """
        Generates a human-readable KEV report.

        Args:
            kev_matches: List of KEV matches from check_findings()

        Returns:
            str: Formatted KEV report

        Example:
            kev_matches = monitor.check_findings(findings)
            report = monitor.generate_kev_report(kev_matches)
            print(report)
        """
        if not kev_matches:
            return "No CISA KEV-listed vulnerabilities detected."

        lines = [
            "CISA KEV (Known Exploited Vulnerabilities) Report",
            "=" * 60,
            "",
            "⚠️  The following findings are associated with CVEs that are",
            "   actively exploited in the wild according to CISA.",
            "",
            "🔴 IMMEDIATE REMEDIATION REQUIRED",
            "",
        ]

        for match in kev_matches:
            kev = match["kev_details"]
            lines.append(f"Finding ID: {match['finding_id']}")
            lines.append(f"CVE: {match['cve_id']}")
            lines.append(f"Vulnerability: {kev['vulnerability_name']}")
            lines.append(f"Vendor/Product: {kev['vendor_project']} / {kev['product']}")
            lines.append(f"Description: {kev['short_description']}")
            lines.append(f"Required Action: {kev['required_action']}")
            lines.append(f"Due Date: {kev['due_date']}")
            
            if kev['known_ransomware'].lower() == "known":
                lines.append("🔴 Known Ransomware Campaign Use")
            
            if kev['notes']:
                lines.append(f"Notes: {kev['notes']}")
            
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"Total KEV-listed findings: {len(kev_matches)}")
        
        ransomware_count = sum(
            1 for m in kev_matches
            if m["kev_details"].get("known_ransomware", "").lower() == "known"
        )
        if ransomware_count > 0:
            lines.append(f"Ransomware-related: {ransomware_count}")

        return "\n".join(lines)

    def _load_cache(self):
        """Loads KEV catalog from cache file."""
        try:
            with open(self.cache_path, "r") as f:
                catalog_data = json.load(f)
            
            self.catalog_date = datetime.fromisoformat(
                catalog_data.get("catalogVersion", datetime.utcnow().isoformat())
            )
            
            vulnerabilities = catalog_data.get("vulnerabilities", [])
            
            self.kev_catalog = {}
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID")
                if cve_id:
                    self.kev_catalog[cve_id] = {
                        "cve_id": cve_id,
                        "vendor_project": vuln.get("vendorProject", "Unknown"),
                        "product": vuln.get("product", "Unknown"),
                        "vulnerability_name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "short_description": vuln.get("shortDescription", ""),
                        "required_action": vuln.get("requiredAction", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                        "notes": vuln.get("notes", ""),
                    }
            
            logger.debug(f"Loaded KEV catalog from cache: {len(self.kev_catalog)} entries")
            
        except Exception as e:
            logger.warning(f"Failed to load KEV cache: {e}")
            self.kev_catalog = {}

    def _save_cache(self, catalog_data: Dict[str, Any]):
        """Saves KEV catalog to cache file."""
        try:
            with open(self.cache_path, "w") as f:
                json.dump(catalog_data, f, indent=2)
            logger.debug(f"Saved KEV catalog to cache: {self.cache_path}")
        except Exception as e:
            logger.warning(f"Failed to save KEV cache: {e}")

    def _is_cache_stale(self) -> bool:
        """Checks if cache is stale (older than 24 hours)."""
        if not self.cache_path.exists():
            return True
        
        cache_age = datetime.utcnow() - datetime.fromtimestamp(self.cache_path.stat().st_mtime)
        return cache_age > timedelta(hours=24)

    def _get_cache_age_hours(self) -> float:
        """Returns cache age in hours."""
        if not self.cache_path.exists():
            return -1.0
        
        cache_age = datetime.utcnow() - datetime.fromtimestamp(self.cache_path.stat().st_mtime)
        return cache_age.total_seconds() / 3600


logger.info("KEV monitor module loaded")
