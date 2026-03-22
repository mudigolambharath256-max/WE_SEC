"""
Intelligence layer — CVE enrichment and vulnerability intelligence.

This package provides vulnerability intelligence capabilities:
- cve_cache.py: Local CVE database cache with NVD API integration
- cve_enricher.py: Enriches findings with CVE data and exploit availability
- tech_cve_scanner.py: Scans detected technologies for known CVEs
- kev_monitor.py: Checks findings against CISA KEV catalog

Intelligence sources:
- NVD (National Vulnerability Database) via nvdlib
- CISA KEV (Known Exploited Vulnerabilities) catalog
- MCP-NVD server for real-time CVE lookups
- CVE-Search MCP server for historical data

All CVE data is cached locally to reduce API calls and improve performance.
"""
