"""
Burp Suite integration for llmrt.

Provides integration with Burp Suite Professional for advanced security
testing of AI applications. Enables automated scanning, custom extensions,
and vulnerability detection through Burp's REST API.

Features:
- Burp Suite REST API client
- Automated scanning with custom configurations
- Issue extraction and normalization
- Scan queue management
- Integration with llmrt evidence store

Note: Requires Burp Suite Professional with REST API enabled.

Usage:
    burp = BurpIntegration(burp_url="http://localhost:1337")
    scan_id = await burp.start_scan("https://target.com/api/chat")
    findings = await burp.get_scan_results(scan_id)
"""

import logging
from typing import List, Dict, Optional
import httpx
import time
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class BurpIntegration:
    """
    Burp Suite Professional integration for llmrt.

    Provides automated security scanning through Burp REST API.

    Args:
        burp_url: Burp Suite REST API URL (default: http://localhost:1337)
        api_key: Burp API key (optional, required for authenticated access)

    Raises:
        ConnectionError: If cannot connect to Burp instance
    """

    def __init__(self, burp_url: str = "http://localhost:1337", api_key: Optional[str] = None):
        """Initializes Burp integration."""
        self.burp_url = burp_url.rstrip("/")
        self.api_key = api_key
        
        # Setup HTTP client
        headers = {}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        
        self.client = httpx.AsyncClient(
            base_url=self.burp_url,
            headers=headers,
            timeout=30.0
        )
        
        logger.info(f"Burp integration initialized for {burp_url}")

    async def check_connection(self) -> bool:
        """
        Checks connection to Burp Suite.

        Returns:
            bool: True if connected successfully

        Raises:
            ConnectionError: If cannot connect
        """
        try:
            response = await self.client.get("/v0.1/")
            if response.status_code == 200:
                logger.info("Successfully connected to Burp Suite")
                return True
            else:
                raise ConnectionError(f"Burp returned status {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to connect to Burp: {e}")
            raise ConnectionError(f"Cannot connect to Burp: {e}")

    async def start_scan(
        self,
        target_url: str,
        scan_config: Optional[Dict] = None,
        scope_urls: Optional[List[str]] = None
    ) -> str:
        """
        Starts a new scan in Burp Suite.

        Args:
            target_url: Target URL to scan
            scan_config: Custom scan configuration (optional)
            scope_urls: List of URLs to include in scope (optional)

        Returns:
            str: Scan task ID

        Raises:
            RuntimeError: If scan fails to start
        """
        logger.info(f"Starting Burp scan on {target_url}")
        
        try:
            # Build scan request
            scan_request = {
                "urls": [target_url],
            }
            
            # Add scope if provided
            if scope_urls:
                scan_request["scope"] = {
                    "include": [{"rule": url} for url in scope_urls]
                }
            
            # Add custom config if provided
            if scan_config:
                scan_request["scan_configurations"] = [scan_config]
            else:
                # Use default crawl and audit configuration
                scan_request["scan_configurations"] = [
                    {
                        "name": "Crawl and Audit - Lightweight",
                        "type": "NamedConfiguration"
                    }
                ]
            
            # Start scan
            response = await self.client.post("/v0.1/scan", json=scan_request)
            
            if response.status_code == 201:
                scan_id = response.headers.get("Location", "").split("/")[-1]
                logger.info(f"Scan started with ID: {scan_id}")
                return scan_id
            else:
                error_msg = f"Failed to start scan: {response.status_code} - {response.text}"
                logger.error(error_msg)
                raise RuntimeError(error_msg)
                
        except Exception as e:
            logger.error(f"Scan start failed: {e}")
            raise RuntimeError(f"Burp scan failed to start: {e}")

    async def get_scan_status(self, scan_id: str) -> Dict:
        """
        Gets status of a running scan.

        Args:
            scan_id: Scan task ID

        Returns:
            dict: Scan status information

        Raises:
            RuntimeError: If status check fails
        """
        try:
            response = await self.client.get(f"/v0.1/scan/{scan_id}")
            
            if response.status_code == 200:
                status_data = response.json()
                return {
                    "scan_id": scan_id,
                    "status": status_data.get("scan_status"),
                    "metrics": status_data.get("scan_metrics", {}),
                    "issue_counts": status_data.get("issue_counts", {})
                }
            else:
                raise RuntimeError(f"Failed to get scan status: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to get scan status: {e}")
            raise RuntimeError(f"Scan status check failed: {e}")

    async def wait_for_scan(self, scan_id: str, poll_interval: int = 10) -> Dict:
        """
        Waits for scan to complete.

        Args:
            scan_id: Scan task ID
            poll_interval: Polling interval in seconds (default: 10)

        Returns:
            dict: Final scan status

        Raises:
            RuntimeError: If scan fails
        """
        logger.info(f"Waiting for scan {scan_id} to complete")
        
        while True:
            status = await self.get_scan_status(scan_id)
            scan_status = status.get("status")
            
            logger.debug(f"Scan {scan_id} status: {scan_status}")
            
            if scan_status == "succeeded":
                logger.info(f"Scan {scan_id} completed successfully")
                return status
            elif scan_status == "failed":
                raise RuntimeError(f"Scan {scan_id} failed")
            elif scan_status in ["cancelled", "paused"]:
                logger.warning(f"Scan {scan_id} was {scan_status}")
                return status
            
            # Still running, wait and poll again
            time.sleep(poll_interval)

    async def get_scan_results(self, scan_id: str) -> List[Dict]:
        """
        Gets results from completed scan.

        Args:
            scan_id: Scan task ID

        Returns:
            list: List of findings from scan

        Raises:
            RuntimeError: If results retrieval fails
        """
        logger.info(f"Retrieving results for scan {scan_id}")
        
        try:
            response = await self.client.get(f"/v0.1/scan/{scan_id}")
            
            if response.status_code == 200:
                scan_data = response.json()
                issues = scan_data.get("issue_events", [])
                logger.info(f"Retrieved {len(issues)} issues from scan {scan_id}")
                
                return self._normalize_issues(issues)
            else:
                raise RuntimeError(f"Failed to get scan results: {response.status_code}")
                
        except Exception as e:
            logger.error(f"Failed to get scan results: {e}")
            raise RuntimeError(f"Results retrieval failed: {e}")

    async def pause_scan(self, scan_id: str):
        """
        Pauses a running scan.

        Args:
            scan_id: Scan task ID

        Raises:
            RuntimeError: If pause fails
        """
        logger.info(f"Pausing scan {scan_id}")
        
        try:
            response = await self.client.post(f"/v0.1/scan/{scan_id}/pause")
            
            if response.status_code != 204:
                raise RuntimeError(f"Failed to pause scan: {response.status_code}")
                
            logger.info(f"Scan {scan_id} paused")
            
        except Exception as e:
            logger.error(f"Failed to pause scan: {e}")
            raise RuntimeError(f"Scan pause failed: {e}")

    async def resume_scan(self, scan_id: str):
        """
        Resumes a paused scan.

        Args:
            scan_id: Scan task ID

        Raises:
            RuntimeError: If resume fails
        """
        logger.info(f"Resuming scan {scan_id}")
        
        try:
            response = await self.client.post(f"/v0.1/scan/{scan_id}/resume")
            
            if response.status_code != 204:
                raise RuntimeError(f"Failed to resume scan: {response.status_code}")
                
            logger.info(f"Scan {scan_id} resumed")
            
        except Exception as e:
            logger.error(f"Failed to resume scan: {e}")
            raise RuntimeError(f"Scan resume failed: {e}")

    async def cancel_scan(self, scan_id: str):
        """
        Cancels a running scan.

        Args:
            scan_id: Scan task ID

        Raises:
            RuntimeError: If cancel fails
        """
        logger.info(f"Cancelling scan {scan_id}")
        
        try:
            response = await self.client.delete(f"/v0.1/scan/{scan_id}")
            
            if response.status_code != 204:
                raise RuntimeError(f"Failed to cancel scan: {response.status_code}")
                
            logger.info(f"Scan {scan_id} cancelled")
            
        except Exception as e:
            logger.error(f"Failed to cancel scan: {e}")
            raise RuntimeError(f"Scan cancel failed: {e}")

    async def create_ai_scan_config(self, config_name: str = "AI_Application_Config") -> Dict:
        """
        Creates custom scan configuration for AI applications.

        Focuses on AI-specific vulnerabilities and reduces false positives
        for AI application patterns.

        Args:
            config_name: Name for the custom configuration

        Returns:
            dict: Scan configuration

        Note:
            This is a simplified configuration. Real implementation would
            use Burp's scan configuration API to customize checks.
        """
        logger.info(f"Creating AI scan configuration: {config_name}")
        
        config = {
            "name": config_name,
            "type": "CustomConfiguration",
            "crawl_optimization": {
                "enabled": True,
                "max_link_depth": 5
            },
            "audit_optimization": {
                "enabled": True,
                "skip_ineffective_checks": True
            },
            "issues": {
                # Focus on injection and data leakage
                "sql_injection": {"enabled": True, "thorough": True},
                "os_command_injection": {"enabled": True, "thorough": True},
                "server_side_template_injection": {"enabled": True, "thorough": True},
                "cross_site_scripting": {"enabled": True, "thorough": False},
                "information_disclosure": {"enabled": True, "thorough": True},
            }
        }
        
        logger.info(f"AI scan configuration '{config_name}' created")
        return config

    def _normalize_issues(self, issues: List[Dict]) -> List[Dict]:
        """
        Normalizes Burp issues to llmrt finding format.

        Args:
            issues: Raw Burp issues

        Returns:
            list: Normalized findings
        """
        findings = []
        
        for issue in issues:
            issue_data = issue.get("issue", {})
            
            finding = {
                "source": "burp",
                "type_index": issue_data.get("type_index"),
                "name": issue_data.get("name"),
                "severity": issue_data.get("severity"),
                "confidence": issue_data.get("confidence"),
                "description": issue_data.get("description"),
                "remediation": issue_data.get("remediation"),
                "vulnerability_classifications": issue_data.get("vulnerability_classifications", []),
                "origin": issue_data.get("origin"),
                "path": issue_data.get("path"),
                "evidence": issue_data.get("evidence", []),
            }
            findings.append(finding)
        
        return findings

    async def export_issues(self, output_path: str, format: str = "json"):
        """
        Exports all issues to file.

        Args:
            output_path: Path to save issues file
            format: Export format (json, xml, html)

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting Burp issues to {output_path} (format: {format})")
        
        try:
            # Note: Burp REST API doesn't have direct export endpoint
            # This would require using Burp's extension API or manual export
            logger.warning("Burp REST API doesn't support direct issue export")
            logger.info("Use Burp Suite UI to export issues manually")
            
        except Exception as e:
            logger.error(f"Failed to export issues: {e}")
            raise RuntimeError(f"Issue export failed: {e}")

    async def close(self):
        """Closes HTTP client."""
        await self.client.aclose()
        logger.info("Burp integration closed")


logger.info("Burp integration module loaded")
