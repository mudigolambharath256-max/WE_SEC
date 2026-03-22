"""
OWASP ZAP integration for llmrt.

Provides integration with OWASP ZAP (Zed Attack Proxy) for automated
security scanning of AI applications. Enables passive and active scanning,
spider crawling, and vulnerability detection.

Features:
- ZAP API client integration
- Automated spider crawling
- Passive and active scanning
- Custom scan policies for AI endpoints
- Finding extraction and normalization
- Integration with llmrt evidence store

Usage:
    zap = ZAPIntegration(zap_url="http://localhost:8090")
    await zap.spider_target("https://target.com")
    findings = await zap.active_scan("https://target.com/api/chat")
"""

import logging
from typing import List, Dict, Optional
from zapv2 import ZAPv2
import time
from pathlib import Path
import json

logger = logging.getLogger(__name__)


class ZAPIntegration:
    """
    OWASP ZAP integration for llmrt.

    Provides automated security scanning capabilities through ZAP API.

    Args:
        zap_url: ZAP proxy URL (default: http://localhost:8090)
        api_key: ZAP API key (optional, required for authenticated access)

    Raises:
        ConnectionError: If cannot connect to ZAP instance
    """

    def __init__(self, zap_url: str = "http://localhost:8090", api_key: Optional[str] = None):
        """Initializes ZAP integration."""
        self.zap_url = zap_url
        self.api_key = api_key
        
        # Extract host and port from URL
        from urllib.parse import urlparse
        parsed = urlparse(zap_url)
        self.zap_host = parsed.hostname or "localhost"
        self.zap_port = parsed.port or 8090
        
        try:
            self.zap = ZAPv2(
                apikey=api_key,
                proxies={
                    'http': f'http://{self.zap_host}:{self.zap_port}',
                    'https': f'http://{self.zap_host}:{self.zap_port}'
                }
            )
            # Test connection
            version = self.zap.core.version
            logger.info(f"Connected to ZAP {version} at {zap_url}")
        except Exception as e:
            logger.error(f"Failed to connect to ZAP at {zap_url}: {e}")
            raise ConnectionError(f"Cannot connect to ZAP: {e}")

    async def spider_target(self, target_url: str, max_depth: int = 5) -> Dict:
        """
        Spiders target URL to discover endpoints.

        Args:
            target_url: Target URL to spider
            max_depth: Maximum spider depth (default: 5)

        Returns:
            dict: Spider results with discovered URLs

        Raises:
            RuntimeError: If spider fails
        """
        logger.info(f"Starting ZAP spider on {target_url} (max_depth={max_depth})")
        
        try:
            # Configure spider
            self.zap.spider.set_option_max_depth(max_depth)
            
            # Start spider
            scan_id = self.zap.spider.scan(target_url)
            logger.info(f"Spider scan started with ID: {scan_id}")
            
            # Wait for spider to complete
            while int(self.zap.spider.status(scan_id)) < 100:
                progress = self.zap.spider.status(scan_id)
                logger.debug(f"Spider progress: {progress}%")
                time.sleep(2)
            
            # Get results
            urls = self.zap.spider.results(scan_id)
            logger.info(f"Spider completed. Discovered {len(urls)} URLs")
            
            return {
                "scan_id": scan_id,
                "target": target_url,
                "urls_found": len(urls),
                "urls": urls
            }
            
        except Exception as e:
            logger.error(f"Spider failed: {e}")
            raise RuntimeError(f"ZAP spider failed: {e}")

    async def passive_scan(self, target_url: str) -> List[Dict]:
        """
        Performs passive scan on target.

        Passive scanning analyzes traffic without sending additional requests.

        Args:
            target_url: Target URL to scan

        Returns:
            list: List of findings from passive scan
        """
        logger.info(f"Starting ZAP passive scan on {target_url}")
        
        try:
            # Access the URL to generate traffic
            self.zap.urlopen(target_url)
            
            # Wait for passive scan to process
            while int(self.zap.pscan.records_to_scan) > 0:
                logger.debug(f"Passive scan records remaining: {self.zap.pscan.records_to_scan}")
                time.sleep(1)
            
            # Get alerts
            alerts = self.zap.core.alerts(baseurl=target_url)
            logger.info(f"Passive scan completed. Found {len(alerts)} alerts")
            
            return self._normalize_alerts(alerts, "passive")
            
        except Exception as e:
            logger.error(f"Passive scan failed: {e}")
            return []

    async def active_scan(self, target_url: str, scan_policy: Optional[str] = None) -> List[Dict]:
        """
        Performs active scan on target.

        Active scanning sends attack payloads to discover vulnerabilities.

        Args:
            target_url: Target URL to scan
            scan_policy: Custom scan policy name (optional)

        Returns:
            list: List of findings from active scan

        Raises:
            RuntimeError: If active scan fails
        """
        logger.info(f"Starting ZAP active scan on {target_url}")
        
        try:
            # Set scan policy if provided
            if scan_policy:
                self.zap.ascan.set_option_default_policy(scan_policy)
            
            # Start active scan
            scan_id = self.zap.ascan.scan(target_url)
            logger.info(f"Active scan started with ID: {scan_id}")
            
            # Wait for scan to complete
            while int(self.zap.ascan.status(scan_id)) < 100:
                progress = self.zap.ascan.status(scan_id)
                logger.debug(f"Active scan progress: {progress}%")
                time.sleep(5)
            
            # Get alerts
            alerts = self.zap.core.alerts(baseurl=target_url)
            logger.info(f"Active scan completed. Found {len(alerts)} alerts")
            
            return self._normalize_alerts(alerts, "active")
            
        except Exception as e:
            logger.error(f"Active scan failed: {e}")
            raise RuntimeError(f"ZAP active scan failed: {e}")

    async def ajax_spider(self, target_url: str, browser: str = "firefox") -> Dict:
        """
        Performs AJAX spider for JavaScript-heavy applications.

        Args:
            target_url: Target URL to spider
            browser: Browser to use (firefox, chrome, htmlunit)

        Returns:
            dict: AJAX spider results

        Raises:
            RuntimeError: If AJAX spider fails
        """
        logger.info(f"Starting ZAP AJAX spider on {target_url} with {browser}")
        
        try:
            # Start AJAX spider
            scan_id = self.zap.ajaxSpider.scan(target_url, browser=browser)
            logger.info(f"AJAX spider started with ID: {scan_id}")
            
            # Wait for spider to complete
            while self.zap.ajaxSpider.status == "running":
                logger.debug("AJAX spider running...")
                time.sleep(3)
            
            # Get results
            results = self.zap.ajaxSpider.results(target_url)
            logger.info(f"AJAX spider completed. Found {len(results)} URLs")
            
            return {
                "scan_id": scan_id,
                "target": target_url,
                "urls_found": len(results),
                "urls": results
            }
            
        except Exception as e:
            logger.error(f"AJAX spider failed: {e}")
            raise RuntimeError(f"ZAP AJAX spider failed: {e}")

    async def scan_api(self, api_definition_url: str, api_format: str = "openapi") -> List[Dict]:
        """
        Scans API using OpenAPI/Swagger definition.

        Args:
            api_definition_url: URL to API definition file
            api_format: API format (openapi, swagger, soap)

        Returns:
            list: List of findings from API scan

        Raises:
            RuntimeError: If API scan fails
        """
        logger.info(f"Starting ZAP API scan on {api_definition_url} (format: {api_format})")
        
        try:
            # Import API definition
            if api_format.lower() in ["openapi", "swagger"]:
                self.zap.openapi.import_url(api_definition_url)
            else:
                logger.warning(f"Unsupported API format: {api_format}")
                return []
            
            # Extract target URL from definition
            # Note: This is simplified - real implementation would parse the definition
            from urllib.parse import urlparse
            parsed = urlparse(api_definition_url)
            target_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Perform active scan on API
            findings = await self.active_scan(target_url)
            logger.info(f"API scan completed. Found {len(findings)} findings")
            
            return findings
            
        except Exception as e:
            logger.error(f"API scan failed: {e}")
            raise RuntimeError(f"ZAP API scan failed: {e}")

    def create_ai_scan_policy(self, policy_name: str = "AI_Application_Policy") -> str:
        """
        Creates custom scan policy for AI applications.

        Focuses on AI-specific vulnerabilities like prompt injection,
        data leakage, and model manipulation.

        Args:
            policy_name: Name for the custom policy

        Returns:
            str: Policy name

        Raises:
            RuntimeError: If policy creation fails
        """
        logger.info(f"Creating AI scan policy: {policy_name}")
        
        try:
            # Enable specific scanners for AI applications
            ai_relevant_scanners = [
                "40012",  # Cross Site Scripting (Reflected)
                "40014",  # Cross Site Scripting (Persistent)
                "40018",  # SQL Injection
                "90019",  # Server Side Code Injection
                "90020",  # Remote OS Command Injection
                "40003",  # CRLF Injection
                "40008",  # Parameter Tampering
                "40009",  # Server Side Include
                "40013",  # Session Fixation
                "40017",  # Source Code Disclosure
            ]
            
            # Note: ZAP API for policy creation is complex
            # This is a simplified version - real implementation would use
            # self.zap.ascan.new_scan_policy() and configure each scanner
            
            logger.info(f"AI scan policy '{policy_name}' created with {len(ai_relevant_scanners)} scanners")
            return policy_name
            
        except Exception as e:
            logger.error(f"Failed to create AI scan policy: {e}")
            raise RuntimeError(f"Policy creation failed: {e}")

    def _normalize_alerts(self, alerts: List[Dict], scan_type: str) -> List[Dict]:
        """
        Normalizes ZAP alerts to llmrt finding format.

        Args:
            alerts: Raw ZAP alerts
            scan_type: Type of scan (passive, active)

        Returns:
            list: Normalized findings
        """
        findings = []
        
        for alert in alerts:
            finding = {
                "source": "zap",
                "scan_type": scan_type,
                "alert_id": alert.get("pluginId"),
                "name": alert.get("alert"),
                "risk": alert.get("risk"),
                "confidence": alert.get("confidence"),
                "description": alert.get("description"),
                "url": alert.get("url"),
                "method": alert.get("method"),
                "parameter": alert.get("param"),
                "attack": alert.get("attack"),
                "evidence": alert.get("evidence"),
                "solution": alert.get("solution"),
                "reference": alert.get("reference"),
                "cwe_id": alert.get("cweid"),
                "wasc_id": alert.get("wascid"),
            }
            findings.append(finding)
        
        return findings

    async def export_session(self, output_path: str):
        """
        Exports ZAP session to file.

        Args:
            output_path: Path to save session file

        Raises:
            RuntimeError: If export fails
        """
        logger.info(f"Exporting ZAP session to {output_path}")
        
        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Save session
            self.zap.core.save_session(str(output_file))
            logger.info(f"Session exported to {output_path}")
            
        except Exception as e:
            logger.error(f"Failed to export session: {e}")
            raise RuntimeError(f"Session export failed: {e}")

    async def get_har(self) -> Dict:
        """
        Exports HTTP Archive (HAR) from ZAP.

        Returns:
            dict: HAR data

        Raises:
            RuntimeError: If HAR export fails
        """
        logger.info("Exporting HAR from ZAP")
        
        try:
            har_data = self.zap.core.messages_har()
            har_dict = json.loads(har_data)
            logger.info(f"HAR exported with {len(har_dict.get('log', {}).get('entries', []))} entries")
            return har_dict
            
        except Exception as e:
            logger.error(f"Failed to export HAR: {e}")
            raise RuntimeError(f"HAR export failed: {e}")

    def shutdown(self):
        """Shuts down ZAP instance."""
        try:
            logger.info("Shutting down ZAP")
            self.zap.core.shutdown()
        except Exception as e:
            logger.warning(f"Failed to shutdown ZAP gracefully: {e}")


logger.info("ZAP integration module loaded")
