"""
Selenium-based fallback crawler for complex SPAs.

Provides Selenium WebDriver fallback when Playwright fails or for
specific scenarios requiring Selenium's capabilities:
- Complex authentication flows
- CAPTCHA handling (with manual intervention)
- Browser extension integration
- Legacy browser support

Selenium is slower than Playwright but more widely supported and
has better extension ecosystem for security testing.

This module is used as a fallback when:
1. Playwright fails to render a page
2. Target requires specific browser extensions
3. Manual intervention is needed (CAPTCHA, 2FA)
"""

import logging
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
import time

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service
    from selenium.common.exceptions import TimeoutException, WebDriverException
except ImportError:
    webdriver = None
    logging.warning("selenium not installed, selenium_fallback will be limited")

from ..core.scope_validator import ScopeValidator, OutOfScopeError

logger = logging.getLogger(__name__)


class SeleniumFallback:
    """
    Selenium-based fallback crawler for complex SPAs.

    Provides robust crawling for applications that require:
    - Complex JavaScript execution
    - Browser extension support
    - Manual intervention (CAPTCHA, 2FA)

    Args:
        scope_validator: Scope validator instance
        headless: Run browser in headless mode (default: True)
        timeout: Page load timeout in seconds (default: 30)
        driver_path: Path to ChromeDriver (optional, uses system PATH if not provided)

    Usage:
        crawler = SeleniumFallback(scope_validator)
        endpoints = crawler.crawl("https://example.com/chat")
        print(f"Discovered {len(endpoints)} endpoints")
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        headless: bool = True,
        timeout: int = 30,
        driver_path: Optional[str] = None,
    ):
        """Initializes Selenium fallback crawler."""
        if not webdriver:
            raise ImportError("selenium not installed. Install with: pip install selenium")
        
        self.scope_validator = scope_validator
        self.headless = headless
        self.timeout = timeout
        self.driver_path = driver_path
        
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        
        logger.info(f"Selenium fallback initialized: headless={headless}, timeout={timeout}s")

    def crawl(self, start_url: str) -> List[str]:
        """
        Crawls a URL using Selenium and discovers endpoints.

        Args:
            start_url: Starting URL to crawl

        Returns:
            List[str]: List of discovered endpoints

        Raises:
            OutOfScopeError: If start_url is out of scope

        Example:
            endpoints = crawler.crawl("https://example.com/chat")
            for endpoint in endpoints:
                print(f"Discovered: {endpoint}")
        """
        # Validate scope
        self.scope_validator.validate_or_raise(start_url)
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        
        logger.info(f"Starting Selenium crawl: {start_url}")
        
        # Setup Chrome options
        chrome_options = ChromeOptions()
        if self.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        
        # Enable performance logging to capture network requests
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        
        # Create driver
        if self.driver_path:
            service = Service(executable_path=self.driver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options)
        else:
            driver = webdriver.Chrome(options=chrome_options)
        
        driver.set_page_load_timeout(self.timeout)
        
        try:
            self._crawl_page(driver, start_url)
        except Exception as e:
            logger.error(f"Selenium crawl error: {e}")
        finally:
            driver.quit()
        
        logger.info(f"Selenium crawl complete: {len(self.discovered_endpoints)} endpoints")
        return list(self.discovered_endpoints)

    def _crawl_page(self, driver: webdriver.Chrome, url: str):
        """
        Crawls a single page with Selenium.

        Args:
            driver: Selenium WebDriver
            url: URL to crawl
        """
        if url in self.visited_urls:
            return
        
        # Validate scope
        try:
            self.scope_validator.validate_or_raise(url)
        except OutOfScopeError:
            logger.debug(f"Out of scope: {url}")
            return
        
        self.visited_urls.add(url)
        logger.debug(f"Crawling with Selenium: {url}")
        
        try:
            # Navigate to page
            driver.get(url)
            
            # Wait for page to load
            WebDriverWait(driver, self.timeout).until(
                EC.presence_of_element_located((By.TAG_NAME, "body"))
            )
            
            # Wait for JavaScript to execute
            time.sleep(2)
            
            # Extract endpoints from network logs
            self._extract_endpoints_from_logs(driver)
            
            # Extract endpoints from page source
            self._extract_endpoints_from_page(driver, url)
            
            # Trigger interactions
            self._trigger_interactions(driver)
            
            # Extract endpoints again after interactions
            self._extract_endpoints_from_logs(driver)
        
        except TimeoutException:
            logger.warning(f"Timeout loading page: {url}")
        except WebDriverException as e:
            logger.warning(f"WebDriver error on {url}: {e}")
        except Exception as e:
            logger.error(f"Error crawling {url}: {e}")

    def _extract_endpoints_from_logs(self, driver: webdriver.Chrome):
        """
        Extracts API endpoints from Chrome performance logs.

        Args:
            driver: Selenium WebDriver
        """
        try:
            logs = driver.get_log("performance")
            
            for log in logs:
                try:
                    import json
                    message = json.loads(log["message"])
                    
                    # Extract network requests
                    if "Network.requestWillBeSent" in message.get("message", {}).get("method", ""):
                        request = message["message"]["params"]["request"]
                        url = request.get("url", "")
                        method = request.get("method", "GET")
                        
                        # Check for API patterns
                        if any(pattern in url for pattern in ["/api/", "/v1/", "/graphql", "/ws/"]):
                            endpoint = f"{method} {url}"
                            self.discovered_endpoints.add(endpoint)
                            logger.debug(f"Discovered endpoint from logs: {endpoint}")
                
                except Exception as e:
                    logger.debug(f"Error parsing log entry: {e}")
        
        except Exception as e:
            logger.debug(f"Error extracting endpoints from logs: {e}")

    def _extract_endpoints_from_page(self, driver: webdriver.Chrome, base_url: str):
        """
        Extracts API endpoints from page source.

        Args:
            driver: Selenium WebDriver
            base_url: Base URL for relative paths
        """
        try:
            # Execute JavaScript to find fetch/axios calls
            endpoints = driver.execute_script("""
                const endpoints = [];
                const scripts = Array.from(document.scripts);
                
                for (const script of scripts) {
                    const text = script.textContent || '';
                    
                    // Match fetch() calls
                    const fetchMatches = text.matchAll(/fetch\\s*\\(\\s*['"`]([^'"`]+)['"`]/g);
                    for (const match of fetchMatches) {
                        endpoints.push(match[1]);
                    }
                    
                    // Match axios calls
                    const axiosMatches = text.matchAll(/axios\\.(get|post|put|delete|patch)\\s*\\(\\s*['"`]([^'"`]+)['"`]/g);
                    for (const match of axiosMatches) {
                        endpoints.push(match[2]);
                    }
                }
                
                return endpoints;
            """)
            
            for endpoint in endpoints:
                full_url = urljoin(base_url, endpoint)
                self.discovered_endpoints.add(full_url)
                logger.debug(f"Discovered endpoint from page: {full_url}")
        
        except Exception as e:
            logger.debug(f"Error extracting endpoints from page: {e}")

    def _trigger_interactions(self, driver: webdriver.Chrome):
        """
        Triggers interactions to discover dynamic content.

        Args:
            driver: Selenium WebDriver
        """
        try:
            # Find and click buttons
            buttons = driver.find_elements(By.TAG_NAME, "button")
            buttons.extend(driver.find_elements(By.CSS_SELECTOR, "input[type='button']"))
            buttons.extend(driver.find_elements(By.CSS_SELECTOR, "input[type='submit']"))
            
            for button in buttons[:5]:  # Limit to first 5 buttons
                try:
                    if button.is_displayed() and button.is_enabled():
                        button.click()
                        time.sleep(1)  # Wait for AJAX
                except Exception:
                    pass
        
        except Exception as e:
            logger.debug(f"Error triggering interactions: {e}")

    def crawl_with_auth(
        self,
        start_url: str,
        login_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        submit_button: str = "button[type='submit']",
    ) -> List[str]:
        """
        Crawls with authentication.

        Args:
            start_url: Starting URL to crawl
            login_url: Login page URL
            username: Username for authentication
            password: Password for authentication
            username_field: Username field selector (default: "username")
            password_field: Password field selector (default: "password")
            submit_button: Submit button selector (default: "button[type='submit']")

        Returns:
            List[str]: List of discovered endpoints

        Example:
            endpoints = crawler.crawl_with_auth(
                start_url="https://example.com/chat",
                login_url="https://example.com/login",
                username="test@example.com",
                password="password123",
            )
        """
        # Validate scope
        self.scope_validator.validate_or_raise(start_url)
        self.scope_validator.validate_or_raise(login_url)
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        
        logger.info(f"Starting authenticated Selenium crawl: {start_url}")
        
        # Setup Chrome options
        chrome_options = ChromeOptions()
        if self.headless:
            chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--window-size=1920,1080")
        chrome_options.set_capability("goog:loggingPrefs", {"performance": "ALL"})
        
        # Create driver
        if self.driver_path:
            service = Service(executable_path=self.driver_path)
            driver = webdriver.Chrome(service=service, options=chrome_options)
        else:
            driver = webdriver.Chrome(options=chrome_options)
        
        driver.set_page_load_timeout(self.timeout)
        
        try:
            # Perform login
            logger.info(f"Logging in at: {login_url}")
            driver.get(login_url)
            
            # Wait for login form
            WebDriverWait(driver, self.timeout).until(
                EC.presence_of_element_located((By.NAME, username_field))
            )
            
            # Fill in credentials
            driver.find_element(By.NAME, username_field).send_keys(username)
            driver.find_element(By.NAME, password_field).send_keys(password)
            
            # Submit form
            driver.find_element(By.CSS_SELECTOR, submit_button).click()
            
            # Wait for redirect
            time.sleep(3)
            
            logger.info("Login successful, starting crawl")
            
            # Crawl authenticated pages
            self._crawl_page(driver, start_url)
        
        except Exception as e:
            logger.error(f"Authenticated crawl error: {e}")
        
        finally:
            driver.quit()
        
        logger.info(f"Authenticated crawl complete: {len(self.discovered_endpoints)} endpoints")
        return list(self.discovered_endpoints)


logger.info("Selenium fallback module loaded")
