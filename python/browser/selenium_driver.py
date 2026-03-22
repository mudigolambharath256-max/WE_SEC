"""
Selenium browser driver for llmrt.

Provides browser automation using Selenium WebDriver as fallback
for complex scenarios or when Playwright is not available.

Features:
- Multiple browser support
- Headless mode
- Cookie management
- Screenshot capture
- JavaScript execution
- Element interaction

Usage:
    driver = SeleniumDriver()
    driver.start()
    driver.navigate("https://target.com")
    content = driver.get_content()
    driver.stop()
"""

import logging
from typing import Optional, Dict, List
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.common.exceptions import TimeoutException, WebDriverException

logger = logging.getLogger(__name__)


class SeleniumDriver:
    """
    Selenium WebDriver automation driver.

    Provides browser automation interface for security testing.
    """

    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chrome",
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None
    ):
        """
        Initializes Selenium driver.

        Args:
            headless: Run browser in headless mode
            browser_type: Browser type (chrome, firefox)
            user_agent: Custom user agent string
            proxy: Proxy server URL
        """
        self.headless = headless
        self.browser_type = browser_type
        self.user_agent = user_agent
        self.proxy = proxy
        
        self.driver = None
        
        logger.info(f"Selenium driver initialized ({browser_type}, headless={headless})")

    def start(self):
        """
        Starts browser instance.

        Raises:
            RuntimeError: If browser fails to start
        """
        logger.info("Starting Selenium browser")
        
        try:
            if self.browser_type == "chrome":
                self.driver = self._start_chrome()
            elif self.browser_type == "firefox":
                self.driver = self._start_firefox()
            else:
                raise ValueError(f"Invalid browser type: {self.browser_type}")
            
            logger.info("Selenium browser started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start browser: {e}")
            raise RuntimeError(f"Browser start failed: {e}")

    def _start_chrome(self):
        """Starts Chrome browser."""
        options = ChromeOptions()
        
        if self.headless:
            options.add_argument("--headless=new")
        
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        
        if self.user_agent:
            options.add_argument(f"user-agent={self.user_agent}")
        
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")
        
        return webdriver.Chrome(options=options)

    def _start_firefox(self):
        """Starts Firefox browser."""
        options = FirefoxOptions()
        
        if self.headless:
            options.add_argument("--headless")
        
        if self.user_agent:
            options.set_preference("general.useragent.override", self.user_agent)
        
        if self.proxy:
            # Parse proxy URL
            from urllib.parse import urlparse
            parsed = urlparse(self.proxy)
            options.set_preference("network.proxy.type", 1)
            options.set_preference("network.proxy.http", parsed.hostname)
            options.set_preference("network.proxy.http_port", parsed.port or 8080)
            options.set_preference("network.proxy.ssl", parsed.hostname)
            options.set_preference("network.proxy.ssl_port", parsed.port or 8080)
        
        return webdriver.Firefox(options=options)

    def stop(self):
        """Stops browser instance."""
        logger.info("Stopping Selenium browser")
        
        try:
            if self.driver:
                self.driver.quit()
            
            logger.info("Selenium browser stopped")
            
        except Exception as e:
            logger.warning(f"Error stopping browser: {e}")

    def navigate(self, url: str, timeout: int = 30) -> bool:
        """
        Navigates to URL.

        Args:
            url: Target URL
            timeout: Page load timeout in seconds

        Returns:
            bool: True if navigation successful

        Raises:
            RuntimeError: If navigation fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started. Call start() first.")
        
        logger.info(f"Navigating to {url}")
        
        try:
            self.driver.set_page_load_timeout(timeout)
            self.driver.get(url)
            logger.info(f"Successfully navigated to {url}")
            return True
            
        except TimeoutException:
            logger.warning(f"Navigation timeout for {url}")
            return False
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            raise RuntimeError(f"Navigation to {url} failed: {e}")

    def get_content(self) -> str:
        """
        Gets page HTML content.

        Returns:
            str: Page HTML content

        Raises:
            RuntimeError: If page not loaded
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        try:
            content = self.driver.page_source
            logger.debug(f"Retrieved page content ({len(content)} bytes)")
            return content
            
        except Exception as e:
            logger.error(f"Failed to get content: {e}")
            raise RuntimeError(f"Content retrieval failed: {e}")

    def get_text(self) -> str:
        """
        Gets page text content (without HTML tags).

        Returns:
            str: Page text content
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        try:
            text = self.driver.find_element(By.TAG_NAME, "body").text
            return text
            
        except Exception as e:
            logger.error(f"Failed to get text: {e}")
            return ""

    def screenshot(self, output_path: str):
        """
        Takes screenshot of page.

        Args:
            output_path: Path to save screenshot

        Raises:
            RuntimeError: If screenshot fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.info(f"Taking screenshot: {output_path}")
        
        try:
            from pathlib import Path
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            self.driver.save_screenshot(str(output_file))
            logger.info(f"Screenshot saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            raise RuntimeError(f"Screenshot failed: {e}")

    def click(self, selector: str, by: str = "css"):
        """
        Clicks element by selector.

        Args:
            selector: Element selector
            by: Selector type (css, xpath, id, name)

        Raises:
            RuntimeError: If click fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Clicking element: {selector}")
        
        try:
            by_type = self._get_by_type(by)
            element = self.driver.find_element(by_type, selector)
            element.click()
            logger.debug(f"Clicked element: {selector}")
            
        except Exception as e:
            logger.error(f"Click failed: {e}")
            raise RuntimeError(f"Click on {selector} failed: {e}")

    def fill(self, selector: str, value: str, by: str = "css"):
        """
        Fills input field.

        Args:
            selector: Element selector
            value: Value to fill
            by: Selector type (css, xpath, id, name)

        Raises:
            RuntimeError: If fill fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Filling field: {selector}")
        
        try:
            by_type = self._get_by_type(by)
            element = self.driver.find_element(by_type, selector)
            element.clear()
            element.send_keys(value)
            logger.debug(f"Filled field: {selector}")
            
        except Exception as e:
            logger.error(f"Fill failed: {e}")
            raise RuntimeError(f"Fill on {selector} failed: {e}")

    def execute_script(self, script: str):
        """
        Executes JavaScript in page context.

        Args:
            script: JavaScript code to execute

        Returns:
            Result of script execution

        Raises:
            RuntimeError: If execution fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.debug("Executing JavaScript")
        
        try:
            result = self.driver.execute_script(script)
            return result
            
        except Exception as e:
            logger.error(f"JavaScript execution failed: {e}")
            raise RuntimeError(f"Script execution failed: {e}")

    def wait_for_element(self, selector: str, by: str = "css", timeout: int = 10):
        """
        Waits for element to appear.

        Args:
            selector: Element selector
            by: Selector type (css, xpath, id, name)
            timeout: Timeout in seconds

        Raises:
            RuntimeError: If element doesn't appear
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Waiting for element: {selector}")
        
        try:
            by_type = self._get_by_type(by)
            wait = WebDriverWait(self.driver, timeout)
            wait.until(EC.presence_of_element_located((by_type, selector)))
            logger.debug(f"Element appeared: {selector}")
            
        except TimeoutException:
            logger.error(f"Element did not appear: {selector}")
            raise RuntimeError(f"Element {selector} did not appear within {timeout}s")
        except Exception as e:
            logger.error(f"Wait for element failed: {e}")
            raise RuntimeError(f"Wait failed: {e}")

    def get_cookies(self) -> List[Dict]:
        """
        Gets browser cookies.

        Returns:
            list: List of cookie dictionaries
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        try:
            cookies = self.driver.get_cookies()
            logger.debug(f"Retrieved {len(cookies)} cookies")
            return cookies
            
        except Exception as e:
            logger.error(f"Failed to get cookies: {e}")
            return []

    def set_cookie(self, cookie: Dict):
        """
        Sets browser cookie.

        Args:
            cookie: Cookie dictionary

        Raises:
            RuntimeError: If setting cookie fails
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        logger.debug("Setting cookie")
        
        try:
            self.driver.add_cookie(cookie)
            logger.debug("Cookie set successfully")
            
        except Exception as e:
            logger.error(f"Failed to set cookie: {e}")
            raise RuntimeError(f"Cookie setting failed: {e}")

    def get_local_storage(self) -> Dict:
        """
        Gets localStorage data.

        Returns:
            dict: localStorage key-value pairs
        """
        if not self.driver:
            raise RuntimeError("Browser not started")
        
        try:
            storage = self.driver.execute_script(
                "return Object.assign({}, window.localStorage);"
            )
            return storage
            
        except Exception as e:
            logger.error(f"Failed to get localStorage: {e}")
            return {}

    def _get_by_type(self, by: str):
        """Converts string selector type to Selenium By type."""
        by_map = {
            "css": By.CSS_SELECTOR,
            "xpath": By.XPATH,
            "id": By.ID,
            "name": By.NAME,
            "class": By.CLASS_NAME,
            "tag": By.TAG_NAME
        }
        return by_map.get(by.lower(), By.CSS_SELECTOR)


logger.info("Selenium driver module loaded")
