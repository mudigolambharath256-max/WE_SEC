"""
Playwright browser driver for llmrt.

Provides headless browser automation using Playwright for testing
AI applications with JavaScript-heavy interfaces.

Features:
- Headless and headed modes
- Stealth techniques
- Screenshot capture
- Network interception
- Cookie management
- Form interaction

Usage:
    driver = PlaywrightDriver()
    await driver.start()
    await driver.navigate("https://target.com")
    content = await driver.get_content()
    await driver.stop()
"""

import logging
from typing import Optional, Dict, List
from playwright.async_api import async_playwright, Browser, Page, BrowserContext
import asyncio

logger = logging.getLogger(__name__)


class PlaywrightDriver:
    """
    Playwright browser automation driver.

    Provides high-level browser automation interface for security testing.
    """

    def __init__(
        self,
        headless: bool = True,
        browser_type: str = "chromium",
        user_agent: Optional[str] = None,
        proxy: Optional[Dict] = None
    ):
        """
        Initializes Playwright driver.

        Args:
            headless: Run browser in headless mode
            browser_type: Browser type (chromium, firefox, webkit)
            user_agent: Custom user agent string
            proxy: Proxy configuration dict
        """
        self.headless = headless
        self.browser_type = browser_type
        self.user_agent = user_agent
        self.proxy = proxy
        
        self.playwright = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        
        logger.info(f"Playwright driver initialized ({browser_type}, headless={headless})")

    async def start(self):
        """
        Starts browser instance.

        Raises:
            RuntimeError: If browser fails to start
        """
        logger.info("Starting Playwright browser")
        
        try:
            self.playwright = await async_playwright().start()
            
            # Select browser type
            if self.browser_type == "chromium":
                browser_launcher = self.playwright.chromium
            elif self.browser_type == "firefox":
                browser_launcher = self.playwright.firefox
            elif self.browser_type == "webkit":
                browser_launcher = self.playwright.webkit
            else:
                raise ValueError(f"Invalid browser type: {self.browser_type}")
            
            # Launch browser
            launch_options = {
                "headless": self.headless,
                "proxy": self.proxy
            }
            
            self.browser = await browser_launcher.launch(**launch_options)
            
            # Create context
            context_options = {}
            if self.user_agent:
                context_options["user_agent"] = self.user_agent
            
            self.context = await self.browser.new_context(**context_options)
            
            # Create page
            self.page = await self.context.new_page()
            
            logger.info("Playwright browser started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start browser: {e}")
            raise RuntimeError(f"Browser start failed: {e}")

    async def stop(self):
        """Stops browser instance."""
        logger.info("Stopping Playwright browser")
        
        try:
            if self.page:
                await self.page.close()
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            
            logger.info("Playwright browser stopped")
            
        except Exception as e:
            logger.warning(f"Error stopping browser: {e}")

    async def navigate(self, url: str, wait_until: str = "networkidle") -> bool:
        """
        Navigates to URL.

        Args:
            url: Target URL
            wait_until: Wait condition (load, domcontentloaded, networkidle)

        Returns:
            bool: True if navigation successful

        Raises:
            RuntimeError: If navigation fails
        """
        if not self.page:
            raise RuntimeError("Browser not started. Call start() first.")
        
        logger.info(f"Navigating to {url}")
        
        try:
            response = await self.page.goto(url, wait_until=wait_until, timeout=30000)
            
            if response and response.ok:
                logger.info(f"Successfully navigated to {url}")
                return True
            else:
                logger.warning(f"Navigation returned status {response.status if response else 'None'}")
                return False
                
        except Exception as e:
            logger.error(f"Navigation failed: {e}")
            raise RuntimeError(f"Navigation to {url} failed: {e}")

    async def get_content(self) -> str:
        """
        Gets page HTML content.

        Returns:
            str: Page HTML content

        Raises:
            RuntimeError: If page not loaded
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        try:
            content = await self.page.content()
            logger.debug(f"Retrieved page content ({len(content)} bytes)")
            return content
            
        except Exception as e:
            logger.error(f"Failed to get content: {e}")
            raise RuntimeError(f"Content retrieval failed: {e}")

    async def get_text(self) -> str:
        """
        Gets page text content (without HTML tags).

        Returns:
            str: Page text content
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        try:
            text = await self.page.inner_text("body")
            return text
            
        except Exception as e:
            logger.error(f"Failed to get text: {e}")
            return ""

    async def screenshot(self, output_path: str, full_page: bool = True):
        """
        Takes screenshot of page.

        Args:
            output_path: Path to save screenshot
            full_page: Capture full page or viewport only

        Raises:
            RuntimeError: If screenshot fails
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.info(f"Taking screenshot: {output_path}")
        
        try:
            from pathlib import Path
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            await self.page.screenshot(path=str(output_file), full_page=full_page)
            logger.info(f"Screenshot saved to {output_path}")
            
        except Exception as e:
            logger.error(f"Screenshot failed: {e}")
            raise RuntimeError(f"Screenshot failed: {e}")

    async def click(self, selector: str):
        """
        Clicks element by selector.

        Args:
            selector: CSS selector

        Raises:
            RuntimeError: If click fails
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Clicking element: {selector}")
        
        try:
            await self.page.click(selector, timeout=5000)
            logger.debug(f"Clicked element: {selector}")
            
        except Exception as e:
            logger.error(f"Click failed: {e}")
            raise RuntimeError(f"Click on {selector} failed: {e}")

    async def fill(self, selector: str, value: str):
        """
        Fills input field.

        Args:
            selector: CSS selector
            value: Value to fill

        Raises:
            RuntimeError: If fill fails
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Filling field: {selector}")
        
        try:
            await self.page.fill(selector, value, timeout=5000)
            logger.debug(f"Filled field: {selector}")
            
        except Exception as e:
            logger.error(f"Fill failed: {e}")
            raise RuntimeError(f"Fill on {selector} failed: {e}")

    async def evaluate(self, script: str):
        """
        Evaluates JavaScript in page context.

        Args:
            script: JavaScript code to evaluate

        Returns:
            Result of script evaluation

        Raises:
            RuntimeError: If evaluation fails
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.debug("Evaluating JavaScript")
        
        try:
            result = await self.page.evaluate(script)
            return result
            
        except Exception as e:
            logger.error(f"JavaScript evaluation failed: {e}")
            raise RuntimeError(f"Script evaluation failed: {e}")

    async def wait_for_selector(self, selector: str, timeout: int = 5000):
        """
        Waits for element to appear.

        Args:
            selector: CSS selector
            timeout: Timeout in milliseconds

        Raises:
            RuntimeError: If element doesn't appear
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Waiting for selector: {selector}")
        
        try:
            await self.page.wait_for_selector(selector, timeout=timeout)
            logger.debug(f"Selector appeared: {selector}")
            
        except Exception as e:
            logger.error(f"Wait for selector failed: {e}")
            raise RuntimeError(f"Selector {selector} did not appear: {e}")

    async def get_cookies(self) -> List[Dict]:
        """
        Gets browser cookies.

        Returns:
            list: List of cookie dictionaries
        """
        if not self.context:
            raise RuntimeError("Browser not started")
        
        try:
            cookies = await self.context.cookies()
            logger.debug(f"Retrieved {len(cookies)} cookies")
            return cookies
            
        except Exception as e:
            logger.error(f"Failed to get cookies: {e}")
            return []

    async def set_cookies(self, cookies: List[Dict]):
        """
        Sets browser cookies.

        Args:
            cookies: List of cookie dictionaries

        Raises:
            RuntimeError: If setting cookies fails
        """
        if not self.context:
            raise RuntimeError("Browser not started")
        
        logger.debug(f"Setting {len(cookies)} cookies")
        
        try:
            await self.context.add_cookies(cookies)
            logger.debug("Cookies set successfully")
            
        except Exception as e:
            logger.error(f"Failed to set cookies: {e}")
            raise RuntimeError(f"Cookie setting failed: {e}")

    async def intercept_requests(self, callback):
        """
        Intercepts network requests.

        Args:
            callback: Async function to handle requests

        Raises:
            RuntimeError: If interception setup fails
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        logger.info("Setting up request interception")
        
        try:
            await self.page.route("**/*", callback)
            logger.info("Request interception enabled")
            
        except Exception as e:
            logger.error(f"Failed to setup interception: {e}")
            raise RuntimeError(f"Request interception failed: {e}")

    async def get_local_storage(self) -> Dict:
        """
        Gets localStorage data.

        Returns:
            dict: localStorage key-value pairs
        """
        if not self.page:
            raise RuntimeError("Browser not started")
        
        try:
            storage = await self.page.evaluate("() => Object.assign({}, window.localStorage)")
            return storage
            
        except Exception as e:
            logger.error(f"Failed to get localStorage: {e}")
            return {}


logger.info("Playwright driver module loaded")
