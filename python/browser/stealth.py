"""
Browser stealth techniques for llmrt.

Implements anti-detection and fingerprint evasion techniques to avoid
bot detection during security testing.

Features:
- WebDriver detection evasion
- Canvas fingerprint randomization
- WebGL fingerprint randomization
- User agent rotation
- Timezone spoofing
- Language spoofing

Usage:
    stealth = BrowserStealth()
    await stealth.apply_playwright(page)
    # or
    stealth.apply_selenium(driver)
"""

import logging
import random
from typing import Optional

logger = logging.getLogger(__name__)


class BrowserStealth:
    """
    Browser stealth and anti-detection techniques.

    Applies various techniques to evade bot detection systems.
    """

    def __init__(self):
        """Initializes browser stealth."""
        self.user_agents = self._get_user_agents()
        logger.info("Browser stealth initialized")

    def _get_user_agents(self) -> list:
        """Returns list of realistic user agents."""
        return [
            # Chrome on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Chrome on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Firefox on Windows
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            # Firefox on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            # Safari on macOS
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        ]

    def get_random_user_agent(self) -> str:
        """Returns random user agent string."""
        return random.choice(self.user_agents)

    async def apply_playwright(self, page):
        """
        Applies stealth techniques to Playwright page.

        Args:
            page: Playwright Page object

        Raises:
            RuntimeError: If stealth application fails
        """
        logger.info("Applying stealth techniques to Playwright")
        
        try:
            # Remove webdriver property
            await page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            # Override permissions
            await page.add_init_script("""
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            
            # Override plugins
            await page.add_init_script("""
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
            """)
            
            # Override languages
            await page.add_init_script("""
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
            """)
            
            # Canvas fingerprint randomization
            await page.add_init_script("""
                const getImageData = CanvasRenderingContext2D.prototype.getImageData;
                CanvasRenderingContext2D.prototype.getImageData = function() {
                    const imageData = getImageData.apply(this, arguments);
                    for (let i = 0; i < imageData.data.length; i += 4) {
                        imageData.data[i] += Math.floor(Math.random() * 10) - 5;
                        imageData.data[i + 1] += Math.floor(Math.random() * 10) - 5;
                        imageData.data[i + 2] += Math.floor(Math.random() * 10) - 5;
                    }
                    return imageData;
                };
            """)
            
            # WebGL fingerprint randomization
            await page.add_init_script("""
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) {
                        return 'Intel Inc.';
                    }
                    if (parameter === 37446) {
                        return 'Intel Iris OpenGL Engine';
                    }
                    return getParameter.apply(this, arguments);
                };
            """)
            
            # Chrome runtime
            await page.add_init_script("""
                window.chrome = {
                    runtime: {}
                };
            """)
            
            # Timezone spoofing
            await page.add_init_script("""
                Date.prototype.getTimezoneOffset = function() {
                    return -300; // EST timezone
                };
            """)
            
            logger.info("Stealth techniques applied to Playwright")
            
        except Exception as e:
            logger.error(f"Failed to apply stealth techniques: {e}")
            raise RuntimeError(f"Stealth application failed: {e}")

    def apply_selenium(self, driver):
        """
        Applies stealth techniques to Selenium driver.

        Args:
            driver: Selenium WebDriver object

        Raises:
            RuntimeError: If stealth application fails
        """
        logger.info("Applying stealth techniques to Selenium")
        
        try:
            # Remove webdriver property
            driver.execute_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            # Override permissions
            driver.execute_script("""
                const originalQuery = window.navigator.permissions.query;
                window.navigator.permissions.query = (parameters) => (
                    parameters.name === 'notifications' ?
                        Promise.resolve({ state: Notification.permission }) :
                        originalQuery(parameters)
                );
            """)
            
            # Override plugins
            driver.execute_script("""
                Object.defineProperty(navigator, 'plugins', {
                    get: () => [1, 2, 3, 4, 5]
                });
            """)
            
            # Override languages
            driver.execute_script("""
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
            """)
            
            # Canvas fingerprint randomization
            driver.execute_script("""
                const getImageData = CanvasRenderingContext2D.prototype.getImageData;
                CanvasRenderingContext2D.prototype.getImageData = function() {
                    const imageData = getImageData.apply(this, arguments);
                    for (let i = 0; i < imageData.data.length; i += 4) {
                        imageData.data[i] += Math.floor(Math.random() * 10) - 5;
                        imageData.data[i + 1] += Math.floor(Math.random() * 10) - 5;
                        imageData.data[i + 2] += Math.floor(Math.random() * 10) - 5;
                    }
                    return imageData;
                };
            """)
            
            # WebGL fingerprint randomization
            driver.execute_script("""
                const getParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {
                    if (parameter === 37445) {
                        return 'Intel Inc.';
                    }
                    if (parameter === 37446) {
                        return 'Intel Iris OpenGL Engine';
                    }
                    return getParameter.apply(this, arguments);
                };
            """)
            
            # Chrome runtime
            driver.execute_script("""
                window.chrome = {
                    runtime: {}
                };
            """)
            
            # Timezone spoofing
            driver.execute_script("""
                Date.prototype.getTimezoneOffset = function() {
                    return -300; // EST timezone
                };
            """)
            
            logger.info("Stealth techniques applied to Selenium")
            
        except Exception as e:
            logger.error(f"Failed to apply stealth techniques: {e}")
            raise RuntimeError(f"Stealth application failed: {e}")

    def get_stealth_headers(self) -> dict:
        """
        Returns HTTP headers for stealth requests.

        Returns:
            dict: HTTP headers
        """
        return {
            "User-Agent": self.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0"
        }

    def randomize_viewport(self) -> tuple:
        """
        Returns randomized viewport dimensions.

        Returns:
            tuple: (width, height)
        """
        common_resolutions = [
            (1920, 1080),
            (1366, 768),
            (1440, 900),
            (1536, 864),
            (1280, 720)
        ]
        return random.choice(common_resolutions)

    def get_random_timezone(self) -> str:
        """
        Returns random timezone.

        Returns:
            str: Timezone string
        """
        timezones = [
            "America/New_York",
            "America/Los_Angeles",
            "America/Chicago",
            "Europe/London",
            "Europe/Paris",
            "Asia/Tokyo",
            "Australia/Sydney"
        ]
        return random.choice(timezones)

    def get_random_locale(self) -> str:
        """
        Returns random locale.

        Returns:
            str: Locale string
        """
        locales = [
            "en-US",
            "en-GB",
            "en-CA",
            "en-AU",
            "fr-FR",
            "de-DE",
            "es-ES"
        ]
        return random.choice(locales)


logger.info("Browser stealth module loaded")
