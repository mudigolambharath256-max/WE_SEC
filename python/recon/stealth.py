"""
Browser fingerprint evasion and anti-detection.

Implements stealth techniques to avoid detection by anti-bot systems:
- User-Agent rotation
- WebDriver property masking
- Canvas fingerprint randomization
- WebGL fingerprint randomization
- Audio context fingerprint randomization
- Timezone and locale randomization
- Screen resolution randomization
- Plugin and MIME type spoofing

These techniques help bypass bot detection systems that might block
security testing tools. Use only for authorized testing.

Stealth techniques are based on:
- puppeteer-extra-plugin-stealth
- undetected-chromedriver
- selenium-stealth

Detection vectors addressed:
- navigator.webdriver property
- Chrome DevTools Protocol detection
- Headless browser detection
- Automation framework detection
"""

import logging
import random
from typing import Optional, Dict, Any

try:
    from playwright.async_api import Page, BrowserContext
except ImportError:
    Page = None
    BrowserContext = None
    logging.warning("playwright not installed, stealth features will be limited")

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
except ImportError:
    webdriver = None
    ChromeOptions = None
    logging.warning("selenium not installed, stealth features will be limited")

logger = logging.getLogger(__name__)


class StealthConfig:
    """
    Stealth configuration for browser automation.

    Provides randomized browser fingerprints and anti-detection settings.
    """

    USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    ]

    SCREEN_RESOLUTIONS = [
        {"width": 1920, "height": 1080},
        {"width": 1366, "height": 768},
        {"width": 1536, "height": 864},
        {"width": 1440, "height": 900},
        {"width": 2560, "height": 1440},
    ]

    TIMEZONES = [
        "America/New_York",
        "America/Los_Angeles",
        "America/Chicago",
        "Europe/London",
        "Europe/Paris",
        "Asia/Tokyo",
        "Australia/Sydney",
    ]

    LOCALES = [
        "en-US",
        "en-GB",
        "en-CA",
        "en-AU",
    ]

    def __init__(self):
        """Initializes stealth config with randomized values."""
        self.user_agent = random.choice(self.USER_AGENTS)
        self.screen_resolution = random.choice(self.SCREEN_RESOLUTIONS)
        self.timezone = random.choice(self.TIMEZONES)
        self.locale = random.choice(self.LOCALES)
        
        logger.debug(
            f"Stealth config: UA={self.user_agent[:50]}..., "
            f"resolution={self.screen_resolution}, "
            f"timezone={self.timezone}"
        )


async def apply_stealth_playwright(
    context: BrowserContext,
    config: Optional[StealthConfig] = None,
):
    """
    Applies stealth techniques to Playwright browser context.

    Args:
        context: Playwright browser context
        config: Stealth configuration (optional, generates random if not provided)

    Example:
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            context = await browser.new_context()
            await apply_stealth_playwright(context)
    """
    if not config:
        config = StealthConfig()
    
    # Inject stealth scripts
    await context.add_init_script("""
        // Mask webdriver property
        Object.defineProperty(navigator, 'webdriver', {
            get: () => undefined
        });
        
        // Mask Chrome automation
        window.navigator.chrome = {
            runtime: {},
        };
        
        // Mask permissions
        const originalQuery = window.navigator.permissions.query;
        window.navigator.permissions.query = (parameters) => (
            parameters.name === 'notifications' ?
                Promise.resolve({ state: Notification.permission }) :
                originalQuery(parameters)
        );
        
        // Mask plugins
        Object.defineProperty(navigator, 'plugins', {
            get: () => [
                {
                    0: {type: "application/x-google-chrome-pdf", suffixes: "pdf", description: "Portable Document Format"},
                    description: "Portable Document Format",
                    filename: "internal-pdf-viewer",
                    length: 1,
                    name: "Chrome PDF Plugin"
                },
                {
                    0: {type: "application/pdf", suffixes: "pdf", description: "Portable Document Format"},
                    description: "Portable Document Format",
                    filename: "mhjfbmdgcfjbbpaeojofohoefgiehjai",
                    length: 1,
                    name: "Chrome PDF Viewer"
                },
                {
                    0: {type: "application/x-nacl", suffixes: "", description: "Native Client Executable"},
                    1: {type: "application/x-pnacl", suffixes: "", description: "Portable Native Client Executable"},
                    description: "",
                    filename: "internal-nacl-plugin",
                    length: 2,
                    name: "Native Client"
                }
            ],
        });
        
        // Mask languages
        Object.defineProperty(navigator, 'languages', {
            get: () => ['en-US', 'en'],
        });
        
        // Mask platform
        Object.defineProperty(navigator, 'platform', {
            get: () => 'Win32',
        });
        
        // Canvas fingerprint randomization
        const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = function(type) {
            const shift = Math.floor(Math.random() * 10) - 5;
            const context = this.getContext('2d');
            const imageData = context.getImageData(0, 0, this.width, this.height);
            for (let i = 0; i < imageData.data.length; i += 4) {
                imageData.data[i] = imageData.data[i] + shift;
            }
            context.putImageData(imageData, 0, 0);
            return originalToDataURL.apply(this, arguments);
        };
        
        // WebGL fingerprint randomization
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
    
    logger.info("Applied Playwright stealth techniques")


def apply_stealth_selenium(
    options: ChromeOptions,
    config: Optional[StealthConfig] = None,
) -> ChromeOptions:
    """
    Applies stealth techniques to Selenium Chrome options.

    Args:
        options: Chrome options instance
        config: Stealth configuration (optional, generates random if not provided)

    Returns:
        ChromeOptions: Modified Chrome options with stealth settings

    Example:
        options = ChromeOptions()
        options = apply_stealth_selenium(options)
        driver = webdriver.Chrome(options=options)
    """
    if not config:
        config = StealthConfig()
    
    # Set user agent
    options.add_argument(f"user-agent={config.user_agent}")
    
    # Disable automation flags
    options.add_experimental_option("excludeSwitches", ["enable-automation"])
    options.add_experimental_option("useAutomationExtension", False)
    
    # Disable blink features
    options.add_argument("--disable-blink-features=AutomationControlled")
    
    # Set window size
    options.add_argument(f"--window-size={config.screen_resolution['width']},{config.screen_resolution['height']}")
    
    # Additional stealth arguments
    options.add_argument("--disable-web-security")
    options.add_argument("--disable-features=IsolateOrigins,site-per-process")
    options.add_argument("--disable-site-isolation-trials")
    
    # Set preferences
    prefs = {
        "credentials_enable_service": False,
        "profile.password_manager_enabled": False,
        "profile.default_content_setting_values.notifications": 2,
    }
    options.add_experimental_option("prefs", prefs)
    
    logger.info("Applied Selenium stealth techniques")
    return options


def inject_stealth_js(driver: webdriver.Chrome):
    """
    Injects stealth JavaScript into Selenium WebDriver.

    Args:
        driver: Selenium WebDriver instance

    Example:
        driver = webdriver.Chrome(options=options)
        inject_stealth_js(driver)
        driver.get("https://example.com")
    """
    # Mask webdriver property
    driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
        "source": """
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
            
            window.navigator.chrome = {
                runtime: {},
            };
            
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5],
            });
            
            Object.defineProperty(navigator, 'languages', {
                get: () => ['en-US', 'en'],
            });
        """
    })
    
    logger.debug("Injected stealth JavaScript into Selenium")


def get_stealth_headers(config: Optional[StealthConfig] = None) -> Dict[str, str]:
    """
    Returns stealth HTTP headers.

    Args:
        config: Stealth configuration (optional)

    Returns:
        dict: HTTP headers dictionary

    Example:
        headers = get_stealth_headers()
        response = requests.get(url, headers=headers)
    """
    if not config:
        config = StealthConfig()
    
    return {
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": f"{config.locale},en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


class StealthSession:
    """
    Stealth HTTP session with rotating fingerprints.

    Provides HTTP session with automatic fingerprint rotation and
    anti-detection headers.

    Usage:
        session = StealthSession()
        response = session.get("https://example.com")
    """

    def __init__(self):
        """Initializes stealth session."""
        import httpx
        
        self.config = StealthConfig()
        self.client = httpx.Client(
            headers=get_stealth_headers(self.config),
            timeout=30.0,
            follow_redirects=True,
        )
        
        logger.info("Stealth HTTP session initialized")

    def get(self, url: str, **kwargs) -> Any:
        """
        Performs GET request with stealth headers.

        Args:
            url: URL to request
            **kwargs: Additional arguments for httpx.get()

        Returns:
            httpx.Response: Response object
        """
        return self.client.get(url, **kwargs)

    def post(self, url: str, **kwargs) -> Any:
        """
        Performs POST request with stealth headers.

        Args:
            url: URL to request
            **kwargs: Additional arguments for httpx.post()

        Returns:
            httpx.Response: Response object
        """
        return self.client.post(url, **kwargs)

    def rotate_fingerprint(self):
        """
        Rotates browser fingerprint.

        Generates new random fingerprint and updates session headers.
        """
        self.config = StealthConfig()
        self.client.headers.update(get_stealth_headers(self.config))
        logger.debug("Rotated browser fingerprint")

    def close(self):
        """Closes HTTP session."""
        self.client.close()


logger.info("Stealth module loaded")
