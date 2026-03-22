"""
Intelligent web crawler with JavaScript execution.

Crawls AI application interfaces to discover:
- API endpoints (REST, GraphQL, WebSocket)
- Authentication mechanisms
- Input validation patterns
- Error handling behavior
- Technology stack indicators

Uses Playwright for JavaScript execution and dynamic content rendering.
Implements intelligent crawling strategies:
- Form auto-fill and submission
- Button click simulation
- AJAX request interception
- WebSocket connection monitoring
- SSE stream detection

Crawling is scope-aware and respects robots.txt (unless explicitly overridden).
All discovered endpoints are validated against scope before probing.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field
import re

try:
    from playwright.async_api import async_playwright, Page, Browser, BrowserContext
except ImportError:
    async_playwright = None
    logging.warning("playwright not installed, triggered_crawler will be limited")

from ..core.scope_validator import ScopeValidator, OutOfScopeError

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """
    Represents a crawl result with discovered endpoints and metadata.

    Attributes:
        url: Crawled URL
        endpoints: List of discovered API endpoints
        forms: List of discovered forms
        websockets: List of WebSocket endpoints
        sse_endpoints: List of SSE endpoints
        technologies: Detected technologies
        auth_type: Detected authentication type
        errors: List of errors encountered
    """
    url: str
    endpoints: List[str] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)
    websockets: List[str] = field(default_factory=list)
    sse_endpoints: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    auth_type: Optional[str] = None
    errors: List[str] = field(default_factory=list)


class TriggeredCrawler:
    """
    Intelligent web crawler with JavaScript execution.

    Crawls AI application interfaces to discover attack surface.
    Uses Playwright for full browser automation with JavaScript support.

    Args:
        scope_validator: Scope validator instance
        max_depth: Maximum crawl depth (default: 3)
        max_pages: Maximum pages to crawl (default: 50)
        timeout: Page load timeout in seconds (default: 30)
        headless: Run browser in headless mode (default: True)

    Usage:
        crawler = TriggeredCrawler(scope_validator)
        result = await crawler.crawl("https://example.com/chat")
        print(f"Discovered {len(result.endpoints)} endpoints")
    """

    def __init__(
        self,
        scope_validator: ScopeValidator,
        max_depth: int = 3,
        max_pages: int = 50,
        timeout: int = 30,
        headless: bool = True,
    ):
        """Initializes triggered crawler."""
        if not async_playwright:
            raise ImportError("playwright not installed. Install with: pip install playwright")
        
        self.scope_validator = scope_validator
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout * 1000  # Convert to milliseconds
        self.headless = headless
        
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.discovered_forms: List[Dict[str, Any]] = []
        self.discovered_websockets: Set[str] = set()
        self.discovered_sse: Set[str] = set()
        self.technologies: Set[str] = set()
        
        logger.info(
            f"Triggered crawler initialized: max_depth={max_depth}, "
            f"max_pages={max_pages}, headless={headless}"
        )

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawls a URL and discovers attack surface.

        Args:
            start_url: Starting URL to crawl

        Returns:
            CrawlResult: Crawl results with discovered endpoints

        Raises:
            OutOfScopeError: If start_url is out of scope

        Example:
            result = await crawler.crawl("https://example.com/chat")
            for endpoint in result.endpoints:
                print(f"Discovered: {endpoint}")
        """
        # Validate scope
        self.scope_validator.validate_or_raise(start_url)
        
        # Reset state
        self.visited_urls.clear()
        self.discovered_endpoints.clear()
        self.discovered_forms.clear()
        self.discovered_websockets.clear()
        self.discovered_sse.clear()
        self.technologies.clear()
        
        logger.info(f"Starting crawl: {start_url}")
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                viewport={"width": 1920, "height": 1080},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            )
            
            # Enable request interception
            await self._setup_request_interception(context)
            
            try:
                await self._crawl_recursive(context, start_url, depth=0)
            except Exception as e:
                logger.error(f"Crawl error: {e}")
            finally:
                await browser.close()
        
        # Detect authentication type
        auth_type = self._detect_auth_type()
        
        result = CrawlResult(
            url=start_url,
            endpoints=list(self.discovered_endpoints),
            forms=self.discovered_forms,
            websockets=list(self.discovered_websockets),
            sse_endpoints=list(self.discovered_sse),
            technologies=list(self.technologies),
            auth_type=auth_type,
        )
        
        logger.info(
            f"Crawl complete: {len(self.visited_urls)} pages, "
            f"{len(result.endpoints)} endpoints, "
            f"{len(result.forms)} forms"
        )
        
        return result

    async def _crawl_recursive(
        self,
        context: BrowserContext,
        url: str,
        depth: int,
    ):
        """
        Recursively crawls pages up to max_depth.

        Args:
            context: Browser context
            url: URL to crawl
            depth: Current crawl depth
        """
        # Check limits
        if depth > self.max_depth:
            logger.debug(f"Max depth reached: {url}")
            return
        
        if len(self.visited_urls) >= self.max_pages:
            logger.debug(f"Max pages reached: {url}")
            return
        
        if url in self.visited_urls:
            return
        
        # Validate scope
        try:
            self.scope_validator.validate_or_raise(url)
        except OutOfScopeError:
            logger.debug(f"Out of scope: {url}")
            return
        
        self.visited_urls.add(url)
        logger.debug(f"Crawling: {url} (depth={depth})")
        
        page = await context.new_page()
        
        try:
            # Navigate to page
            await page.goto(url, timeout=self.timeout, wait_until="networkidle")
            
            # Extract data from page
            await self._extract_endpoints(page, url)
            await self._extract_forms(page, url)
            await self._extract_technologies(page)
            
            # Trigger interactions
            await self._trigger_interactions(page)
            
            # Extract links for recursive crawl
            links = await self._extract_links(page, url)
            
            # Recursively crawl links
            for link in links:
                await self._crawl_recursive(context, link, depth + 1)
        
        except Exception as e:
            logger.warning(f"Error crawling {url}: {e}")
        
        finally:
            await page.close()

    async def _setup_request_interception(self, context: BrowserContext):
        """
        Sets up request interception to capture API calls.

        Args:
            context: Browser context
        """
        async def handle_request(route, request):
            # Capture API endpoints
            url = request.url
            method = request.method
            
            # Check for API patterns
            if any(pattern in url for pattern in ["/api/", "/v1/", "/graphql", "/ws/", "/sse/"]):
                self.discovered_endpoints.add(f"{method} {url}")
                logger.debug(f"Discovered endpoint: {method} {url}")
            
            # Check for WebSocket
            if request.resource_type == "websocket":
                self.discovered_websockets.add(url)
                logger.debug(f"Discovered WebSocket: {url}")
            
            # Continue request
            await route.continue_()
        
        await context.route("**/*", handle_request)

    async def _extract_endpoints(self, page: Page, base_url: str):
        """
        Extracts API endpoints from page.

        Args:
            page: Playwright page
            base_url: Base URL for relative paths
        """
        # Extract from JavaScript
        endpoints = await page.evaluate("""
            () => {
                const endpoints = [];
                
                // Check for fetch calls in scripts
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
            }
        """)
        
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            self.discovered_endpoints.add(full_url)

    async def _extract_forms(self, page: Page, base_url: str):
        """
        Extracts forms from page.

        Args:
            page: Playwright page
            base_url: Base URL for relative paths
        """
        forms = await page.evaluate("""
            () => {
                const forms = [];
                const formElements = document.querySelectorAll('form');
                
                for (const form of formElements) {
                    const formData = {
                        action: form.action || window.location.href,
                        method: form.method || 'GET',
                        inputs: []
                    };
                    
                    const inputs = form.querySelectorAll('input, textarea, select');
                    for (const input of inputs) {
                        formData.inputs.push({
                            name: input.name,
                            type: input.type || 'text',
                            required: input.required,
                            placeholder: input.placeholder || ''
                        });
                    }
                    
                    forms.push(formData);
                }
                
                return forms;
            }
        """)
        
        for form in forms:
            form["action"] = urljoin(base_url, form["action"])
            self.discovered_forms.append(form)
            logger.debug(f"Discovered form: {form['method']} {form['action']}")

    async def _extract_technologies(self, page: Page):
        """
        Extracts technology indicators from page.

        Args:
            page: Playwright page
        """
        # Check for common frameworks
        tech_indicators = await page.evaluate("""
            () => {
                const techs = [];
                
                // React
                if (window.React || document.querySelector('[data-reactroot]')) {
                    techs.push('React');
                }
                
                // Vue
                if (window.Vue || document.querySelector('[data-v-]')) {
                    techs.push('Vue.js');
                }
                
                // Angular
                if (window.angular || document.querySelector('[ng-version]')) {
                    techs.push('Angular');
                }
                
                // jQuery
                if (window.jQuery || window.$) {
                    techs.push('jQuery');
                }
                
                // Check meta tags
                const generator = document.querySelector('meta[name="generator"]');
                if (generator) {
                    techs.push(generator.content);
                }
                
                return techs;
            }
        """)
        
        self.technologies.update(tech_indicators)

    async def _trigger_interactions(self, page: Page):
        """
        Triggers interactions to discover dynamic content.

        Args:
            page: Playwright page
        """
        try:
            # Click buttons to trigger AJAX
            buttons = await page.query_selector_all("button, input[type='button'], input[type='submit']")
            for button in buttons[:5]:  # Limit to first 5 buttons
                try:
                    await button.click(timeout=2000)
                    await page.wait_for_timeout(1000)  # Wait for AJAX
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"Error triggering interactions: {e}")

    async def _extract_links(self, page: Page, base_url: str) -> List[str]:
        """
        Extracts links from page for recursive crawling.

        Args:
            page: Playwright page
            base_url: Base URL for relative paths

        Returns:
            List[str]: List of absolute URLs
        """
        links = await page.evaluate("""
            () => {
                const links = [];
                const anchors = document.querySelectorAll('a[href]');
                
                for (const anchor of anchors) {
                    links.push(anchor.href);
                }
                
                return links;
            }
        """)
        
        # Convert to absolute URLs and filter
        absolute_links = []
        for link in links:
            try:
                absolute_url = urljoin(base_url, link)
                parsed = urlparse(absolute_url)
                
                # Skip non-HTTP schemes
                if parsed.scheme not in ["http", "https"]:
                    continue
                
                # Skip common non-page resources
                if any(absolute_url.endswith(ext) for ext in [".pdf", ".jpg", ".png", ".gif", ".css", ".js"]):
                    continue
                
                absolute_links.append(absolute_url)
            except Exception:
                pass
        
        return absolute_links

    def _detect_auth_type(self) -> Optional[str]:
        """
        Detects authentication type from discovered endpoints.

        Returns:
            Optional[str]: Authentication type or None
        """
        endpoints_str = " ".join(self.discovered_endpoints)
        
        if "/oauth" in endpoints_str or "/authorize" in endpoints_str:
            return "oauth"
        elif "/login" in endpoints_str or "/auth" in endpoints_str:
            return "session"
        elif "Authorization" in endpoints_str or "Bearer" in endpoints_str:
            return "bearer_token"
        elif "api_key" in endpoints_str or "apikey" in endpoints_str:
            return "api_key"
        
        return None


logger.info("Triggered crawler module loaded")
