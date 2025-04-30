"""Remote website fetching and analysis module for HashCSP.

This module provides functionality for fetching remote websites, analyzing their
content, and extracting information needed for CSP generation. It handles both
static and dynamic content, and supports various levels of user interaction
simulation.
"""

import asyncio
import re
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Tag
from playwright.async_api import Browser, Page, Response, async_playwright
from rich.console import Console

from .csp_generator import CSPGenerator
from .logging_config import ErrorCodes, get_logger

logger = get_logger(__name__)
console = Console()


class RemoteFetcher:
    """Fetches and analyzes remote websites for CSP generation.

    This class uses Playwright to fetch remote websites, analyze their content,
    and extract information needed for CSP generation. It handles both static
    and dynamic content, and can perform various levels of user interaction
    simulation.

    Attributes:
        csp (CSPGenerator): The CSP generator instance to update with found resources.
    """

    def __init__(self, csp_generator: CSPGenerator):
        """Initialize a RemoteFetcher instance.

        Args:
            csp_generator (CSPGenerator): The CSP generator to update with found resources.
        """
        self.csp = csp_generator

    async def fetch_remote_site(
        self, url: str, wait_time: int, interaction_level: int = 0, retries: int = 2
    ) -> Tuple[bool, Optional[str]]:
        """Fetch a website, mimic user behavior, and extract resources for CSP generation.

        Performs a comprehensive analysis of a remote website including:
        - Fetching the initial page
        - Analyzing inline scripts and styles
        - Tracking network requests for external resources
        - Simulating user interactions based on the specified level
        - Handling dynamic content injection

        Args:
            url (str): The target URL to fetch.
            wait_time (int): Base wait time for resources (seconds).
            interaction_level (int, optional): Level of user interaction simulation:
                - 0: No interaction
                - 1: Basic (scrolling)
                - 2: Advanced (clicking, hovering)
                Defaults to 0.
            retries (int, optional): Number of retry attempts for failed fetches.
                Defaults to 2.

        Returns:
            Tuple[bool, Optional[str]]: A tuple containing:
                - bool: True if the fetch was successful, False otherwise
                - Optional[str]: The website's CSP header if found, None otherwise

        Raises:
            TypeError: If BeautifulSoup returns non-Tag elements.
            ValueError: If the URL protocol is invalid.
        """
        # Validate URL protocol
        if not re.match(r"^https?://", url):
            suggested_url = (
                f"https://{url}" if not url.startswith("http://") else f"http://{url}"
            )
            logger.error("Invalid URL protocol",
                        url=url,
                        suggested_url=suggested_url,
                        operation="fetch_remote_site",
                        error_code=ErrorCodes.VALIDATION_ERROR)
            console.print(
                f"[red]Invalid URL: '{url}'. URLs must start with 'http://' or 'https://'. [/red]"
                f"[yellow]Did you mean '{suggested_url}'?[/yellow]"
            )
            return False, None

        try:
            async with async_playwright() as p:
                logger.debug("Launching browser",
                           url=url,
                           operation="fetch_remote_site")
                
                # Configure stealth settings to bypass bot protection
                browser: Browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    java_script_enabled=True,
                    has_touch=False,
                )
                page: Page = await context.new_page()

                # Track network requests
                network_resources: Dict[str, List[str]] = {
                    "scripts": [],
                    "styles": [],
                    "images": [],
                }
                external_js_urls: List[str] = []

                def handle_request(request):
                    resource_type = request.resource_type
                    if resource_type == "script":
                        network_resources["scripts"].append(request.url)
                        external_js_urls.append(request.url)
                        self.csp.stats["external_scripts"] += 1
                        logger.debug("Detected external script",
                                   url=request.url,
                                   operation="handle_request")
                    elif resource_type == "stylesheet":
                        network_resources["styles"].append(request.url)
                        self.csp.stats["external_styles"] += 1
                        logger.debug("Detected external stylesheet",
                                   url=request.url,
                                   operation="handle_request")
                    elif resource_type == "image":
                        network_resources["images"].append(request.url)
                        self.csp.stats["external_images"] += 1
                        logger.debug("Detected external image",
                                   url=request.url,
                                   operation="handle_request")

                page.on("request", handle_request)

                # Navigate to the URL with retries
                website_csp_header: Optional[str] = None
                for attempt in range(retries + 1):
                    try:
                        logger.info("Attempting to fetch URL",
                                  url=url,
                                  attempt=attempt + 1,
                                  total_attempts=retries + 1,
                                  operation="fetch_remote_site")
                        
                        response: Optional[Response] = await page.goto(
                            url, wait_until="networkidle", timeout=30000
                        )
                        if response:
                            headers = await response.all_headers()
                            website_csp_header = headers.get("content-security-policy")
                            if website_csp_header:
                                logger.info("Found CSP header",
                                          url=url,
                                          operation="fetch_remote_site")
                            else:
                                logger.info("No CSP header found",
                                          url=url,
                                          operation="fetch_remote_site")
                        else:
                            logger.error("No response received",
                                       url=url,
                                       operation="fetch_remote_site",
                                       error_code=ErrorCodes.NETWORK_ERROR)
                            if attempt == retries:
                                await browser.close()
                                return False, None
                            await asyncio.sleep(2**attempt)
                            continue
                        break
                    except Exception as e:
                        logger.error("Failed to fetch URL",
                                   url=url,
                                   attempt=attempt + 1,
                                   error=str(e),
                                   operation="fetch_remote_site",
                                   error_code=ErrorCodes.NETWORK_ERROR,
                                   exc_info=True)
                        if attempt == retries:
                            await browser.close()
                            return False, None
                        await asyncio.sleep(2**attempt)

                # Perform user interactions based on interaction_level
                if interaction_level >= 1:  # Basic interactions
                    logger.debug("Performing basic interactions",
                               url=url,
                               operation="fetch_remote_site")
                    await page.evaluate(
                        "window.scrollTo(0, document.body.scrollHeight)"
                    )
                    await page.wait_for_timeout(1000)
                    await page.wait_for_load_state("networkidle")

                if interaction_level >= 2:  # Advanced interactions
                    logger.debug("Performing advanced interactions",
                               url=url,
                               operation="fetch_remote_site")
                    buttons = await page.query_selector_all(
                        "button, a[href], [onclick]"
                    )
                    for i, element in enumerate(
                        buttons[:5]
                    ):  # Limit to 5 interactions
                        try:
                            await element.click()
                            logger.debug(f"Clicked element {i + 1}",
                                       url=url,
                                       operation="fetch_remote_site")
                            await page.wait_for_timeout(1000)
                            await page.wait_for_load_state("networkidle")
                        except Exception as e:
                            logger.warning(f"Failed to click element {i + 1}",
                                         url=url,
                                         error=str(e),
                                         operation="fetch_remote_site")

                    hoverable = await page.query_selector_all("[onmouseover]")
                    for i, element in enumerate(hoverable[:5]):
                        try:
                            await element.hover()
                            logger.debug(f"Hovered over element {i + 1}",
                                       url=url,
                                       operation="fetch_remote_site")
                            await page.wait_for_timeout(500)
                            await page.wait_for_load_state("networkidle")
                        except Exception as e:
                            logger.warning(f"Failed to hover over element {i + 1}",
                                         url=url,
                                         error=str(e),
                                         operation="fetch_remote_site")

                # Analyze external JS for DOM insertion
                for js_url in external_js_urls:
                    try:
                        js_response = await page.context.request.get(js_url)
                        js_content = await js_response.text()
                        if any(
                            pattern in js_content.lower()
                            for pattern in [
                                "document.createelement('script')",
                                "document.createelement('style')",
                                "innerhtml",
                            ]
                        ):
                            logger.info("Detected dynamic DOM insertion",
                                      url=url,
                                      js_url=js_url,
                                      operation="fetch_remote_site")
                            # Simulate DOM insertion
                            await page.evaluate(
                                """
                                const script = document.createElement('script');
                                script.textContent = 'console.log("Simulated inline script");';
                                document.body.appendChild(script);
                            """
                            )
                            await page.wait_for_timeout(1000)
                            await page.wait_for_load_state("networkidle")
                    except Exception as e:
                        logger.warning("Failed to analyze JS file",
                                     url=url,
                                     js_url=js_url,
                                     error=str(e),
                                     operation="fetch_remote_site")

                # Get page content after interactions
                content = await page.content()
                soup = BeautifulSoup(content, "html.parser")

                # Process inline scripts
                inline_scripts = soup.find_all("script", src=False)
                for script in inline_scripts:
                    if not isinstance(script, Tag):
                        logger.error("Invalid script element type",
                                   url=url,
                                   expected_type="Tag",
                                   actual_type=type(script),
                                   operation="fetch_remote_site",
                                   error_code=ErrorCodes.VALIDATION_ERROR)
                        raise TypeError(f"Expected Tag, got {type(script)}")
                    script_content: Optional[str] = script.string
                    if script_content and script_content.strip():
                        hash_value = self.csp.compute_hash(script_content, url)
                        if (
                            hash_value
                            and hash_value not in self.csp.hashes["script-src"]
                        ):
                            self.csp.hashes["script-src"].append(hash_value)
                            self.csp.stats["unique_script_hashes"] += 1
                            logger.debug("Added script hash",
                                       url=url,
                                       hash=hash_value,
                                       operation="fetch_remote_site")

                # Process inline styles
                inline_styles = soup.find_all("style")
                for style in inline_styles:
                    if not isinstance(style, Tag):
                        logger.error("Invalid style element type",
                                   url=url,
                                   expected_type="Tag",
                                   actual_type=type(style),
                                   operation="fetch_remote_site",
                                   error_code=ErrorCodes.VALIDATION_ERROR)
                        raise TypeError(f"Expected Tag, got {type(style)}")
                    style_content: Optional[str] = style.string
                    if style_content and style_content.strip():
                        hash_value = self.csp.compute_hash(style_content, url)
                        if (
                            hash_value
                            and hash_value not in self.csp.hashes["style-src"]
                        ):
                            self.csp.hashes["style-src"].append(hash_value)
                            self.csp.stats["unique_style_hashes"] += 1
                            logger.debug("Added style hash",
                                       url=url,
                                       hash=hash_value,
                                       operation="fetch_remote_site")

                # Update directives with network resources
                for script_url in network_resources["scripts"]:
                    if script_url not in self.csp.directives["script-src"]:
                        self.csp.directives["script-src"].append(script_url)
                for style_url in network_resources["styles"]:
                    if style_url not in self.csp.directives["style-src"]:
                        self.csp.directives["style-src"].append(style_url)
                for image_url in network_resources["images"]:
                    if image_url not in self.csp.directives["img-src"]:
                        self.csp.directives["img-src"].append(image_url)

                # Final wait for any remaining dynamic content
                await page.wait_for_timeout(wait_time * 1000)
                await page.wait_for_load_state("networkidle")

                logger.info("Successfully fetched and analyzed site",
                          url=url,
                          script_count=len(network_resources["scripts"]),
                          style_count=len(network_resources["styles"]),
                          image_count=len(network_resources["images"]),
                          operation="fetch_remote_site")

                await browser.close()
                return True, website_csp_header

        except Exception as e:
            logger.error("Error during site fetch",
                        url=url,
                        error=str(e),
                        operation="fetch_remote_site",
                        error_code=ErrorCodes.NETWORK_ERROR,
                        exc_info=True)
            return False, None
