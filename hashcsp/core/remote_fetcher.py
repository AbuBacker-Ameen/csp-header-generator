"""Remote website fetching and analysis module for HashCSP.

This module provides functionality for fetching remote websites, analyzing their
content, and extracting information needed for CSP generation. It handles both
static and dynamic content, and supports various levels of user interaction
simulation.
"""

import asyncio
import re
from typing import Dict, List, Optional, Set, Tuple

from bs4 import BeautifulSoup, Tag
from playwright.async_api import Browser, Page, Response, async_playwright
from rich.console import Console

from .csp_generator import CSPGenerator
from .logging_config import ErrorCodes, get_logger

logger = get_logger(__name__)
console = Console()


def normalize_css(content: str) -> str:
    """Normalize CSS content by stripping whitespace and standardizing formatting."""
    if not content:
        logger.debug(
            "Empty CSS content provided for normalization",
            operation="normalize_css",
            error_code=ErrorCodes.SUCCESS.value,
        )
        return ""
    # Remove comments
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    # Normalize whitespace
    content = re.sub(r"\s+", " ", content.strip())
    # Standardize separators
    content = re.sub(r"\s*([{:;}])\s*", r"\1", content)
    # Handle declarations (with or without braces)
    if "{" in content and "}" in content:
        selector, declarations = content.split("{", 1)
        declarations = declarations.rsplit("}", 1)[0]
        props = [prop.strip() for prop in declarations.split(";") if prop.strip()]
        normalized = f"{selector}{{{';'.join(props)}}}"
    else:
        # Handle style attributes or simple declarations
        props = [prop.strip() for prop in content.split(";") if prop.strip()]
        normalized = ";".join(props)
        if normalized and not normalized.endswith(";"):
            normalized += ";"
    logger.debug(
        "Normalized CSS content",
        original=content[:50],
        normalized=normalized[:50],
        operation="normalize_css",
        error_code=ErrorCodes.SUCCESS.value,
    )
    return normalized


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

    async def _setup_mutation_observer(self, page: Page) -> None:
        """Inject a MutationObserver to capture dynamically inserted scripts, styles, and attributes."""
        await page.evaluate(
            """
            () => {
                // Define a no-op disconnect function by default
                window.__hashcsp_disconnect_observer = () => {};
                window.__hashcsp_observed_elements = [];
                const observer = new MutationObserver((mutations) => {
                    mutations.forEach((mutation) => {
                        mutation.addedNodes.forEach((node) => {
                            if (node.nodeType !== 1) return; // Element nodes only
                            if (node.tagName === 'SCRIPT' || node.tagName === 'STYLE' || node.hasAttribute('style')) {
                                window.__hashcsp_observed_elements.push({
                                    tag: node.tagName || 'ELEMENT',
                                    content: node.tagName === 'SCRIPT' || node.tagName === 'STYLE' ? node.textContent : null,
                                    src: node.getAttribute('src') || null,
                                    style: node.getAttribute('style') || null
                                });
                            }
                            // Check child nodes for scripts, styles, and style attributes
                            node.querySelectorAll('script, style, [style]').forEach((el) => {
                                window.__hashcsp_observed_elements.push({
                                    tag: el.tagName || 'ELEMENT',
                                    content: el.tagName === 'SCRIPT' || node.tagName === 'STYLE' ? el.textContent : null,
                                    src: el.getAttribute('src') || null,
                                    style: el.getAttribute('style') || null
                                });
                            });
                        });
                        // Handle attribute changes
                        if (mutation.type === 'attributes' && mutation.attributeName === 'style') {
                            const el = mutation.target;
                            window.__hashcsp_observed_elements.push({
                                tag: 'ELEMENT',
                                content: null,
                                src: null,
                                style: el.getAttribute('style') || null
                            });
                        }
                    });
                });
                observer.observe(document, {
                    childList: true,
                    subtree: true,
                    attributes: true,
                    attributeFilter: ['style']
                });
                // Override with actual disconnect function
                window.__hashcsp_disconnect_observer = () => observer.disconnect();
            }
        """
        )
        logger.info(
            "MutationObserver enabled",
            operation="setup_mutation_observer",
            error_code=ErrorCodes.SUCCESS.value,
        )

    async def _get_observed_elements(
        self, page: Page
    ) -> List[Dict[str, Optional[str]]]:
        """Retrieve elements captured by MutationObserver."""
        try:
            elements = await page.evaluate("window.__hashcsp_observed_elements || []")
            logger.debug(
                "Retrieved observed elements",
                count=len(elements),
                operation="get_observed_elements",
                error_code=ErrorCodes.SUCCESS.value,
            )
            return elements
        except Exception as e:
            logger.error(
                "Failed to retrieve observed elements",
                error=str(e),
                operation="get_observed_elements",
                error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                exc_info=True,
            )
            return []

    async def _process_observed_elements(
        self,
        observed_elements: List[Dict[str, Optional[str]]],
        url: str,
        processed_hashes: Set[str],
    ) -> None:
        """Process dynamically observed scripts, styles, and style attributes."""
        for element in observed_elements:
            tag = element["tag"]
            if tag is None:
                logger.warning(
                    "Skipping element with None tag",
                    operation="process_observed_elements",
                    error_code=ErrorCodes.VALIDATION_ERROR.value,
                )
                continue
            tag = tag.lower()
            content = element["content"]
            src = element["src"]
            style = element["style"]

            if tag == "script" and content and not src:  # Inline script
                hash_value = self.csp.compute_hash(content, url)
                if (
                    hash_value
                    and hash_value not in self.csp.hashes["script-src"]
                    and hash_value not in processed_hashes
                ):
                    self.csp.hashes["script-src"].append(hash_value)
                    self.csp.stats["unique_script_hashes"] += 1
                    processed_hashes.add(hash_value)
                    logger.debug(
                        "Added dynamic script hash",
                        hash=hash_value,
                        content=content[:50],  # Truncate for brevity
                        operation="process_observed_elements",
                        error_code=ErrorCodes.SUCCESS.value,
                    )
            elif tag == "style" and content and not src:  # Inline style
                normalized_content = normalize_css(content)
                if normalized_content:
                    hash_value = self.csp.compute_hash(normalized_content, url)
                    if (
                        hash_value
                        and hash_value not in self.csp.hashes["style-src"]
                        and hash_value not in processed_hashes
                    ):
                        self.csp.hashes["style-src"].append(hash_value)
                        self.csp.stats["unique_style_hashes"] += 1
                        processed_hashes.add(hash_value)
                        logger.debug(
                            "Added dynamic style hash",
                            hash=hash_value,
                            content=normalized_content[:50],
                            operation="process_observed_elements",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    elif not hash_value:
                        logger.warning(
                            "Failed to compute hash for dynamic style",
                            content=normalized_content[:50],
                            operation="process_observed_elements",
                            error_code=ErrorCodes.HASH_COMPUTATION_ERROR.value,
                        )
            elif tag == "script" and src:  # External script
                self.csp.add_external_resource(src, "script")
                logger.debug(
                    "Added dynamic external script",
                    url=src,
                    operation="process_observed_elements",
                    error_code=ErrorCodes.SUCCESS.value,
                )
            elif style:  # Style attribute
                normalized_style = normalize_css(style)
                if normalized_style:
                    hash_value = self.csp.compute_hash(normalized_style, url)
                    if (
                        hash_value
                        and hash_value not in self.csp.hashes["style-src-attr"]
                        and hash_value not in processed_hashes
                    ):
                        self.csp.hashes["style-src-attr"].append(hash_value)
                        self.csp.stats["unique_style_hashes"] += 1
                        processed_hashes.add(hash_value)
                        logger.debug(
                            "Added dynamic style attribute hash",
                            hash=hash_value,
                            style=normalized_style[:50],
                            operation="process_observed_elements",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    elif not hash_value:
                        logger.warning(
                            "Failed to compute hash for dynamic style attribute",
                            style=normalized_style[:50],
                            operation="process_observed_elements",
                            error_code=ErrorCodes.HASH_COMPUTATION_ERROR.value,
                        )

    async def fetch_remote_site(
        self,
        url: str,
        wait_time: int,
        interaction_level: int = 0,
        retries: int = 2,
        observe_dom: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """Fetch a website, mimic user behavior, and extract resources for CSP generation.

        Performs a comprehensive analysis of a remote website including:
        - Fetching the initial page
        - Analyzing inline scripts, styles, and style attributes
        - Tracking network requests for external resources (including favicons, fonts, media)
        - Simulating user interactions based on the specified level
        - Monitoring DOM for dynamic scripts/styles (if observe_dom is True)

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
            observe_dom (bool, optional): Enable MutationObserver for dynamic scripts/styles.
                Defaults to False.

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
            logger.error(
                f"Invalid URL: '{url}'",
                url=url,
                suggested_url=suggested_url,
                operation="fetch_remote_site",
                error_code=ErrorCodes.VALIDATION_ERROR.value,
            )
            console.print(
                f"[red]Invalid URL: '{url}'. URLs must start with 'http://' or 'https://'. [/red]"
                f"[yellow]Did you mean '{suggested_url}'?[/yellow]"
            )
            return False, None

        try:
            async with async_playwright() as p:
                logger.debug(
                    "Launching browser",
                    url=url,
                    operation="fetch_remote_site",
                    error_code=ErrorCodes.SUCCESS.value,
                )

                # Configure stealth settings to bypass bot protection
                browser: Browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1920, "height": 1080},
                    java_script_enabled=True,
                    has_touch=False,
                )
                page: Page = await context.new_page()

                # Track network requests and processed hashes
                network_resources: Dict[str, List[str]] = {
                    "scripts": [],
                    "styles": [],
                    "images": [],
                    "fonts": [],
                    "media": [],
                    "connections": [],
                }
                external_js_urls: List[str] = []
                processed_hashes: Set[str] = set()

                def handle_request(request):
                    resource_type = request.resource_type
                    url = request.url
                    # Map resource types to (csp_type, network_key)
                    resource_map = {
                        "script": ("script", "scripts"),
                        "stylesheet": ("stylesheet", "styles"),
                        "image": ("image", "images"),
                        "font": ("font", "fonts"),
                        "media": ("media", "media"),
                        "fetch": ("fetch", "connections"),
                        "websocket": ("websocket", "connections"),
                    }
                    if resource_type in resource_map:
                        csp_type, network_key = resource_map[resource_type]
                        network_resources[network_key].append(url)
                        self.csp.add_external_resource(url, csp_type)
                        logger.debug(
                            f"Added external {csp_type}",
                            url=url,
                            operation="handle_request",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    else:
                        logger.debug(
                            "Ignored unknown resource type",
                            resource_type=resource_type,
                            url=url,
                            operation="handle_request",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    # Special handling for favicons
                    if resource_type == "image" and any(
                        keyword in url.lower() for keyword in ["favicon", "icon"]
                    ):
                        network_resources["images"].append(url)
                        self.csp.add_external_resource(url, "image")
                        logger.debug(
                            "Detected favicon",
                            url=url,
                            operation="handle_request",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    if resource_type == "script":
                        external_js_urls.append(url)

                page.on("request", handle_request)

                # Set up MutationObserver if enabled
                if observe_dom:
                    await self._setup_mutation_observer(page)

                # Navigate to the URL with retries
                website_csp_header: Optional[str] = None
                for attempt in range(retries + 1):
                    try:
                        logger.info(
                            "Attempting to fetch URL",
                            url=url,
                            attempt=attempt + 1,
                            total_attempts=retries + 1,
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.SUCCESS.value,
                        )

                        response: Optional[Response] = await page.goto(
                            url, wait_until="networkidle", timeout=30000
                        )
                        if response:
                            headers = await response.all_headers()
                            website_csp_header = headers.get("content-security-policy")
                            logger.info(
                                f"{'Found' if website_csp_header else 'No'} CSP header",
                                url=url,
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.SUCCESS.value,
                            )
                        else:
                            logger.error(
                                "No response received",
                                url=url,
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.NETWORK_ERROR.value,
                            )
                            if attempt == retries:
                                await browser.close()
                                return False, None
                            await asyncio.sleep(2**attempt)
                            continue
                        break
                    except Exception as e:
                        logger.error(
                            f"Attempt {attempt + 1} failed to fetch {url}",
                            url=url,
                            attempt=attempt + 1,
                            error=str(e),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                            exc_info=True,
                        )
                        if attempt == retries:
                            await browser.close()
                            return False, None
                        await asyncio.sleep(2**attempt)

                # Perform user interactions based on interaction_level
                if interaction_level >= 1:  # Basic interactions
                    logger.debug(
                        "Performing basic interactions",
                        url=url,
                        operation="fetch_remote_site",
                        error_code=ErrorCodes.SUCCESS.value,
                    )
                    await page.evaluate(
                        "window.scrollTo(0, document.body.scrollHeight)"
                    )
                    await page.wait_for_timeout(1000)
                    await page.wait_for_load_state("networkidle")

                if interaction_level >= 2:  # Advanced interactions
                    logger.debug(
                        "Performing advanced interactions",
                        url=url,
                        operation="fetch_remote_site",
                        error_code=ErrorCodes.SUCCESS.value,
                    )
                    buttons = await page.query_selector_all(
                        "button, a[href], [onclick]"
                    )
                    for i, element in enumerate(buttons[:5]):  # Limit to 5 interactions
                        try:
                            # Check if element is visible and enabled
                            is_visible = await element.is_visible()
                            is_enabled = await element.is_enabled()
                            if is_visible and is_enabled:
                                await element.click()
                                logger.debug(
                                    f"Clicked element {i + 1}",
                                    url=url,
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                                await page.wait_for_timeout(1000)
                                await page.wait_for_load_state("networkidle")
                            else:
                                logger.debug(
                                    f"Skipped clicking element {i + 1}: not visible or enabled",
                                    url=url,
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                        except Exception as e:
                            logger.warning(
                                f"Failed to click element {i + 1}",
                                url=url,
                                error=str(e),
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                                exc_info=True,
                            )

                    hoverable = await page.query_selector_all("[onmouseover]")
                    for i, element in enumerate(hoverable[:5]):
                        try:
                            # Check if element is visible
                            if await element.is_visible():
                                await element.hover()
                                logger.debug(
                                    f"Hovered over element {i + 1}",
                                    url=url,
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                                await page.wait_for_timeout(500)
                                await page.wait_for_load_state("networkidle")
                            else:
                                logger.debug(
                                    f"Skipped hovering element {i + 1}: not visible",
                                    url=url,
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                        except Exception as e:
                            logger.warning(
                                f"Failed to hover over element {i + 1}",
                                url=url,
                                error=str(e),
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                                exc_info=True,
                            )

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
                            logger.info(
                                "Detected dynamic DOM insertion",
                                url=url,
                                js_url=js_url,
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.SUCCESS.value,
                            )
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
                        logger.warning(
                            f"Failed to analyze JS file: {js_url}",
                            url=url,
                            js_url=js_url,
                            error=str(e),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                            exc_info=True,
                        )

                # Process dynamically observed elements
                if observe_dom:
                    observed_elements = await self._get_observed_elements(page)
                    await self._process_observed_elements(
                        observed_elements, url, processed_hashes
                    )
                    try:
                        await page.evaluate(
                            "if (window.__hashcsp_disconnect_observer) window.__hashcsp_disconnect_observer()"
                        )
                        logger.debug(
                            "Disconnected MutationObserver",
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.SUCCESS.value,
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to disconnect MutationObserver",
                            error=str(e),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                            exc_info=True,
                        )

                # Get page content after interactions
                content = await page.content()
                soup = BeautifulSoup(content, "html.parser")

                # Process inline scripts
                inline_scripts = soup.find_all("script", src=False)
                for script in inline_scripts:
                    if not isinstance(script, Tag):
                        logger.error(
                            "Invalid script element type",
                            url=url,
                            expected_type="Tag",
                            actual_type=type(script),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.VALIDATION_ERROR.value,
                        )
                        raise TypeError(f"Expected Tag, got {type(script)}")
                    script_content: Optional[str] = script.string
                    if script_content and script_content.strip():
                        hash_value = self.csp.compute_hash(script_content, url)
                        if (
                            hash_value
                            and hash_value not in self.csp.hashes["script-src"]
                            and hash_value not in processed_hashes
                        ):
                            self.csp.hashes["script-src"].append(hash_value)
                            self.csp.stats["unique_script_hashes"] += 1
                            processed_hashes.add(hash_value)
                            logger.debug(
                                "Added script hash",
                                url=url,
                                hash=hash_value,
                                content=script_content[:50],  # Truncate for brevity
                                operation="fetch_remote_site",
                                error_code=ErrorCodes.SUCCESS.value,
                            )

                # Process inline styles
                inline_styles = soup.find_all("style")
                for style in inline_styles:
                    if not isinstance(style, Tag):
                        logger.error(
                            "Invalid style element type",
                            url=url,
                            expected_type="Tag",
                            actual_type=type(style),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.VALIDATION_ERROR.value,
                        )
                        raise TypeError(f"Expected Tag, got {type(style)}")
                    style_content: Optional[str] = style.string
                    if style_content and style_content.strip():
                        normalized_content = normalize_css(style_content)
                        if normalized_content:
                            hash_value = self.csp.compute_hash(normalized_content, url)
                            if (
                                hash_value
                                and hash_value not in self.csp.hashes["style-src"]
                                and hash_value not in processed_hashes
                            ):
                                self.csp.hashes["style-src"].append(hash_value)
                                self.csp.stats["unique_style_hashes"] += 1
                                processed_hashes.add(hash_value)
                                logger.debug(
                                    "Added style hash",
                                    url=url,
                                    hash=hash_value,
                                    content=normalized_content[
                                        :50
                                    ],  # Truncate for brevity
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                            elif not hash_value:
                                logger.warning(
                                    "Failed to compute hash for style",
                                    content=normalized_content[:50],
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.HASH_COMPUTATION_ERROR.value,
                                )

                # Process style attributes (only if not already processed dynamically)
                elements_with_style = soup.find_all(attrs={"style": True})
                for element in elements_with_style:
                    if not isinstance(element, Tag):
                        logger.error(
                            "Invalid element with style attribute",
                            url=url,
                            expected_type="Tag",
                            actual_type=type(element),
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.VALIDATION_ERROR.value,
                        )
                        raise TypeError(f"Expected Tag, got {type(element)}")
                    style_value = element.get("style")
                    style_attr_content: Optional[str] = None
                    if isinstance(style_value, str):
                        style_attr_content = style_value
                    elif isinstance(style_value, list):
                        logger.warning(
                            "Style attribute is a list, using first value",
                            style_value=style_value,
                            url=url,
                            operation="fetch_remote_site",
                            error_code=ErrorCodes.VALIDATION_ERROR.value,
                        )
                        style_attr_content = style_value[0] if style_value else None
                    if style_attr_content and style_attr_content.strip():
                        normalized_style = normalize_css(style_attr_content)
                        if normalized_style:
                            hash_value = self.csp.compute_hash(normalized_style, url)
                            if (
                                hash_value
                                and hash_value not in self.csp.hashes["style-src-attr"]
                                and hash_value not in processed_hashes
                            ):
                                self.csp.hashes["style-src-attr"].append(hash_value)
                                self.csp.stats["unique_style_hashes"] += 1
                                processed_hashes.add(hash_value)
                                logger.debug(
                                    "Added style attribute hash",
                                    url=url,
                                    hash=hash_value,
                                    style=normalized_style[:50],  # Truncate for brevity
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.SUCCESS.value,
                                )
                            elif not hash_value:
                                logger.warning(
                                    "Failed to compute hash for style attribute",
                                    style=normalized_style[:50],
                                    operation="fetch_remote_site",
                                    error_code=ErrorCodes.HASH_COMPUTATION_ERROR.value,
                                )

                # Final wait for any remaining dynamic content
                await page.wait_for_timeout(wait_time * 1000)
                await page.wait_for_load_state("networkidle")

                logger.info(
                    "Successfully fetched and analyzed site",
                    url=url,
                    script_count=len(network_resources["scripts"]),
                    style_count=len(network_resources["styles"]),
                    image_count=len(network_resources["images"]),
                    font_count=len(network_resources["fonts"]),
                    media_count=len(network_resources["media"]),
                    connection_count=len(network_resources["connections"]),
                    operation="fetch_remote_site",
                    error_code=ErrorCodes.SUCCESS.value,
                )

                await browser.close()
                return True, website_csp_header

        except Exception as e:
            logger.error(
                "Error during site fetch",
                url=url,
                error=str(e),
                operation="fetch_remote_site",
                error_code=ErrorCodes.PLAYWRIGHT_ERROR.value,
                exc_info=True,
            )
            raise
