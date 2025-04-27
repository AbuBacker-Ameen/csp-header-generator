import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup, Tag
from playwright.async_api import Browser, Page, Response, async_playwright
from rich.console import Console

from .csp_generator import CSPGenerator

console = Console()

logger = logging.getLogger(__name__)


class RemoteFetcher:
    def __init__(self, csp_generator: CSPGenerator):
        self.csp = csp_generator

    async def fetch_remote_site(
        self, url: str, wait_time: int, interaction_level: int = 0, retries: int = 2
    ) -> Tuple[bool, Optional[str]]:
        """Fetch a website, mimic user behavior, and extract resources for CSP generation.

        Args:
            url: The target URL to fetch.
            wait_time: Base wait time for resources (seconds).
            interaction_level: Level of user interaction (0 = none, 1 = basic, 2 = advanced).
            retries: Number of retry attempts for failed fetches.

        Returns:
            Tuple[bool, Optional[str]]: (success, website_csp_header)
        """
        # Validate URL protocol
        if not re.match(r"^https?://", url):
            suggested_url = (
                f"https://{url}" if not url.startswith("http://") else f"http://{url}"
            )
            logger.error(
                f"Invalid URL: '{url}'. URLs must start with 'http://' or 'https://'. "
                f"Did you mean '{suggested_url}'?"
            )
            console.print(
                f"[red]Invalid URL: '{url}'. URLs must start with 'http://' or 'https://'. [/red]"
                f"[yellow]Did you mean '{suggested_url}'?[/yellow]"
            )
            return False, None

        try:
            async with async_playwright() as p:
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
                    elif resource_type == "stylesheet":
                        network_resources["styles"].append(request.url)
                        self.csp.stats["external_styles"] += 1
                    elif resource_type == "image":
                        network_resources["images"].append(request.url)
                        self.csp.stats["external_images"] += 1

                page.on("request", handle_request)

                # Navigate to the URL with retries
                website_csp_header: Optional[str] = None
                for attempt in range(retries + 1):
                    try:
                        response: Optional[Response] = await page.goto(
                            url, wait_until="networkidle", timeout=30000
                        )
                        if response:
                            headers = await response.all_headers()  # Properly awaited
                            website_csp_header = headers.get("content-security-policy")
                            if website_csp_header:
                                logger.info(
                                    f"Website CSP header found: {website_csp_header}"
                                )
                            else:
                                logger.info(
                                    "No CSP header found in the website's response."
                                )
                        else:
                            logger.error(
                                f"No response received from {url}. The site may be down or blocking access."
                            )
                            if attempt == retries:
                                await browser.close()
                                return False, None
                            await asyncio.sleep(2**attempt)
                            continue
                        break
                    except Exception as e:
                        logger.error(
                            f"Attempt {attempt + 1} failed to fetch {url}: {str(e)}"
                        )
                        if attempt == retries:
                            await browser.close()
                            return False, None
                        # Exponential backoff: wait 2^attempt seconds
                        await asyncio.sleep(2**attempt)

                # Perform user interactions based on interaction_level
                if interaction_level >= 1:  # Basic interactions
                    # Scroll to the bottom
                    await page.evaluate(
                        "window.scrollTo(0, document.body.scrollHeight)"
                    )
                    await page.wait_for_timeout(1000)  # Wait for dynamic content
                    await page.wait_for_load_state("networkidle")

                if interaction_level >= 2:  # Advanced interactions
                    # Click on interactive elements
                    buttons = await page.query_selector_all(
                        "button, a[href], [onclick]"
                    )
                    for i, element in enumerate(
                        buttons[:5]
                    ):  # Limit to 5 interactions to avoid overload
                        try:
                            await element.click()
                            logger.info(f"Clicked element {i + 1}")
                            await page.wait_for_timeout(1000)
                            await page.wait_for_load_state("networkidle")
                        except Exception as e:
                            logger.warning(f"Failed to click element {i + 1}: {e}")

                    # Hover over elements with onmouseover
                    hoverable = await page.query_selector_all("[onmouseover]")
                    for i, element in enumerate(hoverable[:5]):
                        try:
                            await element.hover()
                            logger.info(f"Hovered over element {i + 1}")
                            await page.wait_for_timeout(500)
                            await page.wait_for_load_state("networkidle")
                        except Exception as e:
                            logger.warning(f"Failed to hover over element {i + 1}: {e}")

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
                            logger.info(f"DOM insertion detected in {js_url}")
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
                        logger.warning(f"Failed to analyze JS file {js_url}: {e}")

                # Get page content after interactions
                content = await page.content()
                soup = BeautifulSoup(content, "html.parser")

                # Process inline scripts
                inline_scripts = soup.find_all("script", src=False)
                for script in inline_scripts:
                    assert isinstance(script, Tag), f"Expected Tag, got {type(script)}"
                    script_content: Optional[str] = script.string
                    if script_content and script_content.strip():
                        hash_value = self.csp.compute_hash(script_content, url)
                        if (
                            hash_value
                            and hash_value not in self.csp.hashes["script-src"]
                        ):
                            self.csp.hashes["script-src"].append(hash_value)
                            self.csp.stats["unique_script_hashes"] += 1
                            logger.info(f"Added script hash {hash_value} from {url}")

                # Process inline styles
                inline_styles = soup.find_all("style")
                for style in inline_styles:
                    assert isinstance(style, Tag), f"Expected Tag, got {type(style)}"
                    style_content: Optional[str] = style.string
                    if style_content and style_content.strip():
                        hash_value = self.csp.compute_hash(style_content, url)
                        if (
                            hash_value
                            and hash_value not in self.csp.hashes["style-src"]
                        ):
                            self.csp.hashes["style-src"].append(hash_value)
                            self.csp.stats["unique_style_hashes"] += 1
                            logger.info(f"Added style hash {hash_value} from {url}")

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

                await browser.close()
                return True, website_csp_header

        except Exception as e:
            logger.error(f"Error fetching {url}: {e}", exc_info=True)
            return False, None
