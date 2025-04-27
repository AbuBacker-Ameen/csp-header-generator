import logging
from typing import Dict, List, Optional

from bs4 import BeautifulSoup, Tag
from playwright.async_api import Browser, Page, async_playwright

from .csp_generator import CSPGenerator

logger = logging.getLogger(__name__)


class RemoteFetcher:
    def __init__(self, csp_generator: CSPGenerator):
        self.csp = csp_generator

    async def fetch_remote_site(self, url: str, wait_time: int) -> bool:
        """Fetch a website and extract resources."""
        try:
            async with async_playwright() as p:
                browser: Browser = await p.chromium.launch(headless=True)
                page: Page = await browser.new_page()

                # Track network requests
                network_resources: Dict[str, List[str]] = {
                    "scripts": [],
                    "styles": [],
                    "images": [],
                }

                def handle_request(request):
                    resource_type = request.resource_type
                    if resource_type == "script":
                        network_resources["scripts"].append(request.url)
                        self.csp.stats["external_scripts"] += 1
                    elif resource_type == "stylesheet":
                        network_resources["styles"].append(request.url)
                        self.csp.stats["external_styles"] += 1
                    elif resource_type == "image":
                        network_resources["images"].append(request.url)
                        self.csp.stats["external_images"] += 1

                page.on("request", handle_request)

                # Navigate to the URL
                await page.goto(url, wait_until="networkidle")

                # Wait for additional resources
                await page.wait_for_timeout(wait_time * 1000)

                # Get page content
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

                await browser.close()
                return True

        except Exception as e:
            logger.error(f"Error fetching {url}: {e}", exc_info=True)
            return False
