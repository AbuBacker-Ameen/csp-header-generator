import asyncio
import logging
from playwright.async_api import async_playwright
from .csp_generator import CSPGenerator

logger = logging.getLogger(__name__)

class RemoteFetcher:
    def __init__(self, csp_generator: CSPGenerator):
        self.csp = csp_generator

    async def fetch_remote_site(self, url: str, wait_time: int) -> bool:
        """Fetch a website using Playwright and collect all resources."""
        try:
            if not url.startswith(("http://", "https://")):
                logger.error(f"Invalid URL format: {url}")
                return False

            logger.info(f"Fetching website with Playwright: {url}")

            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
                )
                page = await context.new_page()

                # Collect network requests
                network_resources = {
                    "script-src": set(),
                    "style-src": set(),
                    "img-src": set(),
                    "connect-src": set(),
                    "font-src": set(),
                    "media-src": set(),
                    "frame-src": set(),
                }

                async def handle_request(request):
                    url = request.url
                    resource_type = request.resource_type
                    if resource_type == "script":
                        network_resources["script-src"].add(url)
                    elif resource_type == "stylesheet":
                        network_resources["style-src"].add(url)
                    elif resource_type == "image":
                        network_resources["img-src"].add(url)
                    elif resource_type in ["xhr", "fetch"]:
                        network_resources["connect-src"].add(url)
                    elif resource_type == "font":
                        network_resources["font-src"].add(url)
                    elif resource_type == "media":
                        network_resources["media-src"].add(url)

                page.on("request", handle_request)

                # Navigate to the page
                logger.debug("Navigating to page...")
                await page.goto(url, timeout=60000)

                # Wait for the DOM to load, then add a configurable delay
                logger.debug("Waiting for page load...")
                await page.wait_for_load_state("load", timeout=60000)
                logger.debug(f"Waiting {wait_time} seconds for additional resources...")
                await page.wait_for_timeout(wait_time * 1000)

                # Extract inline and DOM-based resources
                logger.debug("Extracting DOM resources...")
                page_data = await page.evaluate('''() => {
                    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'))
                        .map(el => el.textContent.trim())
                        .filter(content => content);
                    const inlineStyles = Array.from(document.querySelectorAll('style'))
                        .map(el => el.textContent.trim())
                        .filter(content => content);
                    const externalScripts = Array.from(document.querySelectorAll('script[src]'))
                        .map(el => el.getAttribute('src'));
                    const externalStyles = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
                        .map(el => el.getAttribute('href'));
                    const images = Array.from(document.querySelectorAll('img[src]'))
                        .map(el => el.getAttribute('src'));
                    const frames = Array.from(document.querySelectorAll('iframe[src]'))
                        .map(el => el.getAttribute('src'));
                    return {
                        inlineScripts,
                        inlineStyles,
                        externalScripts,
                        externalStyles,
                        images,
                        frames,
                    };
                }''')

                # Process inline scripts
                for script in page_data["inlineScripts"]:
                    hash_value = self.csp.compute_hash(script, url)
                    if hash_value and hash_value not in self.csp.hashes["script-src"]:
                        self.csp.hashes["script-src"].append(hash_value)
                        self.csp.stats["unique_script_hashes"] += 1

                # Process inline styles
                for style in page_data["inlineStyles"]:
                    hash_value = self.csp.compute_hash(style, url)
                    if hash_value and hash_value not in self.csp.hashes["style-src"]:
                        self.csp.hashes["style-src"].append(hash_value)
                        self.csp.stats["unique_style_hashes"] += 1

                # Update directives with DOM and network data
                for src in page_data["externalScripts"]:
                    if src and src not in self.csp.directives["script-src"]:
                        self.csp.directives["script-src"].append(src)
                        self.csp.stats["external_scripts"] += 1
                for src in page_data["externalStyles"]:
                    if src and src not in self.csp.directives["style-src"]:
                        self.csp.directives["style-src"].append(src)
                        self.csp.stats["external_styles"] += 1
                for src in page_data["images"]:
                    if src and src not in self.csp.directives["img-src"]:
                        self.csp.directives["img-src"].append(src)
                        self.csp.stats["external_images"] += 1
                for src in page_data["frames"]:
                    if src and src not in self.csp.directives["frame-src"]:
                        self.csp.directives["frame-src"].append(src)

                # Merge network resources into directives
                for directive, sources in network_resources.items():
                    for src in sources:
                        if src and src not in self.csp.directives[directive]:
                            self.csp.directives[directive].append(src)
                            if directive == "script-src":
                                self.csp.stats["external_scripts"] += 1
                            elif directive == "style-src":
                                self.csp.stats["external_styles"] += 1
                            elif directive == "img-src":
                                self.csp.stats["external_images"] += 1

                # Check for no inline content
                if not page_data["inlineScripts"] and not page_data["inlineStyles"]:
                    self.csp.stats["files_with_no_inline_scripts"] += 1

                await browser.close()

            logger.info(f"Successfully fetched and analyzed {url}")
            return True

        except Exception as e:
            logger.error(f"Error fetching {url}: {e}", exc_info=True)
            return False
