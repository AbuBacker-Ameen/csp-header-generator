import os
import asyncio
import typer
from rich.console import Console
from playwright.async_api import async_playwright

from .. import __logfile__
from ..core.csp_generator import CSPGenerator

app = typer.Typer(
    name="fetch",
    help="Fetch a website by URL, analyze its resources, and generate a tailored CSP header. Outputs a detailed report.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

async def fetch_remote_site_async(csp: CSPGenerator, url: str, wait_time: int) -> bool:
    """Fetch a website using Playwright and collect all resources."""
    try:
        if not url.startswith(("http://", "https://")):
            console.print(
                f"[red]Error: Invalid URL format: {url}. Must start with http:// or https:// :no_entry_sign:[/red]"
            )
            return False

        console.print(
            f"[cyan]Fetching website: {url} :globe_with_meridians:[/cyan]"
        )

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            # Set a realistic user agent to avoid anti-bot protections
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

            # Navigate to the page with an increased timeout
            console.print("[cyan]Navigating to page...[/cyan]")
            await page.goto(url, timeout=60000)  # 60 seconds

            # Wait for the DOM to load, then add a configurable delay for dynamic content
            console.print("[cyan]Waiting for page load...[/cyan]")
            await page.wait_for_load_state("load", timeout=60000)  # Use 'load' instead of 'networkidle'
            console.print(f"[cyan]Waiting {wait_time} seconds for additional resources...[/cyan]")
            await page.wait_for_timeout(wait_time * 1000)  # Convert seconds to milliseconds

            # Extract inline and DOM-based resources
            console.print("[cyan]Extracting DOM resources...[/cyan]")
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
                hash_value = csp.compute_hash(script, url)
                if hash_value not in csp.hashes["script-src"]:
                    csp.hashes["script-src"].append(hash_value)
                    csp.stats["unique_script_hashes"] += 1

            # Process inline styles
            for style in page_data["inlineStyles"]:
                hash_value = csp.compute_hash(style, url)
                if hash_value not in csp.hashes["style-src"]:
                    csp.hashes["style-src"].append(hash_value)
                    csp.stats["unique_style_hashes"] += 1

            # Update directives with DOM and network data
            for src in page_data["externalScripts"]:
                if src and src not in csp.directives["script-src"]:
                    csp.directives["script-src"].append(src)
                    csp.stats["external_scripts"] += 1
            for src in page_data["externalStyles"]:
                if src and src not in csp.directives["style-src"]:
                    csp.directives["style-src"].append(src)
                    csp.stats["external_styles"] += 1
            for src in page_data["images"]:
                if src and src not in csp.directives["img-src"]:
                    csp.directives["img-src"].append(src)
                    csp.stats["external_images"] += 1
            for src in page_data["frames"]:
                if src and src not in csp.directives["frame-src"]:
                    csp.directives["frame-src"].append(src)

            # Merge network resources into directives
            for directive, sources in network_resources.items():
                for src in sources:
                    if src and src not in csp.directives[directive]:
                        csp.directives[directive].append(src)
                        if directive == "script-src":
                            csp.stats["external_scripts"] += 1
                        elif directive == "style-src":
                            csp.stats["external_styles"] += 1
                        elif directive == "img-src":
                            csp.stats["external_images"] += 1

            # Check for no inline content
            if not page_data["inlineScripts"] and not page_data["inlineStyles"]:
                csp.stats["files_with_no_inline_scripts"] += 1

            await browser.close()

        console.print(f"[green]Successfully analyzed {url} :tada:[/green]")
        return True

    except Exception as e:
        console.print(f"[red]Error fetching {url}: {e} :sweat:[/red]")
        return False

@app.callback(invoke_without_command=True)
def fetch(
    ctx: typer.Context,
    url: str = typer.Option(
        None,
        "--url",
        "-u",
        help="Website URL to fetch and analyze (e.g., https://example.com)",
    ),
    output: str = typer.Option(
        None, "--output", "-o", help="Output file for CSP header (defaults to csp.conf)"
    ),
    wait_time: int = typer.Option(
        2,
        "--wait-time",
        "-w",
        help="Time in seconds to wait for additional resources after page load (default: 2)",
        min=0,
    ),
):
    """Fetch a website and generate a CSP header."""
    if ctx.invoked_subcommand is not None:
        return  # Skip if a subcommand is invoked (for future expansion)

    csp = CSPGenerator()

    try:
        if not url:
            url = typer.prompt("Enter the website URL (e.g., https://example.com)")

        # Fetch and check success
        success = asyncio.run(fetch_remote_site_async(csp, url, wait_time))
        if not success:
            console.print(
                f"[red]Failed to fetch {url}. No CSP header generated. :sweat:[/red]"
            )
            raise typer.Exit(code=1)

        csp_header = csp.generate_csp()

        # Write output
        output_file = output or "csp.conf"
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(csp_header)
            console.print(
                f"[green]:small_red_triangle_down: CSP header written to {output_file} :memo:[/green]"
            )
        except PermissionError:
            console.print(
                f"[red]Error: Permission denied writing to {output_file} :no_entry_sign:[/red]"
            )
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]Error writing to {output_file}: {e} :sweat:[/red]")
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Unexpected error in fetch command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)
