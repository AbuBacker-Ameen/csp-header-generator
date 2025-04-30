"""Fetch command for HashCSP.

This module provides the command for fetching remote websites and analyzing their
content to generate appropriate CSP headers. It supports various levels of
interaction simulation and can compare generated headers with existing ones.

The command handles:
- Remote website fetching with retry logic
- Dynamic content analysis
- User interaction simulation
- Network request tracking
- CSP header comparison
"""

import asyncio
import logging

import typer
from rich.console import Console

from ..core.csp_generator import CSPGenerator
from ..core.remote_fetcher import RemoteFetcher

app = typer.Typer(
    name="fetch",
    help="Fetch a remote website, retrieve its CSP header, and generate a computed CSP header.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = logging.getLogger(__name__)


@app.callback(invoke_without_command=True)
def fetch(
    ctx: typer.Context,
    url: str = typer.Option(
        ...,
        "--url",
        "-u",
        help="URL of the website to fetch. Must include 'http://' or 'https://'.",
    ),
    output: str = typer.Option(
        "csp.conf", "--output", "-o", help="Output file for the computed CSP header."
    ),
    wait: int = typer.Option(
        2, "--wait", "-w", help="Time to wait for additional resources (seconds)."
    ),
    compare: bool = typer.Option(
        False,
        "--compare",
        help="Compare the website's CSP header with the computed CSP header.",
    ),
    interaction_level: int = typer.Option(
        0,
        "--interaction-level",
        "-i",
        min=0,
        max=2,
        help="Level of user interaction (0 = none, 1 = basic, 2 = advanced).",
    ),
    retries: int = typer.Option(
        2, "--retries", "-r", help="Number of retry attempts for failed fetches."
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview CSP output without writing to disk.",
    ),
):
    """Fetch a remote website and generate a CSP header based on its content.

    This command fetches a remote website, analyzes its content (including dynamic
    content), and generates an appropriate CSP header. It can simulate different
    levels of user interaction to discover dynamically loaded resources.

    The command supports:
    - Multiple retry attempts for reliability
    - Configurable wait times for dynamic content
    - Different levels of user interaction simulation
    - Comparison with existing CSP headers
    - Preview mode with dry-run option

    Args:
        ctx (typer.Context): The Typer context object containing CLI state.
        url (str): The website URL to analyze (must include protocol).
        output (str, optional): Output file path. Defaults to "csp.conf".
        wait (int, optional): Wait time in seconds. Defaults to 2.
        compare (bool, optional): Enable CSP comparison. Defaults to False.
        interaction_level (int, optional): User interaction simulation level:
            - 0: No interaction (default)
            - 1: Basic (scrolling)
            - 2: Advanced (clicking, hovering)
        retries (int, optional): Number of retry attempts. Defaults to 2.
        dry_run (bool, optional): Preview mode. Defaults to False.

    Raises:
        typer.Exit: Exits with code 1 on error, 0 on success.
    """

    class CLILogHandler(logging.Handler):
        """Custom logging handler for CLI output.

        This handler collects error messages for display in the CLI interface.

        Attributes:
            error_messages (List[str]): List of collected error messages.
        """

        def __init__(self):
            """Initialize the CLI log handler."""
            super().__init__()
            self.error_messages: list[str] = []

        def emit(self, record):
            """Emit a log record.

            Collects error messages from log records for later display.

            Args:
                record: The log record to process.
            """
            if record.levelno >= logging.ERROR:
                self.error_messages.append(self.format(record))

    cli_handler = CLILogHandler()
    cli_handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s: %(message)s"))
    logger.addHandler(cli_handler)
    cli_handler.error_messages.clear()

    csp = CSPGenerator()
    fetcher = RemoteFetcher(csp)

    # Load directives from config if available
    config = ctx.obj.get("config") if ctx.obj else None
    if config:
        for directive, sources in config.directives.items():
            csp.update_directive(directive, sources)

    loop = asyncio.get_event_loop()
    success, website_csp_header = loop.run_until_complete(
        fetcher.fetch_remote_site(url, wait, interaction_level, retries)
    )

    if not success:
        if cli_handler.error_messages:
            for msg in cli_handler.error_messages:
                console.print(f"[red]{msg}[/red]")
        else:
            console.print(f"[red]Failed to fetch {url}. No CSP header generated.[/red]")
        raise typer.Exit(code=1)

    console.print("\n=== Website's CSP Header ===")
    if website_csp_header:
        console.print(website_csp_header)
    else:
        console.print("No CSP header found in the website's response.")

    computed_csp_header = csp.generate_csp(report=True)
    console.print("\n=== Computed CSP Header ===")
    console.print(computed_csp_header)

    if compare and website_csp_header:
        console.print("\n=== CSP Comparison ===")
        existing_directives = csp._parse_csp(website_csp_header)
        generated_directives = csp._parse_csp(computed_csp_header)
        csp.printer.print_csp_diff(existing_directives, generated_directives)
    elif compare and not website_csp_header:
        console.print("Cannot compare: No CSP header found in the website's response.")

    if dry_run:
        console.print("[cyan]Dry-run: CSP header output:[/cyan]")
        console.print(computed_csp_header)
        logger.info(f"Dry-run: CSP header previewed for {output}")
    else:
        try:
            with open(output, "w") as f:
                f.write(computed_csp_header)
            console.print(f"\nComputed CSP header written to {output}")
        except Exception as e:
            console.print(f"[red]Error writing CSP header to {output}: {e}[/red]")
            raise typer.Exit(code=1)
