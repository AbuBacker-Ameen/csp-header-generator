import os
import asyncio
import typer
from rich.console import Console

from .. import __logfile__
from ..core.csp_generator import CSPGenerator
from ..core.remote_fetcher import RemoteFetcher

app = typer.Typer(
    name="fetch",
    help="Fetch a website by URL, analyze its resources, and generate a tailored CSP header. Outputs a detailed report.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

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
    fetcher = RemoteFetcher(csp)

    try:
        if not url:
            url = typer.prompt("Enter the website URL (e.g., https://example.com)")

        # Fetch and check success
        console.print(f"[cyan]Fetching website: {url} :globe_with_meridians:[/cyan]")
        success = asyncio.run(fetcher.fetch_remote_site(url, wait_time))
        if not success:
            console.print(
                f"[red]Failed to fetch {url}. No CSP header generated. :sweat:[/red]"
            )
            raise typer.Exit(code=1)

        csp_header = csp.generate_csp()  # This will print the summary report

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
