import typer
from rich.console import Console
from app.csp_generator import generate_csp_header, validate_csp_header
from pathlib import Path as pathlib_Path
from typing_extensions import Annotated
from rich.progress import track
from app import __version__

app = typer.Typer(
    name="csp-header-gen",
    help="Interactive CLI tool to generate secure Content Security Policy headers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    # If no subcommand was provided, show help and exit
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

@app.command(
    help="Generate CSP headers by hashing inline <script> tags in HTML files.",
    epilog="""
Examples:\n
  csp-header-gen generate -p ./public -o csp.conf\n
  csp-header-gen generate --path ./site/html --output ./headers.conf
"""
)
def generate(
    path: Annotated[
        pathlib_Path,
        typer.Option(
            ...,
            "-p",
            "--path",
            help="Path to your website directory containing HTML files.",
            prompt="Website directory to scan",
            rich_help_panel="Input Options",
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    output: str = typer.Option(
        "csp_headers.conf",
        "-o",
        "--output",
        help="Filename (or path) where the generated CSP headers will be written.",
        rich_help_panel="Output Options",
    ),
):
    """
    Generate CSP headers by hashing inline <script> tags in HTML files under PATH and write them to OUTPUT.
    """
    try:
        csp_header, details = track(
            generate_csp_header(path),
            description="[bold cyan]🔍 Scanning HTML files and generating CSP headers...[/bold cyan]\n")
        with open(output, "w") as file:
            file.write(csp_header)
        console.print(f"[green]✅ CSP headers successfully written to {output}.[/green]")
        console.print(f"[green]🔢 {len(details)} unique script hashes generated.[/green]\n")
        for detail in details:
            console.print(detail)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

@app.command(
    help="Validate existing CSP headers against current HTML files.",
    epilog="""
Examples:
  csp-header-gen validate -p ./public -f csp_headers.conf
"""
)
def validate(
    path: Annotated[
        pathlib_Path,
        typer.Option(
            ...,
            "-p",
            "--path",
            help="Directory of HTML files to validate against.",
            prompt="Website directory to scan for validation",
            rich_help_panel="Input Options",
            exists=True,
            file_okay=False,
            dir_okay=True,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ],
    header_file: Annotated[
        pathlib_Path,
        typer.Option(
            ...,
            "-f",
            "--file",
            help="Path to the CSP header file to validate.",
            prompt="CSP header file path",
            rich_help_panel="Input Options",
            exists=True,
            file_okay=True,
            dir_okay=False,
            writable=False,
            readable=True,
            resolve_path=True,
        ),
    ]

):
    """
    Parse HTML, extract script hashes, and compare against HEADER_FILE.
    """
    console.print("[bold cyan]🔍 Validating CSP headers…[/bold cyan]")
    valid, report = validate_csp_header(path, header_file)
    if valid:
        console.print("[green]✅ All script hashes match the CSP header.[/green]")
    else:
        console.print("[red]❌ Discrepancies found:[/red]")
        for line in report:
            console.print(f" - {line}")
        raise typer.Exit(code=1)

@app.command(help="Show the current version of the tool.")
def version():
    """Print the tool version."""
    console.print(f"CSP Header Generator version {__version__}")


if __name__ == "__main__":
    app()
