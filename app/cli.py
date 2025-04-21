import typer
from rich.console import Console
from app.csp_generator import generate_csp_header
from pathlib import Path as pathlib_Path
from typing_extensions import Annotated

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
    help="Scan a directory for HTML files and generate CSP headers to an output file."
)
def generate(
    path: Annotated[
        pathlib_Path,
        typer.Option(
            ...,
            "-p",
            "--path",
            prompt="Website directory to scan",
            help="Path to your website directory containing HTML files.",
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
    ),
):
    """
    Generate CSP headers by hashing inline <script> tags in HTML files under PATH and write them to OUTPUT.
    """
    console.print("\n[bold cyan]🔍 Scanning HTML files and generating CSP headers...[/bold cyan]\n")
    try:
        csp_header, details = generate_csp_header(path)
        with open(output, "w") as file:
            file.write(csp_header)
        console.print(f"[green]✅ CSP headers successfully written to {output}.[/green]")
        console.print(f"[green]🔢 {len(details)} unique script hashes generated.[/green]\n")
        for detail in details:
            console.print(detail)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    app()
