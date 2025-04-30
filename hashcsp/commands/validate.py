"""Validate command for HashCSP.

This module provides the command for validating existing CSP headers against
HTML files to ensure they match current scripts and styles. It helps identify
discrepancies between the current CSP and the actual resource usage.

The command performs:
- Scanning of HTML files in a directory
- Comparison with existing CSP header
- Detailed reporting of differences
- Suggestions for updates
"""

import os

import typer
from rich.console import Console

from ..core.csp_generator import CSPGenerator

app = typer.Typer(
    name="validate",
    help="Validate an existing CSP header against HTML files to ensure it matches current scripts and styles.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()


@app.callback(invoke_without_command=True)
def validate(
    ctx: typer.Context,
    path: str = typer.Option(
        None,
        "--path",
        "-p",
        help="Directory containing HTML files to scan (e.g., ./public)",
    ),
    file: str = typer.Option(
        None, "--file", "-f", help="CSP header file to validate (e.g., csp.conf)"
    ),
):
    """Validate an existing CSP header against HTML files.

    This command compares an existing CSP header with the current state of HTML
    files in a directory. It helps identify:
    - Missing hashes for inline scripts and styles
    - Missing or extra external resource sources
    - Changes in resource usage patterns

    Args:
        ctx (typer.Context): The Typer context object containing CLI state.
        path (str, optional): Directory containing HTML files to scan.
            Will prompt if not provided.
        file (str, optional): Path to the CSP header file to validate.
            Will prompt if not provided.

    Raises:
        typer.Exit: Exits with code 1 on validation failure or error,
            0 on successful validation.
    """
    if ctx.invoked_subcommand is not None:
        return

    csp = CSPGenerator()

    # Load directives from config if available
    config = ctx.obj.get("config") if ctx.obj else None
    if config:
        for directive, sources in config.directives.items():
            csp.update_directive(directive, sources)

    try:
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not file:
            file = typer.prompt("Enter the CSP header file path")

        if not os.path.exists(path) or not os.path.isdir(path):
            console.print(
                f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]"
            )
            raise typer.Exit(code=1)
        if not os.path.exists(file) or not os.path.isfile(file):
            console.print(
                f"[red]Error: File {file} does not exist or is not a file :no_entry_sign:[/red]"
            )
            raise typer.Exit(code=1)

        success = csp.validate_csp(file, path)
        if success:
            console.print("[green]CSP validation passed! :white_check_mark:[/green]")
        else:
            console.print("[yellow]CSP header mismatch! :warning:[/yellow]")
            console.print(
                "[bold cyan]To create the correct CSP header, run the `generate` command with the same path[/bold cyan]"
            )
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Unexpected error in validate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)
