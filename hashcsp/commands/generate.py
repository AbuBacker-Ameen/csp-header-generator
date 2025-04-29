import os
import sys

import typer
from rich.console import Console

from ..core.config import load_config, validate_json_config
from ..core.csp_generator import CSPGenerator
from ..core.local_scanner import LocalScanner

app = typer.Typer(
    name="generate",
    help="Generate CSP headers by scanning HTML files for inline scripts and styles. Outputs a detailed report of findings.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

@app.callback(invoke_without_command=True)
def generate(
    ctx: typer.Context,
    path: str = typer.Option(
        None,
        "--path",
        "-p",
        help="Directory containing HTML files to scan (e.g., ./public)",
    ),
    output: str = typer.Option(
        "csp.conf",
        "--output",
        "-o",
        help="Output file for CSP header (defaults to csp.conf)",
    ),
    directives: str = typer.Option(
        None,
        "--directives",
        "-d",
        help="Comma-separated directive:value pairs (e.g., script-src:'self' https://example.com,style-src:'self')",
    ),
    directives_file: str = typer.Option(
        None,
        "--directives-file",
        "-f",
        help="JSON file containing CSP directives (e.g., directives.json)",
    ),
):
    """Generate CSP headers for HTML files."""
    if ctx.invoked_subcommand is not None:
        return

    csp = CSPGenerator()
    scanner = LocalScanner(csp)

    try:
        # Validate path
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not os.path.exists(path) or not os.path.isdir(path):
            console.print(f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]")
            raise typer.Exit(code=1)

        # Load directives from --directives-file (JSON) if provided
        if directives_file:
            json_config = validate_json_config(directives_file)
            if json_config:
                for directive, sources in json_config.directives.items():
                    csp.update_directive(directive, sources)
            else:
                raise typer.Exit(code=1)
        else:
            # Load directives from config if no --directives-file
            config = ctx.obj.get("config") if ctx.obj else None
            if config:
                for directive, sources in config.directives.items():
                    csp.update_directive(directive, sources)

        # Process directives from --directives
        if directives:
            try:
                for directive_pair in directives.split(","):
                    if not directive_pair.strip():
                        continue
                    directive, sources = directive_pair.split(":")
                    csp.update_directive(directive.strip(), sources.strip().split())
            except ValueError as e:
                console.print(
                    f"[red]Error: Invalid directives format. Use 'directive:value' (e.g., script-src:'self'). Error: {e} :no_entry_sign:[/red]"
                )
                raise typer.Exit(code=1)

        # Scan and generate CSP
        scanner.scan_directory(path)
        csp_header = csp.generate_csp()

        # Write output
        output_file = output or "csp.conf"
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(csp_header)
            console.print(f"[green]:small_red_triangle_down: CSP header written to {output_file} :memo:[/green]")
        except PermissionError:
            console.print(f"[red]Error: Permission denied writing to {output_file} :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        except Exception as e:
            console.print(f"[red]Error writing to {output_file}: {e} :sweat:[/red]")
            raise typer.Exit(code=1)

    except typer.Exit:
        raise
    except Exception as e:
        console.print(f"[red]Unexpected error in generate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)
