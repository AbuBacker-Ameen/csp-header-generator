"""Generate command for HashCSP.

This module provides the command for generating CSP headers by scanning HTML files
for inline scripts, styles, and external resources. It supports various output
formats and configuration options.

The command can:
- Scan directories for HTML files
- Process inline scripts and styles
- Track external resources
- Generate CSP headers in text or JSON format
- Validate CSP directives for security issues
"""

import json
import logging
import os
from typing import List

import typer
from rich.console import Console

from ..core.config import CSPConfig, validate_json_config
from ..core.csp_generator import CSPGenerator
from ..core.local_scanner import LocalScanner

app = typer.Typer(
    name="generate",
    help="Generate CSP headers by scanning HTML files for inline scripts and styles. Outputs a detailed report of findings.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()
logger = logging.getLogger(__name__)


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
        None,
        "--output",
        "-o",
        help="Output file for CSP header (defaults to csp.conf or csp.json with --json-output)",
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
    json_output: bool = typer.Option(
        False,
        "--json-output",
        help="Output CSP directives as a JSON file instead of a text header.",
    ),
    lint: bool = typer.Option(
        False,
        "--lint",
        help="Warn about unsafe CSP sources like *, data:, or 'unsafe-inline'.",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview output without writing to disk.",
    ),
):
    """Generate CSP headers for HTML files.

    This command scans a directory of HTML files and generates appropriate CSP
    headers based on the content found. It can process both inline content
    (scripts and styles) and external resources.

    The command supports multiple configuration methods:
    - Command-line directives
    - JSON configuration file
    - Default directives from global config

    Args:
        ctx (typer.Context): The Typer context object containing CLI state.
        path (str, optional): Directory to scan. Will prompt if not provided.
        output (str, optional): Output file path. Defaults based on format.
        directives (str, optional): Inline directive specifications.
        directives_file (str, optional): JSON file with directives.
        json_output (bool, optional): Use JSON output format. Defaults to False.
        lint (bool, optional): Enable security linting. Defaults to False.
        dry_run (bool, optional): Flag for preview mode. Defaults to False.

    Raises:
        typer.Exit: Exits with code 1 on error, 0 on success.
    """
    if ctx.invoked_subcommand is not None:
        return

    csp = CSPGenerator()
    scanner = LocalScanner(csp)

    try:
        # Validate path
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not os.path.exists(path) or not os.path.isdir(path):
            console.print(
                f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]"
            )
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
                    directive_pair = directive_pair.strip()
                    if not directive_pair:
                        continue
                    parts = directive_pair.split(":", 1)  # Split on first ":" only
                    if len(parts) != 2:
                        raise ValueError(
                            f"Invalid directive format: '{directive_pair}'. Expected 'directive:value'"
                        )
                    directive, sources_str = parts
                    directive = directive.strip()
                    directive_sources: List[str] = [
                        s for s in sources_str.strip().split() if s
                    ]
                    if not directive:
                        raise ValueError(f"Empty directive in '{directive_pair}'")
                    if not directive_sources:
                        raise ValueError(
                            f"No sources provided for directive '{directive}' in '{directive_pair}'"
                        )
                    csp.update_directive(directive, directive_sources)
            except ValueError as e:
                console.print(
                    f"[red]Error: Invalid directives format. Use 'directive:value' (e.g., script-src:'self' https://example.com). Error: {e} :no_entry_sign:[/red]"
                )
                raise typer.Exit(code=1)

        # Scan and generate CSP
        scanner.scan_directory(path)
        csp_header = csp.generate_csp()

        # Lint directives if enabled
        if lint:
            warnings = csp.lint_directives()
            for warning in warnings:
                console.print(f"[yellow]Warning: {warning}[/yellow]")
            if warnings:
                console.print(
                    f"[yellow]Lint mode: {len(warnings)} unsafe sources detected[/yellow]"
                )
            else:
                console.print("[green]Lint mode: No unsafe sources detected[/green]")

        # Determine output file and format
        output_file = output or ("csp.json" if json_output else "csp.conf")
        try:
            if dry_run:
                if json_output:
                    console.print("[cyan]Dry-run: CSP JSON output:[/cyan]")
                    config = CSPConfig(directives=csp.directives)
                    console.print(json.dumps(config.dict(), indent=2))
                    logger.info(f"Dry-run: CSP JSON previewed for {output_file}")
                else:
                    console.print("[cyan]Dry-run: CSP header output:[/cyan]")
                    console.print(csp_header)
                    logger.info(f"Dry-run: CSP header previewed for {output_file}")
            else:
                if json_output:
                    # Serialize directives to JSON
                    config = CSPConfig(directives=csp.directives)
                    with open(output_file, "w", encoding="utf-8") as f:
                        json.dump(config.dict(), f, indent=2)
                    console.print(
                        f"[green]:small_red_triangle_down: CSP JSON written to {output_file} :memo:[/green]"
                    )
                else:
                    # Write text-based CSP header
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
        console.print(f"[red]Unexpected error in generate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)
