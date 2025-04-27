import os
import sys
import typer
from rich.console import Console

from .. import __logfile__
from ..core.csp_generator import CSPGenerator

app = typer.Typer(
    name="generate",
    help="Generate CSP headers by scanning HTML files for inline scripts and styles. Outputs a detailed report of findings.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

def read_directives_file(file_path: str) -> str:
    """Read directives from a file."""
    try:
        if not os.path.isfile(file_path):
            console.print(
                f"[red]Error: Directives file {file_path} not found :no_entry_sign:[/red]"
            )
            raise typer.Exit(code=1)
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            return content
    except UnicodeDecodeError:
        console.print(
            f"[red]Error: Directives file {file_path} has invalid encoding :no_entry_sign:[/red]"
        )
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(
            f"[red]Error reading directives file {file_path}: {e} :sweat:[/red]"
        )
        raise typer.Exit(code=1)

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
        None, "--output", "-o", help="Output file for CSP header (defaults to csp.conf)"
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
        help="File containing directives (one per line, format: directive:value)",
    ),
):
    """Generate CSP headers for HTML files."""
    if ctx.invoked_subcommand is not None:
        return  # Skip if a subcommand is invoked (for future expansion)

    csp = CSPGenerator()

    try:
        # Validate path
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not os.path.exists(path) or not os.path.isdir(path):
            console.print(
                f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]"
            )
            raise typer.Exit(code=1)

        # Process directives
        directives_input = directives
        if not directives and directives_file:
            directives_input = read_directives_file(directives_file)
        elif not directives and not directives_file and sys.stdin.isatty():
            console.print(
                "[cyan]Enter directives (e.g., script-src:'self' https://example.com,style-src:'self') or press Enter to skip:[/cyan]"
            )
            directives_input = input()

        if directives_input:
            try:
                for directive_pair in directives_input.split(","):
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
        csp.scan_directory(path)
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
        console.print(f"[red]Unexpected error in generate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)
