import typer
from rich.console import Console
from .csp_generator import CSPGenerator
from importlib.metadata import version, PackageNotFoundError
import os
import sys
import logging, datetime

app = typer.Typer(
    name="hashcsp",
    help="Interactive CLI tool to generate secure Content Security Policy headers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
)

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.FileHandler('csp_generator.log', encoding="utf-8")]
)
logger = logging.getLogger(__name__)
SEP = "\n" + "=" * 80 + "\n"
logger.info(
    "%sRun started at %s%s",
    SEP, datetime.datetime.now().isoformat(timespec='seconds'), SEP
)

def read_directives_file(file_path: str) -> str:
    """Read directives from a file."""
    try:
        if not os.path.isfile(file_path):
            logger.error(f"Directives file not found: {file_path}")
            console.print(f"[red]Error: Directives file {file_path} not found :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            logger.info(f"Read directives from file: {file_path}")
            return content
    except UnicodeDecodeError:
        logger.error(f"Invalid encoding in directives file: {file_path}")
        console.print(f"[red]Error: Directives file {file_path} has invalid encoding :no_entry_sign:[/red]")
        raise typer.Exit(code=1)
    except Exception as e:
        logger.error(f"Error reading directives file {file_path}: {e}", exc_info=True)
        console.print(f"[red]Error reading directives file {file_path}: {e} :sweat:[/red]")
        raise typer.Exit(code=1)

@app.command(help="Generate CSP headers by scanning HTML files for inline scripts and styles. Outputs a detailed report of findings.")
def generate(
    path: str = typer.Option(None, "--path", "-p", help="Directory containing HTML files to scan (e.g., ./public)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file for CSP header (defaults to csp.conf)"),
    directives: str = typer.Option(None, "--directives", "-d", help="Comma-separated directive:value pairs (e.g., script-src:'self' https://example.com,style-src:'self')"),
    directives_file: str = typer.Option(None, "--directives-file", "-f", help="File containing directives (one per line, format: directive:value)")
):
    """Generate CSP headers for HTML files."""
    csp = CSPGenerator()
    
    try:
        # Validate path
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not os.path.exists(path) or not os.path.isdir(path):
            logger.error(f"Invalid directory: {path}")
            console.print(f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        
        # Process directives
        directives_input = directives
        if not directives and directives_file:
            directives_input = read_directives_file(directives_file)
        elif not directives and not directives_file and sys.stdin.isatty():
            console.print("[cyan]Enter directives (e.g., script-src:'self' https://example.com,style-src:'self') or press Enter to skip:[/cyan]")
            directives_input = input()
        
        if directives_input:
            try:
                for directive_pair in directives_input.split(','):
                    if not directive_pair.strip():
                        continue
                    directive, sources = directive_pair.split(':')
                    csp.update_directive(directive.strip(), sources.strip().split())
            except ValueError as e:
                logger.error(f"Invalid directives format: {directives_input}, error: {e}")
                console.print(f"[red]Error: Invalid directives format. Use 'directive:value' (e.g., script-src:'self'). Error: {e} :no_entry_sign:[/red]")
                raise typer.Exit(code=1)
        
        # Scan and generate CSP
        csp.scan_directory(path)
        csp_header = csp.generate_csp()
        
        # Write output
        output_file = output or "csp.conf"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(csp_header)
            logger.info(f"CSP header written to {output_file}")
            console.print(f"[green]:small_red_triangle_down: CSP header written to {output_file} :memo:[/green]")
        except PermissionError:
            logger.error(f"Permission denied writing to {output_file}")
            console.print(f"[red]Error: Permission denied writing to {output_file} :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        except Exception as e:
            logger.error(f"Error writing to {output_file}: {e}", exc_info=True)
            console.print(f"[red]Error writing to {output_file}: {e} :sweat:[/red]")
            raise typer.Exit(code=1)
        
    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in generate command: {e}", exc_info=True)
        console.print(f"[red]Unexpected error in generate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)

@app.command(help="Validate an existing CSP header against HTML files to ensure it matches current scripts and styles.")
def validate(
    path: str = typer.Option(None, "--path", "-p", help="Directory containing HTML files to scan (e.g., ./public)"),
    file: str = typer.Option(None, "--file", "-f", help="CSP header file to validate (e.g., csp.conf)")
):
    """Validate an existing CSP header against HTML files."""
    csp = CSPGenerator()
    
    try:
        if not path:
            path = typer.prompt("Enter the directory containing HTML files")
        if not file:
            file = typer.prompt("Enter the CSP header file path")
        
        if not os.path.exists(path) or not os.path.isdir(path):
            logger.error(f"Invalid directory: {path}")
            console.print(f"[red]Error: Directory {path} does not exist or is not a directory :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        if not os.path.exists(file) or not os.path.isfile(file):
            logger.error(f"Invalid file: {file}")
            console.print(f"[red]Error: File {file} does not exist or is not a file :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        
        csp.validate_csp(file, path)
    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in validate command: {e}", exc_info=True)
        console.print(f"[red]Unexpected error in validate command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)

@app.command(help="Fetch a website by URL, analyze its resources, and generate a tailored CSP header. Outputs a detailed report.")
def fetch(
    url: str = typer.Option(None, "--url", "-u", help="Website URL to fetch and analyze (e.g., https://example.com)"),
    output: str = typer.Option(None, "--output", "-o", help="Output file for CSP header (defaults to csp.conf)")
):
    """Fetch a website and generate a CSP header."""
    csp = CSPGenerator()
    
    try:
        if not url:
            url = typer.prompt("Enter the website URL (e.g., https://example.com)")
        
        # Fetch and check success
        if not csp.fetch_remote_site(url):
            logger.error(f"Failed to fetch and analyze {url}, aborting CSP generation")
            console.print(f"[red]Failed to fetch {url}. No CSP header generated. :sweat:[/red]")
            raise typer.Exit(code=1)
        
        csp_header = csp.generate_csp()
        
        # Write output
        output_file = output or "csp.conf"
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(csp_header)
            logger.info(f"CSP header written to {output_file}")
            console.print(f"[green]CSP header written to {output_file} :memo:[/green]")
        except PermissionError:
            logger.error(f"Permission denied writing to {output_file}")
            console.print(f"[red]Error: Permission denied writing to {output_file} :no_entry_sign:[/red]")
            raise typer.Exit(code=1)
        except Exception as e:
            logger.error(f"Error writing to {output_file}: {e}", exc_info=True)
            console.print(f"[red]Error writing to {output_file}: {e} :sweat:[/red]")
            raise typer.Exit(code=1)
        
        console.print("[cyan]Generated CSP Header:[/cyan]")
        console.print(csp_header)
    except typer.Exit:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in fetch command: {e}", exc_info=True)
        console.print(f"[red]Unexpected error in fetch command: {e} :sweat:[/red]")
        raise typer.Exit(code=1)



def _version_callback(value: bool):
    if value:
        try:
            current_version = version("hashcsp")
            console.print(f"[cyan bold]hashcsp v{current_version}[/cyan bold]")
        except PackageNotFoundError:
            console.print("[red]Version info not available[/red]")
        raise typer.Exit()

@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the hashcsp version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
):
    """hashcsp - Generate secure Content Security Policies."""
    pass

def main():
    app()


if __name__ == "__main__":
    app()
