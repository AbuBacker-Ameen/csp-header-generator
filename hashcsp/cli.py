import datetime
import logging
from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console

from . import __logfile__
from .commands import fetch, generate, validate
from .core.config import load_config
from .core.init import CSPInitializer

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
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(__logfile__, encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)
SEP = "\n" + "=" * 80 + "\n"
logger.info(
    "%sRun started at %s%s",
    SEP,
    datetime.datetime.now().isoformat(timespec="seconds"),
    SEP,
)

# Register commands
app.add_typer(generate.app, name="generate")
app.add_typer(validate.app, name="validate")
app.add_typer(fetch.app, name="fetch")

def _version_callback(value: bool):
    if value:
        try:
            current_version = version("hashcsp")
            console.print(f"[cyan bold]hashcsp v{current_version}[/cyan bold]")
        except PackageNotFoundError:
            console.print("[red]Version info not available[/red]")
        raise typer.Exit()

def _init_callback(value: bool, ctx: typer.Context):
    if value:
        initializer = CSPInitializer()
        config_path = ctx.params.get("config") or "hashcsp.json"
        dry_run = ctx.params.get("dry_run", False)
        success = initializer.run(config_path, dry_run=dry_run)
        if not success:
            raise typer.Exit(code=1)
        raise typer.Exit()

@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the hashcsp version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
    init: bool = typer.Option(
        False,
        "--init",
        help="Initialize a new CSP configuration file interactively.",
        callback=_init_callback,
        is_eager=True,
    ),
    config: str = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to CSP configuration file (default: hashcsp.json).",
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Preview output without writing to disk.",
    ),
):
    """hashcsp - Generate secure Content Security Policies."""
    # Initialize context object with config and dry-run
    ctx.obj = {"config": load_config(config), "dry_run": dry_run}
    logger.info(f"Context initialized with config: {config}, dry_run: {dry_run}")

if __name__ == "__main__":
    app()
