import datetime
import logging
from importlib.metadata import PackageNotFoundError, version

import typer
from rich.console import Console

from . import __logfile__
from .commands import generate, validate, fetch

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
    handlers=[logging.FileHandler(__logfile__, encoding="utf-8")],
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
app.add_typer(generate.app, name="generate", )
# app.add_typer(validate.app, name="validate")
# app.add_typer(fetch.app, name="fetch")

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
        is_eager=True
    ),
):
    """hashcsp - Generate secure Content Security Policies."""
    pass

if __name__ == "__main__":
    app()
