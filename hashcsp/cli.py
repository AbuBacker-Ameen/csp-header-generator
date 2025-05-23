"""Command-line interface for HashCSP.

This module provides the main entry point for the HashCSP CLI tool, which helps
generate and manage Content Security Policy headers. It includes commands for
generating, validating, and fetching CSP headers.

The CLI is built using Typer and provides rich text output formatting.
"""

import datetime
import zoneinfo
from importlib.metadata import PackageNotFoundError, version
from typing import Dict, List

import typer
from rich.console import Console

from .commands import fetch, generate, validate
from .core.config import load_config
from .core.init import CSPInitializer
from .core.logging_config import (
    LoggingConfig,
    get_default_timezone,
    get_logger,
    setup_logging,
)

app = typer.Typer(
    name="hashcsp",
    help="Interactive CLI tool to generate secure Content Security Policy headers.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=True,
)

console = Console()

# Get list of available timezones for autocompletion
AVAILABLE_TIMEZONES = sorted(zoneinfo.available_timezones())

logger = get_logger(__name__)

logger.info("HashCSP CLI started", operation="cli_startup")

# Register commands
app.add_typer(generate.app, name="generate")
app.add_typer(validate.app, name="validate")
app.add_typer(fetch.app, name="fetch")


def _version_callback(value: bool):
    """Handle the --version flag in the CLI.

    Args:
        value (bool): The flag value from the CLI.

    Raises:
        typer.Exit: Always exits after displaying version information.
    """
    if value:
        try:
            current_version = version("hashcsp")
            logger.info(
                "Version information requested",
                version=current_version,
                operation="version_check",
            )
            console.print(f"[cyan bold]hashcsp v{current_version}[/cyan bold]")
        except PackageNotFoundError:
            logger.error("Version information not available", operation="version_check")
            console.print("[red]Version info not available[/red]")
        raise typer.Exit()


def _init_callback(value: bool, ctx: typer.Context):
    """Handle the --init flag in the CLI.

    Initializes a new CSP configuration file interactively if the flag is set.

    Args:
        value (bool): The flag value from the CLI.
        ctx (typer.Context): The Typer context object containing CLI state.

    Raises:
        typer.Exit: Exits with code 1 on failure, 0 on success.
    """
    if value:
        initializer = CSPInitializer()
        config_path = ctx.params.get("config") or "hashcsp.json"
        dry_run = ctx.params.get("dry_run", False)
        logger.info(
            "Starting configuration initialization",
            config_path=config_path,
            dry_run=dry_run,
            operation="init_config",
        )
        success = initializer.run(config_path, dry_run=dry_run)
        if not success:
            logger.error(
                "Configuration initialization failed",
                config_path=config_path,
                operation="init_config",
            )
            raise typer.Exit(code=1)
        raise typer.Exit()


def _list_timezones_callback(value: bool):
    """Handle the --list-timezones flag in the CLI.

    Args:
        value (bool): The flag value from the CLI.

    Raises:
        typer.Exit: Always exits after displaying timezone information.
    """
    if value:
        from rich import box
        from rich.box import ROUNDED
        from rich.panel import Panel
        from rich.table import Table

        # Group timezones by region for better readability
        regions: Dict[str, List[str]] = {}
        for tz in AVAILABLE_TIMEZONES:
            region = tz.split("/")[0]
            if region not in regions:
                regions[region] = []
            regions[region].append(tz)

        # Create header
        header = Panel(
            "[bold cyan]HashCSP Timezone Explorer[/bold cyan]",
            subtitle="All available IANA timezones",
            border_style="cyan",
        )
        console.print(header)

        # Get console width to adapt display
        console_width = console.width or 80
        compact_mode = console_width < 100

        # Process each region
        for region in sorted(regions):
            # Create a table for each region with appropriate sizing
            table = Table(
                box=box.SIMPLE if compact_mode else ROUNDED,
                expand=False,
                show_header=True,
                header_style="bold yellow",
                title=f"[bold yellow]{region}[/bold yellow]",
                title_style="yellow",
                min_width=40,
                padding=(0, 1) if compact_mode else (0, 2),
            )

            # Adjust columns based on available space
            if compact_mode:
                table.add_column("Timezone", no_wrap=True, overflow="ellipsis")
                table.add_column("Time", justify="right", width=8)
            else:
                table.add_column("Timezone", no_wrap=False)
                table.add_column("Current Time", justify="right")

            # Add timezone data
            for tz in sorted(regions[region]):
                try:
                    current_time = datetime.datetime.now(zoneinfo.ZoneInfo(tz))
                    time_format = "%H:%M" if compact_mode else "%H:%M:%S"
                    time_str = f"[green]{current_time.strftime(time_format)}[/green]"
                except Exception:
                    time_str = "[dim]N/A[/dim]"

                # Truncate timezone name if needed in compact mode
                display_tz = tz
                if compact_mode and len(tz) > 30:
                    display_tz = tz[:27] + "..."

                table.add_row(display_tz, time_str)

            # Print the table directly instead of using panels
            console.print(table)

            # Add a small separator between regions
            if region != sorted(regions)[-1]:
                console.print("")

        console.print("\n[dim]Use --timezone TIMEZONE to set a specific timezone[/dim]")
        raise typer.Exit()


def timezone_callback(value: str) -> str:
    """Validate the timezone value.

    Args:
        value (str): The timezone value from the CLI.

    Returns:
        str: The validated timezone value.

    Raises:
        typer.BadParameter: If the timezone is invalid.
    """
    if not value:
        return get_default_timezone()
    try:
        zoneinfo.ZoneInfo(value)
        return value
    except zoneinfo.ZoneInfoNotFoundError:
        # Find similar timezones for suggestion
        suggestions = [tz for tz in AVAILABLE_TIMEZONES if value.lower() in tz.lower()][
            :3
        ]
        suggestion_msg = (
            f"\nDid you mean one of these?\n  {', '.join(suggestions)}"
            if suggestions
            else ""
        )
        raise typer.BadParameter(
            f"Invalid timezone: {value}. Must be a valid IANA timezone name.{suggestion_msg}\n"
            "Use --list-timezones to see all available options."
        )


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    tz: str = typer.Option(
        get_default_timezone(),  # Use system timezone as default
        "--timezone",
        "-t",
        help="Set the timezone for log timestamps (e.g., 'Asia/Dubai', 'Europe/London'). Defaults to system timezone.",
        callback=timezone_callback,
        autocompletion=lambda: AVAILABLE_TIMEZONES,
    ),
    version: bool = typer.Option(
        None,
        "--version",
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
    list_timezones: bool = typer.Option(
        False,
        "--list-timezones",
        help="List all available timezone names and exit.",
        callback=_list_timezones_callback,
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
    verbose: int = typer.Option(
        0,
        "--verbose",
        "-v",
        count=True,
        help="Enable verbose output. Use -v for INFO, -vv for DEBUG.",
    ),
):
    """HashCSP - Generate secure Content Security Policies.

    This is the main entry point for the HashCSP CLI tool. It provides commands
    for generating, validating, and fetching CSP headers. The tool can work with
    both local files and remote websites.

    Args:
        ctx (typer.Context): The Typer context object for managing CLI state.
        version (bool, optional): Flag to show version information. Defaults to None.
        init (bool, optional): Flag to initialize configuration. Defaults to False.
        list_timezones (bool, optional): List available timezones. Defaults to False.
        config (str, optional): Path to config file. Defaults to None.
        dry_run (bool, optional): Flag for preview mode. Defaults to False.
        verbose (int, optional): Verbosity level (0=no console, 1=INFO, 2=DEBUG).
        timezone (str, optional): Timezone for log timestamps. Defaults to system timezone.
    """
    # If no command is provided and no eager option was triggered, show help
    if ctx.invoked_subcommand is None and not any([version, init, list_timezones]):
        console.print(ctx.get_help())
        raise typer.Exit()

    # Set up logging based on verbosity
    console_level = None
    if verbose == 1:
        console_level = "INFO"
    elif verbose >= 2:
        console_level = "DEBUG"

    # Initialize context object with config and dry-run
    ctx.ensure_object(dict)

    # Create logging config
    logging_config = LoggingConfig(console_level=console_level, timezone=tz)

    # Store logging config in context first (needed for timestamp processor)
    ctx.obj["logging_config"] = logging_config

    # Now set up logging with context
    setup_logging(logging_config, ctx)

    # Load and store CSP config
    loaded_config = load_config(config)
    ctx.obj.update(
        {
            "config": loaded_config,
            "dry_run": dry_run,
        }
    )
    logger = get_logger(__name__)
    logger.info(
        "CLI context initialized",
        config_path=config,
        dry_run=dry_run,
        verbose_level=verbose,
        timezone=tz,
        operation="cli_init",
    )


if __name__ == "__main__":
    app()
