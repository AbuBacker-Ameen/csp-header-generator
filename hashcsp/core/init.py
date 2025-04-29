import logging
from typing import Dict, List

from pydantic import ValidationError
from rich.console import Console
from rich.live import Live
from rich.prompt import Prompt
from rich.table import Table

from .config import CSPConfig, save_config

logger = logging.getLogger(__name__)
console = Console()


class CSPInitializer:
    def __init__(self):
        self.config = CSPConfig()

    def _prompt_for_directives(self) -> Dict[str, List[str]]:
        """Prompt the user for CSP directives interactively."""
        directives: Dict[str, List[str]] = {}
        directive_names = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
            "font-src",
            "media-src",
            "frame-src",
        ]

        table = Table(title="CSP Directives")
        table.add_column("Directive", style="cyan")
        table.add_column("Sources", style="green")

        with Live(table, refresh_per_second=4) as live:
            for directive in directive_names:
                sources = Prompt.ask(
                    f"Enter sources for {directive} (comma-separated, or Enter to skip)",
                    default="",
                )
                if sources:
                    sources_list = [s.strip() for s in sources.split(",") if s.strip()]
                    directives[directive] = sources_list
                    table.add_row(directive, ", ".join(sources_list))
                else:
                    table.add_row(directive, "(skipped)")
                live.update(table)

        return directives

    def run(self, output_path: str = "hashcsp.json", dry_run: bool = False) -> bool:
        """Run the interactive CSP configuration process."""
        logger.info("Starting interactive CSP configuration")
        console.print("[bold cyan]Starting CSP configuration wizard...[/bold cyan]")

        try:
            directives = self._prompt_for_directives()
            self.config.directives = directives

            # Validate the config
            try:
                CSPConfig(directives=directives)
            except ValidationError as e:
                console.print(f"[red]Error: Invalid CSP configuration: {e}[/red]")
                logger.error(f"Invalid CSP configuration: {e}")
                return False

            # Save or preview the config
            return save_config(self.config, output_path, dry_run=dry_run)

        except KeyboardInterrupt:
            console.print("\n[yellow]Configuration interrupted by user[/yellow]")
            logger.info("Configuration interrupted by user")
            return False
        except Exception as e:
            console.print(f"[red]Error during configuration: {e}[/red]")
            logger.error(f"Error during configuration: {e}")
            return False
