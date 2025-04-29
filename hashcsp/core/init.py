import logging
from typing import Dict, List

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.text import Text


from .config import CSPConfig, save_config

logger = logging.getLogger(__name__)
console = Console()


class CSPInitializer:
    def __init__(self):
        self.config = CSPConfig()
        self.current_directive = ""
        self.directive_index = 0
        self.directives = list(self.config.directives.keys())

    def get_panel_content(self) -> Text:
        """Generate content for the live display panel."""
        content = Text()
        content.append("Configuring CSP Directives\n\n", style="bold cyan")
        for i, directive in enumerate(self.directives):
            if i == self.directive_index:
                content.append(
                    f"> {directive}: {self.config.directives[directive]}\n",
                    style="bold green",
                )
            else:
                content.append(f"  {directive}: {self.config.directives[directive]}\n")
        content.append(
            "\nEnter sources (space-separated) (e.g., 'self' https://example.com) \nor press Enter to keep default."
        )
        content.append("(CTRL C to exit)\n", style="#1f6468")
        return content

    def run(self, output_path: str = "hashcsp.json") -> bool:
        """Run the interactive CSP configuration shell."""
        console.print("[cyan]Starting interactive CSP configuration...[/cyan]")
        logger.info("Starting interactive CSP configuration")

        with Live(
            Panel(
                self.get_panel_content(), title="CSP Configuration", border_style="blue"
            ),
            # refresh_per_second=0,
            auto_refresh=False,
            transient=True,
            screen=False,
            console=console,
        ) as live:
            while self.directive_index < len(self.directives):
                self.current_directive = self.directives[self.directive_index]

                sources = Prompt.ask(
                    f"[bold]{self.current_directive}[/bold]",
                    default=" ".join(self.config.directives[self.current_directive]),
                ).strip()

                live.stop()
                live.start()

                if sources:
                    self.config.directives[self.current_directive] = sources.split()
                else:
                    # Keep default if no input
                    pass

                
                self.directive_index += 1

                live.update(
                    Panel(
                        self.get_panel_content(),
                        title="CSP Configuration",
                        border_style="blue",
                        ),
                    refresh=True)

        # Save the configuration
        success = save_config(self.config, output_path)
        if success:
            console.print(
                f"[green]Configuration complete! Saved to {output_path}[/green]"
            )
        return success


