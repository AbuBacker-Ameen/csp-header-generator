"""Output formatting module for HashCSP.

This module handles the formatted output of CSP generation reports and comparisons
using rich text formatting. It supports both rich text and plain text output modes.
"""

import os
from typing import Dict, List

from rich import box
from rich.align import Align
from rich.console import Console
from rich.table import Table

from .logging_config import get_logger

logger = get_logger(__name__)
console = Console()


class Printer:
    """Handles formatted output of CSP generation reports and comparisons.

    This class provides methods to print summary reports and detailed comparisons
    of CSP configurations using rich text formatting. It supports both rich text
    and plain text output modes.

    Attributes:
        stats (Dict[str, int]): Statistics about processed files and resources.
    """

    def __init__(self, stats: Dict[str, int]):
        """Initialize a Printer instance.

        Args:
            stats (Dict[str, int]): Dictionary containing statistics about processed
                files and resources.
        """
        self.stats = stats

    def print_summary_report(self):
        """Print a summary report of CSP generation stats.

        Outputs a formatted table containing statistics about processed files,
        including counts of:
        - Total files processed
        - Files with no inline scripts/styles
        - Unique script and style hashes
        - External scripts, styles, and images

        The output format depends on the CSP_PLAIN_OUTPUT environment variable:
        - If set to "1": Plain text output
        - Otherwise: Rich text table with formatting
        """
        logger.info(
            "Generating summary report",
            files_processed=self.stats["files_processed"],
            unique_script_hashes=self.stats["unique_script_hashes"],
            unique_style_hashes=self.stats["unique_style_hashes"],
            operation="print_summary_report",
        )

        if os.environ.get("CSP_PLAIN_OUTPUT") == "1":
            print("CSP Generation Report :dart:")
            print(f"Files Processed :page_facing_up: : {self.stats['files_processed']}")
            print(
                f"Files With No inline scripts or styles :scroll: : {self.stats['files_with_no_inline_scripts']}"
            )
            print(
                f"Unique Script Hashes :hammer_and_wrench: : {self.stats['unique_script_hashes']}"
            )
            print(f"Unique Style Hashes :art: : {self.stats['unique_style_hashes']}")
            print(
                f"External Scripts :globe_with_meridians: : {self.stats['external_scripts']}"
            )
            print(f"External Styles :art: : {self.stats['external_styles']}")
            print(f"External Images :framed_picture: : {self.stats['external_images']}")
            print(":sparkles: CSP Header Generated Successfully!")
        else:
            table = Table(
                title="CSP Generation Report :dart:",
                box=box.MINIMAL_DOUBLE_HEAD,
                title_justify="center",
                title_style="bold bright_cyan",
                show_header=True,
                header_style="bold magenta",
                pad_edge=False,
                row_styles=("none", "yellow"),
                expand=True,
            )
            table.add_column(
                "Metric", justify="center", style="cyan", no_wrap=True, ratio=2
            )
            table.add_column("Value", justify="center", style="green", overflow="fold")
            rows = [
                ("Files Processed :page_facing_up: ", self.stats["files_processed"]),
                (
                    "Files With No inline scripts or styles :scroll: ",
                    self.stats["files_with_no_inline_scripts"],
                ),
                (
                    "Unique Script Hashes :hammer_and_wrench: ",
                    self.stats["unique_script_hashes"],
                ),
                ("Unique Style Hashes :art: ", self.stats["unique_style_hashes"]),
                (
                    "External Scripts :globe_with_meridians:",
                    self.stats["external_scripts"],
                ),
                ("External Styles :art:", self.stats["external_styles"]),
                ("External Images :framed_picture:", self.stats["external_images"]),
            ]
            for metric, value in rows:
                style = "bold red" if value == 0 else ""
                table.add_row(Align.left(metric), Align.center(str(value)), style=style)
            console.print(Align.center(table))
            console.print(
                "[bold green]:sparkles: CSP Header Generated Successfully! [/bold green]"
            )

    def print_csp_diff(
        self, existing: Dict[str, List[str]], generated: Dict[str, List[str]]
    ):
        """Print a detailed report of CSP differences with metrics.

        Compares two CSP configurations and outputs a detailed report of their
        differences, including:
        - Missing and extra sources for each directive
        - Missing and extra directives
        - Detailed metrics about hash and link differences

        Args:
            existing (Dict[str, List[str]]): The existing CSP configuration.
            generated (Dict[str, List[str]]): The newly generated CSP configuration.

        The output format depends on the CSP_PLAIN_OUTPUT environment variable:
        - If set to "1": Plain text output
        - Otherwise: Rich text tables with formatting
        """
        logger.info(
            "Comparing CSP configurations",
            existing_directives=len(existing),
            generated_directives=len(generated),
            operation="print_csp_diff",
        )

        if os.environ.get("CSP_PLAIN_OUTPUT") == "1":
            print("CSP Mismatch Details :warning:")
            all_directives = set(existing.keys()) | set(generated.keys())
            metrics = {
                "script-src": {
                    "missing_hashes": 0,
                    "extra_hashes": 0,
                    "missing_links": 0,
                    "extra_links": 0,
                },
                "style-src": {
                    "missing_hashes": 0,
                    "extra_hashes": 0,
                    "missing_links": 0,
                    "extra_links": 0,
                },
                "img-src": {"missing_links": 0, "extra_links": 0},
                "connect-src": {"missing_links": 0, "extra_links": 0},
                "font-src": {"missing_links": 0, "extra_links": 0},
                "media-src": {"missing_links": 0, "extra_links": 0},
                "frame-src": {"missing_links": 0, "extra_links": 0},
            }
            differences = []
            for directive in sorted(all_directives):
                existing_sources = set(existing.get(directive, []))
                generated_sources = set(generated.get(directive, []))
                missing = generated_sources - existing_sources
                extra = existing_sources - generated_sources
                if missing or extra:
                    missing_str = ", ".join(sorted(missing)) if missing else "-"
                    extra_str = ", ".join(sorted(extra)) if extra else "-"
                    differences.append((directive, missing_str, extra_str))
                    # Update metrics
                    if directive in metrics:
                        for source in missing:
                            if source.startswith("'sha256-"):
                                metrics[directive]["missing_hashes"] += 1
                            else:
                                metrics[directive]["missing_links"] += 1
                        for source in extra:
                            if source.startswith("'sha256-"):
                                metrics[directive]["extra_hashes"] += 1
                            else:
                                metrics[directive]["extra_links"] += 1

            for diff in differences[:10]:
                directive, missing_str, extra_str = diff
                print(f"Directive: {directive}")
                print(f"Missing in Existing: {missing_str}")
                print(f"Extra in Existing: {extra_str}")
            if len(differences) > 10:
                print(f"... and {len(differences) - 10} more differences not shown.")

            missing_directives = set(generated.keys()) - set(existing.keys())
            extra_directives = set(existing.keys()) - set(generated.keys())
            if missing_directives:
                print(
                    f"Directives missing in existing CSP: {', '.join(sorted(missing_directives))} :no_entry_sign:"
                )
            if extra_directives:
                print(
                    f"Extra directives in existing CSP: {', '.join(sorted(extra_directives))} :warning:"
                )

            # Print metrics
            print("\nMismatch Metrics:")
            for directive, counts in metrics.items():
                if any(counts.values()):
                    print(f"{directive}:")
                    if "missing_hashes" in counts and counts["missing_hashes"] > 0:
                        print(f"  Missing Hashes: {counts['missing_hashes']}")
                    if "extra_hashes" in counts and counts["extra_hashes"] > 0:
                        print(f"  Extra Hashes: {counts['extra_hashes']}")
                    if "missing_links" in counts and counts["missing_links"] > 0:
                        print(f"  Missing Links: {counts['missing_links']}")
                    if "extra_links" in counts and counts["extra_links"] > 0:
                        print(f"  Extra Links: {counts['extra_links']}")
        else:
            table = Table(
                title="CSP Mismatch Details :warning:",
                box=box.MINIMAL_DOUBLE_HEAD,
                title_justify="center",
                title_style="bold yellow",
                show_header=True,
                header_style="bold magenta",
                pad_edge=False,
                expand=True,
            )
            table.add_column("Directive", justify="center", style="cyan", no_wrap=True)
            table.add_column("Missing in Existing", justify="left", style="red")
            table.add_column("Extra in Existing", justify="left", style="yellow")

            all_directives = set(existing.keys()) | set(generated.keys())
            metrics = {
                "script-src": {
                    "missing_hashes": 0,
                    "extra_hashes": 0,
                    "missing_links": 0,
                    "extra_links": 0,
                },
                "style-src": {
                    "missing_hashes": 0,
                    "extra_hashes": 0,
                    "missing_links": 0,
                    "extra_links": 0,
                },
                "img-src": {"missing_links": 0, "extra_links": 0},
                "connect-src": {"missing_links": 0, "extra_links": 0},
                "font-src": {"missing_links": 0, "extra_links": 0},
                "media-src": {"missing_links": 0, "extra_links": 0},
                "frame-src": {"missing_links": 0, "extra_links": 0},
            }
            differences = []
            for directive in sorted(all_directives):
                existing_sources = set(existing.get(directive, []))
                generated_sources = set(generated.get(directive, []))
                missing = generated_sources - existing_sources
                extra = existing_sources - generated_sources
                if missing or extra:
                    missing_str = ", ".join(sorted(missing)) if missing else "-"
                    extra_str = ", ".join(sorted(extra)) if extra else "-"
                    differences.append((directive, missing_str, extra_str))
                    # Update metrics
                    if directive in metrics:
                        for source in missing:
                            if source.startswith("'sha256-"):
                                metrics[directive]["missing_hashes"] += 1
                            else:
                                metrics[directive]["missing_links"] += 1
                        for source in extra:
                            if source.startswith("'sha256-"):
                                metrics[directive]["extra_hashes"] += 1
                            else:
                                metrics[directive]["extra_links"] += 1

            # Limit to first 10 differences
            for diff in differences[:10]:
                directive, missing_str, extra_str = diff
                table.add_row(directive, missing_str, extra_str)
            if len(differences) > 10:
                table.add_row(
                    "...",
                    f"[italic]and {len(differences) - 10} more differences not shown[/italic]",
                    "",
                    style="dim",
                )

            if table.row_count == 0:
                console.print(
                    "[yellow]No specific differences found in directives, but CSP strings differ.[/yellow]"
                )
            else:
                console.print(Align.center(table))

            missing_directives = set(generated.keys()) - set(existing.keys())
            extra_directives = set(existing.keys()) - set(generated.keys())
            if missing_directives:
                console.print(
                    f"[red]Directives missing in existing CSP: {', '.join(sorted(missing_directives))} :no_entry_sign:[/red]"
                )
            if extra_directives:
                console.print(
                    f"[yellow]Extra directives in existing CSP: {', '.join(sorted(extra_directives))} :warning:[/yellow]"
                )

            # Print metrics
            metrics_table = Table(
                title="Mismatch Metrics",
                box=box.MINIMAL_DOUBLE_HEAD,
                title_justify="center",
                title_style="bold cyan",
                show_header=True,
                header_style="bold magenta",
                pad_edge=False,
                expand=True,
            )
            metrics_table.add_column("Directive", justify="center", style="cyan")
            metrics_table.add_column("Missing Hashes", justify="center", style="red")
            metrics_table.add_column("Extra Hashes", justify="center", style="yellow")
            metrics_table.add_column("Missing Links", justify="center", style="red")
            metrics_table.add_column("Extra Links", justify="center", style="yellow")

            has_metrics = False
            for directive in sorted(metrics.keys()):
                counts = metrics[directive]
                if any(counts.values()):
                    has_metrics = True
                    missing_hashes = (
                        str(counts.get("missing_hashes", 0))
                        if "missing_hashes" in counts
                        else "-"
                    )
                    extra_hashes = (
                        str(counts.get("extra_hashes", 0))
                        if "extra_hashes" in counts
                        else "-"
                    )
                    missing_links = str(counts["missing_links"])
                    extra_links = str(counts["extra_links"])
                    metrics_table.add_row(
                        directive,
                        missing_hashes,
                        extra_hashes,
                        missing_links,
                        extra_links,
                    )

            if has_metrics:
                console.print("\n")
                console.print(Align.center(metrics_table))

            logger.info(
                "CSP comparison completed",
                differences_count=len(differences),
                missing_directives=len(missing_directives),
                extra_directives=len(extra_directives),
                operation="print_csp_diff",
            )
