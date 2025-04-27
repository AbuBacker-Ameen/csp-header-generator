import hashlib
import logging
import os
from typing import Dict, List
from rich import box
from rich.align import Align
from rich.console import Console
from rich.table import Table

logger = logging.getLogger(__name__)
console = Console()

class CSPGenerator:
    def __init__(self):
        self.hashes: Dict[str, List[str]] = {
            "script-src": [],
            "style-src": [],
        }
        self.directives: Dict[str, List[str]] = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'"],
            "connect-src": ["'self'"],
            "font-src": ["'self'"],
            "media-src": ["'self'"],
            "frame-src": ["'self'"],
        }
        self.stats: Dict[str, int] = {
            "files_processed": 0,
            "files_with_no_inline_scripts": 0,
            "unique_script_hashes": 0,
            "unique_style_hashes": 0,
            "external_scripts": 0,
            "external_styles": 0,
            "external_images": 0,
        }

    def compute_hash(self, content: str, source: str) -> str:
        """Compute the SHA256 hash of a script or style content."""
        if not content:
            logger.warning(f"Empty content provided for hashing from {source}")
            return ""
        hash_obj = hashlib.sha256(content.encode("utf-8"))
        hash_value = f"'sha256-{hash_obj.digest().hex()}'"
        return hash_value

    def update_directive(self, directive: str, sources: List[str]) -> None:
        """Update a CSP directive with new sources."""
        if directive not in self.directives:
            self.directives[directive] = []
        for source in sources:
            if source and source not in self.directives[directive]:
                self.directives[directive].append(source)
                logger.info(f"Added {source} to {directive}")

    def _print_summary_report(self):
        """Print a summary report of CSP generation stats."""
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

    def generate_csp(self, report: bool = True) -> str:
        """Generate the CSP header string."""
        csp_parts = []
        if self.hashes["script-src"]:
            self.directives["script-src"].extend(self.hashes["script-src"])
        if self.hashes["style-src"]:
            self.directives["style-src"].extend(self.hashes["style-src"])

        for directive, sources in self.directives.items():
            if sources:
                sources_str = " ".join(sources)
                csp_parts.append(f"{directive} {sources_str}")
        csp_header = "; ".join(csp_parts)
        if csp_header:
            csp_header += ";"
        logger.info("Generated CSP header: %s", csp_header)

        if report:
            self._print_summary_report()

        return csp_header

    def _parse_csp(self, csp: str) -> Dict[str, List[str]]:
        """Parse a CSP header into a dictionary of directives and sources."""
        directives: Dict[str, List[str]] = {}
        if not csp:
            logger.warning("Empty CSP string provided for parsing")
            return directives
        for part in csp.split(";"):
            part = part.strip()
            if part:
                try:
                    directive, *sources = part.split()
                    directives[directive] = sources
                    logger.debug(
                        f"Parsed directive: {directive} with sources: {sources}"
                    )
                except ValueError:
                    logger.warning(f"Invalid CSP directive format: {part}")
                    continue
        return directives

    def _print_csp_diff(
        self, existing: Dict[str, List[str]], generated: Dict[str, List[str]]
    ):
        """Print a detailed report of CSP differences."""
        if os.environ.get("CSP_PLAIN_OUTPUT") == "1":
            print("CSP Mismatch Details :warning:")
            all_directives = set(existing.keys()) | set(generated.keys())
            for directive in sorted(all_directives):
                existing_sources = set(existing.get(directive, []))
                generated_sources = set(generated.get(directive, []))
                missing = generated_sources - existing_sources
                extra = existing_sources - generated_sources
                if missing or extra:
                    missing_str = ", ".join(sorted(missing)) if missing else "-"
                    extra_str = ", ".join(sorted(extra)) if extra else "-"
                    print(f"Directive: {directive}")
                    print(f"Missing in Existing: {missing_str}")
                    print(f"Extra in Existing: {extra_str}")
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
            for directive in sorted(all_directives):
                existing_sources = set(existing.get(directive, []))
                generated_sources = set(generated.get(directive, []))

                missing = generated_sources - existing_sources
                extra = existing_sources - generated_sources

                if missing or extra:
                    missing_str = ", ".join(sorted(missing)) if missing else "-"
                    extra_str = ", ".join(sorted(extra)) if extra else "-"
                    table.add_row(directive, missing_str, extra_str)

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
            console.print(
                "[bold cyan]To create the correct CSP header, run the `generate` command with the same path[/bold cyan]"
            )

    def validate_csp(self, csp_file: str, path: str) -> bool:
        """Validate a CSP header against scanned resources."""
        from .local_scanner import LocalScanner  # Import here to avoid circular dependency

        logger.info(f"Validating CSP from {csp_file} against files in {path}")

        # Read the existing CSP header
        try:
            with open(csp_file, "r", encoding="utf-8") as f:
                existing_csp = f.read().strip()
        except Exception as e:
            logger.error(f"Error reading CSP file {csp_file}: {e}")
            return False

        # Scan the directory to collect current resources
        scanner = LocalScanner(self)
        scanner.scan_directory(path)

        # Generate a new CSP header based on the scanned resources
        new_csp = self.generate_csp(report=False)

        # Compare the two CSP headers
        if existing_csp == new_csp:
            logger.info("CSP validation passed: The existing CSP matches the current resources.")
            return True
        else:
            logger.warning("CSP validation failed: Differences found.")
            logger.warning(f"Existing CSP: {existing_csp}")
            logger.warning(f"Expected CSP: {new_csp}")
            
            # Parse and compare CSPs
            existing_directives = self._parse_csp(existing_csp)
            generated_directives = self._parse_csp(new_csp)
            self._print_csp_diff(existing_directives, generated_directives)
            return False
