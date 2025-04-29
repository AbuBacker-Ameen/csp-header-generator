import hashlib
import logging
from typing import Dict, List

from .printer import Printer

logger = logging.getLogger(__name__)

class CSPGenerator:
    def __init__(self):
        self.hashes: Dict[str, List[str]] = {
            "script-src": [],
            "style-src": [],
        }
        self.directives: Dict[str, List[str]] = {}
        self.stats: Dict[str, int] = {
            "files_processed": 0,
            "files_with_no_inline_scripts": 0,
            "unique_script_hashes": 0,
            "unique_style_hashes": 0,
            "external_scripts": 0,
            "external_styles": 0,
            "external_images": 0,
        }
        self.printer = Printer(self.stats)

    def set_default_directives(self) -> None:
        """Set default CSP directives if none are provided."""
        default_directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "img-src": ["'self'"],
            "connect-src": ["'self'"],
            "font-src": ["'self'"],
            "media-src": ["'self'"],
            "frame-src": ["'self'"],
        }
        self.directives = default_directives
        logger.info("Set default CSP directives")

    def compute_hash(self, content: str, source: str) -> str:
        """Compute the SHA256 hash of a script or style content."""
        if not content:
            logger.warning(f"Empty content provided for hashing from {source}")
            return ""
        hash_obj = hashlib.sha256(content.encode("utf-8"))
        hash_value = f"'sha256-{hash_obj.digest().hex()}'"
        return hash_value

    def update_directive(self, directive: str, sources: List[str]) -> None:
        """Update a CSP directive with new sources, replacing existing ones."""
        if not sources:
            logger.warning(f"No sources provided for {directive}")
            return
        self.directives[directive] = [source for source in sources if source]
        logger.info(f"Updated {directive} with sources: {self.directives[directive]}")

    def generate_csp(self, report: bool = True) -> str:
        """Generate the CSP header string."""
        # If no directives are set, use defaults
        if not self.directives:
            self.set_default_directives()

        csp_parts = []
        if self.hashes["script-src"]:
            self.directives.setdefault("script-src", []).extend(self.hashes["script-src"])
        if self.hashes["style-src"]:
            self.directives.setdefault("style-src", []).extend(self.hashes["style-src"])

        for directive, sources in self.directives.items():
            if sources:
                sources_str = " ".join(sources)
                csp_parts.append(f"{directive} {sources_str}")
        csp_header = "; ".join(csp_parts)
        if csp_header:
            csp_header += ";"
        logger.info("Generated CSP header: %s", csp_header)

        if report:
            self.printer.print_summary_report()

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

    def validate_csp(self, csp_file: str, path: str) -> bool:
        """Validate a CSP header against scanned resources."""
        from .local_scanner import (
            LocalScanner,  # Import here to avoid circular dependency
        )

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
            logger.info(
                "CSP validation passed: The existing CSP matches the current resources."
            )
            return True
        else:
            logger.warning("CSP validation failed: Differences found.")
            logger.warning(f"Existing CSP: {existing_csp}")
            logger.warning(f"Expected CSP: {new_csp}")

            # Parse and compare CSPs
            existing_directives = self._parse_csp(existing_csp)
            generated_directives = self._parse_csp(new_csp)
            self.printer.print_csp_diff(existing_directives, generated_directives)
            return False
