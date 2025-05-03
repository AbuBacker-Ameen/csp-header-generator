"""CSP header generation and validation module for HashCSP.

This module handles the generation, validation, and management of CSP directives
and hashes for inline scripts and styles. It maintains statistics about processed
files and resources.
"""

import hashlib
from typing import Dict, List

from .logging_config import ErrorCodes, get_logger
from .printer import Printer

logger = get_logger(__name__)


class CSPGenerator:
    """A generator for Content Security Policy (CSP) headers.

    This class handles the generation, validation, and management of CSP directives
    and hashes for inline scripts and styles. It maintains statistics about processed
    files and resources.

    Attributes:
        hashes (Dict[str, List[str]]): Dictionary of CSP hashes for scripts and styles.
        directives (Dict[str, List[str]]): Dictionary of CSP directives and their sources.
        stats (Dict[str, int]): Statistics about processed files and resources.
        printer (Printer): Instance of Printer class for output formatting.
    """

    def __init__(self):
        """Initialize a new CSPGenerator instance with default settings."""
        self.hashes: Dict[str, List[str]] = {
            "script-src": [],
            "style-src": [],
            "style-src-attr": [],  # Added for style attribute hashes
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
            "external_fonts": 0,
            "external_media": 0,
            "external_connections": 0,
        }
        self.printer = Printer(self.stats)

    def set_default_directives(self) -> None:
        """Set default CSP directives if none are provided.

        Sets a baseline set of CSP directives with 'self' as the default source
        for all major directive categories.
        """
        default_directives = {
            "default-src": ["'self'"],
            "script-src": ["'self'"],
            "style-src": ["'self'"],
            "style-src-attr": [],  # Added for style attributes
            "img-src": ["'self'"],
            "font-src": ["'self'"],
            "media-src": ["'self'"],
            "connect-src": ["'self'"],
            "object-src": ["'none'"],
            "frame-src": ["'self'"],
            "worker-src": ["'self'"],
            "manifest-src": ["'self'"],
        }
        self.directives = default_directives
        logger.info(
            "Set default CSP directives",
            operation="set_default_directives",
            directive_count=len(default_directives),
        )

    def compute_hash(self, content: str, source: str) -> str:
        """Compute the SHA256 hash of a script or style content.

        Args:
            content (str): The content to hash (script or style content).
            source (str): Source identifier for logging purposes.

        Returns:
            str: The computed hash in CSP format ('sha256-{hash}') or empty string if content is empty.
        """
        if not content:
            logger.warning(
                "Empty content provided for hashing",
                source=source,
                operation="compute_hash",
            )
            return ""
        hash_obj = hashlib.sha256(content.encode("utf-8"))
        hash_value = f"'sha256-{hash_obj.hexdigest()}'"
        logger.debug(
            "Computed content hash",
            source=source,
            hash=hash_value,
            operation="compute_hash",
        )
        return hash_value

    def update_directive(self, directive: str, sources: List[str]) -> None:
        """Update a CSP directive with new sources, replacing existing ones.

        Args:
            directive (str): The CSP directive to update (e.g., 'script-src').
            sources (List[str]): List of sources to set for the directive.
        """
        if not sources:
            logger.warning(
                "No sources provided for directive",
                directive=directive,
                operation="update_directive",
            )
            return
        self.directives[directive] = [source for source in sources if source]
        logger.info(
            "Updated directive sources",
            directive=directive,
            source_count=len(self.directives[directive]),
            operation="update_directive",
        )

    def lint_directives(self) -> List[str]:
        """Check directives for unsafe sources and return warning messages.

        Returns:
            List[str]: List of warning messages for any unsafe sources found.
        """
        unsafe_sources = ["*", "data:", "'unsafe-inline'"]
        warnings = []
        for directive, sources in self.directives.items():
            for source in sources:
                if source in unsafe_sources:
                    warning = f"Unsafe source '{source}' found in {directive}"
                    warnings.append(warning)
                    logger.warning(
                        "Detected unsafe CSP source",
                        directive=directive,
                        source=source,
                        operation="lint_directives",
                        error_code=ErrorCodes.UNSAFE_DIRECTIVE,
                    )
        return warnings

    def add_external_resource(self, url: str, resource_type: str) -> None:
        """Add an external resource URL to the appropriate CSP directive.

        Args:
            url (str): The resource URL.
            resource_type (str): The resource type (e.g., script, stylesheet, font).
        """
        directive_map = {
            "script": "script-src",
            "stylesheet": "style-src",
            "image": "img-src",
            "font": "font-src",
            "media": "media-src",
            "fetch": "connect-src",
            "websocket": "connect-src",
        }
        directive = directive_map.get(resource_type)
        if not directive:
            logger.warning(
                "Unknown resource type",
                resource_type=resource_type,
                url=url,
                operation="add_external_resource",
                error_code=ErrorCodes.VALIDATION_ERROR.value,
            )
            return

        if url not in self.directives.get(directive, []):
            self.directives.setdefault(directive, []).append(url)
            # Correct stat key for media to match expected 'external_media'
            stat_key = (
                "external_media"
                if resource_type == "media"
                else (
                    f"external_{resource_type}s"
                    if resource_type not in ["fetch", "websocket"]
                    else "external_connections"
                )
            )
            self.stats[stat_key] = self.stats.get(stat_key, 0) + 1
            logger.debug(
                f"Added external {resource_type}",
                url=url,
                directive=directive,
                stat_key=stat_key,
                operation="add_external_resource",
                error_code=ErrorCodes.SUCCESS.value,
            )

    def generate_csp(self, report: bool = True) -> str:
        """Generate the CSP header string.

        Args:
            report (bool, optional): Whether to print a summary report. Defaults to True.

        Returns:
            str: The complete CSP header string.
        """
        # If no directives are set, use defaults
        if not self.directives:
            self.set_default_directives()

        csp_parts = []
        if self.hashes["script-src"]:
            self.directives.setdefault("script-src", []).extend(
                self.hashes["script-src"]
            )
        if self.hashes["style-src"]:
            self.directives.setdefault("style-src", []).extend(self.hashes["style-src"])

        for directive, sources in self.directives.items():
            if sources:
                sources_str = " ".join(sources)
                csp_parts.append(f"{directive} {sources_str}")
        csp_header = "; ".join(csp_parts)
        if csp_header:
            csp_header += ";"

        logger.info(
            "Generated CSP header",
            directive_count=len(self.directives),
            hash_count=len(self.hashes["script-src"]) + len(self.hashes["style-src"]),
            operation="generate_csp",
        )

        if report:
            self.printer.print_summary_report()

        return csp_header

    def _parse_csp(self, csp: str) -> Dict[str, List[str]]:
        """Parse a CSP header into a dictionary of directives and sources.

        Args:
            csp (str): The CSP header string to parse.

        Returns:
            Dict[str, List[str]]: Dictionary of directives and their sources.
        """
        directives: Dict[str, List[str]] = {}
        if not csp:
            logger.warning(
                "Empty CSP string provided for parsing", operation="_parse_csp"
            )
            return directives
        for part in csp.split(";"):
            part = part.strip()
            if part:
                try:
                    directive, *sources = part.split()
                    directives[directive] = sources
                    logger.debug(
                        "Parsed CSP directive",
                        directive=directive,
                        source_count=len(sources),
                        operation="_parse_csp",
                    )
                except ValueError:
                    logger.warning(
                        "Invalid CSP directive format",
                        directive_part=part,
                        operation="_parse_csp",
                        error_code=ErrorCodes.INVALID_CSP,
                    )
                    continue
        return directives

    def validate_csp(self, csp_file: str, path: str) -> bool:
        """Validate a CSP header against scanned resources.

        Args:
            csp_file (str): Path to the file containing the CSP header to validate.
            path (str): Path to the directory containing resources to validate against.

        Returns:
            bool: True if validation passes, False otherwise.
        """
        from .local_scanner import (
            LocalScanner,  # Import here to avoid circular dependency
        )

        logger.info(
            "Starting CSP validation",
            csp_file=csp_file,
            path=path,
            operation="validate_csp",
        )

        # Read the existing CSP header
        try:
            with open(csp_file, "r", encoding="utf-8") as f:
                existing_csp = f.read().strip()
        except Exception as e:
            logger.error(
                "Failed to read CSP file",
                csp_file=csp_file,
                error=str(e),
                operation="validate_csp",
                error_code=ErrorCodes.FILE_NOT_FOUND,
                exc_info=True,
            )
            return False

        # Scan the directory to collect current resources
        scanner = LocalScanner(self)
        scanner.scan_directory(path)

        # Generate a new CSP header based on the scanned resources
        new_csp = self.generate_csp(report=False)

        # Compare the two CSP headers
        if existing_csp == new_csp:
            logger.info(
                "CSP validation passed", csp_file=csp_file, operation="validate_csp"
            )
            return True
        else:
            logger.warning(
                "CSP validation failed",
                csp_file=csp_file,
                operation="validate_csp",
                error_code=ErrorCodes.VALIDATION_ERROR,
            )
            logger.debug(
                "CSP comparison",
                existing_csp=existing_csp,
                new_csp=new_csp,
                operation="validate_csp",
            )

            # Parse and compare CSPs
            existing_directives = self._parse_csp(existing_csp)
            generated_directives = self._parse_csp(new_csp)
            self.printer.print_csp_diff(existing_directives, generated_directives)
            return False
