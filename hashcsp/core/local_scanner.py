"""Local HTML file scanning module for HashCSP.

This module provides functionality for scanning local HTML files to extract
inline scripts, styles, and external resources for CSP generation.
"""

import os
from typing import Dict, List

from bs4 import BeautifulSoup, Tag

from .csp_generator import CSPGenerator
from .logging_config import ErrorCodes, get_logger

logger = get_logger(__name__)


class LocalScanner:
    """Scanner for analyzing local HTML files to generate CSP directives.

    This class scans HTML files for inline scripts, styles, and external resources
    to generate appropriate CSP directives and hashes.

    Attributes:
        csp (CSPGenerator): The CSP generator instance to update with found resources.
    """

    def __init__(self, csp_generator: CSPGenerator):
        """Initialize a LocalScanner instance.

        Args:
            csp_generator (CSPGenerator): The CSP generator to update with found resources.
        """
        self.csp = csp_generator
        # Initialize directive keys if not present
        for key in ["script-src", "style-src", "img-src"]:
            if key not in self.csp.directives:
                self.csp.directives[key] = []

    def scan_html_file(self, file_path: str) -> bool:
        """Scan an HTML file for inline scripts, styles, and external resources.

        Analyzes a single HTML file for:
        - Inline scripts and their hashes
        - Inline styles and their hashes
        - External script sources
        - External style sources
        - Image sources

        Args:
            file_path (str): Path to the HTML file to scan.

        Returns:
            bool: True if the file was successfully processed, False otherwise.

        Raises:
            TypeError: If BeautifulSoup returns non-Tag elements.
        """
        try:
            logger.info("Starting file scan",
                       file_path=file_path,
                       operation="scan_html_file")

            with open(file_path, "r", encoding="utf-8") as f:
                soup = BeautifulSoup(f, "html.parser")

            # Process inline scripts
            inline_scripts = soup.find_all("script", src=False)
            for script in inline_scripts:
                if not isinstance(script, Tag):
                    logger.error("Invalid script element type",
                               file_path=file_path,
                               expected_type="Tag",
                               actual_type=type(script),
                               operation="scan_html_file",
                               error_code=ErrorCodes.VALIDATION_ERROR)
                    raise TypeError(f"Expected Tag, got {type(script)}")
                content = script.string
                if content and content.strip():
                    hash_value = self.csp.compute_hash(content, file_path)
                    if hash_value and hash_value not in self.csp.hashes["script-src"]:
                        self.csp.hashes["script-src"].append(hash_value)
                        self.csp.stats["unique_script_hashes"] += 1
                        logger.debug("Added script hash",
                                   file_path=file_path,
                                   hash=hash_value,
                                   operation="scan_html_file")

            # Process inline styles
            inline_styles = soup.find_all("style")
            for style in inline_styles:
                if not isinstance(style, Tag):
                    logger.error("Invalid style element type",
                               file_path=file_path,
                               expected_type="Tag",
                               actual_type=type(style),
                               operation="scan_html_file",
                               error_code=ErrorCodes.VALIDATION_ERROR)
                    raise TypeError(f"Expected Tag, got {type(style)}")
                content = style.string
                if content and content.strip():
                    hash_value = self.csp.compute_hash(content, file_path)
                    if hash_value and hash_value not in self.csp.hashes["style-src"]:
                        self.csp.hashes["style-src"].append(hash_value)
                        self.csp.stats["unique_style_hashes"] += 1
                        logger.debug("Added style hash",
                                   file_path=file_path,
                                   hash=hash_value,
                                   operation="scan_html_file")

            # Process external scripts
            external_scripts = soup.find_all("script", src=True)
            for script in external_scripts:
                if not isinstance(script, Tag):
                    logger.error("Invalid script element type",
                               file_path=file_path,
                               expected_type="Tag",
                               actual_type=type(script),
                               operation="scan_html_file",
                               error_code=ErrorCodes.VALIDATION_ERROR)
                    raise TypeError(f"Expected Tag, got {type(script)}")
                src = script.get("src")
                if (
                    src
                    and isinstance(src, str)
                    and src not in self.csp.directives["script-src"]
                ):
                    self.csp.directives["script-src"].append(src)
                    self.csp.stats["external_scripts"] += 1
                    logger.debug("Added external script source",
                               file_path=file_path,
                               src=src,
                               operation="scan_html_file")

            # Process external styles
            external_styles = soup.find_all("link", rel="stylesheet")
            for style in external_styles:
                if not isinstance(style, Tag):
                    logger.error("Invalid style element type",
                               file_path=file_path,
                               expected_type="Tag",
                               actual_type=type(style),
                               operation="scan_html_file",
                               error_code=ErrorCodes.VALIDATION_ERROR)
                    raise TypeError(f"Expected Tag, got {type(style)}")
                href = style.get("href")
                if (
                    href
                    and isinstance(href, str)
                    and href not in self.csp.directives["style-src"]
                ):
                    self.csp.directives["style-src"].append(href)
                    self.csp.stats["external_styles"] += 1
                    logger.debug("Added external style source",
                               file_path=file_path,
                               href=href,
                               operation="scan_html_file")

            # Process images
            images = soup.find_all("img", src=True)
            for img in images:
                if not isinstance(img, Tag):
                    logger.error("Invalid image element type",
                               file_path=file_path,
                               expected_type="Tag",
                               actual_type=type(img),
                               operation="scan_html_file",
                               error_code=ErrorCodes.VALIDATION_ERROR)
                    raise TypeError(f"Expected Tag, got {type(img)}")
                src = img.get("src")
                if (
                    src
                    and isinstance(src, str)
                    and src not in self.csp.directives["img-src"]
                ):
                    self.csp.directives["img-src"].append(src)
                    self.csp.stats["external_images"] += 1
                    logger.debug("Added image source",
                               file_path=file_path,
                               src=src,
                               operation="scan_html_file")

            # Check for no inline content
            if not inline_scripts and not inline_styles:
                self.csp.stats["files_with_no_inline_scripts"] += 1
                logger.info("No inline scripts or styles found",
                          file_path=file_path,
                          operation="scan_html_file")

            self.csp.stats["files_processed"] += 1
            logger.info("File scan completed",
                       file_path=file_path,
                       operation="scan_html_file")
            return True

        except UnicodeDecodeError:
            logger.error("Invalid file encoding",
                        file_path=file_path,
                        operation="scan_html_file",
                        error_code=ErrorCodes.INVALID_ENCODING,
                        exc_info=True)
            return False
        except Exception as e:
            logger.error("Error processing file",
                        file_path=file_path,
                        error=str(e),
                        operation="scan_html_file",
                        error_code=ErrorCodes.FILE_PROCESSING_ERROR,
                        exc_info=True)
            return False

    def scan_directory(self, directory: str) -> None:
        """Scan all HTML files in a directory and its subdirectories.

        Recursively scans a directory for HTML files (*.html, *.htm) and processes
        each file to extract CSP-relevant content.

        Args:
            directory (str): Path to the directory to scan.
        """
        logger.info("Starting directory scan",
                   directory=directory,
                   operation="scan_directory")

        html_extensions = (".html", ".htm")
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(html_extensions):
                    file_path = os.path.join(root, file)
                    self.scan_html_file(file_path)

        logger.info("Directory scan completed",
                   directory=directory,
                   files_processed=self.csp.stats["files_processed"],
                   operation="scan_directory")
