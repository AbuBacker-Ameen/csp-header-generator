import logging
import os

from bs4 import BeautifulSoup

from .csp_generator import CSPGenerator

logger = logging.getLogger(__name__)


class LocalScanner:
    def __init__(self, csp_generator: CSPGenerator):
        self.csp = csp_generator

    def scan_html_file(self, file_path: str) -> bool:
        """Scan an HTML file for inline scripts, styles, and external resources."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                soup = BeautifulSoup(f, "html.parser")

            # Process inline scripts
            inline_scripts = soup.find_all("script", src=False)
            for script in inline_scripts:
                content = script.string
                if content and content.strip():
                    hash_value = self.csp.compute_hash(content, file_path)
                    if hash_value and hash_value not in self.csp.hashes["script-src"]:
                        self.csp.hashes["script-src"].append(hash_value)
                        self.csp.stats["unique_script_hashes"] += 1
                        logger.info(f"Added script hash {hash_value} from {file_path}")

            # Process inline styles
            inline_styles = soup.find_all("style")
            for style in inline_styles:
                content = style.string
                if content and content.strip():
                    hash_value = self.csp.compute_hash(content, file_path)
                    if hash_value and hash_value not in self.csp.hashes["style-src"]:
                        self.csp.hashes["style-src"].append(hash_value)
                        self.csp.stats["unique_style_hashes"] += 1
                        logger.info(f"Added style hash {hash_value} from {file_path}")

            # Process external scripts
            external_scripts = soup.find_all("script", src=True)
            for script in external_scripts:
                src = script.get("src")
                if src and src not in self.csp.directives["script-src"]:
                    self.csp.directives["script-src"].append(src)
                    self.csp.stats["external_scripts"] += 1

            # Process external styles
            external_styles = soup.find_all("link", rel="stylesheet")
            for style in external_styles:
                href = style.get("href")
                if href and href not in self.csp.directives["style-src"]:
                    self.csp.directives["style-src"].append(href)
                    self.csp.stats["external_styles"] += 1

            # Process images
            images = soup.find_all("img", src=True)
            for img in images:
                src = img.get("src")
                if src and src not in self.csp.directives["img-src"]:
                    self.csp.directives["img-src"].append(src)
                    self.csp.stats["external_images"] += 1

            # Check for no inline content
            if not inline_scripts and not inline_styles:
                self.csp.stats["files_with_no_inline_scripts"] += 1
                logger.info(f"No inline scripts or styles in {file_path}")

            self.csp.stats["files_processed"] += 1
            logger.info(f"Processed file: {file_path}")
            return True

        except UnicodeDecodeError:
            logger.error(f"File {file_path} has invalid encoding", exc_info=True)
            return False
        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}", exc_info=True)
            return False

    def scan_directory(self, directory: str) -> None:
        """Scan all HTML files in a directory."""
        html_extensions = (".html", ".htm")
        for root, _, files in os.walk(directory):
            for file in files:
                if file.lower().endswith(html_extensions):
                    file_path = os.path.join(root, file)
                    self.scan_html_file(file_path)
