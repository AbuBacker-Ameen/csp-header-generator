import hashlib
import base64
import os
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.align import Align
from rich import box
import requests
from bs4 import BeautifulSoup
from requests.exceptions import HTTPError, ConnectionError, Timeout, RequestException
import logging
from urllib.parse import urlparse
from . import __logfile__

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(__logfile__),
        # logging.StreamHandler()  # Optional: remove for production
    ]
)
logger = logging.getLogger(__name__)

class CSPGenerator:
    def __init__(self):
        self.directives = {
            'default-src': ["'self'"],
            'script-src': ["'self'"],
            'style-src': ["'self'"],
            'img-src': ["'self'"],
            'connect-src': ["'self'"],
            'font-src': ["'self'"],
            'object-src': ["'none'"],
            'media-src': ["'self'"],
            'frame-src': ["'none'"],
            'child-src': ["'self'"],
            'worker-src': ["'self'"],
            'base-uri': ["'self'"],
            'form-action': ["'self'"],
            'frame-ancestors': ["'none'"],
            'manifest-src': ["'self'"],
        }
        self.hashes = {'script-src': [], 'style-src': []}
        self.stats = {
            'files_processed': 0,
            'unique_script_hashes': 0,
            'unique_style_hashes': 0,
            'external_scripts': 0,
            'external_styles': 0,
            'external_images': 0,
            'files_with_no_inline_scripts': 0
        }
        logger.info("Initialized CSPGenerator with default directives")

    def compute_hash(self, content: str, source: str) -> str:
        try:
            sha256_hash = hashlib.sha256(content.encode('utf-8')).digest()
            hash_value = f"'sha256-{base64.b64encode(sha256_hash).decode('utf-8')}'"
            logger.info(f"Computed hash {hash_value} for content from {source}")
            return hash_value
        except UnicodeEncodeError as e:
            logger.error(f"Encoding error for content from {source}: {e}")
            raise

    def scan_html_file(self, file_path: str):
        try:
            if not os.path.isfile(file_path):
                logger.error(f"Invalid file: {file_path}")
                console.print(f"[red]Error: {file_path} is not a valid file :no_entry_sign:[/red]")
                return
            with open(file_path, 'r', encoding='utf-8') as f:
                logger.info(f"Scanning file: {file_path}")
                soup = BeautifulSoup(f, 'html.parser')
                
                scripts = soup.find_all('script', src=False)
                styles = soup.find_all('style')
                
                if not scripts and not styles:
                    self.stats['files_with_no_inline_scripts'] += 1
                    logger.info(f"No inline scripts or styles in {file_path}")
                    # console.print(f"[yellow]No inline scripts or styles in {file_path} :page_facing_up:[/yellow]")
                
                for script in scripts:
                    if script.string:
                        script_hash = self.compute_hash(script.string.strip(), file_path)
                        if script_hash not in self.hashes['script-src']:
                            self.hashes['script-src'].append(script_hash)
                            self.stats['unique_script_hashes'] += 1
                            logger.info(f"Added script hash {script_hash} from {file_path}")
                
                for style in styles:
                    if style.string:
                        style_hash = self.compute_hash(style.string.strip(), file_path)
                        if style_hash not in self.hashes['style-src']:
                            self.hashes['style-src'].append(style_hash)
                            self.stats['unique_style_hashes'] += 1
                            logger.info(f"Added style hash {style_hash} from {file_path}")
                
                self.stats['files_processed'] += 1
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            console.print(f"[red]Error: File {file_path} not found :no_entry_sign:[/red]")
        except UnicodeDecodeError:
            logger.error(f"Invalid encoding in file: {file_path}")
            console.print(f"[red]Error: File {file_path} has invalid encoding :no_entry_sign:[/red]")
        except Exception as e:
            logger.error(f"Unexpected error scanning {file_path}: {e}", exc_info=True)
            console.print(f"[red]Unexpected error scanning {file_path}: {e} :cold_sweat:[/red]")

    def scan_directory(self, path: str):
        try:
            if not os.path.isdir(path):
                logger.error(f"Invalid directory: {path}")
                console.print(f"[red]Error: {path} is not a valid directory :no_entry_sign:[/red]")
                return
            logger.info(f"Scanning directory: {path}")
            html_files = 0
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.html'):
                        html_files += 1
                        self.scan_html_file(os.path.join(root, file))
            if html_files == 0:
                logger.info(f"No HTML files found in {path}")
                console.print(f"[yellow]No HTML files found in {path} :open_file_folder:[/yellow]")
            else:
                logger.info(f"Scanned {html_files} HTML files in {path}")
                console.print(f"[green]Scanned {html_files} HTML files :books:[/green]")
        except Exception as e:
            logger.error(f"Error scanning directory {path}: {e}", exc_info=True)
            console.print(f"[red]Error scanning directory {path}: {e} :cold_sweat:[/red]")

    def fetch_remote_site(self, url: str) -> bool:
        try:
            if not url.startswith(('http://', 'https://')):
                logger.error(f"Invalid URL format: {url}")
                console.print(f"[red]Error: Invalid URL format: {url}. Must start with http:// or https:// :no_entry_sign:[/red]")
                return False
            logger.info(f"Fetching website: {url}")
            console.print(f"[cyan]Fetching website: {url} :globe_with_meridians:[/cyan]")
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            scripts = soup.find_all('script', src=False)
            styles = soup.find_all('style')
            
            if not scripts and not styles:
                self.stats['files_with_no_inline_scripts'] += 1
                logger.info(f"No inline scripts or styles at {url}")
                console.print(f"[yellow]No inline scripts or styles at {url} :satellite:[/yellow]")

            for script in scripts:
                if script.string:
                    script_hash = self.compute_hash(script.string.strip(), url)
                    if script_hash not in self.hashes['script-src']:
                        self.hashes['script-src'].append(script_hash)
                        self.stats['unique_script_hashes'] += 1
                        logger.info(f"Added script hash {script_hash} from {url}")

            for style in styles:
                if style.string:
                    style_hash = self.compute_hash(style.string.strip(), url)
                    if style_hash not in self.hashes['style-src']:
                        self.hashes['style-src'].append(style_hash)
                        self.stats['unique_style_hashes'] += 1
                        logger.info(f"Added style hash {style_hash} from {url}")

            for script in soup.find_all('script', src=True):
                src = script.get('src')
                if src and src not in self.directives['script-src']:
                    self.directives['script-src'].append(src)
                    self.stats['external_scripts'] += 1
                    logger.info(f"Added external script source: {src} from {url}")

            for link in soup.find_all('link', href=True):
                href = link.get('href')
                if href and link.get('rel') == ['stylesheet'] and href not in self.directives['style-src']:
                    self.directives['style-src'].append(href)
                    self.stats['external_styles'] += 1
                    logger.info(f"Added external style source: {href} from {url}")

            for img in soup.find_all('img', src=True):
                src = img.get('src')
                if src and src not in self.directives['img-src']:
                    self.directives['img-src'].append(src)
                    self.stats['external_images'] += 1
                    logger.info(f"Added image source: {src} from {url}")

            logger.info(f"Successfully fetched and analyzed {url}")
            console.print(f"[green]Successfully analyzed {url} :tada:[/green]")
            return True
        except HTTPError as e:
            logger.error(f"HTTP error fetching {url}: {e.response.status_code} {e.response.reason}")
            console.print(f"[red]HTTP error: {e.response.status_code} {e.response.reason} :no_entry_sign:[/red]")
            return False
        except ConnectionError:
            logger.error(f"Connection error fetching {url}: Unable to reach server")
            console.print(f"[red]Connection error: Unable to reach {url}. Check your network. :globe_with_meridians:[/red]")
            return False
        except Timeout:
            logger.error(f"Timeout fetching {url}: Request took too long")
            console.print(f"[red]Timeout: Request to {url} took too long. Try again later. :hourglass_flowing_sand:[/red]")
            return False
        except RequestException as e:
            logger.error(f"Request error fetching {url}: {e}")
            console.print(f"[red]Request error fetching {url}: {e} :cold_sweat:[/red]")
            return False
        except Exception as e:
            logger.error(f"Unexpected error fetching {url}: {e}", exc_info=True)
            console.print(f"[red]Unexpected error processing {url}: {e} :cold_sweat:[/red]")
            return False

    def generate_csp(self, report: bool = True) -> str:
        try:
            csp_parts = []
            for directive, sources in self.directives.items():
                if sources:
                    if directive in self.hashes and self.hashes[directive]:
                        sources = sources + self.hashes[directive]
                    csp_parts.append(f"{directive} {' '.join(sources)}")
            if not csp_parts:
                logger.warning("No directives to generate CSP header")
                console.print("[yellow]No directives to generate CSP header :scroll:[/yellow]")
                return "default-src 'self'"
            csp_header = '; '.join(csp_parts)
            logger.info(f"Generated CSP header: {csp_header}")
            if report:
                self._print_summary_report()
            return csp_header
        except Exception as e:
            logger.error(f"Error generating CSP header: {e}", exc_info=True)
            console.print(f"[red]Error generating CSP header: {e} :cold_sweat:[/red]")
            raise

    def _print_summary_report(self):
        if os.environ.get('CSP_PLAIN_OUTPUT') == '1':
            print("CSP Generation Report :dart:")
            print(f"Files Processed :page_facing_up: : {self.stats['files_processed']}")
            print(f"Files With No inline scripts or styles :scroll: : {self.stats['files_with_no_inline_scripts']}")
            print(f"Unique Script Hashes :hammer_and_wrench: : {self.stats['unique_script_hashes']}")
            print(f"Unique Style Hashes :art: : {self.stats['unique_style_hashes']}")
            print(f"External Scripts :globe_with_meridians: : {self.stats['external_scripts']}")
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
            table.add_column("Metric", justify="center", style="cyan", no_wrap=True, ratio=2)
            table.add_column("Value", justify="center", style="green", overflow="fold")
            rows = [
                ("Files Processed :page_facing_up: ", self.stats["files_processed"]),
                ("Files With No inline scripts or styles :scroll: ", self.stats["files_with_no_inline_scripts"]),
                ("Unique Script Hashes :hammer_and_wrench: ", self.stats["unique_script_hashes"]),
                ("Unique Style Hashes :art: ", self.stats["unique_style_hashes"]),
                ("External Scripts :globe_with_meridians:", self.stats["external_scripts"]),
                ("External Styles :art:", self.stats["external_styles"]),
                ("External Images :framed_picture:", self.stats["external_images"]),
            ]
            for metric, value in rows:
                style = "bold red" if value == 0 else ""
                table.add_row(Align.left(metric), Align.center(str(value)), style=style)
            console.print(Align.center(table))
            console.print("[bold green]:sparkles: CSP Header Generated Successfully! [/bold green]")

    def _parse_csp(self, csp: str) -> Dict[str, List[str]]:
        """Parse a CSP header into a dictionary of directives and sources."""
        directives = {}
        if not csp:
            logger.warning("Empty CSP string provided for parsing")
            return directives
        for part in csp.split(';'):
            part = part.strip()
            if part:
                try:
                    directive, *sources = part.split()
                    directives[directive] = sources
                    logger.debug(f"Parsed directive: {directive} with sources: {sources}")
                except ValueError:
                    logger.warning(f"Invalid CSP directive format: {part}")
                    continue
        return directives

    def _print_csp_diff(self, existing: Dict[str, List[str]], generated: Dict[str, List[str]]):
        """Print a detailed report of CSP differences."""
        if os.environ.get('CSP_PLAIN_OUTPUT') == '1':
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
                print(f"Directives missing in existing CSP: {', '.join(sorted(missing_directives))} :no_entry_sign:")
            if extra_directives:
                print(f"Extra directives in existing CSP: {', '.join(sorted(extra_directives))} :warning:")
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
                console.print("[yellow]No specific differences found in directives, but CSP strings differ.[/yellow]")
            else:
                console.print(Align.center(table))
            
            missing_directives = set(generated.keys()) - set(existing.keys())
            extra_directives = set(existing.keys()) - set(generated.keys())
            if missing_directives:
                console.print(f"[red]Directives missing in existing CSP: {', '.join(sorted(missing_directives))} :no_entry_sign:[/red]")
            if extra_directives:
                console.print(f"[yellow]Extra directives in existing CSP: {', '.join(sorted(extra_directives))} :warning:[/yellow]")

    def validate_csp(self, csp_file: str, path: str) -> bool:
        """Validate existing CSP header against current HTML."""
        try:
            if not os.path.isfile(csp_file):
                logger.error(f"CSP file not found: {csp_file}")
                console.print(f"[red]Error: CSP file {csp_file} not found :no_entry_sign:[/red]")
                return False
            self.scan_directory(path)
            with open(csp_file, 'r', encoding='utf-8') as f:
                existing_csp = f.read().strip()
            
            generated_csp = self.generate_csp(report=False)
            if existing_csp == generated_csp:
                logger.info("CSP header validation successful")
                console.print("[green]CSP header is valid! :white_check_mark:[/green]")
                return True
            else:
                logger.warning("CSP header mismatch")
                console.print("[yellow]CSP header mismatch! :warning:[/yellow]")
                # console.print(f"[cyan]Expected:[/cyan] {generated_csp}")
                # console.print(f"[cyan]Found:[/cyan] {existing_csp}")
                
                # Parse and compare CSPs
                existing_directives = self._parse_csp(existing_csp)
                generated_directives = self._parse_csp(generated_csp)
                self._print_csp_diff(existing_directives, generated_directives)
                
                return False
        except UnicodeDecodeError:
            logger.error(f"Invalid encoding in CSP file: {csp_file}")
            console.print(f"[red]Error: CSP file {csp_file} has invalid encoding :no_entry_sign:[/red]")
            return False
        except Exception as e:
            logger.error(f"Error validating CSP file {csp_file}: {e}", exc_info=True)
            console.print(f"[red]Error validating CSP file {csp_file}: {e} :cold_sweat:[/red]")
            return False

    def update_directive(self, directive: str, sources: List[str]):
        try:
            if directive in self.directives:
                self.directives[directive] = sources
                logger.info(f"Updated {directive} with sources: {sources}")
                console.print(f"[green]Updated {directive} with sources: {sources} :white_check_mark:[/green]")
            else:
                logger.error(f"Invalid directive: {directive}")
                console.print(f"[red]Error: Invalid directive: {directive}. Valid directives: {list(self.directives.keys())} :no_entry_sign:[/red]")
                raise ValueError(f"Invalid directive: {directive}")
        except Exception as e:
            logger.error(f"Error updating directive {directive}: {e}", exc_info=True)
            console.print(f"[red]Error updating directive {directive}: {e} :cold_sweat:[/red]")
            raise