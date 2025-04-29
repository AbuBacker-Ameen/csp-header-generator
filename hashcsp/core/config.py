import json
import logging
import os
from typing import Dict, List, Optional

from pydantic import BaseModel, ValidationError
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()

class CSPConfig(BaseModel):
    directives: Dict[str, List[str]] = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "img-src": ["'self'"],
        "connect-src": ["'self'"],
        "font-src": ["'self'"],
        "media-src": ["'self'"],
        "frame-src": ["'self'"],
    }

def load_config(config_path: Optional[str] = None) -> Optional[CSPConfig]:
    """Load CSP configuration from a JSON file."""
    default_path = "hashcsp.json"
    path = config_path or default_path

    if not os.path.exists(path):
        logger.info(f"No config file found at {path}. Using default directives.")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        config = CSPConfig(**data)
        logger.info(f"Loaded config from {path}")
        return config
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON in {path}: {e}[/red]")
        logger.error(f"Invalid JSON in {path}: {e}")
        return None
    except ValidationError as e:
        console.print(f"[red]Error: Invalid CSP config in {path}: {e}[/red]")
        logger.error(f"Invalid CSP config in {path}: {e}")
        return None
    except Exception as e:
        console.print(f"[red]Error loading config from {path}: {e}[/red]")
        logger.error(f"Error loading config from {path}: {e}")
        return None

def validate_json_config(file_path: str) -> Optional[CSPConfig]:
    """Validate a JSON file against the CSPConfig schema."""
    if not os.path.isfile(file_path):
        console.print(f"[red]Error: File {file_path} not found[/red]")
        logger.error(f"File {file_path} not found")
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        config = CSPConfig(**data)
        logger.info(f"Validated JSON config from {file_path}")
        return config
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON in {file_path}: {e}[/red]")
        logger.error(f"Invalid JSON in {file_path}: {e}")
        return None
    except ValidationError as e:
        console.print(f"[red]Error: Invalid CSP config in {file_path}: {e}[/red]")
        logger.error(f"Invalid CSP config in {file_path}: {e}")
        return None
    except Exception as e:
        console.print(f"[red]Error reading {file_path}: {e}[/red]")
        logger.error(f"Error reading {file_path}: {e}")
        return None

def save_config(config: CSPConfig, path: str = "hashcsp.json", dry_run: bool = False) -> bool:
    """Save CSP configuration to a JSON file or print for dry-run."""
    try:
        config_json = json.dumps(config.dict(), indent=2)
        if dry_run:
            console.print("[cyan]Dry-run: Config JSON to be saved:[/cyan]")
            console.print(config_json)
            logger.info(f"Dry-run: Config JSON previewed for {path}")
            return True
        with open(path, "w", encoding="utf-8") as f:
            f.write(config_json)
        console.print(f"[green]Config saved to {path}[/green]")
        logger.info(f"Config saved to {path}")
        return True
    except Exception as e:
        console.print(f"[red]Error saving config to {path}: {e}[/red]")
        logger.error(f"Error saving config to {path}: {e}")
        return False
