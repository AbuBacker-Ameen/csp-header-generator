import json
import logging
import os
from typing import Dict, List, Optional

from pydantic import BaseModel
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
    except Exception as e:
        console.print(f"[red]Error loading config from {path}: {e}[/red]")
        logger.error(f"Error loading config from {path}: {e}")
        return None


def save_config(config: CSPConfig, path: str = "hashcsp.json") -> bool:
    """Save CSP configuration to a JSON file."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(config.dict(), f, indent=2)
        #console.print(f"[green]Config saved to {path}[/green]")
        logger.info(f"Config saved to {path}")
        return True
    except Exception as e:
        console.print(f"[red]Error saving config to {path}: {e}[/red]")
        logger.error(f"Error saving config to {path}: {e}")
        return False
