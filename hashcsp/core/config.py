"""Configuration model for Content Security Policy directives.

This module provides configuration loading, validation, and saving functionality
for CSP directives. It uses structured logging for better debugging and auditing.
"""

import json
import os
from typing import Dict, List, Optional

from pydantic import BaseModel, ValidationError
from rich.console import Console

from .logging_config import ErrorCodes, get_logger

logger = get_logger(__name__)
console = Console()


class CSPConfig(BaseModel):
    """Configuration model for Content Security Policy directives.

    A Pydantic model that defines the structure and validation rules for CSP
    configuration. Provides default directives that follow security best practices.

    Attributes:
        directives (Dict[str, List[str]]): Dictionary mapping CSP directive names
            to lists of allowed sources.
    """

    directives: Dict[str, List[str]] = {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'"],
        "style-src-attr": [],
        "img-src": ["'self'"],
        "font-src": ["'self'"],
        "media-src": ["'self'"],
        "connect-src": ["'self'"],
        "object-src": ["'none'"],
        "frame-src": ["'self'"],
        "worker-src": ["'self'"],
        "manifest-src": ["'self'"],
    }


def load_config(config_path: Optional[str] = None) -> Optional[CSPConfig]:
    """Load CSP configuration from a JSON file.

    Attempts to load and validate a CSP configuration from a JSON file. If no path
    is provided, looks for 'hashcsp.json' in the current directory. Returns None
    and logs appropriate messages if the file is not found or is invalid.

    Args:
        config_path (Optional[str], optional): Path to the config file. Defaults to None.

    Returns:
        Optional[CSPConfig]: A validated CSPConfig instance if successful, None otherwise.

    Raises:
        ValidationError: If the configuration format is invalid.
        JSONDecodeError: If the file contains invalid JSON.
    """
    default_path = "hashcsp.json"
    path = config_path or default_path

    if not os.path.exists(path):
        logger.info("No config file found", file_path=path, operation="load_config")
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        config = CSPConfig(**data)
        logger.info(
            "Loaded config successfully",
            file_path=path,
            operation="load_config",
            directive_count=len(config.directives),
        )
        return config
    except json.JSONDecodeError as e:
        logger.error(
            "Invalid JSON in config file",
            file_path=path,
            operation="load_config",
            error_code=ErrorCodes.INVALID_JSON,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error: Invalid JSON in {path}: {e}[/red]")
        return None
    except ValidationError as e:
        logger.error(
            "Invalid CSP config format",
            file_path=path,
            operation="load_config",
            error_code=ErrorCodes.VALIDATION_ERROR,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error: Invalid CSP config in {path}: {e}[/red]")
        return None
    except Exception as e:
        logger.error(
            "Unexpected error loading config",
            file_path=path,
            operation="load_config",
            error_code=ErrorCodes.PERMISSION_DENIED,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error loading config from {path}: {e}[/red]")
        return None


def validate_json_config(file_path: str) -> Optional[CSPConfig]:
    """Validate a JSON file against the CSPConfig schema.

    Reads a JSON file and validates its contents against the CSPConfig schema.
    Provides detailed error messages for invalid configurations.

    Args:
        file_path (str): Path to the JSON configuration file.

    Returns:
        Optional[CSPConfig]: A validated CSPConfig instance if successful, None otherwise.

    Raises:
        ValidationError: If the configuration format is invalid.
        JSONDecodeError: If the file contains invalid JSON.
    """
    if not os.path.isfile(file_path):
        logger.error(
            "Config file not found",
            file_path=file_path,
            operation="validate_json_config",
            error_code=ErrorCodes.FILE_NOT_FOUND,
        )
        console.print(f"[red]Error: File {file_path} not found[/red]")
        return None

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        config = CSPConfig(**data)
        logger.info(
            "Validated JSON config successfully",
            file_path=file_path,
            operation="validate_json_config",
            directive_count=len(config.directives),
        )
        return config
    except json.JSONDecodeError as e:
        logger.error(
            "Invalid JSON in config file",
            file_path=file_path,
            operation="validate_json_config",
            error_code=ErrorCodes.INVALID_JSON,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error: Invalid JSON in {file_path}: {e}[/red]")
        return None
    except ValidationError as e:
        logger.error(
            "Invalid CSP config format",
            file_path=file_path,
            operation="validate_json_config",
            error_code=ErrorCodes.VALIDATION_ERROR,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error: Invalid CSP config in {file_path}: {e}[/red]")
        return None
    except Exception as e:
        logger.error(
            "Error reading config file",
            file_path=file_path,
            operation="validate_json_config",
            error_code=ErrorCodes.PERMISSION_DENIED,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error reading {file_path}: {e}[/red]")
        return None


def save_config(
    config: CSPConfig, path: str = "hashcsp.json", dry_run: bool = False
) -> bool:
    """Save CSP configuration to a JSON file or print for dry-run.

    Serializes a CSPConfig instance to JSON and either saves it to a file or
    prints it to the console in dry-run mode.

    Args:
        config (CSPConfig): The configuration to save.
        path (str, optional): Path where to save the config. Defaults to "hashcsp.json".
        dry_run (bool, optional): Whether to print instead of save. Defaults to False.

    Returns:
        bool: True if the operation was successful, False otherwise.
    """
    try:
        config_json = json.dumps(config.model_dump(), indent=2)
        if dry_run:
            logger.info(
                "Dry-run: Config preview",
                file_path=path,
                operation="save_config",
                directive_count=len(config.directives),
            )
            console.print("[cyan]Dry-run: Config JSON to be saved:[/cyan]")
            console.print(config_json)
            return True

        with open(path, "w", encoding="utf-8") as f:
            f.write(config_json)
        logger.info(
            "Config saved successfully",
            file_path=path,
            operation="save_config",
            directive_count=len(config.directives),
        )
        console.print(f"[green]Config saved to {path}[/green]")
        return True
    except Exception as e:
        logger.error(
            "Error saving config",
            file_path=path,
            operation="save_config",
            error_code=ErrorCodes.PERMISSION_DENIED,
            error=str(e),
            exc_info=True,
        )
        console.print(f"[red]Error saving config to {path}: {e}[/red]")
        return False
