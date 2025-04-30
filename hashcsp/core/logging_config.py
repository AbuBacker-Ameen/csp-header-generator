"""Centralized logging configuration for HashCSP.

This module provides a logging setup with structured JSON logging,
multiple handlers (console and file), and environment variable configuration.
It supports both development (rich console output) and production (JSON) modes.

Environment Variables:
    LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Default: INFO
    LOG_FORMAT: Output format (json, console). Default: console
    LOG_FILE: Log file path. Default: hashcsp/logs/hashcsp.log
    LOG_MAX_BYTES: Maximum log file size in bytes. Default: 10485760 (10MB)
    LOG_BACKUP_COUNT: Number of backup files to keep. Default: 5

Example JSON Log:
    {
        "timestamp": "2025-04-30T12:00:00Z",
        "level": "ERROR",
        "message": "Invalid JSON in config.json",
        "module": "config",
        "file_path": "config.json",
        "function": "load_config",
        "line_number": 43,
        "error_code": "INVALID_JSON",
        "request_id": "abc123",
        "operation": "load_config"
    }
"""

import contextlib
import dataclasses
import enum
import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

import structlog
from rich.console import Console
from rich.logging import RichHandler
from structlog.processors import JSONRenderer
from structlog.stdlib import ProcessorFormatter

# Get the root directory of the package
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Default log file path
DEFAULT_LOG_FILE = os.path.join(ROOT_DIR, "logs", "hashcsp_log.json")

# Create logs directory if it doesn't exist
os.makedirs(os.path.dirname(DEFAULT_LOG_FILE), exist_ok=True)

# Environment variable configuration
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.environ.get("LOG_FORMAT", "console").lower()
LOG_FILE = os.environ.get("LOG_FILE", DEFAULT_LOG_FILE)
LOG_MAX_BYTES = int(os.environ.get("LOG_MAX_BYTES", 10485760))  # 10MB
LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", 5))

# Console for rich output
console = Console()


@dataclasses.dataclass
class LoggingConfig:
    """Centralized logging configuration with validation."""

    VALID_LOG_LEVELS: Set[str] = dataclasses.field(
        default_factory=lambda: {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    )
    VALID_LOG_FORMATS: Set[str] = dataclasses.field(
        default_factory=lambda: {"json", "console"}
    )

    # Default configuration
    level: str = "INFO"
    format: str = "console"
    file: str = ""  # Will be set in __post_init__
    max_bytes: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    package_name: str = "hashcsp"

    def __post_init__(self):
        """Validate and normalize configuration after initialization."""
        # Normalize and validate log level
        self.level = self.level.upper()
        if self.level not in self.VALID_LOG_LEVELS:
            raise ValueError(
                f"Invalid LOG_LEVEL: {self.level}. Must be one of {self.VALID_LOG_LEVELS}"
            )

        # Normalize and validate log format
        self.format = self.format.lower()
        if self.format not in self.VALID_LOG_FORMATS:
            raise ValueError(
                f"Invalid LOG_FORMAT: {self.format}. Must be one of {self.VALID_LOG_FORMATS}"
            )

        # Set default log file path if not provided
        if not self.file:
            package_root = Path(__file__).parent.parent
            self.file = str(package_root / "logs" / f"{self.package_name}.log")

        # Validate numeric values
        if self.max_bytes <= 0:
            raise ValueError("LOG_MAX_BYTES must be positive")
        if self.backup_count <= 0:
            raise ValueError("LOG_BACKUP_COUNT must be positive")

    @classmethod
    def from_env(cls) -> "LoggingConfig":
        """Create configuration from environment variables with validation."""
        return cls(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            format=os.environ.get("LOG_FORMAT", "console"),
            file=os.environ.get("LOG_FILE", ""),
            max_bytes=int(os.environ.get("LOG_MAX_BYTES", 10 * 1024 * 1024)),
            backup_count=int(os.environ.get("LOG_BACKUP_COUNT", 5)),
        )


class ErrorCodes(str, enum.Enum):
    """Standardized error codes for logging."""

    # File operations
    FILE_NOT_FOUND = "FILE_NOT_FOUND"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    INVALID_ENCODING = "INVALID_ENCODING"
    FILE_PROCESSING_ERROR = "FILE_PROCESSING_ERROR"

    # Configuration
    INVALID_JSON = "INVALID_JSON"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_CSP = "INVALID_CSP"
    UNSAFE_DIRECTIVE = "UNSAFE_DIRECTIVE"
    LOGGING_CONFIG_ERROR = "LOGGING_CONFIG_ERROR"

    # Network
    NETWORK_ERROR = "NETWORK_ERROR"
    CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"
    SSL_ERROR = "SSL_ERROR"


def sanitize_log_record(logger: str, method_name: str, event_dict: Dict) -> Dict:
    """Sanitize sensitive data from log records.

    Args:
        logger: Logger name
        method_name: Logging method name
        event_dict: Log event dictionary

    Returns:
        Dict: Sanitized log event dictionary
    """
    # List of keys that might contain sensitive data
    sensitive_keys = {"password", "token", "secret", "key", "auth"}
    
    # List of patterns indicating sensitive data
    sensitive_patterns = {"password=", "token=", "secret=", "key=", "auth="}

    def redact_value(value: Any, key: str = "") -> Any:
        """Redact sensitive values recursively.
        
        Args:
            value: The value to redact
            key: The key associated with this value (for key-based redaction)
        """
        if any(sensitive in key.lower() for sensitive in sensitive_keys):
            return "***REDACTED***"

        if isinstance(value, dict):
            return {k: redact_value(v, k) for k, v in value.items()}
        elif isinstance(value, (list, tuple)):
            return [redact_value(v) for v in value]
        elif isinstance(value, str):
            # Check if the string contains sensitive patterns
            if any(pattern in value.lower() for pattern in sensitive_patterns):
                return "***REDACTED***"
            return value
        return value

    # Create a new dict with sanitized values
    return {k: redact_value(v, k) for k, v in event_dict.items()}


def normalize_event_dict(logger: str, method_name: str, event_dict: Dict) -> Dict:
    """Normalize the event dictionary for consistent output.

    Args:
        logger: Logger name
        method_name: Logging method name
        event_dict: Log event dictionary

    Returns:
        Dict: Normalized log event dictionary
    """
    # Ensure level is lowercase for consistency
    if "level" in event_dict:
        event_dict["level"] = event_dict["level"].lower()
    elif method_name:
        event_dict["level"] = method_name.lower()

    # Move log message to event field if not already set
    if "event" not in event_dict:
        if "_" in event_dict:
            event_dict["event"] = event_dict.pop("_")
        elif "msg" in event_dict:
            event_dict["event"] = event_dict.pop("msg")

    return event_dict


def setup_logging(config: Optional[LoggingConfig] = None) -> None:
    """Configure the logging system with both JSON and console handlers.

    Args:
        config: Optional logging configuration. If not provided, loads from environment.

    Raises:
        OSError: If log directory creation fails
        PermissionError: If log file creation fails
        ValueError: If configuration validation fails
    """
    try:
        # Load or validate config
        config = config or LoggingConfig.from_env()

        # Ensure log directory exists
        log_dir = os.path.dirname(config.file)
        with contextlib.suppress(FileExistsError):
            os.makedirs(log_dir, mode=0o755)

        # Clear any existing handlers
        root_logger = logging.getLogger()
        root_logger.handlers = []

        # Set the root logger's level
        root_logger.setLevel(config.level)

        # Configure processors for structlog
        processors = [
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            normalize_event_dict,
            sanitize_log_record,
        ]

        # Configure structlog
        structlog.configure(
            processors=processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        # Create JSON formatter for file handler
        json_formatter = ProcessorFormatter(
            processor=JSONRenderer(sort_keys=True),
            foreign_pre_chain=processors,
        )

        # File handler (JSON format)
        try:
            file_handler = logging.handlers.RotatingFileHandler(
                config.file,
                maxBytes=config.max_bytes,
                backupCount=config.backup_count,
                encoding="utf-8",
                mode="w",  # Start with a fresh file for tests
            )
            file_handler.setFormatter(json_formatter)
            file_handler.setLevel(config.level)
            root_logger.addHandler(file_handler)
        except (PermissionError, OSError) as e:
            console.print(f"[red]Error creating log file: {e}[/red]")
            raise

        # Console handler (development mode)
        if config.format == "console":
            console_handler = RichHandler(
                console=console,
                show_time=True,
                show_path=True,
                rich_tracebacks=True,
                tracebacks_show_locals=True,
                level=config.level,
            )
            console_handler.setFormatter(ProcessorFormatter(
                processor=structlog.dev.ConsoleRenderer(),
                foreign_pre_chain=processors,
            ))
            root_logger.addHandler(console_handler)

        # Log initial configuration
        logger = get_logger(__name__)
        logger.info(
            "Logging system initialized",
            level=config.level,
            format=config.format,
            log_file=config.file,
            max_bytes=config.max_bytes,
            backup_count=config.backup_count,
            operation="setup_logging",
        )

    except Exception as e:
        console.print(f"[red]Failed to initialize logging: {e}[/red]")
        raise


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a logger instance with the specified name.

    Args:
        name: The name of the logger (typically __name__)

    Returns:
        A configured structlog logger instance
    """
    return structlog.get_logger(name)


# Initialize logging configuration
try:
    setup_logging()
except Exception as e:
    console.print(f"[red]Critical error during logging setup: {e}[/red]")
    sys.exit(1)
