"""Unit tests for hashcsp.core.logging_config.

Tests cover configuration validation, initialization, sanitization,
and error handling in the logging system.
"""

import json
import logging
import logging.handlers
import tempfile
from pathlib import Path

import pytest
import structlog
from structlog.stdlib import ProcessorFormatter

from hashcsp.core.logging_config import (
    LoggingConfig,
    sanitize_log_record,
    setup_logging,
)


@pytest.fixture
def temp_log_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for log files."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


@pytest.fixture
def valid_config(temp_log_dir: Path) -> LoggingConfig:
    """Create a valid logging configuration."""
    return LoggingConfig(
        level="INFO",
        format="json",
        file=str(temp_log_dir / "test.log"),
        max_bytes=1024,
        backup_count=2,
    )


# Test LoggingConfig
def test_logging_config_defaults():
    """Test default values in LoggingConfig."""
    config = LoggingConfig()
    assert config.level == "INFO"
    assert config.format == "console"
    assert config.max_bytes == 10 * 1024 * 1024
    assert config.backup_count == 5
    assert "hashcsp_log.json" in config.file


def test_logging_config_validation():
    """Test validation of logging configuration values."""
    # Test invalid log level
    with pytest.raises(ValueError, match="Invalid LOG_LEVEL"):
        LoggingConfig(level="INVALID")

    # Test invalid format
    with pytest.raises(ValueError, match="Invalid LOG_FORMAT"):
        LoggingConfig(format="INVALID")

    # Test invalid max_bytes
    with pytest.raises(ValueError, match="LOG_MAX_BYTES must be positive"):
        LoggingConfig(max_bytes=0)

    # Test invalid backup_count
    with pytest.raises(ValueError, match="LOG_BACKUP_COUNT must be positive"):
        LoggingConfig(backup_count=0)


def test_logging_config_from_env(monkeypatch: pytest.MonkeyPatch):
    """Test loading configuration from environment variables."""
    env_vars = {
        "LOG_LEVEL": "DEBUG",
        "LOG_FORMAT": "json",
        "LOG_FILE": str(tempfile.NamedTemporaryFile(delete=False).name),
        "LOG_MAX_BYTES": "2048",
        "LOG_BACKUP_COUNT": "3",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    config = LoggingConfig.from_env()
    assert config.level == "DEBUG"
    assert config.format == "json"
    assert config.file == env_vars["LOG_FILE"]
    assert config.max_bytes == 2048
    assert config.backup_count == 3


# Test setup_logging
def test_setup_logging_creates_handlers(valid_config: LoggingConfig):
    """Test that setup_logging creates the expected handlers."""
    setup_logging(valid_config)
    root_logger = logging.getLogger()

    assert len(root_logger.handlers) == 1  # Just file handler for json format
    assert isinstance(root_logger.handlers[0], logging.handlers.RotatingFileHandler)
    assert root_logger.level == logging.INFO


def test_setup_logging_console_format(valid_config: LoggingConfig):
    """Test console format creates both handlers."""
    valid_config.console_level = "INFO"
    setup_logging(valid_config)
    root_logger = logging.getLogger()

    assert len(root_logger.handlers) == 2  # File and console handlers
    assert any(
        isinstance(h, logging.handlers.RotatingFileHandler)
        for h in root_logger.handlers
    )
    assert any(
        isinstance(h.formatter, ProcessorFormatter) for h in root_logger.handlers
    )


def test_setup_logging_invalid_directory(temp_log_dir: Path):
    """Test handling of invalid log directory."""
    config = LoggingConfig(file="/nonexistent/dir/test.log")
    with pytest.raises((OSError, PermissionError)):
        setup_logging(config)


def test_setup_logging_creates_log_file(valid_config: LoggingConfig):
    """Test that log file is created."""
    setup_logging(valid_config)
    assert Path(valid_config.file).exists()


# Test sanitize_log_record
def test_sanitize_log_record_sensitive_keys():
    """Test sanitization of sensitive data in log records."""
    test_cases = [
        (
            {"password": "secret123"},
            {"password": "***REDACTED***"},
        ),
        (
            {"api_key": "abc123", "message": "test"},
            {"api_key": "***REDACTED***", "message": "test"},
        ),
        (
            {"auth_token": "xyz789", "level": "INFO"},
            {"auth_token": "***REDACTED***", "level": "INFO"},
        ),
    ]

    for input_dict, expected in test_cases:
        result = sanitize_log_record("test_logger", "info", input_dict)
        assert result == expected


def test_sanitize_log_record_sensitive_patterns():
    """Test sanitization of sensitive patterns in values."""
    test_cases = [
        (
            {"message": "password=secret123"},
            {"message": "***REDACTED***"},
        ),
        (
            {"error": "Failed with token=abc123"},
            {"error": "***REDACTED***"},
        ),
        (
            {"debug": "key=xyz789 in config"},
            {"debug": "***REDACTED***"},
        ),
    ]

    for input_dict, expected in test_cases:
        result = sanitize_log_record("test_logger", "info", input_dict)
        assert result == expected


def test_sanitize_log_record_nested_content():
    """Test sanitization of nested structures."""
    input_dict = {
        "outer": {"inner": {"password": "secret", "safe": "value"}},
        "message": "test",
    }
    result = sanitize_log_record("test_logger", "info", input_dict)
    assert result["outer"]["inner"]["password"] == "***REDACTED***"
    assert result["outer"]["inner"]["safe"] == "value"
    assert result["message"] == "test"


# Integration tests
def test_logging_output_format(valid_config: LoggingConfig, temp_log_dir: Path):
    """Test the format of logged output."""
    setup_logging(valid_config)
    logger = structlog.get_logger("test")

    test_message = "Test log message"
    logger.info(test_message, custom_param="test_value")

    # Read the log file and get the last line (skipping initialization message)
    with open(valid_config.file) as f:
        log_lines = f.readlines()
        log_line = log_lines[-1]  # Get the last line which should be our test message

    # Parse JSON and verify structure
    log_entry = json.loads(log_line)
    assert log_entry["event"] == test_message
    assert log_entry["level"] == "info"
    assert log_entry["custom_param"] == "test_value"
    assert "timestamp" in log_entry


def test_logging_rotation(valid_config: LoggingConfig, temp_log_dir: Path):
    """Test log file rotation."""
    # Set small max_bytes to trigger rotation
    valid_config.max_bytes = 100
    setup_logging(valid_config)
    logger = structlog.get_logger("test")

    # Write enough logs to trigger rotation
    for i in range(10):
        logger.info("Test message " * 5)

    # Check that backup files were created
    log_file = Path(valid_config.file)
    assert log_file.exists()
    assert (log_file.parent / f"{log_file.name}.1").exists()


def test_error_logging(valid_config: LoggingConfig, temp_log_dir: Path):
    """Test error logging with stack traces."""
    setup_logging(valid_config)
    logger = structlog.get_logger("test")

    try:
        raise ValueError("Test error")
    except ValueError:
        logger.error("Error occurred", exc_info=True)

    # Read the log file and get the last line (skipping initialization message)
    with open(valid_config.file) as f:
        log_lines = f.readlines()
        log_line = log_lines[-1]  # Get the last line which should be our error message

    # Verify error details
    log_entry = json.loads(log_line)
    assert log_entry["level"] == "error"
    assert "exception" in log_entry
    assert "ValueError: Test error" in log_entry["exception"]
