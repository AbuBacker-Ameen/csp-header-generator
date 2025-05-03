"""Unit tests for hashcsp.core.config.

Tests cover CSPConfig initialization, loading JSON configs, validating
configurations, and saving configs to files. Includes tests for structured logging.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

from hashcsp.core.config import (
    CSPConfig,
    load_config,
    save_config,
    validate_json_config,
)
from hashcsp.core.logging_config import ErrorCodes


@pytest.fixture
def valid_config_data():
    """Return a valid JSON config dictionary."""
    return {
        "directives": {
            "script-src": ["'self'", "https://example.com"],
            "style-src": ["'self'"],
            "img-src": ["https://images.example.com"],
        }
    }


@pytest.fixture
def default_directives():
    """Return expected default directives for CSPConfig."""
    return {
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


@pytest.fixture
def csp_config():
    """Return a CSPConfig instance with default settings."""
    return CSPConfig()


def get_log_message(
    caplog: pytest.LogCaptureFixture, level: str, operation: str
) -> Dict[str, Any]:
    """Helper function to find and parse a JSON log message.

    Args:
        caplog: The pytest caplog fixture
        level: The log level to search for
        operation: The operation field to match

    Returns:
        dict: The parsed JSON log message or empty dict if not found
    """
    for record in caplog.records:
        try:
            # Parse record.msg as JSON or use directly if dict
            log_data = (
                json.loads(record.msg) if isinstance(record.msg, str) else record.msg
            )
            print(f"Raw log record.msg: {record.msg}")  # Debug output
            print(f"Parsed log_data: {log_data}")  # Debug output
            if (
                record.levelname == level
                and isinstance(log_data, dict)
                and log_data.get("operation") == operation
            ):
                return {
                    "level": record.levelname,
                    "event": log_data.get("event"),
                    "operation": log_data.get("operation"),
                    "file_path": log_data.get("file_path"),
                    "error_code": log_data.get("error_code"),
                    "error": log_data.get("error"),
                    "directive_count": log_data.get("directive_count"),
                }
        except (json.JSONDecodeError, TypeError) as e:
            print(
                f"Failed to parse log record: {record.msg}, error: {e}"
            )  # Debug output
            continue
    print(
        f"No matching log found for level={level}, operation={operation}"
    )  # Debug output
    return {}


# Tests for CSPConfig
def test_csp_config_init(csp_config, default_directives):
    """Test CSPConfig initializes with default directives."""
    assert (
        csp_config.directives == default_directives
    ), f"Expected {default_directives}, got {csp_config.directives}"


def test_csp_config_set_directives(csp_config):
    """Test setting directives on CSPConfig."""
    directives = {"script-src": ["'self'"], "style-src": ["https://cdn.com"]}
    csp_config.directives = directives
    assert csp_config.directives == directives


def test_csp_config_str(csp_config):
    """Test string representation of CSPConfig."""
    csp_config.directives = {"script-src": ["'self'"]}
    assert "directives={'script-src': [\"'self'\"]}" in str(csp_config)


# Tests for load_config
def test_load_config_valid(tmp_path: Path, valid_config_data, caplog):
    """Test loading a valid JSON config file with structured logging."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(valid_config_data))

    with caplog.at_level(logging.INFO):
        config = load_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert config.directives == valid_config_data["directives"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "load_config")
    assert (
        log["event"] == "Loaded config successfully"
    ), f"Expected 'Loaded config successfully', got {log}"
    assert log["file_path"] == str(config_file)
    assert log.get("directive_count") == len(
        valid_config_data["directives"]
    ), f"Expected directive_count={len(valid_config_data['directives'])}, got {log.get('directive_count')}"


def test_load_config_empty(tmp_path: Path, default_directives, caplog):
    """Test loading an empty JSON config file."""
    config_file = tmp_path / "config.json"
    config_file.write_text("{}")

    with caplog.at_level(logging.INFO):
        config = load_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert (
        config.directives == default_directives
    ), f"Expected {default_directives}, got {config.directives}"

    # Verify log message
    log = get_log_message(caplog, "INFO", "load_config")
    assert log["event"] == "Loaded config successfully"
    assert log["file_path"] == str(config_file)


def test_load_config_missing_file(caplog):
    """Test loading a non-existent config file."""
    with caplog.at_level(logging.INFO):
        config = load_config("nonexistent.json")

    assert config is None

    # Verify log message
    log = get_log_message(caplog, "INFO", "load_config")
    assert log["event"] == "No config file found"
    assert log["file_path"] == "nonexistent.json"


def test_load_config_invalid_json(tmp_path: Path, caplog):
    """Test loading a file with invalid JSON."""
    config_file = tmp_path / "config.json"
    config_file.write_text("{invalid json")

    with caplog.at_level(logging.ERROR):
        config = load_config(str(config_file))

    assert config is None

    # Verify log message
    log = get_log_message(caplog, "ERROR", "load_config")
    assert log["event"] == "Invalid JSON in config file"
    assert log["file_path"] == str(config_file)
    assert log["error_code"] == ErrorCodes.INVALID_JSON.value


def test_load_config_schema_violation(tmp_path: Path, caplog):
    """Test loading a config with unsafe directives."""
    invalid_config = {"directives": {"script-src": ["'unsafe-inline'"]}}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(invalid_config))

    with caplog.at_level(logging.INFO):
        config = load_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert config.directives == invalid_config["directives"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "load_config")
    assert log["event"] == "Loaded config successfully"
    assert log["file_path"] == str(config_file)


# Tests for validate_json_config
def test_validate_json_config_valid(tmp_path: Path, valid_config_data, caplog):
    """Test validating a valid config file."""
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(valid_config_data))

    with caplog.at_level(logging.INFO):
        config = validate_json_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert config.directives == valid_config_data["directives"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "validate_json_config")
    assert log["event"] == "Validated JSON config successfully"
    assert log["file_path"] == str(config_file)


def test_validate_json_config_missing_file(caplog):
    """Test validating a non-existent config file."""
    with caplog.at_level(logging.ERROR):
        config = validate_json_config("nonexistent.json")

    assert config is None

    # Verify log message
    log = get_log_message(caplog, "ERROR", "validate_json_config")
    assert log["event"] == "Config file not found"
    assert log["file_path"] == "nonexistent.json"
    assert log["error_code"] == ErrorCodes.FILE_NOT_FOUND.value


def test_validate_json_config_unsafe_directive(tmp_path: Path, caplog):
    """Test validating a config with unsafe directives."""
    invalid_config = {"directives": {"script-src": ["'unsafe-inline'"]}}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(invalid_config))

    with caplog.at_level(logging.INFO):
        config = validate_json_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert config.directives == invalid_config["directives"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "validate_json_config")
    assert log["event"] == "Validated JSON config successfully"
    assert log["file_path"] == str(config_file)


def test_validate_json_config_malformed_directive(tmp_path: Path, caplog):
    """Test validating a config with malformed directives."""
    invalid_config = {"directives": {"script-src": [""]}}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(invalid_config))

    with caplog.at_level(logging.INFO):
        config = validate_json_config(str(config_file))

    assert isinstance(config, CSPConfig)
    assert config.directives == invalid_config["directives"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "validate_json_config")
    assert log["event"] == "Validated JSON config successfully"
    assert log["file_path"] == str(config_file)


def test_validate_json_config_invalid_json(tmp_path: Path, caplog):
    """Test validating a file with invalid JSON."""
    config_file = tmp_path / "config.json"
    config_file.write_text("{invalid json")

    with caplog.at_level(logging.ERROR):
        config = validate_json_config(str(config_file))

    assert config is None

    # Verify log message
    log = get_log_message(caplog, "ERROR", "validate_json_config")
    assert log["event"] == "Invalid JSON in config file"
    assert log["file_path"] == str(config_file)
    assert log["error_code"] == ErrorCodes.INVALID_JSON.value


# Tests for save_config
def test_save_config_valid(tmp_path: Path, csp_config, caplog):
    """Test saving a valid config to a JSON file."""
    csp_config.directives = {"script-src": ["'self'"]}
    output_file = tmp_path / "csp.conf"

    with caplog.at_level(logging.INFO):
        save_config(csp_config, str(output_file))

    assert output_file.exists()
    with open(output_file) as f:
        content = json.load(f)
    assert content["directives"]["script-src"] == ["'self'"]

    # Verify log message
    log = get_log_message(caplog, "INFO", "save_config")
    assert log["event"] == "Config saved successfully"
    assert log["file_path"] == str(output_file)


def test_save_config_dry_run(tmp_path: Path, csp_config, caplog):
    """Test dry-run mode does not write to file."""
    csp_config.directives = {"script-src": ["'self'"]}
    output_file = tmp_path / "csp.conf"

    with caplog.at_level(logging.INFO):
        save_config(csp_config, str(output_file), dry_run=True)

    assert not output_file.exists()

    # Verify log message
    log = get_log_message(caplog, "INFO", "save_config")
    assert log["event"] == "Dry-run: Config preview"
    assert log["file_path"] == str(output_file)


def test_save_config_permission_denied(tmp_path: Path, csp_config, caplog):
    """Test handling permission denied when saving config."""
    csp_config.directives = {"script-src": ["'self'"]}
    output_file = tmp_path / "csp.conf"

    with patch("builtins.open", side_effect=PermissionError("Permission denied")):
        with caplog.at_level(logging.ERROR):
            save_config(csp_config, str(output_file))

    # Verify log message
    log = get_log_message(caplog, "ERROR", "save_config")
    assert log["event"] == "Error saving config"
    assert log["file_path"] == str(output_file)
    assert log["error_code"] == ErrorCodes.PERMISSION_DENIED.value


def test_save_config_invalid_path(csp_config, caplog):
    """Test saving to an invalid path."""
    csp_config.directives = {"script-src": ["'self'"]}
    output_file = "/invalid/path/csp.conf"

    with caplog.at_level(logging.ERROR):
        save_config(csp_config, output_file)

    # Verify log message
    log = get_log_message(caplog, "ERROR", "save_config")
    assert log["event"] == "Error saving config"
    assert log["file_path"] == output_file
    assert log["error_code"] == ErrorCodes.PERMISSION_DENIED.value
