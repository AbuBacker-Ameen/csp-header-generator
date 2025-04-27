import logging
from contextlib import redirect_stdout
from io import StringIO

import pytest
import requests_mock
from rich.console import Console

from ..core.csp_generator import CSPGenerator

from .. import __logfile__


@pytest.fixture
def csp_generator():
    return CSPGenerator()


@pytest.fixture
def console_output():
    return Console(file=StringIO(), force_terminal=True, width=80)


def test_compute_hash(csp_generator, tmp_path):
    content = "console.log('test');"
    log_file = tmp_path / __logfile__
    logging.basicConfig(filename=log_file, level=logging.DEBUG, force=True)
    hash_value = csp_generator.compute_hash(content, "test")
    assert hash_value.startswith("'sha256-")
    with open(log_file, "r") as f:
        log_content = f.read()
        assert f"Computed hash {hash_value} for content from test" in log_content


def test_scan_html_file(csp_generator, tmp_path, console_output):
    html_content = """
    <html>
        <script>console.log('test');</script>
        <style>body { color: blue; }</style>
    </html>
    """
    html_file = tmp_path / "test.html"
    html_file.write_text(html_content)

    csp_generator.scan_html_file(str(html_file))
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_fetch_remote_site_success(csp_generator, console_output):
    with requests_mock.Mocker() as m:
        m.get(
            "https://example.com",
            text="""
        <html>
            <script>console.log('remote');</script>
            <link rel="stylesheet" href="https://example.com/style.css">
        </html>
        """,
        )
        success = csp_generator.fetch_remote_site("https://example.com")
        assert success
        assert csp_generator.stats["unique_script_hashes"] == 1
        assert csp_generator.stats["external_styles"] == 1
        assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_fetch_remote_site_failure(csp_generator, console_output):
    with requests_mock.Mocker() as m:
        m.get("https://example.com", status_code=404)
        success = csp_generator.fetch_remote_site("https://example.com")
        assert not success
        assert csp_generator.stats["unique_script_hashes"] == 0
        assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_generate_csp_report(csp_generator, console_output, monkeypatch):
    csp_generator.stats["unique_script_hashes"] = 2
    csp_generator.stats["unique_style_hashes"] = 1
    csp_generator.stats["files_processed"] = 3
    csp_generator.stats["external_scripts"] = 1
    csp_generator.stats["files_with_no_inline_scripts"] = 0
    csp_generator.stats["external_styles"] = 0
    csp_generator.stats["external_images"] = 0

    # Force plain output for testing
    monkeypatch.setenv("CSP_PLAIN_OUTPUT", "1")

    # Capture output using redirect_stdout
    output_buffer = StringIO()
    with redirect_stdout(output_buffer):
        csp_generator._print_summary_report()

    output = output_buffer.getvalue()
    print("Captured console output:")
    print(output)
    print("Captured console output (escaped):")
    print(repr(output))

    # Assertions
    assert "CSP Generation Report :dart:" in output, "Report title not found"
    assert (
        "Files Processed :page_facing_up: : 3" in output
    ), "Files processed metric not found"
    assert (
        "Files With No inline scripts or styles :scroll: : 0" in output
    ), "No inline scripts metric not found"
    assert (
        "Unique Script Hashes :hammer_and_wrench: : 2" in output
    ), "Script hashes metric not found"
    assert "Unique Style Hashes :art: : 1" in output, "Style hashes metric not found"
    assert (
        "External Scripts :globe_with_meridians: : 1" in output
    ), "External scripts metric not found"
    assert "External Styles :art: : 0" in output, "External styles metric not found"
    assert (
        "External Images :framed_picture: : 0" in output
    ), "External images metric not found"
    assert (
        ":sparkles: CSP Header Generated Successfully!" in output
    ), "Success message not found"


def test_validate_csp_match(csp_generator, tmp_path, console_output, monkeypatch):
    # Create a temporary CSP file
    csp_file = tmp_path / "csp.txt"
    csp_content = (
        "default-src 'self'; script-src 'self' https://example.com; style-src 'self'"
    )
    csp_file.write_text(csp_content)

    # Mock scan_directory to set directives
    csp_generator.directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://example.com"],
        "style-src": ["'self'"],
    }

    # Force plain output for testing
    monkeypatch.setenv("CSP_PLAIN_OUTPUT", "1")

    # Capture output
    output_buffer = StringIO()
    with redirect_stdout(output_buffer):
        result = csp_generator.validate_csp(str(csp_file), str(tmp_path))

    output = output_buffer.getvalue()
    print("Captured console output for validate_csp_match:")
    print(output)

    assert result is True
    assert "CSP header is valid!" in output


def test_validate_csp_mismatch(csp_generator, tmp_path, console_output, monkeypatch):
    # Create a temporary CSP file with different content
    csp_file = tmp_path / "csp.txt"
    csp_content = (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    )
    csp_file.write_text(csp_content)

    # Mock scan_directory to set directives and hashes
    csp_generator.directives = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://example.com"],
        "style-src": ["'self'"],
        "img-src": ["'self'", "https://images.com"],
    }
    csp_generator.hashes = {
        "script-src": ["'sha256-abc123'"],
        "style-src": ["'sha256-def456'"],
    }

    # Force plain output for testing
    monkeypatch.setenv("CSP_PLAIN_OUTPUT", "1")

    # Capture output
    output_buffer = StringIO()
    with redirect_stdout(output_buffer):
        result = csp_generator.validate_csp(str(csp_file), str(tmp_path))

    output = output_buffer.getvalue()
    print("Captured console output for validate_csp_mismatch:")
    print(output)
    print("Captured console output (escaped):")
    print(repr(output))

    assert result is False
    assert "CSP header mismatch!" in output
    # assert "Expected: default-src 'self'; script-src 'self' https://example.com 'sha256-abc123'; style-src 'self' 'sha256-def456'; img-src 'self' https://images.com" in output
    # assert "Found: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'" in output
    assert "Directive: script-src" in output
    assert "Missing in Existing: 'sha256-abc123', https://example.com" in output
    assert "Extra in Existing: -" in output
    assert "Directive: style-src" in output
    assert "Missing in Existing: 'sha256-def456'" in output
    assert "Extra in Existing: 'unsafe-inline'" in output
    assert "Directive: img-src" in output
    assert "Missing in Existing: 'self', https://images.com" in output
    assert "Directives missing in existing CSP: img-src" in output
