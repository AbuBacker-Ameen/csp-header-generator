import logging

import pytest
from bs4 import BeautifulSoup

from hashcsp.core.csp_generator import CSPGenerator
from hashcsp.core.local_scanner import LocalScanner


@pytest.fixture
def csp_generator():
    """Fixture to provide a fresh CSPGenerator instance."""
    return CSPGenerator()


@pytest.fixture
def scanner(csp_generator):
    """Fixture to provide a LocalScanner instance with a CSPGenerator."""
    return LocalScanner(csp_generator)


@pytest.fixture
def html_file(tmp_path):
    """Fixture to create a sample HTML file with inline and external resources."""
    html_content = """
    <html>
        <script>console.log('test');</script>
        <style>body { color: blue; }</style>
        <script src="https://example.com/script.js"></script>
        <link rel="stylesheet" href="https://example.com/style.css">
        <img src="https://example.com/image.png">
    </html>
    """
    file_path = tmp_path / "test.html"
    file_path.write_text(html_content, encoding="utf-8")
    return file_path


# scan_html_file tests
def test_scan_html_file_normal(scanner, html_file, csp_generator):
    """Test scanning a normal HTML file with inline and external resources."""
    success = scanner.scan_html_file(str(html_file))
    assert success is True
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["external_scripts"] == 1
    assert csp_generator.stats["external_styles"] == 1
    assert csp_generator.stats["external_images"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 0
    assert len(csp_generator.hashes["script-src"]) == 1
    assert len(csp_generator.hashes["style-src"]) == 1
    assert csp_generator.directives["script-src"] == ["https://example.com/script.js"]
    assert csp_generator.directives["style-src"] == ["https://example.com/style.css"]
    assert csp_generator.directives["img-src"] == ["https://example.com/image.png"]


def test_scan_html_file_empty(scanner, tmp_path, csp_generator):
    """Test scanning an empty HTML file."""
    empty_html = tmp_path / "empty.html"
    empty_html.write_text("<html></html>", encoding="utf-8")
    success = scanner.scan_html_file(str(empty_html))
    assert success is True
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 0
    assert csp_generator.stats["unique_style_hashes"] == 0
    assert csp_generator.stats["external_scripts"] == 0
    assert csp_generator.stats["external_styles"] == 0
    assert csp_generator.stats["external_images"] == 0


def test_scan_html_file_invalid_encoding(scanner, tmp_path, csp_generator):
    """Test scanning a file with invalid encoding."""
    invalid_file = tmp_path / "invalid.html"
    invalid_file.write_bytes(b"\xFF\xFE<html></html>")  # Invalid UTF-8
    success = scanner.scan_html_file(str(invalid_file))
    assert success is False
    assert csp_generator.stats["files_processed"] == 0  # Not incremented on failure


def test_scan_html_file_malformed(scanner, tmp_path, csp_generator):
    """Test scanning a malformed HTML file."""
    malformed_html = tmp_path / "malformed.html"
    malformed_html.write_text(
        "<html><script>alert('test')</script><style>body { color: red; }</style>",
        encoding="utf-8",
    )
    success = scanner.scan_html_file(str(malformed_html))
    assert success is True
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_scan_html_file_non_tag_elements(
    scanner, tmp_path, csp_generator, monkeypatch, caplog
):
    """Test handling of non-Tag elements from BeautifulSoup."""
    html_file = tmp_path / "test.html"
    html_file.write_text(
        "<html><script>console.log('test');</script></html>", encoding="utf-8"
    )

    def mock_find_all(tag, *args, **kwargs):
        return ["not a tag"]  # Simulate non-Tag return

    monkeypatch.setattr(BeautifulSoup, "find_all", mock_find_all)
    with caplog.at_level(logging.ERROR):
        success = scanner.scan_html_file(str(html_file))
    assert success is False
    assert csp_generator.stats["files_processed"] == 0
    assert "Expected Tag, got <class 'str'>" in caplog.text


def test_scan_html_file_duplicate_resources(scanner, html_file, csp_generator):
    """Test that duplicate resources are not added multiple times."""
    html_content = """
    <html>
        <script>console.log('test');</script>
        <script>console.log('test');</script>
        <script src="https://example.com/script.js"></script>
        <script src="https://example.com/script.js"></script>
    </html>
    """
    dup_file = html_file.parent / "dup.html"
    dup_file.write_text(html_content, encoding="utf-8")
    success = scanner.scan_html_file(str(dup_file))
    assert success is True
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 1  # Same hash added once
    assert csp_generator.stats["external_scripts"] == 1  # Same URL added once
    assert len(csp_generator.hashes["script-src"]) == 1
    assert csp_generator.directives["script-src"] == ["https://example.com/script.js"]


def test_scan_html_file_no_inline_content(scanner, tmp_path, csp_generator):
    """Test a file with only external resources."""
    external_html = tmp_path / "external.html"
    external_html.write_text(
        """
    <html>
        <script src="https://example.com/script.js"></script>
        <link rel="stylesheet" href="https://example.com/style.css">
    </html>
    """,
        encoding="utf-8",
    )
    success = scanner.scan_html_file(str(external_html))
    assert success is True
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 0
    assert csp_generator.stats["unique_style_hashes"] == 0
    assert csp_generator.stats["external_scripts"] == 1
    assert csp_generator.stats["external_styles"] == 1


# scan_directory tests
def test_scan_directory_multiple_files(scanner, tmp_path, csp_generator):
    """Test scanning a directory with multiple HTML files."""
    html1 = tmp_path / "file1.html"
    html1.write_text(
        "<html><script>console.log('test1');</script></html>", encoding="utf-8"
    )
    html2 = tmp_path / "file2.html"
    html2.write_text(
        "<html><style>body { color: red; }</style></html>", encoding="utf-8"
    )
    scanner.scan_directory(str(tmp_path))
    assert csp_generator.stats["files_processed"] == 2
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_scan_directory_mixed_files(scanner, tmp_path, csp_generator):
    """Test scanning a directory with HTML and non-HTML files."""
    html_file = tmp_path / "test.html"
    html_file.write_text(
        "<html><script>console.log('test');</script></html>", encoding="utf-8"
    )
    txt_file = tmp_path / "test.txt"
    txt_file.write_text("not an HTML file", encoding="utf-8")
    scanner.scan_directory(str(tmp_path))
    assert csp_generator.stats["files_processed"] == 1
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["files_with_no_inline_scripts"] == 0


def test_scan_directory_empty(scanner, tmp_path, csp_generator):
    """Test scanning an empty directory."""
    scanner.scan_directory(str(tmp_path))
    assert csp_generator.stats["files_processed"] == 0
    assert csp_generator.stats["unique_script_hashes"] == 0
    assert csp_generator.stats["unique_style_hashes"] == 0


def test_scan_directory_nested(scanner, tmp_path, csp_generator):
    """Test scanning a directory with nested subdirectories."""
    html1 = tmp_path / "file1.html"
    html1.write_text(
        "<html><script>console.log('test1');</script></html>", encoding="utf-8"
    )
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    html2 = subdir / "file2.html"
    html2.write_text(
        "<html><style>body { color: red; }</style></html>", encoding="utf-8"
    )
    scanner.scan_directory(str(tmp_path))
    assert csp_generator.stats["files_processed"] == 2
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1


def test_scan_directory_case_insensitive(scanner, tmp_path, csp_generator):
    """Test scanning files with case-insensitive HTML extensions."""
    html1 = tmp_path / "file1.HTML"
    html1.write_text(
        "<html><script>console.log('test1');</script></html>", encoding="utf-8"
    )
    html2 = tmp_path / "file2.HtM"
    html2.write_text(
        "<html><style>body { color: red; }</style></html>", encoding="utf-8"
    )
    scanner.scan_directory(str(tmp_path))
    assert csp_generator.stats["files_processed"] == 2
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1


def test_scan_directory_invalid(scanner, csp_generator):
    """Test scanning a non-existent directory."""
    scanner.scan_directory("/non/existent/path")
    assert csp_generator.stats["files_processed"] == 0
