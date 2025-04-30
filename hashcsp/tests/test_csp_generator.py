import hashlib
import pytest
from hashcsp.core.csp_generator import CSPGenerator
from hashcsp.core.local_scanner import LocalScanner

@pytest.fixture
def csp_generator():
    """Fixture to provide a fresh CSPGenerator instance for each test."""
    return CSPGenerator()

# compute_hash tests
def test_compute_hash_normal(csp_generator):
    content = "console.log('test');"
    expected_hash = "'sha256-" + hashlib.sha256(content.encode("utf-8")).hexdigest() + "'"
    hash_value = csp_generator.compute_hash(content, "test_source")
    assert hash_value.startswith("'sha256-")
    assert len(hash_value) == 8 + 64 + 1  # "'sha256-" (8) + hex (64) + "'" (1)
    assert hash_value == expected_hash

def test_compute_hash_empty_content(csp_generator):
    hash_value = csp_generator.compute_hash("", "test_source")
    assert hash_value == ""

def test_compute_hash_special_characters(csp_generator):
    # Test hashing of content with non-ASCII (Unicode) characters to ensure proper UTF-8 encoding
    content = "alert('Hello, 世界!');"
    hash_value = csp_generator.compute_hash(content, "test_source")
    assert hash_value.startswith("'sha256-")
    assert len(hash_value) == 8 + 64 + 1  # "'sha256-" (8) + hex (64) + "'" (1)

def test_compute_hash_large_content(csp_generator):
    large_content = "let x = 1;" * 10000
    hash_value = csp_generator.compute_hash(large_content, "test_source")
    assert hash_value.startswith("'sha256-")
    assert len(hash_value) == 8 + 64 + 1  # "'sha256-" (8) + hex (64) + "'" (1)

# update_directive tests
def test_update_directive_new(csp_generator):
    csp_generator.update_directive("script-src", ["'self'", "https://example.com"])
    assert csp_generator.directives["script-src"] == ["'self'", "https://example.com"]

def test_update_directive_existing(csp_generator):
    csp_generator.directives["script-src"] = ["'self'"]
    csp_generator.update_directive("script-src", ["https://example.com"])
    assert csp_generator.directives["script-src"] == ["https://example.com"]

def test_update_directive_empty_sources(csp_generator):
    csp_generator.update_directive("script-src", [])
    assert "script-src" not in csp_generator.directives

def test_update_directive_whitespace_sources(csp_generator):
    csp_generator.update_directive("script-src", [" ", "'self'", ""])
    assert csp_generator.directives["script-src"] == [" ", "'self'"]

# lint_directives tests
def test_lint_directives_safe(csp_generator):
    csp_generator.directives = {"script-src": ["'self'"], "style-src": ["https://cdn.com"]}
    warnings = csp_generator.lint_directives()
    assert len(warnings) == 0

def test_lint_directives_unsafe(csp_generator):
    csp_generator.directives = {"script-src": ["'self'", "'unsafe-inline'"], "style-src": ["*"]}
    warnings = csp_generator.lint_directives()
    assert len(warnings) == 2
    assert "Unsafe source ''unsafe-inline'' found in script-src" in warnings
    assert "Unsafe source '*' found in style-src" in warnings

def test_lint_directives_multiple_unsafe(csp_generator):
    csp_generator.directives = {
        "script-src": ["'unsafe-inline'", "*"],
        "style-src": ["data:"]
    }
    warnings = csp_generator.lint_directives()
    assert len(warnings) == 3
    assert "Unsafe source ''unsafe-inline'' found in script-src" in warnings
    assert "Unsafe source '*' found in script-src" in warnings
    assert "Unsafe source 'data:' found in style-src" in warnings

def test_lint_directives_custom(csp_generator):
    csp_generator.directives = {"custom-directive": ["'unsafe-inline'"]}
    warnings = csp_generator.lint_directives()
    assert len(warnings) == 1
    assert "Unsafe source ''unsafe-inline'' found in custom-directive" in warnings

# generate_csp tests
def test_generate_csp_default(csp_generator, capsys, monkeypatch):
    monkeypatch.setenv("CSP_PLAIN_OUTPUT", "1")  # Force plain text output
    csp_header = csp_generator.generate_csp(report=True)
    assert "default-src 'self'" in csp_header
    assert "script-src 'self'" in csp_header
    captured = capsys.readouterr()
    assert "Files Processed :page_facing_up: : 0" in captured.out
    assert ":sparkles: CSP Header Generated Successfully!" in captured.out

def test_generate_csp_with_hashes(csp_generator):
    csp_generator.hashes["script-src"] = ["'sha256-abc123'"]
    csp_generator.hashes["style-src"] = ["'sha256-def456'"]
    csp_header = csp_generator.generate_csp(report=False)
    assert "script-src 'self' 'sha256-abc123'" in csp_header
    assert "style-src 'self' 'sha256-def456'" in csp_header

def test_generate_csp_empty_directives(csp_generator):
    csp_generator.directives = {"script-src": []}
    csp_header = csp_generator.generate_csp(report=False)
    assert csp_header == ""

def test_generate_csp_custom_directives(csp_generator):
    csp_generator.directives = {"custom-src": ["https://custom.com"]}
    csp_header = csp_generator.generate_csp(report=False)
    assert "custom-src https://custom.com" in csp_header

# _parse_csp tests
def test_parse_csp_valid(csp_generator):
    csp = "script-src 'self' https://example.com; style-src 'self';"
    result = csp_generator._parse_csp(csp)
    assert result == {
        "script-src": ["'self'", "https://example.com"],
        "style-src": ["'self'"]
    }

def test_parse_csp_empty(csp_generator):
    result = csp_generator._parse_csp("")
    assert result == {}

def test_parse_csp_malformed(csp_generator):
    csp = "script-src 'self'; invalid; style-src"
    result = csp_generator._parse_csp(csp)
    assert "script-src" in result
    assert "style-src" in result
    assert "invalid" in result
    assert result["invalid"] == []

def test_parse_csp_no_sources(csp_generator):
    csp = "script-src;"
    result = csp_generator._parse_csp(csp)
    assert result == {"script-src": []}

# validate_csp tests
@pytest.fixture
def mock_scanner(monkeypatch):
    def mock_scan_directory(self, directory):
        self.csp.directives = {"script-src": ["'self'"], "style-src": ["'self'"]}
        self.csp.hashes["script-src"] = ["'sha256-abc123'"]
    monkeypatch.setattr(LocalScanner, "scan_directory", mock_scan_directory)

def test_validate_csp_matching(csp_generator, tmp_path, mock_scanner):
    csp_file = tmp_path / "csp.conf"
    csp_content = "script-src 'self' 'sha256-abc123'; style-src 'self';"
    csp_file.write_text(csp_content)
    result = csp_generator.validate_csp(str(csp_file), str(tmp_path))
    assert result is True

def test_validate_csp_mismatching(csp_generator, tmp_path, mock_scanner, capsys, monkeypatch):
    monkeypatch.setenv("CSP_PLAIN_OUTPUT", "1")  # Force plain text output
    csp_file = tmp_path / "csp.conf"
    csp_content = "script-src 'self';"
    csp_file.write_text(csp_content)
    result = csp_generator.validate_csp(str(csp_file), str(tmp_path))
    assert result is False
    captured = capsys.readouterr()
    assert "Directive: script-src" in captured.out
    assert "Missing in Existing: 'sha256-abc123'" in captured.out
    assert "Directives missing in existing CSP: style-src" in captured.out
    assert "Mismatch Metrics:" in captured.out
    assert "script-src:" in captured.out
    assert "Missing Hashes: 1" in captured.out

def test_validate_csp_non_existent_file(csp_generator, tmp_path):
    result = csp_generator.validate_csp(str(tmp_path / "nonexistent.conf"), str(tmp_path))
    assert result is False

def test_validate_csp_invalid_file(csp_generator, tmp_path, monkeypatch):
    csp_file = tmp_path / "csp.conf"
    csp_file.write_text("valid content")
    def mock_open(*args, **kwargs):
        raise IOError("Permission denied")
    monkeypatch.setattr("builtins.open", mock_open)
    result = csp_generator.validate_csp(str(csp_file), str(tmp_path))
    assert result is False
