# HashCSP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)
[![Typer](https://img.shields.io/badge/Made%20with-Typer-04AA6D?logo=python)](https://typer.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/Dockerfile)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)

HashCSP is a powerful Python tool designed to generate and validate Content Security Policy (CSP) headers for web applications. It helps developers secure their websites by creating comprehensive CSP headers that mitigate risks like Cross-Site Scripting (XSS) by specifying trusted sources for scripts, styles, and other resources.

## Features

### Core Functionality
- **Generate CSP Headers**: Scan local HTML files to generate CSP headers with:
  - Hashes for inline scripts and styles
  - External resource tracking
  - Smart directive management
- **Validate CSP Headers**: Compare existing CSP headers against scanned resources with:
  - Detailed mismatch reports
  - Hash and link difference metrics
  - Suggestions for updates

### Advanced Capabilities
- **Remote Site Analysis**:
  - Fetch and analyze remote websites using Playwright
  - Support for dynamic content and JavaScript execution
  - Multiple interaction levels (none, basic scrolling, advanced clicking/hovering)
  - Smart retry logic for reliability
- **Dynamic Content Handling**:
  - Capture dynamically inserted scripts and styles
  - Track network requests in real-time
  - Adaptive waiting based on DOM mutations
  - Late-loaded resource hashing

### Developer Experience
- **Rich CLI Interface**:
  - Colored output with progress indicators
  - Detailed error reporting
  - Dry-run mode for preview
  - Verbose and silent modes
- **Comprehensive Logging**:
  - Structured JSON logging
  - Configurable log levels and formats
  - Detailed error context
  - Audit trail for debugging

## Installation

### Prerequisites
- Python 3.12 or higher
- [Poetry](https://python-poetry.org/) for dependency management

### Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/AbuBacker-Ameen/HashCSP.git
   cd HashCSP
   ```

2. Install with Poetry:
   ```bash
   poetry install
   eval $(poetry env activate) # To activate poetry environment
   ```

3. Install Playwright browsers (required for remote site analysis):
   ```bash
   playwright install
   ```

### Docker Alternative

Build:
```bash
docker-compose build
```

Run:
```bash
docker-compose run --rm hashcsp --help
```

## Usage

HashCSP provides three main commands: `generate`, `validate`, and `fetch`.

### 1. Generate CSP Headers

Generate a CSP header by scanning local HTML files:

```bash
hashcsp generate -p ./public
```

Options:
- `-p/--path`: Directory containing HTML files (required)
- `-o/--output`: Output file (defaults to `csp.conf`)
- `-d/--directives`: Add custom directives (e.g., `script-src:'self' https://example.com`)
- `-f/--directives-file`: Load directives from JSON file
- `--json-output`: Output in JSON format
- `--lint`: Check for unsafe sources
- `--dry-run`: Preview without writing to disk

### 2. Validate CSP Headers

Compare an existing CSP header against current resources:

```bash
hashcsp validate -p ./public -f csp.conf
```

Options:
- `-p/--path`: Directory containing HTML files (required)
- `-f/--file`: Existing CSP header file (required)

### 3. Analyze Remote Sites

Fetch and analyze a remote website:

```bash
hashcsp fetch -u https://example.com --interaction-level 2 --wait 5 --compare
```

Options:
- `-u/--url`: Website URL (required)
- `-o/--output`: Output file (defaults to `csp.conf`)
- `-w/--wait`: Wait time for resources in seconds (default: 2)
- `--compare`: Compare with site's existing CSP
- `-i/--interaction-level`: User interaction simulation:
  - `0`: No interaction (default)
  - `1`: Basic scrolling
  - `2`: Advanced clicking/hovering
- `-r/--retries`: Number of retry attempts (default: 2)
- `--dry-run`: Preview mode

## Configuration

### Logging Configuration

Configure logging behavior through environment variables:
- `LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `LOG_FORMAT`: Choose output format (json, console)
- `LOG_FILE`: Specify log file path
- `LOG_MAX_BYTES`: Maximum log file size
- `LOG_BACKUP_COUNT`: Number of backup files to keep

Example:
```bash
export LOG_FORMAT=json
export LOG_LEVEL=INFO
hashcsp generate -p ./public
```

### CSP Configuration

Create a `hashcsp.json` file to define default CSP directives:

```json
{
  "directives": {
    "default-src": ["'self'"],
    "script-src": ["'self'", "https://trusted.com"],
    "style-src": ["'self'"]
  }
}
```

## Contributing

1. Fork the repository
2. Install development dependencies:
   ```bash
   poetry install --with dev
   ```
3. Run tests:
   ```bash
   poetry run pytest
   ```
4. Ensure code quality:
   ```bash
   poetry run ruff check .
   poetry run black .
   poetry run isort .
   poetry run mypy hashcsp
   ```
5. Submit a pull request

## License

HashCSP is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Roadmap

See [ROADMAP.md](./ROADMAP.md) for upcoming features and development plans.
