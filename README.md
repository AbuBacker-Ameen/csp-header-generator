# CSP Header Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)
[![Typer](https://img.shields.io/badge/Made%20with-Typer-04AA6D?logo=python)](https://typer.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/Dockerfile)
[![GitHub Issues](https://img.shields.io/github/issues/AbuBacker-Ameen/HashCSP)](https://github.com/AbuBacker-Ameen/HashCSP/issues)

[![GitHub Stars](https://img.shields.io/github/stars/AbuBacker-Ameen/HashCSP?style=for-the-badge)](https://github.com/AbuBacker-Ameen/HashCSP/stargazers)

A Python tool to generate Content Security Policy (CSP) headers for web
applications by scanning HTML files or remote websites for inline scripts,
styles, and external resources. Built with `rich` for a polished CLI experience
and `BeautifulSoup` for HTML parsing. ideal for static sites and general web
projects.

## Status

- **Generate Command**: Fully tested and functional. Scans HTML files or
  websites, computes SHA256 hashes for inline scripts/styles, and generates CSP
  headers with a detailed summary report.
- **Other Commands**: Under development. Commands like `validate` and `fetch`
  require further refinement and code fixes for reliability.

## Features

- Scans local HTML files or directories for inline scripts and styles.
- Fetches and analyzes remote websites for CSP-relevant resources.
- Computes SHA256 hashes for inline content to include in CSP headers.
- Generates comprehensive CSP headers with default secure directives.
- Displays a styled summary report with metrics (e.g., files processed, unique
  hashes).
- Logs actions to `csp_generator.log` for debugging.

---

## Repository Structure

```plaintext
├── app/
│   ├── __init__.py            # Package entry point
│   ├── cli.py                 # Typer-based CLI definitions
│   ├── csp_generator.py       # Core hashing & validation logic
│   └── utils.py               # Shared helpers (logging)
├── tests/
│   └── test_csp_generator.py  # Unit tests (Need some work)
├── Dockerfile                 # Docker setup for the app
├── docker-compose.yml         # Compose for development & production
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation (this file)
└── LICENSE                    # MIT License
```

---

## Prerequisites

- Python 3.12+
- Dependencies:
- - `typer` (for CLI)
  - `rich` (for CLI output)
  - `beautifulsoup4` (for HTML parsing)
  - `requests` (for fetching remote sites)
  - `pytest` & `requests_mock` (for running tests)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/AbuBacker-Ameen/HashCSP.git
   cd HashCSP
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. (Optional) Set up Docker:

   ```bash
   docker-compose build
   ```

## Usage

Run the `generate` command to scan and generate CSP headers:

```bash
python -m app.cli generate -p ./public
```

Or with Docker:

```bash
docker-compose run --rm app generate -p ./public
```

Example output:

```txt
    CSP Generation Report 🎯
═════╤══════════════════════════════════════╤═══════
     │ Metric                               │ Value
═════╪══════════════════════════════════════╪═══════
     │ Files Processed 📄                   │   3
     │ Files With No inline scripts or      │   0
     │ styles 📜                           │
     │ Unique Script Hashes 🛠              │   2
     │ Unique Style Hashes 🎨              │   1
     │ External Scripts 🌐                 │   1
     │ External Styles 🎨                  │   0
     │ External Images 🖼                  │   0
═════╧══════════════════════════════════════╧═══════
✨ CSP Header Generated Successfully!
```

**Note**: Other commands (`validate`, `fetch`) are experimental and may not work
as expected. Will Work on it.

## Running Tests

Run the test suite:

```bash
pytest -v
```

## Known Issues

- `validate` and `fetch` commands are incomplete and may fail.
- Test coverage is limited to the `generate` command.

## License

MIT License. See `LICENSE` for details.
