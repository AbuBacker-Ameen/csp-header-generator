# HashCSP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)
[![Typer](https://img.shields.io/badge/Made%20with-Typer-04AA6D?logo=python)](https://typer.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/Dockerfile)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)

**`hashcsp`** is a Python CLI tool to generate strong, hash-based Content
Security Policy (CSP) headers for web applications. It scans HTML files (local
or remote) for inline scripts, styles, and external resources. It’s ideal for
static sites, hardened deployments, and secure-by-default pipelines. **Future
updates will also add support for dynamic websites that generate content at
runtime.**

Built with [Typer](https://typer.tiangolo.com/) for a clean CLI,
[Rich](https://github.com/Textualize/rich) for styled output, and
[BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) for parsing
HTML.

---

## Status

- **`generate` command**: Fully functional. Scans HTML content, computes SHA256
  hashes for inline content, and builds a secure CSP header.
- **Other commands (`validate`, `fetch`, etc.)**: Under development.

---

## Features

- Scans local or remote HTML sources
- Computes CSP-safe SHA256 hashes for inline scripts and styles
- Outputs a production-ready CSP header string
- Logs actions to `csp_generator.log`
- CLI-first; supports Docker and Poetry installs
- Fancy, readable reports via Rich
- Future: Support for dynamic content and JavaScript-heavy websites

---

## Repository Structure

```plaintext
├── hashcsp/
│   ├── __init__.py            # Package entry point
│   ├── cli.py                 # Main Typer-based CLI entry point
│   ├── csp_generator.py       # Core hashing & logic
│   └── utils.py               # Shared helpers (logging)
├── tests/
│   └── test_csp_generator.py  # Unit tests (Need some work)
├── Dockerfile                 # Docker build file
├── docker-compose.yml         # Optional Docker orchestration
├── pyproject.toml             # Poetry-managed metadata and dependencies
├── poetry.lock                # poetry.lock file
├── README.md                  # Project documentation (this file)
└── LICENSE                    # MIT License
```

---

## Prerequisites

- Python 3.12+
- [Poetry](https://python-poetry.org/) for dependency and CLI management

### What is Poetry?

[**Poetry**](https://python-poetry.org/) is a modern dependency and package
manager for Python. It simplifies:

- Installing and managing dependencies
- Creating and using virtual environments automatically
- Building and publishing Python packages (like `hashcsp`)
- Managing tool versioning via `pyproject.toml`

It’s a cleaner alternative to using `pip` and `requirements.txt`.

#### How to Install Poetry

1. Run the official install script:

   ```bash
   curl -sSL https://install.python-poetry.org | python3 -
   ```

2. Add Poetry to your shell environment if needed (it tells you how after
   install), or restart your terminal.

3. Verify it worked:

```bash
poetry --version
```

---

## Installation (Recommended: Poetry)

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

   Now you can run:

   ```bash
   hashcsp --help
   ```

   Or call it directly:

   ```bash
   poetry run hashcsp generate -p ./public
   ```

---

## Docker Alternative

```bash
docker-compose build
```

Run:

```bash
docker-compose run --rm hashcsp generate -p ./public
```

---

## Usage

Scan and generate CSP headers:

```bash
hashcsp generate -p ./public
```

Output example:

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

---

## Running Tests

```bash
pytest -v
```

---

## Known Issues

- `validate`, `fetch` are placeholders and may not function yet
- No hash support for dynamically-injected scripts (future feature)

---

## TODO / Working On

- Dynamic content scanning using headless browsers (e.g., Playwright)
- CSP validation and security linting
- Improved test coverage and CI integration
- CSP "report-only" policy generation mode
- Auto-deploy-ready CSP integration helpers (e.g., for Netlify, Nginx)

---

## License

MIT License. See `LICENSE` file.
