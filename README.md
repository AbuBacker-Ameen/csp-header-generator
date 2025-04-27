# HashCSP

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/LICENSE)
[![Python](https://img.shields.io/badge/Python-3.12-blue)](https://www.python.org/downloads/release/python-3120/)
[![Typer](https://img.shields.io/badge/Made%20with-Typer-04AA6D?logo=python)](https://typer.tiangolo.com/)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=fff)](https://github.com/AbuBacker-Ameen/HashCSP/blob/main/Dockerfile)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)

HashCSP is a Python tool designed to generate and validate Content Security
Policy (CSP) headers for web applications. It helps developers secure their
websites by creating CSP headers that mitigate risks like Cross-Site Scripting
(XSS) by specifying trusted sources for scripts, styles, and other resources.

HashCSP supports both local file scanning and remote website fetching, making it
versatile for different workflows. It provides detailed reports and mismatch
metrics to help you fine-tune your CSP policies.

## Features

- **Generate CSP Headers**: Scan local HTML files to generate a CSP header,
  including hashes for inline scripts and styles, and external resources.
- **Validate CSP Headers**: Compare an existing CSP header against scanned
  resources, with detailed mismatch reports and metrics (e.g., missing/extra
  hashes and links).
- **Fetch Remote Sites**: Use Playwright to fetch remote websites, extract
  resources, and generate CSP headers.
- **User-Friendly Output**: Rich formatting for summary reports and mismatch
  tables, with limits on large difference tables for readability.
- **Type Safety**: Fully type-checked codebase using `mypy` for reliability.
- **Modular Design**: Separated concerns with a dedicated `Printer` class for
  output formatting.

## Installation

### Prerequisites

- Python 3.8 or higher
- [Poetry](https://python-poetry.org/) for dependency management

#### What is Poetry?

[**Poetry**](https://python-poetry.org/) is a modern dependency and package
manager for Python. It simplifies:

- Installing and managing dependencies
- Creating and using virtual environments automatically
- Building and publishing Python packages (like `hashcsp`)
- Managing tool versioning via `pyproject.toml`

It’s a cleaner alternative to using `pip` and `requirements.txt`.

##### How to Install Poetry

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

### Steps

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/AbuBacker-Ameen/HashCSP.git
   cd HashCSP
   ```

2. Install with Poetry:

   ```bash
   poetry install
   eval $(poetry env activate) # To activate poetry environment
   ```

3. Install Playwright Browsers: The fetch command uses Playwright to fetch
   remote sites. Install the required browsers:

   ```bash
   playwright install
   ```

4. Verify Installation: Check that the CLI is working:

   ```bash
   hashcsp --help
   ```

---

## Docker Alternative

```bash
docker-compose build
```

Run:

```bash
docker-compose run --rm hashcsp --help
```

---

## Usage

HashCSP provides three main commands: `generate`, `validate`, and `fetch`. Below
are examples of how to use each.

### 1. Generate a CSP Header for Local Files

Scan a directory of HTML files to generate a CSP header.

```bash
hashcsp generate -p ./public
```

- **Options**:
  - `-p/--path`: Directory containing HTML files (required).
  - `-o/--output`: Output file for the CSP header (defaults to `csp.conf`).
  - `-d/--directives`: Comma-separated directive:value pairs (e.g.,
    `script-src:'self' https://example.com`).
  - `-f/--directives-file`: File containing directives (one per line, format:
    `directive:value`).

**Example Output**: A `csp.conf` file will be created with the generated CSP
header, and a summary report will be printed, detailing the number of files
processed, unique hashes, and external resources.

### 2. Validate an Existing CSP Header

Compare an existing CSP header against the current state of your files.

```bash
hashcsp validate -p ./public -f csp.conf
```

- **Options**:
  - `-p/--path`: Directory containing HTML files (required).
  - `-f/--file`: File containing the existing CSP header (required).

**Example Output**: If there’s a mismatch, HashCSP will display a detailed
report with:

- A "CSP Mismatch Details" table (limited to 10 differences for large policies).
- A "Mismatch Metrics" table showing counts of missing/extra hashes and links.
- Suggestions for fixing the CSP header.

### 3. Fetch a Remote Site and Generate a CSP Header

Fetch a website, retrieve its CSP header (if any), and generate a computed CSP
header based on its resources. Supports dynamic websites with user interaction
simulation.

```bash
hashcsp fetch -u https://developer.mozilla.org --compare --interaction-level 2 --retries 3
```

- **Options**:
  - `-u/--url`: URL of the website to fetch (required). Must include `http://`
    or `https://`.
  - `-o/--output`: Output file for the computed CSP header (defaults to
    `csp.conf`).
  - `-w/--wait`: Time to wait for additional resources (in seconds, defaults to
    2).
  - `--compare`: Compare the website's CSP header with the computed CSP header.
  - `-i/--interaction-level`: Level of user interaction (0 = none, 1 = basic
    scrolling, 2 = advanced clicking/hovering, defaults to 0).
  - `-r/--retries`: Number of retry attempts for failed fetches (defaults to 2).

**Example Output**:

```plaintext
=== Website's CSP Header ===
default-src 'self'; script-src 'self' https://*.mozilla.org; ...

=== Computed CSP Header ===
default-src 'self'; script-src 'self' 'sha256-...' https://*.mozilla.org; ...

=== CSP Comparison ===
[CSP Mismatch Details table and Mismatch Metrics table]

Computed CSP header written to csp.conf
```

If the website has no CSP header:

```plaintext
=== Website's CSP Header ===
No CSP header found in the website's response.

=== Computed CSP Header ===
default-src 'self'; script-src 'self' 'sha256-...'; ...

Computed CSP header written to csp.conf
```

## Contributing

We welcome contributions to HashCSP! Here’s how to get started:

1. **Fork the Repository**: Fork the project on GitHub and clone your fork:

   ```bash
   git clone https://github.com/yourusername/hashcsp.git
   cd hashcsp
   ```

2. **Set Up the Development Environment**: Install dependencies and Playwright
   browsers:

   ```bash
   poetry install
   poetry run playwright install
   ```

3. **Create a Feature Branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

4. **Make Changes**:

   - Follow the existing code style and structure.
   - Add tests for new features or bug fixes.
   - Run type checks with `mypy`:

     ```bash
     mypy hashcsp
     ```

5. **Commit and Push**: Use semantic commit messages (e.g.,
   `feat: add new feature`, `fix: resolve bug`):

   ```bash
   git commit -m "feat: add new feature"
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**: Submit a pull request to the main repository,
   describing your changes and their impact.

## License

HashCSP is licensed under the MIT License. See the [LICENSE](LICENSE) file for
details.
