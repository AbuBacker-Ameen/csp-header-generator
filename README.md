# CSP Header Generator

An interactive Python CLI tool designed to effortlessly generate secure and precise Content Security Policy (CSP) headers. The tool scans HTML files, extracts inline scripts, computes secure hashes, and provides ready-to-use CSP header configurations, ideal for static sites and general web projects.

---

## Features

- **Interactive CLI**: Built with `typer`, providing an intuitive command-line interface.
- **Automatic Script Hashing**: Scans HTML files and generates CSP hashes (`sha256`) for inline scripts.
- **Dockerized Environment**: Ensures reproducibility and isolation for both development and production.
- **Enhanced Logging**: User-friendly, informative output with `rich`.
- **Customizable**: Supports tailored CSP directives to match your project's specific security needs.

---

## Prerequisites

- Docker

---

## Quick Start

Clone the repository:

```bash
git clone https://github.com/yourusername/csp-header-generator.git
cd csp-header-generator
```

Build and launch Docker container:

```bash
docker-compose up --build
```

Run the CLI tool:

```bash
docker-compose run app
```

---

## Usage

The interactive CLI will guide you through:

1. Specifying the directory to scan for HTML files.
2. Generating script hashes.
3. Customizing CSP directives.
4. Exporting CSP headers to a configuration file.

Example:

```bash
docker-compose run app generate --path ./my-website --output ./csp_headers.conf
```

---

## Testing

Tests use `pytest`. Execute tests within the Docker environment:

```bash
docker-compose run app pytest
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

