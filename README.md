# CSP Header Generator

An interactive Python CLI tool designed to effortlessly generate secure and
precise Content Security Policy (CSP) headers. The tool scans HTML files,
extracts inline script hashes, and provides ready-to-use CSP header
configurations, ideal for static sites and general web projects.

---

## Features

- **Interactive CLI**: Built with `typer`, offering prompts when flags are
  omitted but fully scriptable via flags.
- **Automatic Script Hashing**: Scans HTML files and computes SHA256-based,
  Base64-encoded hashes for inline scripts.
- **Header Validation**: Compare existing CSP headers against current HTML
  script hashes to detect discrepancies.
- **Website Fetching**: (Future) Fetch live sites by URL and generate a tailored
  CSP report and header.
- **Dockerized Environment**: Ensures reproducibility and isolation for
  development and production.
- **Enhanced Logging**: User-friendly, informative output powered by `rich`.
- **Customizable**: Full CLI configuration for all CSP directives with sensible
  defaults based on recommended security practices.

---

## TO-DO

1. **Full CSP Customization**: Enable end-to-end CSP header configuration from
   the CLI, exposing every directive (scripts, styles, images, etc.) with a
   secure recommended default.
2. **Remote Site Analysis**: Add a command to fetch a website by URL, scan its
   resources, and produce both a validation report and a correct CSP header
   tailored to that site.

---

## Prerequisites

- Docker (with Compose)
- Python 3.12 (Dockerized)

---

## Repository Structure

```plaintext
├── app/
│   ├── __init__.py            # Package entry point
│   ├── cli.py                 # Typer-based CLI definitions
│   ├── csp_generator.py       # Core hashing & validation logic
│   └── utils.py               # Shared helpers (logging)
├── tests/
│   └── test_csp_generator.py  # Unit tests (TO-DO)
├── Dockerfile                 # Docker setup for the app
├── docker-compose.yml         # Compose for development & production
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation (this file)
└── LICENSE                    # MIT License
```

---

## Quick Start

```bash
git clone https://github.com/AbuBacker-Ameen/csp-header-generator.git
cd csp-header-generator

docker-compose up --build    # Build & show help by default
```

### Scripted Run

```bash
docker-compose run --rm app generate --path ./public --output ./csp.conf
```

---

## CLI Commands

### `generate`

Generate CSP headers:

```bash
csp-header-gen generate \
  --path <HTML_DIRECTORY> \
  --output <HEADER_FILE>
```

### `validate`

Validate an existing CSP header file against current HTML scripts:

```bash
csp-header-gen validate \
  --path <HTML_DIRECTORY> \
  --file <HEADER_FILE>
```

### `version`

Show tool version:

```bash
csp-header-gen version
```

---

## Docker Usage

- **Development** (interactive CLI):

  ```bash
  docker-compose run --rm app generate
  ```

- **Production/CI** (non-interactive):

  ```yaml
  services:
    app:
      image: yourusername/csp-header-gen:latest
      command: ['generate', '--path', '/data', '--output', '/app/csp.conf']
      volumes:
        - ./public:/data:ro
  ```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
