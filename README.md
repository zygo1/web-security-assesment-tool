# Web Security Assessment Tool

A small Python CLI that checks the HTTP security configuration of a web application.

**Work in progress:** This project is under active development. More security checks, validation rules, and reporting features will be added over time.

## Features

- Detects missing security headers.
- Validates basic configurations for:
  - Content-Security-Policy
  - Strict-Transport-Security
  - X-Frame-Options
  - X-Content-Type-Options
  - Referrer-Policy
- Supports custom User-Agent values.
- Displays request and response details in verbose mode.

The tool reports potential configuration weaknesses. A missing or permissive header is not automatically an exploitable vulnerability and may require manual validation.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 main.py https://example.com
```

Use a browser-like User-Agent:

```bash
python3 main.py https://example.com --user-agent default-browser
```

Use a custom User-Agent:

```bash
python3 main.py https://example.com --user-agent "MySecurityTool/1.0"
```

Show response information and headers:

```bash
python3 main.py https://example.com -v
```

## Project structure

```text
.
├── main.py
├── validators.py
├── requirements.txt
└── README.md
```

## Roadmap

Planned features include:

- Cookie security attribute checks
- HTTP-to-HTTPS redirect validation
- Basic TLS certificate information
- CORS configuration checks
- Server information disclosure checks
- Markdown and JSON reports

## Disclaimer

Use this tool only on systems you own or have explicit permission to assess.
