# Vulnerabilities Scanner

A small, extensible static vulnerability and secret scanner for source trees. It ships as a
library and a CLI and is intended for developers, CI pipelines, and security reviewers who want
an auditable, easy-to-extend scanner.

![CI](https://github.com/joemunene-by/Vulnerabilities-Scanner/actions/workflows/python-app.yml/badge.svg)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Highlights

- Fast file-based scanner with a small, auditable codebase
- Built-in detectors for common secrets and insecure patterns
- CLI with human, JSON, and SARIF outputs
- Config-driven allowlist (.vulnscan.yml) and CI integration via GitHub Actions

## New (recent) features

- Extra detectors: GitHub tokens, Slack tokens, JWTs, AWS secret access keys
- Entropy-based confidence scoring and severity labels
- SARIF export (use `--format sarif`) for integration with code scanning tools
- Config support via `.vulnscan.yml` (ignore paths and ignore_patterns)
- Pre-commit configuration and packaging helpers

## Quick start

Install dependencies (recommended inside a virtualenv):

```bash
python -m pip install -r requirements.txt
```

Install the package (editable):

```bash
python -m pip install -e .
```

Run the scanner on a file or directory:

```bash
python -m scanner.cli scan path/to/code --format json
# or SARIF for integration
python -m scanner.cli scan path/to/code --format sarif > results.sarif
```

## Configuration

Create a `.vulnscan.yml` at repo root to ignore files or patterns. Example:

```yaml
ignore_paths:
	- "**/node_modules/**"
	- "**/.venv/**"

ignore_patterns:
	- "^TEST_"
	- "^\\d{3}-\\d{2}-\\d{4}$"  # skip SSN-like patterns
```

## Output schema

Findings are returned as a list of objects with fields:

- `path` — file path
- `findings` — array of findings, each with:
	- `rule_id`, `type`, `severity` (LOW/MEDIUM/HIGH), `confidence` (0.0-1.0)
	- `line`, `start`, `end`, `match`, `snippet`

Use `--format sarif` to export SARIF 2.1.0 compatible results for code scanning tools.

## Tests

Run unit tests with pytest:

```bash
python -m pytest -q
```

## Contributing

Contributions welcome. Suggested next improvements: more detectors (GCP/Azure keys),
entropy-tuning config, and a pre-commit hook for local scanning.

License: MIT

## Get it

Ways to acquire and install the scanner:

- Install from PyPI (when published):

```bash
pip install vulnerabilities-scanner
```

- Install directly from GitHub (stable/main branch):

```bash
pip install git+https://github.com/joemunene-by/Vulnerabilities-Scanner.git
```

- Developer install (editable) — good for contributing or local development:

```cmd
:: Windows cmd
cd "c:\Users\TestUser\Desktop\Vurnelabilities Scanner\Vulnerabilities-Scanner"
"C:/Users/TestUser/Desktop/Vurnelabilities Scanner/.venv/Scripts/python.exe" -m pip install -e .
```

## Usage examples

CLI — scan a directory and show text output:

```cmd
python -m scanner.cli scan src/ --format text
```

CLI — produce JSON:

```cmd
python -m scanner.cli scan src/ --format json > findings.json
```

CLI — produce SARIF (useful for GitHub or other tools):

```cmd
python -m scanner.cli scan src/ --format sarif > results.sarif
```

Python API — quick example:

```python
from scanner import scan_path

for path, findings in scan_path('src/'):
    for f in findings:
        print(path, f['type'], f['confidence'])
```

## Use in CI (GitHub Actions)

Add a step in your workflow to run the scanner and optionally upload SARIF:

```yaml
- name: Install and run Vulnerabilities Scanner
  run: |
    python -m pip install -r requirements.txt
    python -m pip install -e .
    python -m scanner.cli scan . --format sarif > findings.sarif
# optionally upload SARIF as a code scanning artifact
```



