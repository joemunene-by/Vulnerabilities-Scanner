# Vulnerabilities Scanner

A fast, extensible static vulnerability scanner for source code. It detects hardcoded secrets, injection flaws, weak cryptography, insecure configurations, and more across multiple programming languages. Every finding is mapped to the OWASP Top 10 (2021) and a CWE identifier so teams can prioritise remediation effectively.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)

## Features

- Regex-based pattern matching against 40+ vulnerability rules
- Multi-language support: Python, JavaScript/TypeScript, Java, PHP, Ruby, Go
- Severity ratings: Critical, High, Medium, Low
- OWASP Top 10 (2021) category mapping for every finding
- CWE identifiers on each rule
- Colour-coded terminal output and JSON report export
- Recursive directory scanning with smart ignore patterns
- Configurable severity threshold and language filters
- Non-zero exit code on Critical/High findings (CI-friendly)
- Minimal dependencies (only `colorama` for terminal colours)

## Supported Vulnerability Types

| Category | Rule IDs | Severity | OWASP Category |
|---|---|---|---|
| Hardcoded API Keys | SECRET-001 | Critical | A02 - Cryptographic Failures |
| Hardcoded Passwords | SECRET-002 | Critical | A02 - Cryptographic Failures |
| Hardcoded Tokens/Secrets | SECRET-003 | Critical | A02 - Cryptographic Failures |
| AWS Credentials | SECRET-004 | Critical | A02 - Cryptographic Failures |
| Embedded Private Keys | SECRET-005 | Critical | A02 - Cryptographic Failures |
| GitHub Tokens | SECRET-006 | Critical | A02 - Cryptographic Failures |
| Slack Tokens | SECRET-007 | Critical | A02 - Cryptographic Failures |
| SQL Injection | SQLI-001 to SQLI-004 | High | A03 - Injection |
| Cross-Site Scripting (XSS) | XSS-001 to XSS-005 | High/Medium | A03 - Injection |
| Command Injection | CMDI-001 to CMDI-005 | Critical/High/Medium | A03 - Injection |
| Insecure Deserialization | DESER-001 to DESER-005 | High | A08 - Software and Data Integrity Failures |
| Path Traversal | PATH-001 to PATH-003 | High/Medium | A01 - Broken Access Control |
| Weak Cryptography | CRYPTO-001 to CRYPTO-004 | High/Medium | A02 - Cryptographic Failures |
| Insecure HTTP | HTTP-001 to HTTP-004 | High/Medium | A02 - Cryptographic Failures |
| Debug/Misconfiguration | DEBUG-001 to DEBUG-005 | High/Medium/Low | A05 - Security Misconfiguration |
| Broken Access Control | AUTH-001 to AUTH-002 | Medium/Low | A01 - Broken Access Control |

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/joemunene-by/Vulnerabilities-Scanner.git
cd Vulnerabilities-Scanner
pip install -r requirements.txt
```

No additional installation is required. The scanner runs as a standalone Python script.

## Usage

Basic scan of a directory:

```bash
python3 scanner.py --path ./my-project
```

Scan with severity filter (only High and Critical):

```bash
python3 scanner.py --path ./src --severity high
```

JSON report written to a file:

```bash
python3 scanner.py --path ./my-project --format json --output report.json
```

Scan only Python and JavaScript files:

```bash
python3 scanner.py --path ./src --language python javascript
```

Exclude additional directories:

```bash
python3 scanner.py --path . --exclude tests fixtures
```

Full example combining options:

```bash
python3 scanner.py \
  --path ./my-project \
  --severity high \
  --format json \
  --output report.json \
  --language python javascript \
  --exclude tests docs
```

## CLI Options

| Flag | Short | Description |
|---|---|---|
| `--path` | `-p` | File or directory to scan (required) |
| `--output` | `-o` | Write report to file (default: stdout) |
| `--format` | `-f` | Output format: `terminal` or `json` (default: terminal) |
| `--severity` | `-s` | Minimum severity: `low`, `medium`, `high`, `critical` (default: low) |
| `--language` | `-l` | Limit scan to specific languages (python, javascript, java, php, ruby, go) |
| `--exclude` | `-e` | Additional directory names to ignore |
| `--version` | `-V` | Show version and exit |

## Example Terminal Output

```
======================================================================
  VULNERABILITY SCAN REPORT
======================================================================
  Target:   /home/user/my-project
  Files:    47
  Findings: 5
  Duration: 0.12s
======================================================================

  [CRITICAL] SECRET-002 — Hardcoded password detected
    File:  /home/user/my-project/config.py:14
    OWASP: A02:2021 - Cryptographic Failures  |  CWE-798
    Code:  db_password = "super_secret_123"

  [HIGH] SQLI-001 — Possible SQL injection via string formatting in query
    File:  /home/user/my-project/db.py:31
    OWASP: A03:2021 - Injection  |  CWE-89
    Code:  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

  [MEDIUM] CRYPTO-001 — MD5 hash usage — cryptographically broken
    File:  /home/user/my-project/auth.py:55
    OWASP: A02:2021 - Cryptographic Failures  |  CWE-327
    Code:  digest = hashlib.md5(data).hexdigest()

======================================================================
  SUMMARY BY SEVERITY
======================================================================
    CRITICAL    1
    HIGH        2
    MEDIUM      2
======================================================================
  SUMMARY BY OWASP CATEGORY
======================================================================
    A02:2021 - Cryptographic Failures                       3
    A03:2021 - Injection                                    2
```

## Example JSON Output

```json
{
  "target": "/home/user/my-project",
  "files_scanned": 47,
  "total_findings": 5,
  "duration_seconds": 0.123,
  "severity_summary": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2,
    "LOW": 0
  },
  "owasp_summary": {
    "A02:2021 - Cryptographic Failures": 3,
    "A03:2021 - Injection": 2
  },
  "findings": [
    {
      "rule_id": "SECRET-002",
      "severity": "CRITICAL",
      "description": "Hardcoded password detected",
      "owasp_category": "A02:2021 - Cryptographic Failures",
      "cwe": "CWE-798",
      "file": "/home/user/my-project/config.py",
      "line": 14,
      "snippet": "db_password = \"super_secret_123\"",
      "match": "password = \"super_secret_123\""
    }
  ]
}
```

## OWASP Top 10 Mapping

Every rule in the scanner is mapped to one of the OWASP Top 10 (2021) categories. This helps security teams and developers understand the broader risk context of each finding:

| OWASP ID | Category | Scanner Coverage |
|---|---|---|
| A01:2021 | Broken Access Control | Path traversal, file permission checks |
| A02:2021 | Cryptographic Failures | Hardcoded secrets, weak hashing, insecure HTTP, disabled TLS verification |
| A03:2021 | Injection | SQL injection, XSS, command injection, code injection |
| A05:2021 | Security Misconfiguration | Debug flags, overly permissive CORS |
| A08:2021 | Software and Data Integrity Failures | Insecure deserialization (pickle, YAML, Marshal, unserialize) |
| A09:2021 | Security Logging and Monitoring Failures | Sensitive data logged to console |

## CI Integration

The scanner exits with code 2 when Critical or High findings are detected, making it easy to use as a CI gate:

```yaml
- name: Run vulnerability scan
  run: |
    pip install -r requirements.txt
    python3 scanner.py --path . --severity high --format json --output report.json
```

## Project Structure

```
Vulnerabilities-Scanner/
    scanner.py          # Main CLI tool and scanning engine
    rules.py            # Vulnerability detection rule definitions
    requirements.txt    # Python dependencies
    README.md           # This file
    LICENSE             # MIT License
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Areas where help is especially useful:

- Additional detection rules for cloud provider credentials (GCP, Azure)
- SARIF output format support
- Custom rule configuration via YAML
- Performance improvements for very large codebases

## License

MIT
