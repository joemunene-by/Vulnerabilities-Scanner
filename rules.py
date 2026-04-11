"""
rules.py — Vulnerability detection rules for the static scanner.

Each rule is a dict with:
    - id:             Unique rule identifier
    - pattern:        Regex pattern (compiled at import time)
    - severity:       CRITICAL | HIGH | MEDIUM | LOW
    - description:    Human-readable explanation
    - owasp_category: OWASP Top 10 (2021) mapping
    - languages:      List of language tags the rule applies to, or ["*"] for all
    - cwe:            CWE identifier
"""

import re

# ---------------------------------------------------------------------------
# Language → file-extension mapping
# ---------------------------------------------------------------------------
LANGUAGE_EXTENSIONS = {
    "python":     [".py"],
    "javascript": [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"],
    "java":       [".java"],
    "php":        [".php"],
    "ruby":       [".rb"],
    "go":         [".go"],
}

ALL_EXTENSIONS = sorted({ext for exts in LANGUAGE_EXTENSIONS.values() for ext in exts})

# ---------------------------------------------------------------------------
# Helper to build a rule dict
# ---------------------------------------------------------------------------

def _rule(
    rule_id: str,
    pattern: str,
    severity: str,
    description: str,
    owasp_category: str,
    cwe: str,
    languages: list[str] | None = None,
    flags: int = re.IGNORECASE,
) -> dict:
    return {
        "id": rule_id,
        "pattern": re.compile(pattern, flags),
        "severity": severity,
        "description": description,
        "owasp_category": owasp_category,
        "cwe": cwe,
        "languages": languages or ["*"],
    }


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

RULES: list[dict] = [
    # ── Hardcoded Secrets ──────────────────────────────────────────────
    _rule(
        "SECRET-001",
        r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9/+=_\-]{16,}['"]""",
        "CRITICAL",
        "Hardcoded API key detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),
    _rule(
        "SECRET-002",
        r"""(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{4,}['"]""",
        "CRITICAL",
        "Hardcoded password detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),
    _rule(
        "SECRET-003",
        r"""(?:secret|token|auth[_-]?token|access[_-]?token|bearer)\s*[:=]\s*['"][A-Za-z0-9/+=_\-]{8,}['"]""",
        "CRITICAL",
        "Hardcoded secret or token detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),
    _rule(
        "SECRET-004",
        r"""(?:aws_secret_access_key|aws_access_key_id)\s*[:=]\s*['"][A-Za-z0-9/+=]{16,}['"]""",
        "CRITICAL",
        "Hardcoded AWS credential detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),
    _rule(
        "SECRET-005",
        r"""-----BEGIN\s(?:RSA|DSA|EC|OPENSSH)?\s*PRIVATE\sKEY-----""",
        "CRITICAL",
        "Private key embedded in source code",
        "A02:2021 - Cryptographic Failures",
        "CWE-321",
    ),
    _rule(
        "SECRET-006",
        r"""ghp_[A-Za-z0-9]{36}""",
        "CRITICAL",
        "GitHub personal access token detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),
    _rule(
        "SECRET-007",
        r"""xox[bporas]-[A-Za-z0-9\-]{10,}""",
        "CRITICAL",
        "Slack token detected",
        "A02:2021 - Cryptographic Failures",
        "CWE-798",
    ),

    # ── SQL Injection ──────────────────────────────────────────────────
    _rule(
        "SQLI-001",
        r"""(?:execute|query|cursor\.execute)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*|['"].*\.format\s*\()""",
        "HIGH",
        "Possible SQL injection via string formatting in query",
        "A03:2021 - Injection",
        "CWE-89",
        ["python"],
    ),
    _rule(
        "SQLI-002",
        r"""(?:SELECT|INSERT|UPDATE|DELETE)\s+.*\+\s*(?:req\.|request\.|params\.|query\.)""",
        "HIGH",
        "SQL query built with unsanitised request input",
        "A03:2021 - Injection",
        "CWE-89",
    ),
    _rule(
        "SQLI-003",
        r"""(?:createQuery|createNativeQuery|prepareStatement)\s*\(\s*['"].*\+""",
        "HIGH",
        "SQL query built by string concatenation (Java)",
        "A03:2021 - Injection",
        "CWE-89",
        ["java"],
    ),
    _rule(
        "SQLI-004",
        r"""\$(?:wpdb|pdo|mysqli)\s*->\s*(?:query|prepare)\s*\(\s*['"].*\.\s*\$""",
        "HIGH",
        "SQL query built with variable interpolation (PHP)",
        "A03:2021 - Injection",
        "CWE-89",
        ["php"],
    ),

    # ── Cross-Site Scripting (XSS) ─────────────────────────────────────
    _rule(
        "XSS-001",
        r"""(?:innerHTML|outerHTML)\s*=\s*(?!['"]<)""",
        "HIGH",
        "Direct DOM innerHTML assignment — potential XSS",
        "A03:2021 - Injection",
        "CWE-79",
        ["javascript"],
    ),
    _rule(
        "XSS-002",
        r"""document\.write\s*\(""",
        "HIGH",
        "document.write usage — potential XSS vector",
        "A03:2021 - Injection",
        "CWE-79",
        ["javascript"],
    ),
    _rule(
        "XSS-003",
        r"""dangerouslySetInnerHTML""",
        "HIGH",
        "React dangerouslySetInnerHTML — potential XSS",
        "A03:2021 - Injection",
        "CWE-79",
        ["javascript"],
    ),
    _rule(
        "XSS-004",
        r"""\beval\s*\(""",
        "HIGH",
        "eval() usage — code injection risk",
        "A03:2021 - Injection",
        "CWE-94",
    ),
    _rule(
        "XSS-005",
        r"""\|\s*safe\b""",
        "MEDIUM",
        "Django/Jinja2 |safe filter disables auto-escaping",
        "A03:2021 - Injection",
        "CWE-79",
        ["python"],
    ),

    # ── Command Injection ──────────────────────────────────────────────
    _rule(
        "CMDI-001",
        r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.Popen|subprocess\.run)\s*\(\s*(?:f['"]|['"].*%|.*\+)""",
        "CRITICAL",
        "OS command built with dynamic input — command injection risk",
        "A03:2021 - Injection",
        "CWE-78",
        ["python"],
    ),
    _rule(
        "CMDI-002",
        r"""(?:exec|shell_exec|passthru|system|popen)\s*\(\s*\$""",
        "CRITICAL",
        "PHP command execution with variable input",
        "A03:2021 - Injection",
        "CWE-78",
        ["php"],
    ),
    _rule(
        "CMDI-003",
        r"""Runtime\.getRuntime\(\)\.exec\s*\(""",
        "HIGH",
        "Java Runtime.exec — potential command injection",
        "A03:2021 - Injection",
        "CWE-78",
        ["java"],
    ),
    _rule(
        "CMDI-004",
        r"""child_process\.\s*(?:exec|execSync|spawn|spawnSync)\s*\(""",
        "HIGH",
        "Node.js child_process execution — review input sanitisation",
        "A03:2021 - Injection",
        "CWE-78",
        ["javascript"],
    ),
    _rule(
        "CMDI-005",
        r"""`[^`]*\$\{.*\}[^`]*`""",
        "MEDIUM",
        "Shell command in backtick template literal with interpolation",
        "A03:2021 - Injection",
        "CWE-78",
        ["ruby"],
    ),

    # ── Insecure Deserialization ───────────────────────────────────────
    _rule(
        "DESER-001",
        r"""pickle\.loads?\s*\(""",
        "HIGH",
        "Python pickle deserialization — arbitrary code execution risk",
        "A08:2021 - Software and Data Integrity Failures",
        "CWE-502",
        ["python"],
    ),
    _rule(
        "DESER-002",
        r"""yaml\.load\s*\([^)]*(?!Loader)""",
        "HIGH",
        "PyYAML unsafe load — use yaml.safe_load instead",
        "A08:2021 - Software and Data Integrity Failures",
        "CWE-502",
        ["python"],
    ),
    _rule(
        "DESER-003",
        r"""ObjectInputStream\s*\(""",
        "HIGH",
        "Java ObjectInputStream deserialization — review trust boundary",
        "A08:2021 - Software and Data Integrity Failures",
        "CWE-502",
        ["java"],
    ),
    _rule(
        "DESER-004",
        r"""unserialize\s*\(\s*\$""",
        "HIGH",
        "PHP unserialize with user input — object injection risk",
        "A08:2021 - Software and Data Integrity Failures",
        "CWE-502",
        ["php"],
    ),
    _rule(
        "DESER-005",
        r"""Marshal\.load\s*\(""",
        "HIGH",
        "Ruby Marshal.load — arbitrary code execution risk",
        "A08:2021 - Software and Data Integrity Failures",
        "CWE-502",
        ["ruby"],
    ),

    # ── Path Traversal ─────────────────────────────────────────────────
    _rule(
        "PATH-001",
        r"""(?:open|read|write|File)\s*\(.*(?:req\.|request\.|params\.|query\.|\.get\()""",
        "HIGH",
        "File operation with request-derived path — path traversal risk",
        "A01:2021 - Broken Access Control",
        "CWE-22",
    ),
    _rule(
        "PATH-002",
        r"""\.\.(?:/|\\)""",
        "MEDIUM",
        "Path traversal sequence (../) found in source",
        "A01:2021 - Broken Access Control",
        "CWE-22",
    ),
    _rule(
        "PATH-003",
        r"""send_file\s*\(.*(?:request|params)""",
        "HIGH",
        "Flask send_file with user-controlled path",
        "A01:2021 - Broken Access Control",
        "CWE-22",
        ["python"],
    ),

    # ── Weak Cryptography ──────────────────────────────────────────────
    _rule(
        "CRYPTO-001",
        r"""(?:md5|MD5)\s*[.(]""",
        "MEDIUM",
        "MD5 hash usage — cryptographically broken",
        "A02:2021 - Cryptographic Failures",
        "CWE-327",
    ),
    _rule(
        "CRYPTO-002",
        r"""(?:sha1|SHA1|SHA-1)\s*[.(]""",
        "MEDIUM",
        "SHA-1 hash usage — considered weak",
        "A02:2021 - Cryptographic Failures",
        "CWE-327",
    ),
    _rule(
        "CRYPTO-003",
        r"""(?:DES|RC4|RC2|Blowfish)(?:\.|\s|_)""",
        "HIGH",
        "Weak or deprecated cipher algorithm",
        "A02:2021 - Cryptographic Failures",
        "CWE-327",
    ),
    _rule(
        "CRYPTO-004",
        r"""random\.random\s*\(|Math\.random\s*\(""",
        "MEDIUM",
        "Non-cryptographic PRNG used — do not use for security purposes",
        "A02:2021 - Cryptographic Failures",
        "CWE-330",
    ),

    # ── Insecure HTTP ──────────────────────────────────────────────────
    _rule(
        "HTTP-001",
        r"""http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])""",
        "MEDIUM",
        "Plaintext HTTP URL — use HTTPS instead",
        "A02:2021 - Cryptographic Failures",
        "CWE-319",
    ),
    _rule(
        "HTTP-002",
        r"""verify\s*=\s*False""",
        "HIGH",
        "TLS certificate verification disabled",
        "A02:2021 - Cryptographic Failures",
        "CWE-295",
        ["python"],
    ),
    _rule(
        "HTTP-003",
        r"""rejectUnauthorized\s*:\s*false""",
        "HIGH",
        "Node.js TLS certificate verification disabled",
        "A02:2021 - Cryptographic Failures",
        "CWE-295",
        ["javascript"],
    ),
    _rule(
        "HTTP-004",
        r"""CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0|FALSE)""",
        "HIGH",
        "cURL SSL peer verification disabled",
        "A02:2021 - Cryptographic Failures",
        "CWE-295",
        ["php"],
    ),

    # ── Debug / Misconfiguration ───────────────────────────────────────
    _rule(
        "DEBUG-001",
        r"""(?:DEBUG|debug)\s*[:=]\s*(?:True|true|1|'1'|"1")""",
        "MEDIUM",
        "Debug mode enabled — disable in production",
        "A05:2021 - Security Misconfiguration",
        "CWE-489",
    ),
    _rule(
        "DEBUG-002",
        r"""(?:FLASK_DEBUG|DJANGO_DEBUG)\s*=\s*(?:1|True|true)""",
        "HIGH",
        "Web framework debug mode enabled in config",
        "A05:2021 - Security Misconfiguration",
        "CWE-489",
        ["python"],
    ),
    _rule(
        "DEBUG-003",
        r"""console\.log\s*\(.*(?:password|token|secret|key|credential)""",
        "MEDIUM",
        "Sensitive data logged to console",
        "A09:2021 - Security Logging and Monitoring Failures",
        "CWE-532",
        ["javascript"],
    ),
    _rule(
        "DEBUG-004",
        r"""(?:binding\.pry|byebug|debugger)""",
        "LOW",
        "Debugger statement left in code",
        "A05:2021 - Security Misconfiguration",
        "CWE-489",
        ["ruby", "javascript"],
    ),
    _rule(
        "DEBUG-005",
        r"""(?:CORS|cors).*(?:\*|allow_all|AllowAllOrigins)""",
        "MEDIUM",
        "Overly permissive CORS configuration",
        "A05:2021 - Security Misconfiguration",
        "CWE-942",
    ),

    # ── Broken Access Control ──────────────────────────────────────────
    _rule(
        "AUTH-001",
        r"""@app\.route\s*\([^)]*\)\s*\ndef\s+\w+""",
        "LOW",
        "Flask route without explicit authentication decorator — verify access control",
        "A01:2021 - Broken Access Control",
        "CWE-862",
        ["python"],
        flags=re.IGNORECASE | re.MULTILINE,
    ),
    _rule(
        "AUTH-002",
        r"""chmod\s+(?:777|666|o\+w)""",
        "MEDIUM",
        "Overly permissive file permissions",
        "A01:2021 - Broken Access Control",
        "CWE-732",
    ),
]

# ---------------------------------------------------------------------------
# Severity ordering (for filtering)
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}
