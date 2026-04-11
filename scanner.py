#!/usr/bin/env python3
"""
scanner.py — Static vulnerability scanner for source code.

Scans source files for common security vulnerabilities using regex-based
pattern matching.  Supports multiple languages, severity filtering, OWASP
Top 10 category mapping, and JSON/terminal output.

Usage:
    python3 scanner.py --path ./my-project
    python3 scanner.py --path ./src --severity high --format json --output report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

from rules import (
    RULES,
    LANGUAGE_EXTENSIONS,
    ALL_EXTENSIONS,
    SEVERITY_ORDER,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "1.0.0"

DEFAULT_IGNORE_DIRS = {
    ".git",
    ".svn",
    ".hg",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    ".idea",
    ".vscode",
    ".tox",
    "vendor",
    ".mypy_cache",
    ".pytest_cache",
    "eggs",
    "*.egg-info",
}

SEVERITY_COLOURS: dict[str, str] = {}
if HAS_COLOR:
    SEVERITY_COLOURS = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH":     Fore.RED,
        "MEDIUM":   Fore.YELLOW,
        "LOW":      Fore.CYAN,
    }

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single vulnerability finding."""
    rule_id: str
    severity: str
    description: str
    owasp_category: str
    cwe: str
    file: str
    line: int
    snippet: str
    match: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Aggregated scan results."""
    target: str
    files_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0

    # -- Statistics helpers -------------------------------------------------

    @property
    def total(self) -> int:
        return len(self.findings)

    def count_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def count_by_owasp(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.owasp_category] = counts.get(f.owasp_category, 0) + 1
        return counts

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "files_scanned": self.files_scanned,
            "total_findings": self.total,
            "duration_seconds": round(self.duration_seconds, 3),
            "severity_summary": self.count_by_severity(),
            "owasp_summary": self.count_by_owasp(),
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Scanner engine
# ---------------------------------------------------------------------------

class VulnerabilityScanner:
    """Core scanning engine."""

    def __init__(
        self,
        severity_threshold: str = "LOW",
        languages: list[str] | None = None,
        exclude_patterns: list[str] | None = None,
    ):
        self.severity_threshold = SEVERITY_ORDER.get(severity_threshold.upper(), 0)
        self.languages = [lang.lower() for lang in languages] if languages else None
        self.exclude_dirs = set(DEFAULT_IGNORE_DIRS)
        if exclude_patterns:
            self.exclude_dirs.update(exclude_patterns)

        # Pre-filter rules by language
        self.rules = self._filter_rules()

    # -- Rule filtering -----------------------------------------------------

    def _filter_rules(self) -> list[dict]:
        """Return rules applicable to selected languages and severity."""
        filtered = []
        for rule in RULES:
            if SEVERITY_ORDER[rule["severity"]] < self.severity_threshold:
                continue
            if self.languages and "*" not in rule["languages"]:
                if not any(lang in rule["languages"] for lang in self.languages):
                    continue
            filtered.append(rule)
        return filtered

    # -- File discovery -----------------------------------------------------

    def _allowed_extensions(self) -> set[str]:
        if self.languages:
            exts: set[str] = set()
            for lang in self.languages:
                exts.update(LANGUAGE_EXTENSIONS.get(lang, []))
            return exts
        return set(ALL_EXTENSIONS)

    def _should_ignore(self, name: str) -> bool:
        return name in self.exclude_dirs or name.startswith(".")

    def discover_files(self, root: str | Path) -> Iterator[Path]:
        """Yield source files under *root*, respecting ignore rules."""
        root = Path(root)
        if root.is_file():
            yield root
            return

        allowed = self._allowed_extensions()
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune ignored directories in-place
            dirnames[:] = [
                d for d in dirnames if not self._should_ignore(d)
            ]
            for fname in filenames:
                fpath = Path(dirpath) / fname
                if fpath.suffix.lower() in allowed:
                    yield fpath

    # -- Scanning -----------------------------------------------------------

    def _rules_for_file(self, filepath: Path) -> list[dict]:
        """Return rules applicable to a specific file extension."""
        ext = filepath.suffix.lower()
        # Determine which language(s) match this extension
        file_langs: set[str] = set()
        for lang, exts in LANGUAGE_EXTENSIONS.items():
            if ext in exts:
                file_langs.add(lang)

        applicable = []
        for rule in self.rules:
            if "*" in rule["languages"]:
                applicable.append(rule)
            elif file_langs & set(rule["languages"]):
                applicable.append(rule)
        return applicable

    def scan_file(self, filepath: Path) -> list[Finding]:
        """Scan a single file and return findings."""
        findings: list[Finding] = []
        try:
            text = filepath.read_text(errors="replace")
        except (OSError, PermissionError):
            return findings

        lines = text.splitlines()
        applicable_rules = self._rules_for_file(filepath)

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") and len(stripped) < 3:
                continue
            for rule in applicable_rules:
                if rule["pattern"].search(line):
                    match_obj = rule["pattern"].search(line)
                    findings.append(Finding(
                        rule_id=rule["id"],
                        severity=rule["severity"],
                        description=rule["description"],
                        owasp_category=rule["owasp_category"],
                        cwe=rule["cwe"],
                        file=str(filepath),
                        line=lineno,
                        snippet=line.strip()[:200],
                        match=match_obj.group(0)[:120] if match_obj else "",
                    ))
        return findings

    def scan(self, target: str | Path) -> ScanReport:
        """Run a full scan on *target* (file or directory)."""
        report = ScanReport(target=str(target))
        start = time.monotonic()

        for filepath in self.discover_files(target):
            report.files_scanned += 1
            report.findings.extend(self.scan_file(filepath))

        report.duration_seconds = time.monotonic() - start
        # Sort findings: critical first
        report.findings.sort(
            key=lambda f: -SEVERITY_ORDER.get(f.severity, 0)
        )
        return report


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

class TerminalFormatter:
    """Colour-coded terminal output."""

    @staticmethod
    def format(report: ScanReport) -> str:
        lines: list[str] = []
        header = "=" * 70
        lines.append(header)
        lines.append("  VULNERABILITY SCAN REPORT")
        lines.append(header)
        lines.append(f"  Target:   {report.target}")
        lines.append(f"  Files:    {report.files_scanned}")
        lines.append(f"  Findings: {report.total}")
        lines.append(f"  Duration: {report.duration_seconds:.2f}s")
        lines.append(header)
        lines.append("")

        if not report.findings:
            lines.append("  No vulnerabilities found. Nice work!")
            lines.append("")
            return "\n".join(lines)

        for finding in report.findings:
            sev = finding.severity
            colour = SEVERITY_COLOURS.get(sev, "") if HAS_COLOR else ""
            reset = Style.RESET_ALL if HAS_COLOR else ""

            lines.append(f"  {colour}[{sev}]{reset} {finding.rule_id} — {finding.description}")
            lines.append(f"    File:  {finding.file}:{finding.line}")
            lines.append(f"    OWASP: {finding.owasp_category}  |  {finding.cwe}")
            lines.append(f"    Code:  {finding.snippet}")
            lines.append("")

        # Summary
        lines.append(header)
        lines.append("  SUMMARY BY SEVERITY")
        lines.append(header)
        for sev, count in report.count_by_severity().items():
            if count:
                colour = SEVERITY_COLOURS.get(sev, "") if HAS_COLOR else ""
                reset = Style.RESET_ALL if HAS_COLOR else ""
                lines.append(f"    {colour}{sev:10s}{reset}  {count}")

        lines.append("")
        lines.append(header)
        lines.append("  SUMMARY BY OWASP CATEGORY")
        lines.append(header)
        for cat, count in sorted(report.count_by_owasp().items()):
            lines.append(f"    {cat:50s}  {count}")

        lines.append("")
        return "\n".join(lines)


class JsonFormatter:
    """JSON output."""

    @staticmethod
    def format(report: ScanReport) -> str:
        return json.dumps(report.to_dict(), indent=2)


FORMATTERS = {
    "terminal": TerminalFormatter,
    "json": JsonFormatter,
}

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Static vulnerability scanner with OWASP Top 10 mapping",
    )
    parser.add_argument(
        "--path", "-p",
        required=True,
        help="File or directory to scan",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write report to this file (default: stdout)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["terminal", "json"],
        default="terminal",
        dest="fmt",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["low", "medium", "high", "critical"],
        default="low",
        help="Minimum severity to report (default: low)",
    )
    parser.add_argument(
        "--language", "-l",
        nargs="*",
        choices=list(LANGUAGE_EXTENSIONS.keys()),
        default=None,
        help="Limit scan to specific language(s)",
    )
    parser.add_argument(
        "--exclude", "-e",
        nargs="*",
        default=None,
        help="Additional directory names to exclude",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path).resolve()
    if not target.exists():
        print(f"Error: path '{args.path}' does not exist.", file=sys.stderr)
        return 1

    scanner = VulnerabilityScanner(
        severity_threshold=args.severity,
        languages=args.language,
        exclude_patterns=args.exclude,
    )

    report = scanner.scan(target)

    formatter = FORMATTERS[args.fmt]
    output = formatter.format(report)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code: non-zero if critical or high findings exist
    severity_counts = report.count_by_severity()
    if severity_counts.get("CRITICAL", 0) or severity_counts.get("HIGH", 0):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
