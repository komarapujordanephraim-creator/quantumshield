"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .report import html_report, json_report, text_report
from .rules import SEVERITY_ORDER
from .scanner import scan_path

FAIL_CHOICES = ["critical", "high", "medium", "low", "none"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quantumshield",
        description="Find quantum-vulnerable cryptography in source code.",
    )
    parser.add_argument("--version", action="version", version=f"quantumshield {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan a file or directory")
    scan.add_argument("path", help="file or directory to scan")
    scan.add_argument("--format", choices=["text", "json"], default="text",
                      help="console output format (default: text)")
    scan.add_argument("--html", metavar="FILE", help="also write a standalone HTML report")
    scan.add_argument("--exclude", action="append", default=[], metavar="NAME",
                      help="directory name or relative path to skip (repeatable)")
    scan.add_argument("--fail-on", choices=FAIL_CHOICES, default="high",
                      help="exit with code 1 if a finding at or above this severity exists "
                           "(default: high; use 'none' to never fail)")
    return parser


def _should_fail(result, threshold: str) -> bool:
    if threshold == "none":
        return False
    limit = SEVERITY_ORDER[threshold]
    return any(SEVERITY_ORDER[f.severity] >= limit for f in result.findings)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return 2

    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    result = scan_path(args.path, exclude=args.exclude)

    if args.format == "json":
        print(json_report(result))
    else:
        use_color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        sys.stdout.write(text_report(result, color=use_color))

    if args.html:
        Path(args.html).write_text(html_report(result), encoding="utf-8")
        print(f"HTML report written to {args.html}", file=sys.stderr)

    return 1 if _should_fail(result, args.fail_on) else 0
