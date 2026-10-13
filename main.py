from __future__ import annotations

import argparse
from pathlib import Path

from scanner import scan_file, scan_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze log or text data for common cyber threat indicators.")
    parser.add_argument("path", nargs="?", help="Path to a file to analyze")
    parser.add_argument("--stdin", action="store_true", help="Read input from standard input")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.stdin:
        text = __import__("sys").stdin.read()
        result = scan_text(text)
    elif args.path:
        result = scan_file(Path(args.path))
    else:
        example = """2026-10-13 10:42:33 powershell -enc JABjAG ...
GET http://malware.example/loader.exe
password=admin123
"""
        result = scan_text(example)

    print(f"Risk level: {result.risk_level}")
    print(f"Summary: {result.summary}")
    if not result.findings:
        print("No suspicious indicators found.")
        return 0

    for finding in result.findings:
        print(f"- [{finding.severity}] Line {finding.line_no}: {finding.category} -> {finding.message}")

    return 0 if result.risk_level in {"Low", "Medium"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
