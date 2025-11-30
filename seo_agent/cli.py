from __future__ import annotations

import argparse
import sys
from typing import Iterable

from .audit import SeoAuditAgent


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a technical SEO audit for a URL.")
    parser.add_argument("url", nargs="?", help="URL to audit (e.g., https://example.com)")
    parser.add_argument("--goal", help="Primary goal for the audit (traffic growth, technical cleanup, migration prep, etc.)")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip SSL certificate verification (use only if certificate errors block auditing).",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format. Defaults to text.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Quiet mode: suppresses non-essential prompts/errors; useful for CI.",
    )
    parser.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit with non-zero status if critical issues are found (good for CI gates).",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    url = args.url or input("Enter the URL to audit: ").strip()
    if not url:
        print("A URL is required.")
        return 1

    goal = args.goal
    if not goal and not args.quiet:
        goal = input("What's your main goal for this audit (traffic growth, technical fixes, migration prep)? ").strip()

    agent = SeoAuditAgent(verify_ssl=not args.insecure, output_format=args.format)
    report, issues = agent.audit_with_details(url, goal or "")
    print(report)

    if args.fail_on_critical and any(i.severity == "critical" for i in issues):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
