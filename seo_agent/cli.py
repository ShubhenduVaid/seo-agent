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
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=0,
        help="Optional crawl depth to sample internal pages for template-level issues (0 disables crawling).",
    )
    parser.add_argument(
        "--crawl-limit",
        type=int,
        default=5,
        help="Maximum number of additional pages to sample when crawling (only used if depth > 0 or --crawl-sitemaps).",
    )
    parser.add_argument(
        "--crawl-delay",
        type=float,
        default=0.3,
        help="Minimum delay (seconds) between crawl requests; the agent honors the greater of this and robots.txt crawl-delay.",
    )
    parser.add_argument(
        "--crawl-sitemaps",
        action="store_true",
        help="Seed crawl from sitemap URLs (respects --crawl-limit).",
    )
    parser.add_argument(
        "--report",
        help="Optional path to write the report output to a file (respects --format).",
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

    agent = SeoAuditAgent(verify_ssl=not args.insecure, output_format=args.format, crawl_delay=args.crawl_delay)
    report, issues = agent.audit_with_details(
        url,
        goal or "",
        crawl_depth=args.crawl_depth,
        crawl_limit=args.crawl_limit,
        include_sitemaps=args.crawl_sitemaps,
    )
    print(report)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError as exc:
            print(f"Could not write report to {args.report}: {exc}")

    if args.fail_on_critical and any(i.severity == "critical" for i in issues):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
