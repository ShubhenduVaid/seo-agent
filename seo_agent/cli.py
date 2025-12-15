from __future__ import annotations

import argparse
import json
import sys
from typing import Iterable

from .audit import SeoAuditAgent
from .baseline import build_baseline, diff_baselines, load_baseline, render_diff_markdown, render_diff_text, save_baseline
from .constants import DEFAULT_TIMEOUT, USER_AGENT
from .integrations.pagespeed import load_pagespeed_metrics
from .integrations.search_console import load_gsc_pages_csv
from .network import normalize_url


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
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Network timeout in seconds (default: {DEFAULT_TIMEOUT}).",
    )
    parser.add_argument(
        "--user-agent",
        default=USER_AGENT,
        help="User-Agent header to send with requests.",
    )
    parser.add_argument(
        "--enable-plugins",
        action="store_true",
        help="Enable loading additional checks from installed entry points (group: seo_agent.checks).",
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
        "--crawl-max-seconds",
        type=float,
        default=20.0,
        help="Maximum time budget (seconds) for crawl sampling (0 disables the time limit).",
    )
    parser.add_argument(
        "--crawl-sitemaps",
        action="store_true",
        help="Seed crawl from sitemap URLs (respects --crawl-limit).",
    )
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="Enable bounded internal link checking via HEAD requests (may increase audit time).",
    )
    parser.add_argument(
        "--link-check-limit-per-page",
        type=int,
        default=3,
        help="Maximum number of internal links to HEAD-check per page when --check-links is enabled.",
    )
    parser.add_argument(
        "--report",
        help="Optional path to write the report output to a file (respects --format).",
    )
    parser.add_argument(
        "--save-baseline",
        help="Optional path to save a baseline JSON (issues + metadata) for later comparison.",
    )
    parser.add_argument(
        "--compare",
        help="Optional path to a previously saved baseline JSON to compare against.",
    )
    parser.add_argument(
        "--psi-json",
        help="Optional path to a PageSpeed Insights / Lighthouse JSON file to enrich performance reporting.",
    )
    parser.add_argument(
        "--gsc-pages-csv",
        help="Optional path to a Search Console 'Pages' export CSV to weight priorities by impressions/clicks.",
    )
    return parser.parse_args(list(argv))


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    url = args.url or input("Enter the URL to audit: ").strip()
    if not url:
        print("A URL is required.")
        return 1
    try:
        url = normalize_url(url)
    except ValueError as exc:
        print(f"Invalid URL: {exc}")
        return 1

    goal = args.goal
    if not goal and not args.quiet:
        goal = input("What's your main goal for this audit (traffic growth, technical fixes, migration prep)? ").strip()

    timeout = max(1, int(args.timeout))
    agent = SeoAuditAgent(
        verify_ssl=not args.insecure,
        user_agent=args.user_agent,
        timeout=timeout,
        output_format=args.format,
        crawl_delay=args.crawl_delay,
        check_links=args.check_links,
        link_check_limit_per_page=args.link_check_limit_per_page,
        enable_plugins=args.enable_plugins,
    )
    page_metrics = None
    if args.gsc_pages_csv:
        try:
            page_metrics = load_gsc_pages_csv(args.gsc_pages_csv)
        except OSError as exc:
            if not args.quiet:
                print(f"Could not load Search Console CSV from {args.gsc_pages_csv}: {exc}")

    report, issues = agent.audit_with_details(
        url,
        goal or "",
        crawl_depth=args.crawl_depth,
        crawl_limit=args.crawl_limit,
        include_sitemaps=args.crawl_sitemaps,
        crawl_max_seconds=args.crawl_max_seconds,
        page_metrics=page_metrics,
    )

    output = report
    current_baseline = None
    if args.save_baseline or args.compare:
        current_baseline = build_baseline(url, goal or "", issues)

    if args.save_baseline and current_baseline is not None:
        save_baseline(args.save_baseline, current_baseline)

    if args.compare and current_baseline is not None:
        baseline = load_baseline(args.compare)
        diff = diff_baselines(baseline, current_baseline)
        if args.format == "json" and output.lstrip().startswith("{"):
            data = json.loads(output)
            data["compare"] = {"baseline_path": args.compare, **diff}
            output = json.dumps(data, indent=2)
        elif args.format == "markdown":
            output = f"{output}\n\n{render_diff_markdown(diff)}"
        else:
            output = f"{output}\n\n{render_diff_text(diff)}"

    if args.psi_json:
        try:
            metrics = load_pagespeed_metrics(args.psi_json)
        except (OSError, json.JSONDecodeError) as exc:
            if not args.quiet:
                print(f"Could not load PageSpeed JSON from {args.psi_json}: {exc}")
        else:
            if args.format == "json" and output.lstrip().startswith("{"):
                data = json.loads(output)
                data["pagespeed"] = metrics
                output = json.dumps(data, indent=2)
            elif args.format == "markdown":
                lines = ["## PageSpeed metrics"]
                for k, v in metrics.items():
                    if v is None:
                        continue
                    lines.append(f"- **{k}:** {v}")
                output = f"{output}\n\n" + "\n".join(lines)
            else:
                lines = ["PageSpeed metrics"]
                for k, v in metrics.items():
                    if v is None:
                        continue
                    lines.append(f"- {k}: {v}")
                output = f"{output}\n\n" + "\n".join(lines)

    print(output)
    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as f:
                f.write(output)
        except OSError as exc:
            print(f"Could not write report to {args.report}: {exc}")

    if args.fail_on_critical and any(i.severity == "critical" for i in issues):
        return 2
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry
    sys.exit(main())
