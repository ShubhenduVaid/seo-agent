# SEO Audit Agent

[![CI](https://github.com/ShubhenduVaid/seo-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/ShubhenduVaid/seo-agent/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D70%25-brightgreen)](#)

Lightweight CLI that runs a technical SEO audit for a URL and outputs prioritized, actionable recommendations similar to what you would get from a senior technical SEO specialist. The tool relies only on the Python standard library-no external dependencies required.

## Quick start

```bash
python3 -m seo_agent https://example.com --goal "traffic growth"
```

- If `--goal` is omitted, the agent asks for your main objective before auditing.
- If you hit SSL certificate errors, re-run with `--insecure` (only when you trust the site).

## Requirements

- Python 3.9 or newer
- Network access to fetch the target page and `robots.txt`

## Installation

```bash
git clone https://github.com/ShubhenduVaid/seo-agent.git
cd seo-agent
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip  # no additional packages required
python3 -m pip install -e .
```

## Usage

```bash
python3 -m seo_agent <url> [--goal "primary objective"] [--insecure]
```

Examples:

- `python3 -m seo_agent https://example.com --goal "traffic growth"`
- `python3 -m seo_agent https://example.com --insecure`
- `python3 -m seo_agent https://example.com --format json --quiet` (machine-readable output)
- `python3 -m seo_agent https://example.com --fail-on-critical` (exit non-zero if critical issues found; good for CI)
- `python3 -m seo_agent https://example.com --crawl-depth 1 --crawl-limit 5` (sample a handful of internal pages)
- `python3 -m seo_agent https://example.com --crawl-sitemaps --crawl-limit 8` (seed crawl from sitemaps)
- `python3 -m seo_agent https://example.com --crawl-depth 1 --crawl-delay 0.5` (polite crawl with delay; honors robots.txt crawl-delay)
- `python3 -m seo_agent https://example.com --report /tmp/report.txt` (also write the report to a file)

For backward compatibility you can also run `python3 seo_agent.py ...` from the project root.

The report is grouped by severity:
1. Critical Issues - fix immediately (high impact)
2. Important Optimizations - fix soon (medium impact)
3. Recommended Enhancements - nice to have

Each issue includes what is wrong, why it matters, step-by-step fixes, expected outcome, and how to validate.
- Reports include HTTP status, a simple score, and top 5 priorities. JSON output includes scores.
- Response time and document size are included for quick Web Vitals triage.
- Goal-aware scoring slightly boosts performance/content/linking issues when goals mention traffic/growth.
- Crawl summary highlights duplicate titles/descriptions across sampled pages.

### What it checks

- Site speed signals: page weight, script count, render-blocking scripts, resource hints, image sizing, lazy-loading hints (LCP/FID/CLS risk proxies)
- Static asset hygiene: cache-control and compression hints for sampled JS/CSS via HEAD requests
- Crawlability: `robots.txt` availability/content, sitemap discovery, meta robots directives, X-Robots-Tag
- Polite crawling: optional limited crawl that honors robots.txt disallow/crawl-delay and rate limits requests
- Redirects: detects when the requested URL redirects to a different host/path
- Mobile optimization: viewport tag and lazy-loading coverage
- Security: HTTPS presence and HSTS header hint
- Security headers: Content-Security-Policy, Referrer-Policy, X-Content-Type-Options, Permissions-Policy, X-Frame-Options
- Response health: HTTP status reporting (4xx/5xx) for the audited URL
- Structured data: JSON-LD detection
- Internal linking: ratio of internal/external links, low internal link coverage
- Duplicate control: canonical tag presence, host consistency, follow directives
- Meta and headings: title quality, description presence and length, social meta completeness, H1 usage, hreflang `x-default` hint and absolute hrefs, image alt coverage

### Sample output (truncated)

```
Primary goal: traffic growth
URL audited: https://example.com

1. Critical Issues - fix immediately (high impact)
- Title tag missing
  What: No <title> found; search results will lack a meaningful headline and relevance signal.
  Fix steps:
    - Add a concise, descriptive <title> (50-60 chars) targeting the primary keyword.
    - Place the most important terms first and keep branding at the end.
    - Avoid duplicating titles across pages; keep them unique.
  Outcome: Stronger relevance signals and improved CTR from SERPs.
  Validate: View source to confirm the title; check Search Console HTML improvements for duplicates.
```

## Development

Run the CLI locally while iterating:

```bash
python3 -m seo_agent https://example.com --goal "traffic growth"
```

Run tests:

```bash
python3 -m unittest discover -v
```

Lint and type check (optional):

```bash
python3 -m pip install -r requirements-dev.txt
python3 -m ruff check .
python3 -m mypy seo_agent
```

### Output formats

- Default `text`
- `--format json` for structured output (good for CI)
- `--format markdown` for docs/issue comments
- `--report <path>` to write the rendered output to a file
- `--quiet` skips interactive prompts (useful in CI)
- `--fail-on-critical` exits non-zero if critical issues are found (useful for CI gates)

The project intentionally has no external dependencies. If you add new functionality, prefer the standard library when possible and include coverage (unit or integration tests) for new logic.

Project layout (key modules):
- `seo_agent/cli.py` - CLI argument parsing and entry point
- `seo_agent/audit.py` - audit orchestration + crawl sampling
- `seo_agent/analyzer.py` - HTML parser used by audits
- `seo_agent/checks/` - built-in checks + registry (optional plugins)
- `seo_agent/network.py` - network helpers (fetching, robots, normalization)
- `seo_agent/robots.py` - robots.txt parsing and allow/disallow matching
- `seo_agent/baseline.py` - baseline save/compare (diffs)
- `seo_agent/integrations/` - optional offline data enrichers (PageSpeed/GSC exports)
- `seo_agent/reporting.py` - report rendering and formatting
- `tests/` - unit tests for core utilities and checks

## Roadmap / TODO

- `docs/ARCHITECTURE.md` - current architecture and data flow
- `docs/ROADMAP.md` - plan to evolve into a best-in-class SEO CLI agent
- `docs/TODO.md` - implementation backlog derived from the roadmap
- `docs/OUTPUT_SCHEMA.md` - JSON output schema for `--format json`

## Packaging and release

Build a wheel/sdist locally (requires `build` if not already installed):

```bash
python3 -m pip install --upgrade build
python3 -m build
```

This produces artifacts under `dist/`. Upload to PyPI with `twine` or your preferred publisher. Update the version in `seo_agent/__init__.py` and `pyproject.toml` before tagging a release.

GitHub Actions CI:
- Pull requests and main branch: installs in editable mode and runs lint (ruff), mypy, and `python -m unittest discover -v` with coverage >= 70%.
- Tag pushes matching `v*`: builds sdist/wheel and publishes to PyPI using OIDC (`pypa/gh-action-pypi-publish`). Configure PyPI trusted publisher for the repo before tagging.

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for filing issues, proposing features, and submitting pull requests.

## Security

To report a vulnerability, follow the process outlined in `SECURITY.md`. Please avoid filing public GitHub issues for security reports.

## License

This project is available under the MIT License. See `LICENSE` for details.
