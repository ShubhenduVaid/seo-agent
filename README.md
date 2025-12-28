# SEO Audit Agent

[![CI](https://github.com/ShubhenduVaid/seo-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/ShubhenduVaid/seo-agent/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%3E%3D70%25-brightgreen)](#)
[![License](https://img.shields.io/github/license/ShubhenduVaid/seo-agent)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](#)

Dependency-free technical SEO audit CLI for quick, actionable site reviews. Built for developers, SEO engineers, and teams who want fast, deterministic audits that work locally or in CI.

## Why SEO Audit Agent

- Dependency-free runtime (stdlib only) with fast setup
- Actionable recommendations prioritized by impact, effort, and confidence
- Optional crawl sampling and link checks to catch template-level issues
- CI-friendly JSON/Markdown output, baseline diffs, and quiet mode
- Offline enrichers for PageSpeed and Search Console exports

## Quick start

```bash
seo-agent https://example.com --goal "traffic growth"
```

If running from source:

```bash
python3 -m seo_agent https://example.com --goal "traffic growth"
```

- If `--goal` is omitted, the agent asks for your main objective before auditing.
- If you hit SSL certificate errors, re-run with `--insecure` (only when you trust the site).

## Requirements

- Python 3.9 or newer
- Network access to fetch the target page and `robots.txt`

## Installation

### PyPI (recommended)

```bash
pipx install seo-agent
# or
pip install seo-agent
```

If the package is not published yet, install from source:

### From source

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
seo-agent <url> [--goal "primary objective"] [--insecure]
```

Examples:

- `seo-agent https://example.com --goal "traffic growth"`
- `seo-agent https://example.com --insecure`
- `seo-agent https://example.com --format json --quiet` (machine-readable output)
- `seo-agent https://example.com --fail-on-critical` (exit non-zero if critical issues found; good for CI)
- `seo-agent https://example.com --crawl-depth 1 --crawl-limit 5` (sample a handful of internal pages)
- `seo-agent https://example.com --crawl-sitemaps --crawl-limit 8` (seed crawl from sitemaps)
- `seo-agent https://example.com --crawl-depth 1 --crawl-delay 0.5` (polite crawl with delay; honors robots.txt crawl-delay)
- `seo-agent https://example.com --crawl-include "/blog/*" --crawl-exclude "*/tag/*"` (scope crawl sampling)
- `seo-agent https://example.com --report /tmp/report.txt` (also write the report to a file)
- `seo-agent --list-checks` (show available checks)
- `seo-agent --version`
- `seo-agent --config ./seo-agent.ini https://example.com` (use shared defaults from a config file)
- `seo-agent https://example.com --format sarif --report ./reports/seo.sarif` (SARIF for code scanning)
- `seo-agent https://example.com --format github` (GitHub Actions summary format)

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

Crawl filters use glob patterns against URLs or paths (e.g., `/blog/*`, `*/search*`). Excludes always win.

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

## Output formats

- Default `text`
- `--format json` for structured output (good for CI)
- `--format markdown` for docs/issue comments
- `--format sarif` for GitHub code scanning / SARIF-compatible tooling
- `--format github` for GitHub Actions job summaries
- `--report <path>` to write the rendered output to a file
- `--quiet` skips interactive prompts (useful in CI)
- `--fail-on-critical` exits non-zero if critical issues are found (useful for CI gates)

## Configuration file

Use an INI file to keep repeatable defaults and team presets.

```ini
[seo-agent]
url = https://example.com
goal = traffic growth
format = markdown
crawl_depth = 1
crawl_limit = 8
crawl_delay = 0.5
crawl_sitemaps = true
crawl_include = /blog/*
crawl_exclude = /search*, /tag/*
check_links = true
report = reports/seo-report.md
fail_on_critical = true
```

Run with:

```bash
seo-agent --config ./seo-agent.ini
```

CLI flags always override config values. Unknown keys in the config will be reported unless `--quiet` is set.

## GitHub Action

Use the official GitHub Action to run audits in CI and publish a job summary:

```yaml
- uses: ShubhenduVaid/seo-agent@v0.4.0
  with:
    url: https://example.com
    goal: traffic growth
    format: github
    fail_on_critical: true
    extra_args: --crawl-depth 1 --crawl-limit 5 --crawl-exclude "/search*"
```

See `docs/GITHUB_ACTION.md` for full usage.

## Baselines and comparisons

- `--save-baseline <path>` saves a JSON snapshot of issues
- `--compare <path>` compares current issues to a previous baseline
- Useful for tracking improvements across releases and migrations

## Integrations (offline)

- `--psi-json <path>`: include PageSpeed/Lighthouse metrics from a local JSON export
- `--gsc-pages-csv <path>`: weight priorities using Search Console Pages export data

See `docs/INTEGRATIONS.md` for instructions on generating these files.

## Documentation

- `docs/CLI_REFERENCE.md` - full CLI reference and examples
- `docs/ARCHITECTURE.md` - current architecture and data flow
- `docs/OUTPUT_SCHEMA.md` - JSON output schema for `--format json`
- `docs/INTEGRATIONS.md` - PageSpeed and Search Console offline enrichers
- `docs/TROUBLESHOOTING.md` - common issues and fixes
- `docs/ROADMAP.md` - project direction and future features
- `docs/DISCOVERABILITY.md` - GitHub visibility checklist
- `docs/GITHUB_ACTION.md` - GitHub Action usage
- `CHANGELOG.md` - release notes

## Development

Run the CLI locally while iterating:

```bash
seo-agent https://example.com --goal "traffic growth"
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

## Packaging and release

Build a wheel/sdist locally (requires `build` if not already installed):

```bash
python3 -m pip install --upgrade build
python3 -m build
```

This produces artifacts under `dist/`. Update the version in `seo_agent/__init__.py` and `pyproject.toml`, and add notes to `CHANGELOG.md` before tagging a release.

GitHub Actions CI:
- Pull requests and main branch: installs in editable mode and runs lint (ruff), mypy, and `python -m unittest discover -v` with coverage >= 70%.
- Tag pushes matching `v*`: builds sdist/wheel and publishes to PyPI using OIDC (`pypa/gh-action-pypi-publish`). Configure PyPI trusted publisher for the repo before tagging.

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for filing issues, proposing features, and submitting pull requests.

## Security

To report a vulnerability, follow the process outlined in `SECURITY.md`. Please avoid filing public GitHub issues for security reports.

## License

This project is available under the MIT License. See `LICENSE` for details.
