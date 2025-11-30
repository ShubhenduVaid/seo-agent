# SEO Audit Agent

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

For backward compatibility you can also run `python3 seo_agent.py ...` from the project root.

The report is grouped by severity:
1. Critical Issues - fix immediately (high impact)
2. Important Optimizations - fix soon (medium impact)
3. Recommended Enhancements - nice to have

Each issue includes what is wrong, why it matters, step-by-step fixes, expected outcome, and how to validate.

### What it checks

- Site speed signals: page weight, script count, render-blocking scripts, image sizing, lazy-loading hints (LCP/FID/CLS risk proxies)
- Crawlability: `robots.txt` availability/content, sitemap discovery, meta robots directives
- Mobile optimization: viewport tag and lazy-loading coverage
- Security: HTTPS presence and HSTS header hint
- Structured data: JSON-LD detection
- Internal linking: ratio of internal/external links, low internal link coverage
- Duplicate control: canonical tag presence and follow directives
- Meta and headings: title quality, description presence, H1 usage, hreflang `x-default` hint

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

The project intentionally has no external dependencies. If you add new functionality, prefer the standard library when possible and include coverage (unit or integration tests) for new logic.

Project layout (key modules):
- `seo_agent/cli.py` - CLI argument parsing and entry point
- `seo_agent/audit.py` - auditing logic and checks
- `seo_agent/analyzer.py` - HTML parser used by audits
- `seo_agent/network.py` - network helpers (fetching, robots, normalization)
- `seo_agent/reporting.py` - report rendering and formatting
- `tests/` - unit tests for core utilities and checks

## Packaging and release

Build a wheel/sdist locally (requires `build` if not already installed):

```bash
python3 -m pip install --upgrade build
python3 -m build
```

This produces artifacts under `dist/`. Upload to PyPI with `twine` or your preferred publisher. Update the version in `seo_agent/__init__.py` and `pyproject.toml` before tagging a release.

## Contributing

Contributions are welcome! Please read `CONTRIBUTING.md` for filing issues, proposing features, and submitting pull requests.

## Security

To report a vulnerability, follow the process outlined in `SECURITY.md`. Please avoid filing public GitHub issues for security reports.

## License

This project is available under the MIT License. See `LICENSE` for details.
