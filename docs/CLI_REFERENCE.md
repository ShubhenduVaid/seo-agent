# CLI Reference

Use `seo-agent --help` for the full help output. This page documents the most common options and workflows.

## Basic usage

```bash
seo-agent <url> [options]
```

If running from source:

```bash
python3 -m seo_agent <url> [options]
```

## General options

- `--config <path>` - load defaults from an INI config file
- `--goal "..."` - primary objective (traffic growth, technical cleanup, migration prep)
- `--timeout <seconds>` - network timeout for requests
- `--user-agent "..."` - custom User-Agent header
- `--insecure` - skip SSL verification (use only when you trust the site)
- `--quiet` - suppress prompts and non-essential messages (CI-friendly)
- `--version` - print version and exit
- `--list-checks` - list built-in checks and exit

## Configuration

Create a `seo-agent.ini` (or any INI file) with defaults:

```ini
[seo-agent]
goal = traffic growth
format = json
crawl_depth = 1
crawl_limit = 10
crawl_delay = 0.5
check_links = true
crawl_include = /blog/*
crawl_exclude = /search*, /tag/*
```

Run with:

```bash
seo-agent --config ./seo-agent.ini https://example.com
```

CLI flags always override config values.

## Output and automation

- `--format text|json|markdown|sarif` - output format (default: text)
- `--report <path>` - write the rendered report to a file
- `--fail-on-critical` - exit with status 2 if any critical issues are found

## Crawl sampling

- `--crawl-depth <n>` - crawl depth for internal sampling (0 disables)
- `--crawl-limit <n>` - max number of additional pages to sample
- `--crawl-delay <seconds>` - delay between crawl requests
- `--crawl-max-seconds <seconds>` - time budget for crawling (0 disables)
- `--crawl-sitemaps` - seed crawl from sitemap URLs
- `--crawl-include <pattern>` - include only matching URLs in crawl sampling (glob patterns)
- `--crawl-exclude <pattern>` - exclude matching URLs from crawl sampling (glob patterns)

Patterns are simple glob matches against the URL or path (examples: `/blog/*`, `*/search*`). Excludes always win.

## Link checks

- `--check-links` - enable bounded internal link checking (HEAD requests)
- `--link-check-limit-per-page <n>` - cap HEAD checks per page (default: 3)

## Baselines

- `--save-baseline <path>` - save a JSON baseline snapshot
- `--compare <path>` - compare against a previously saved baseline

## Integrations (offline)

- `--psi-json <path>` - include PageSpeed/Lighthouse metrics from a JSON export
- `--gsc-pages-csv <path>` - weight priorities using Search Console Pages export data

## Plugins

- `--enable-plugins` - load checks exposed via the `seo_agent.checks` entry-point group

## Examples

```bash
seo-agent https://example.com --goal "traffic growth"
seo-agent https://example.com --format json --fail-on-critical --quiet
seo-agent https://example.com --crawl-depth 1 --crawl-limit 10 --crawl-delay 0.5
seo-agent https://example.com --save-baseline /tmp/seo-baseline.json
seo-agent https://example.com --compare /tmp/seo-baseline.json
seo-agent https://example.com --psi-json ./lighthouse.json
seo-agent https://example.com --gsc-pages-csv ./gsc-pages.csv
seo-agent https://example.com --format sarif --report ./reports/seo.sarif
seo-agent https://example.com --crawl-include "/blog/*" --crawl-exclude "*/tag/*"
```
