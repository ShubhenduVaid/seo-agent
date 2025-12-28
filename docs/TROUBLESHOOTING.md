# Troubleshooting

## SSL certificate errors

If a site uses a self-signed or misconfigured certificate, run with:

```bash
seo-agent https://example.com --insecure
```

Use this only when you trust the target site.

## Timeouts or slow sites

Increase the timeout if a site is slow or blocks long-running requests:

```bash
seo-agent https://example.com --timeout 30
```

## Non-HTML content errors

The audit only supports HTML documents. Ensure you are auditing a page URL (not a PDF or image). If a site uses dynamic routing, try the canonical page URL in the browser first.

## WAF or bot blocking

Some sites block unfamiliar User-Agent strings. Override it with:

```bash
seo-agent https://example.com --user-agent "Mozilla/5.0 (compatible; SEOAuditAgent/1.0)"
```

## Crawl sampling stops early

If the crawl ends early, increase the limits or time budget:

```bash
seo-agent https://example.com --crawl-depth 2 --crawl-limit 20 --crawl-max-seconds 60
```

## JSON output includes extra text

Use `--format json --quiet` to avoid prompts and non-essential output in CI environments.

## Report file fails to write

Ensure the destination path is writable. The CLI will create missing parent directories when possible.
