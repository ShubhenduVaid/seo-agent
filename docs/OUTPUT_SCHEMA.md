# Output schema (JSON)

When running with `--format json`, the CLI prints a single JSON object to stdout.

For SARIF output (`--format sarif`), the CLI emits a SARIF 2.1.0 JSON document with results mapped from audit issues. Severity mapping: `critical` → `error`, `important` → `warning`, `recommended` → `note`.

For GitHub summary output (`--format github`), the CLI emits a concise Markdown summary designed for GitHub Actions job summaries.

## Top-level fields

- `goal` (string): Goal passed via `--goal` (or `"not provided"`).
- `url` (string): Final URL after redirects.
- `status_code` (number): HTTP status code for the audited URL.
- `response_time_ms` (number): Measured fetch duration (best-effort; varies by network).
- `document_size_bytes` (number): Bytes read for the HTML document (may reflect truncation).
- `score` (object):
  - `overall` (number): 0–100 overall score (heuristic).
  - `by_category` (object): Category scores (0–100).
- `top_five` (array): Backward-compatible list of the first 5 items from `top_actions`.
- `top_actions` (array): Recommended action order across all severities (max 8).
- `quick_wins` (array): High-impact, low-effort actions (max 5).
- `issues` (object): Issues grouped by severity:
  - `critical` (array)
  - `important` (array)
  - `recommended` (array)
- `crawl_summary` (object): Optional crawl sampling summary (present when crawl is enabled).
- `compare` (object): Optional baseline comparison (present when `--compare` is used).
- `pagespeed` (object): Optional PageSpeed/Lighthouse metrics (present when `--psi-json` is used).

## Issue object

Each issue in `top_actions`, `top_five`, `quick_wins`, and `issues.*` has:

- `id` (string): Stable identifier (e.g. `content.title_missing`).
- `severity` (string): `critical` | `important` | `recommended`.
- `category` (string): `status` | `crawl` | `performance` | `content` | `links` | `security` | `general`.
- `title` (string): Human-readable title.
- `what` (string): What’s wrong (human-readable, often includes key numbers).
- `steps` (array of strings): Step-by-step remediation.
- `outcome` (string): Expected outcome if fixed.
- `validation` (string): How to validate the fix.
- `page` (string): URL the issue was detected on (set for both the audited URL and sampled crawl pages).
- `impact` (string): `high` | `medium` | `low`.
- `effort` (string): `high` | `medium` | `low`.
- `confidence` (string): `high` | `medium` | `low`.
- `evidence` (object): Machine-readable evidence used to trigger the issue (counts, header values, sample URLs, etc.).
- `priority_score` (number): Computed score used to rank `top_actions` (higher means earlier to fix).

## Notes

- Ordering is deterministic given the same input HTML/headers, but `response_time_ms` varies by environment.
- The schema is designed to be stable for CI use (`--fail-on-critical`) and future diff/baseline workflows.
- If `--gsc-pages-csv` is provided, issues may include `evidence.gsc` with Search Console metrics (e.g., impressions/clicks) and priorities may be boosted for high-impression pages.
