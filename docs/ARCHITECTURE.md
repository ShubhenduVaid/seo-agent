## Architecture (current)

This project is a dependency-free (runtime) Python CLI that performs a technical SEO audit for a single URL, optionally sampling a handful of internal pages, and returns a prioritized report with actionable recommendations.

### Design constraints

- Runtime: Python standard library only (no external dependencies).
- CLI-first: works well for local runs and CI (`--format json`, `--fail-on-critical`, `--quiet`).
- Deterministic: output is rule/heuristic-based (no LLM calls).

### High-level flow

1. CLI parses args and collects `url` and optional `goal` (`seo_agent/cli.py`).
2. The agent normalizes the URL and fetches HTML (`seo_agent/network.py:normalize_url`, `seo_agent/network.py:fetch_url`).
3. HTML is parsed into a lightweight structure (`seo_agent/analyzer.py:SimpleHTMLAnalyzer`).
4. `robots.txt` is fetched and sitemaps are discovered (`seo_agent/network.py:load_robots_and_sitemaps`).
5. A registry of check functions runs and emits structured `Issue` objects (`seo_agent/checks/`, `seo_agent/checks/registry.py`).
6. Optional: a small crawl samples additional internal pages (BFS) and runs a subset of checks on them (`include_on_crawled_pages`).
7. The report is rendered in `text`, `markdown`, or `json` with a priority-ordered action list (`seo_agent/reporting.py`).

### Key modules

- `seo_agent/cli.py`
  - Defines CLI arguments and constructs `SeoAuditAgent`.
  - Outputs the rendered report and optionally writes to `--report`.
  - Exit code: `2` when `--fail-on-critical` and any critical issues exist.
- `seo_agent/audit.py`
  - `SeoAuditAgent.audit_with_details()` orchestrates fetching/parsing and executes checks.
  - Built-in checks are loaded via `seo_agent/checks/registry.py` and run with a `CheckEnv` containing network helpers and flags.
  - Crawl sampling uses same-host URL collection and `seo_agent/robots.py` rules for allow/disallow and crawl-delay.
  - Dependencies are injectable (fetch/head/robots loaders) to support tests.
- `seo_agent/checks/`
  - Built-in check implementations (one module per check area).
  - `registry.py` defines which checks run by default and optionally loads plugin checks (entry points group: `seo_agent.checks`).
- `seo_agent/analyzer.py`
  - `SimpleHTMLAnalyzer` (stdlib `HTMLParser`) collects only what checks need:
    - `<title>`, headings, meta/link tags, `<a href>`, `<script>`, `<img>`, JSON-LD blocks.
- `seo_agent/network.py`
  - `fetch_url()` does a full GET and returns HTML + headers + timing + size.
  - `head_request()` supports lightweight asset/header checks.
  - `load_robots_and_sitemaps()` fetches `robots.txt` and extracts `Sitemap:` directives.
  - `load_sitemap_urls()` fetches a small sample of sitemap URLs for crawl seeding.
- `seo_agent/robots.py`
  - Parses `robots.txt` into rules and evaluates allow/disallow against URL paths (with conservative precedence).
- `seo_agent/baseline.py`
  - Saves baseline JSON and produces diffs for `--compare` (fixed/new/regressed) so users can validate improvements over time.
- `seo_agent/integrations/`
  - Offline enrichers for optional inputs like PageSpeed/Lighthouse JSON and Search Console CSV exports.
- `seo_agent/models.py`
  - Dataclasses for `AuditContext`, `Issue`, and network results (`FetchResult`, `HeadResult`, `RobotsResult`).
- `seo_agent/reporting.py`
  - Groups issues by severity and renders the report.
  - Computes a score and priority ordering with `impact` / `effort` / `confidence` signals and goal-aware weighting.

### Testing

- `tests/test_agent.py` focuses on:
  - URL normalization
  - Check coverage (expected issues for given HTML/context)
  - Crawl sampling behavior and summary output
  - JSON rendering and scoring presence

### Extension points (today)

- Dependency injection for network functions (testability):
  - `SeoAuditAgent(fetch_func=..., head_func=..., robots_loader=...)`
- Built-in checks:
  - add a new check under `seo_agent/checks/` and register it in `seo_agent/checks/registry.py`.
- Plugin checks (optional):
  - install a package exposing entry points under group `seo_agent.checks` and run with `--enable-plugins`.
