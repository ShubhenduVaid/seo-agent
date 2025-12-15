# Implementation TODO (backlog)

This TODO list is derived from `docs/ROADMAP.md` and is meant to be worked top-to-bottom.

Legend:
- **P0**: enables other work / safety-critical
- **P1**: high impact, near-term
- **P2**: medium impact / longer-term

## P0 — Foundations (make changes easy and safe)

- [x] Define a stable `Issue` schema (`id`, `evidence`, `impact`, `effort`, `confidence`) and update `seo_agent/models.py` + renderers.
- [x] Add `--timeout` and `--user-agent` CLI flags (wired through to fetch/head/robots loaders).
- [x] Add URL scheme validation (only `http`/`https`) and clear error messaging for unsupported schemes.
- [x] Add fetch size guardrails (max HTML bytes, content-type filtering) and surface truncation/skip evidence in the report.
- [x] Split checks into a registry (`seo_agent/checks/`) and make `SeoAuditAgent` orchestration-only.

## P1 — Prioritization and better output (drive real improvements)

- [x] Add impact/effort-based prioritization and render a “Next actions (recommended order)” section.
- [x] Emit `check_id` + evidence in JSON output and document it (`docs/OUTPUT_SCHEMA.md`).
- [x] Add “quick wins” grouping (high impact, low effort) to text/markdown output.
- [x] Add richer evidence for existing checks (title/description lengths, header values, counts, examples).

## P1 — Crawl improvements (more reliable site-wide insights)

- [x] Add crawl budget controls (max pages, max seconds, max depth) and keep polite crawling.
- [x] Improve same-host URL normalization (strip fragments, normalize trailing slashes consistently, handle query canonicalization).
- [x] Improve robots parsing precedence (multiple user-agent sections; conservative behavior on ambiguity).

## P2 — Baselines and diffs (prove improvements)

- [x] Add `--save-baseline <path>` to persist JSON output deterministically.
- [x] Add `--compare <path>` to generate a diff report (fixed/regressed/new issues).
- [x] Add tests for baseline determinism and diff behavior.

## P2 — New checks (high-signal additions only)

- [x] Detect missing/incorrect `lang` attribute and charset hints.
- [x] Detect multiple canonicals and canonical to non-200/redirect targets (via HEAD/GET sampling).
- [x] Detect broken internal links in crawl sample (bounded link-checking).
- [x] Detect duplicate H1/title patterns across crawl sample (template-level issues).

## P2 — Optional integrations (behind flags/extras)

- [x] Design plugin interface and optional dependency strategy (keep core stdlib-only).
- [x] Add optional PageSpeed Insights ingestion for real CWV metrics (no-op if not configured).
- [x] Add optional Search Console integration to prioritize issues by impressions/clicks.
