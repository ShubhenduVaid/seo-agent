# Roadmap: make this the best SEO CLI agent

This roadmap focuses on making the CLI consistently produce accurate, evidence-backed, and high-impact recommendations that users can implement and validate, while keeping the project maintainable and secure.

## Product goals (what “best” means)

1. **Actionable and measurable**: every finding maps to a clear fix, expected outcome, and how to verify (ideally with commands or metrics).
2. **Evidence-backed**: show *why* a recommendation was triggered (values, snippets, URLs), reducing false positives and guesswork.
3. **Prioritized by impact and effort**: order issues into a realistic execution plan, not just severity buckets.
4. **Repeatable improvements**: support baselines and diffs so users can see progress after fixes.
5. **Safe and polite**: strong defaults for timeouts, size limits, robots compliance, and secure network behavior.
6. **Extensible**: adding a new check should be simple and testable; optional integrations should not bloat core runtime.

## Current strengths

- Dependency-free runtime (stdlib only).
- Goal-aware scoring and "Top 5 priorities".
- Optional crawl sampling with duplicate title/description summary.
- CI-friendly output options (`--format json`, `--fail-on-critical`, `--quiet`).

## Current gaps to close

- Checks are implemented as a monolith (`SeoAuditAgent` methods), which makes scaling and tuning harder.
- Issues don’t carry structured evidence/metrics; report is mostly prose.
- No concept of effort, impact, or “quick wins”; prioritization is limited.
- Network fetch reads full bodies into memory; no explicit max size guardrails.
- Crawl/robots logic is intentionally simple (prefix matching) and will miss edge cases.
- No baseline/diff workflow to validate improvements over time.

## Plan of action (phased)

### Phase 1 — Foundation: structure, schema, and maintainability

**Outcome:** stable internal models, clearer separation of responsibilities, and a forward-compatible JSON schema.

- Introduce a structured `Issue` schema:
  - `id` (stable identifier), `severity`, `category`
  - `evidence` (metrics/snippets/urls), `impact`, `effort`, `confidence`
  - keep `what/steps/outcome/validation` for human-readability
- Extract checks into a registry:
  - `checks/` package with one file per check (or per category)
  - uniform signature: `(context) -> list[Issue]`
  - metadata-driven severity/priority computation
- Add internal “scoring/prioritization” layer:
  - compute `priority` using severity + goal weighting + impact/effort
  - render a “Next actions” section: top tasks with concrete order
- Strengthen types and boundaries:
  - tighten `OutputFormat` and public APIs
  - unit tests for scoring/prioritization

### Phase 2 — Accuracy & evidence: reduce false positives, add proof

**Outcome:** recommendations are trustworthy and come with the “why” and “where”.

- Add evidence collection for each check:
  - measured title length, meta description length, header presence, script counts, etc.
  - include sampled URLs when crawl findings apply site-wide
- Make checks more defensive and context-aware:
  - avoid flagging templated pages incorrectly (e.g., empty HTML due to JS rendering)
  - reduce noisy recommendations on thin pages vs product pages (heuristic page-type inference)
- Improve robots parsing and allowance checks (still stdlib):
  - handle multiple user-agent blocks and precedence more robustly
  - keep a safe/fallback behavior when robots is unreachable

### Phase 3 — Crawl & scale: better sampling, performance, and safety

**Outcome:** faster audits, better site-wide insights, safer networking defaults.

- Introduce a crawl “budget” model:
  - max pages, max depth, max time, min delay
  - per-host rate limiting and request retries (bounded)
- Add fetch guardrails:
  - maximum HTML size (and report when truncated)
  - content-type filtering (skip non-HTML)
  - redirect-chain limits and canonicalization of URLs
- Improve internal link extraction:
  - normalize fragments/queries consistently
  - detect repeated template URLs and prioritize unique paths

### Phase 4 — UX that drives outcomes: workflows and reporting

**Outcome:** users can turn output into a tracked remediation plan.

- Add baseline + diff:
  - `--save-baseline path.json`
  - `--compare path.json` producing “fixed/regressed/new” deltas
- Add output templates:
  - “Jira ticket” / “GitHub issue” markdown format
  - “Executive summary” mode for stakeholders
- Add “focus modes” aligned to goals:
  - `--mode migration|performance|indexing|security` (or infer from `--goal`)

### Phase 5 — Optional integrations (keep core dependency-free)

**Outcome:** richer recommendations using authoritative data sources, without bloating core runtime.

- Google Search Console integration (optional):
  - index coverage, page experience, query/CTR signals to prioritize fixes
- PageSpeed Insights / Lighthouse JSON ingestion (optional):
  - correlate audit findings with real perf metrics
- Allow “plugins” to live behind extras:
  - core remains stdlib; integrations can be opt-in via optional dependencies

## Documentation and engineering practices

- Add docs:
  - architecture (`docs/ARCHITECTURE.md`)
  - output schema and examples (`docs/OUTPUT_SCHEMA.md`)
  - check authoring guide (`docs/CHECKS.md`)
- Keep clean code:
  - small functions, cohesive modules, explicit types, deterministic outputs
  - high-signal tests around parsing/scoring and edge cases
- Security posture:
  - restrict schemes to `http/https`
  - safe defaults for timeouts, size limits, redirect limits
  - clarify SSRF risk if used as a service (document + config allow/deny lists)
