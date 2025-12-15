from __future__ import annotations

import urllib.parse

from seo_agent.models import AuditContext, Issue

from .html import get_canonicals, get_meta
from .types import CheckEnv


def check_duplicate_and_canonical(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    canonicals = get_canonicals(analyzer)
    canonical = canonicals[0] if canonicals else None
    issues: list[Issue] = []
    if len(canonicals) > 1:
        issues.append(
            Issue(
                id="crawl.canonical_multiple",
                severity="important",
                category="crawl",
                title="Multiple canonical tags detected",
                what=f"{len(canonicals)} canonical link tags were found; multiple canonicals can confuse indexing signals.",
                steps=[
                    "Keep exactly one canonical tag per page.",
                    "Remove duplicate canonicals introduced by templates, plugins, or client-side frameworks.",
                    "Ensure the remaining canonical is absolute and points to the preferred URL.",
                ],
                outcome="Cleaner canonical signals and more stable indexing of the preferred URL.",
                validation="View source and confirm there is exactly one rel='canonical' link tag.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"canonical_count": len(canonicals), "canonicals": canonicals[:3]},
            )
        )
    if not canonical:
        issues.append(
            Issue(
                id="crawl.canonical_missing",
                severity="important",
                category="crawl",
                title="Canonical tag missing",
                what="No rel='canonical' found; duplicate content signals may be unclear to search engines.",
                steps=[
                    "Add a self-referencing canonical tag in the <head> pointing to the preferred URL.",
                    "Ensure parameters or alternate variations point canonicals to the primary version.",
                    "Keep canonical URLs consistent with sitemaps and internal links.",
                ],
                outcome="Clear duplication signals and stable indexing of the preferred URL.",
                validation="View source and confirm canonical is present and absolute; check in Search Console's URL Inspection.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"canonical_count": len(canonicals), "canonical": None},
            )
        )

    elif canonical:
        parsed_final = urllib.parse.urlparse(context.final_url)
        parsed_canonical = urllib.parse.urlparse(canonical)
        if parsed_canonical.netloc and parsed_canonical.netloc.lower() != parsed_final.netloc.lower():
            issues.append(
                Issue(
                    id="crawl.canonical_cross_host",
                    severity="important",
                    category="crawl",
                    title="Canonical points to a different host",
                    what=f"Canonical URL points to {parsed_canonical.netloc}, which differs from the page host {parsed_final.netloc}.",
                    steps=[
                        "Ensure the canonical uses the same primary domain as the page unless intentionally consolidating.",
                        "Check redirects and internal links to align with the canonical host.",
                        "Update sitemaps to match the canonical host.",
                    ],
                    outcome="Consistent canonical signals and fewer cross-domain consolidation issues.",
                    validation="Inspect the canonical tag and confirm it matches the preferred host.",
                    impact="medium",
                    effort="low",
                    confidence="medium",
                    evidence={"canonical": canonical, "canonical_host": parsed_canonical.netloc, "page_host": parsed_final.netloc},
                )
            )

    meta_robots = get_meta(analyzer, "robots")
    if meta_robots and "nofollow" in meta_robots.get("content", "").lower():
        issues.append(
            Issue(
                id="crawl.meta_robots_nofollow",
                severity="important",
                category="crawl",
                title="Meta robots nofollow set sitewide",
                what="Meta robots contains 'nofollow'; internal links will not pass equity for this page.",
                steps=[
                    "Remove 'nofollow' from meta robots where crawling is desired.",
                    "Use page-level rel='nofollow' only for specific links that need it.",
                    "Confirm server headers do not override with X-Robots-Tag: nofollow.",
                ],
                outcome="Internal links can pass PageRank and improve crawl flow.",
                validation="Inspect meta robots after deploy; Search Console should show 'index, follow'.",
                impact="medium",
                effort="low",
                confidence="high",
                evidence={"meta_robots": meta_robots.get("content", "")},
            )
        )

    return issues


def check_canonical_target(context: AuditContext, env: CheckEnv) -> list[Issue]:
    canonicals = get_canonicals(context.analyzer)
    if not canonicals:
        return []
    canonical_href = canonicals[0]
    canonical_url = urllib.parse.urljoin(context.final_url, canonical_href)

    res = env.head(canonical_url, verify_ssl=env.verify_ssl, timeout=env.timeout, user_agent=env.user_agent)
    if res.error or not res.status_code:
        return []
    if res.status_code == 405:
        return []

    if res.status_code >= 400:
        return [
            Issue(
                id="crawl.canonical_target_error",
                severity="important",
                category="crawl",
                title="Canonical points to a non-200 URL",
                what=f"Canonical URL returned HTTP {res.status_code}; canonical targets should be reachable (200) and indexable.",
                steps=[
                    "Update the canonical tag to point to the final, indexable 200 URL.",
                    "Fix redirects/chains so canonicals, internal links, and sitemaps align.",
                    "Confirm the canonical target is not blocked by robots/noindex.",
                ],
                outcome="Canonical signals consolidate properly and indexing stabilizes on the preferred URL.",
                validation="Fetch the canonical target and confirm HTTP 200 with the correct content.",
                impact="high",
                effort="medium",
                confidence="medium",
                evidence={"canonical_url": canonical_url, "status_code": res.status_code},
            )
        ]

    if 300 <= res.status_code < 400:
        return [
            Issue(
                id="crawl.canonical_target_redirect",
                severity="recommended",
                category="crawl",
                title="Canonical points to a redirect",
                what=f"Canonical URL returned HTTP {res.status_code}; canonicals should point directly to the final destination.",
                steps=[
                    "Update the canonical tag to the final destination URL (after redirects).",
                    "Avoid canonical-to-redirect patterns across templates.",
                    "Align sitemaps and internal links to the canonical destination.",
                ],
                outcome="Cleaner canonical consolidation with fewer crawl hops.",
                validation="Fetch the canonical URL and confirm it returns HTTP 200 without redirecting.",
                impact="medium",
                effort="low",
                confidence="medium",
                evidence={"canonical_url": canonical_url, "status_code": res.status_code},
            )
        ]

    return []
