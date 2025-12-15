from __future__ import annotations

import urllib.parse

from seo_agent.models import AuditContext, Issue

from .types import CheckEnv


def check_internal_links(context: AuditContext, _env: CheckEnv) -> list[Issue]:
    analyzer = context.analyzer
    parsed = urllib.parse.urlparse(context.final_url)
    domain = parsed.netloc.lower()
    internal = 0
    external = 0
    for href in analyzer.links:
        parsed_href = urllib.parse.urlparse(href)
        if not parsed_href.netloc or parsed_href.netloc.lower() == domain:
            internal += 1
        else:
            external += 1

    issues: list[Issue] = []
    if internal < 10:
        issues.append(
            Issue(
                id="links.low_internal_linking",
                severity="important",
                category="links",
                title="Low internal linking on the page",
                what="Few internal links detected; link equity and crawl flow are limited.",
                steps=[
                    "Add contextual links to related high-value pages using descriptive anchor text.",
                    "Ensure primary navigation and breadcrumbs are present and crawlable.",
                    "Surface links to orphan or deep pages that need authority.",
                ],
                outcome="Stronger crawl paths, better PageRank distribution, and improved topical signals.",
                validation="Re-crawl with Screaming Frog/Sitebulb; internal link counts should increase.",
                impact="medium",
                effort="medium",
                confidence="medium",
                evidence={"internal_links": internal, "external_links": external},
            )
        )

    if external > internal * 2 and external > 20:
        issues.append(
            Issue(
                id="links.external_links_dominate",
                severity="recommended",
                category="links",
                title="External links dominate over internal links",
                what=f"{external} external links vs {internal} internal links; excessive externals can dilute link equity.",
                steps=[
                    "Prioritize internal linking to key pages before linking out.",
                    "Use rel='nofollow' or rel='sponsored' where appropriate for external references.",
                    "Group external references and keep anchors concise.",
                ],
                outcome="Better retention of link equity and clearer site architecture.",
                validation="Re-run crawl and verify internal/external link ratio improves.",
                impact="low",
                effort="low",
                confidence="medium",
                evidence={"internal_links": internal, "external_links": external},
            )
        )

    return issues
